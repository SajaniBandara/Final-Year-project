#!/usr/bin/env python3
"""Collect the run set the demo GUI needs, including the two missing baselines.

Two batches, run through the GUI's own :class:`gui.backend.runner.RunManager` so
they exercise exactly the path the demo will use on the night.

**Batch A -- demo runs.** One full-stack MOBIGUARD run per attack variant plus
the benign baseline. These are what the Attack Lab opens on, and because they go
through the runner they get an ``.attackers.json`` roster sidecar -- which is
what makes the spot-the-attacker reveal work at all.

**Batch B -- SOTA baselines.** The implementation plan recorded these as
"BLOCKED on the HPC: B1 TAP produced no local output, B3 eFADE's 48 result files
are all header-only". That diagnosis was wrong, and no HPC data was needed.
Both baselines are gated on a flag combination nobody had run:

* ``fade_detection_active = (variant in 4..7) && !enable_lrad_obu &&
  !enable_lrad_rsu`` (routing.cc ~144745). Every existing HF run had LRAD on, so
  eFADE's detection loop was inert and it wrote a header and nothing else.
* TAP needs ``--enable_tap=1`` with both LRAD engines off, the same isolation
  convention (``scripts/run_std_attacks.py``'s ``TAP_PARAMS``).

Both isolations are deliberate: ``record_detection_event()`` buckets by the
CLI-selected variant rather than by the firing signature, so running a baseline
beside the full stack would misattribute MOBIGUARD's own S1/S2 triggers into the
variant under test and corrupt MOBIGUARD's numbers, not just the baseline's.
That is also why these runs write no ``MOBIGUARD_*.csv`` -- see
``writes_metrics_csv()``.

Usage::

    python -m scripts.gui_demo_runs --batch all --sim-time 60 --workers 4
    python -m scripts.gui_demo_runs --batch baselines --dry-run

Shared-host etiquette: this refuses to start when the host is already loaded,
and caps concurrency. Check ``uptime`` first if in doubt.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gui.backend import runner as R  # noqa: E402


@dataclass(frozen=True)
class Job:
    """One planned simulation."""

    name: str
    tag: str
    values: dict[str, Any]
    defences: dict[str, bool]
    note: str


def demo_jobs(sim_time: float, pct: int, seed: int) -> list[Job]:
    """Full-stack MOBIGUARD, one per variant plus the benign baseline."""
    jobs = [
        Job(
            "benign", f"DEMO0s{seed}",
            {"attack_number": 0, "attack_percentage": 0,
             "simTime": sim_time, "sim_seed": seed},
            {},
            "false-positive floor: anything a detector reports here is an FP",
        )
    ]
    for attack in range(1, 9):
        jobs.append(Job(
            f"attack{attack}", f"DEMO{attack}s{seed}",
            {"attack_number": attack, "attack_percentage": pct,
             "simTime": sim_time, "sim_seed": seed},
            {},
            f"attack {attack} at {pct}%, full MOBIGUARD stack",
        ))
    return jobs


def baseline_jobs(sim_time: float, pct: int, seed: int) -> list[Job]:
    """The B1 and B3 comparators, in the isolation each requires."""
    jobs = [
        Job(
            "tap-attack2", f"TAP2s{seed}",
            {"attack_number": 2, "attack_percentage": pct,
             "simTime": sim_time, "sim_seed": seed, "enable_tap": True},
            {"lrad": False},
            "B1 TAP (Arsalan & Rehman, FIT 2018). Comparable on Attack 2 only; "
            "writes TAP_Attack2_*.csv",
        )
    ]
    # eFADE covers variants 5-8 and is inert outside them.
    for attack in (5, 6, 7, 8):
        jobs.append(Job(
            f"efade-attack{attack}", f"FADE{attack}s{seed}",
            {"attack_number": attack, "attack_percentage": pct,
             "simTime": sim_time, "sim_seed": seed},
            {"lrad": False},
            f"B3 eFADE on attack {attack}; writes fade_results_*.csv with rows "
            "rather than a bare header",
        ))
    return jobs


async def run_job(manager: R.RunManager, job: Job, quiet: bool) -> dict[str, Any]:
    started = time.time()
    try:
        record = await manager.start({**job.values, "run_tag": job.tag}, job.defences)
    except R.RunnerError as exc:
        print(f"  [skip] {job.name}: {exc}")
        return {"name": job.name, "state": "skipped", "error": str(exc)}

    if not quiet:
        print(f"  [start] {job.name} pid={record.pid} tag={job.tag}")
    while record.state in (R.RunState.STARTING, R.RunState.RUNNING):
        await asyncio.sleep(5)
    elapsed = time.time() - started
    flag = "ok" if record.state is R.RunState.FINISHED else record.state.value
    print(
        f"  [{flag}] {job.name} in {elapsed:.0f}s"
        f" | cycles={record.cycles_done}"
        f" | attackers={len(record.attackers)}"
        + (f" | {record.error}" if record.error else "")
    )
    return {
        "name": job.name, "tag": job.tag, "state": record.state.value,
        "elapsed_s": round(elapsed), "cycles": record.cycles_done,
        "attackers": len(record.attackers), "error": record.error,
        "metrics": record.metrics_path.name if record.emits_metrics else None,
    }


async def main_async(args: argparse.Namespace) -> int:
    env = R.detect_environment()
    problems = env.problems()
    if problems:
        print("Cannot run:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    load = R.host_load()
    print(f"host: load {load['load1']} over {load['cores']} cores, "
          f"{load['free_gb']} GB free, {load['simulations_on_host']} sims running")
    print(f"build profile: {env.build_profile()}")
    if env.build_profile() != "optimized":
        print("  WARNING: not an optimized build; expect roughly 12x the wall time.")
    # Shared host: refuse rather than pile on. The threshold is deliberately
    # generous -- this only catches a machine already busy with someone's sweep.
    if load["load1"] > load["cores"] * 0.6 and not args.force:
        print("Host is already loaded. Re-run with --force if you are sure.")
        return 1

    jobs: list[Job] = []
    if args.batch in ("demo", "all"):
        jobs += demo_jobs(args.sim_time, args.pct, args.seed)
    if args.batch in ("baselines", "all"):
        jobs += baseline_jobs(args.sim_time, args.pct, args.seed)

    manager = R.RunManager(env)
    print(f"\n{len(jobs)} job(s), {args.workers} at a time, "
          f"simTime={args.sim_time:g}s each\n")
    for job in jobs:
        plan = manager.plan({**job.values, "run_tag": job.tag}, job.defences)
        print(f"  {job.name:16s} {job.note}")
        print(f"  {'':16s} {' '.join(plan['argv'][1:])}")
        for warning in plan["warnings"]:
            print(f"  {'':16s} ! {warning}")
    if args.dry_run:
        print("\n--dry-run: nothing launched.")
        return 0

    semaphore = asyncio.Semaphore(args.workers)

    async def guarded(job: Job) -> dict[str, Any]:
        async with semaphore:
            return await run_job(manager, job, args.quiet)

    print()
    started = time.time()
    results = await asyncio.gather(*(guarded(job) for job in jobs))
    print(f"\nall done in {time.time() - started:.0f}s")

    ok = [r for r in results if r["state"] == "finished"]
    print(f"{len(ok)}/{len(results)} finished")
    for result in results:
        if result["state"] != "finished":
            print(f"  {result['name']}: {result['state']} {result.get('error') or ''}")
    return 0 if len(ok) == len(results) else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--batch", choices=("demo", "baselines", "all"),
                        default="all")
    parser.add_argument("--sim-time", type=float, default=60.0,
                        help="Simulated seconds per run (default 60).")
    parser.add_argument("--pct", type=int, default=60,
                        help="Attacker percentage (default 60).")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--workers", type=int, default=4,
                        help="Concurrent runs. One physical core each.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the commands and exit.")
    parser.add_argument("--force", action="store_true",
                        help="Start even when the host is already loaded.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    # The manager's own cap would otherwise refuse jobs past 4.
    os.environ.setdefault("MOBIGUARD_MAX_CONCURRENT", str(max(args.workers, 4)))
    R.MAX_CONCURRENT = max(R.MAX_CONCURRENT, args.workers)
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
