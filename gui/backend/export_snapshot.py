"""Export a self-contained JSON snapshot of ``results_routing/``.

Every GUI request the Offline Analytics tab (and friends) can make is computed
*once* here, through the same :class:`~gui.backend.service.ResultsService`
the live server uses, and written out as plain JSON. Point the server at the
snapshot afterwards and it never touches ``results_routing/`` again -- useful
for a demo laptop that should not have to carry the HPC's CSVs (some of the
``bc_detection_log_*`` sidecars alone reach ~600MB) or re-copy them before
every run-through.

Usage::

    # everything except the per-run maps (fast, seconds)
    python -m gui.backend.export_snapshot --out gui/snapshots/demo

    # + map scenes for specific runs worth demoing live (still reads their
    # bc_detection_log_* sidecar once, here, so the server never has to)
    python -m gui.backend.export_snapshot --out gui/snapshots/demo \\
        --map-runs MOBIGUARD_Attack1_40_d100ms_seed1 MOBIGUARD_Attack3_60_seed1

    # + maps for every run (slow; only do this if you really want all of them)
    python -m gui.backend.export_snapshot --out gui/snapshots/demo --include-map

Then run the server against it instead of ``results_routing/``::

    # PowerShell
    $env:MOBIGUARD_SNAPSHOT_DIR = "gui/snapshots/demo"
    python -m uvicorn gui.backend.app:app --port 8021

The exported snapshot is plain JSON on disk -- copy the directory anywhere
(a laptop, a USB stick) and it needs nothing else, not even this repo's
``results_routing/``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from . import schema
from .service import ResultsService, ServiceError


def _write(path: Path, data: Any) -> int:
    """Write ``data`` as compact JSON to ``path``, returning the byte count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, separators=(",", ":"))
    path.write_text(text, encoding="utf-8")
    return len(text.encode("utf-8"))


def _kib(n: int) -> str:
    return f"{n / 1024:.1f} KiB"


def export_snapshot(
    out_dir: Path,
    *,
    results_dir: str | None = None,
    include_map: bool = False,
    map_runs: list[str] | None = None,
) -> None:
    """Build a snapshot of every run currently indexed under ``results_dir``.

    Skips (rather than fails on) any panel/run that errors -- a snapshot from
    a partial results copy should still be usable for what it does have,
    exactly like the live server degrades tab-by-tab today.
    """
    service = ResultsService(results_dir)
    catalog_payload = service.list_runs()
    runs = catalog_payload["runs"]
    attack_ids = catalog_payload["attacks"]

    print(f"Source: {service.catalog.results_dir}  ({len(runs)} runs)")

    index: dict[str, Any] = {
        "health": service.health(),
        "catalog": catalog_payload,
        "metric_definitions": {},
        "sweeps": {},
        "panels": {},
        "figures": service.figures(),
    }

    for attack_id in attack_ids:
        index["metric_definitions"][str(attack_id)] = service.metric_definitions(attack_id)

    # Every metric with a known unit/caveat, plus the live KPI set -- the
    # union the frontend's metric picker and Live tab actually ask for.
    metrics_to_sweep = sorted(set(schema.METRIC_UNITS) | set(schema.LIVE_KPI_COLUMNS))
    sweep_count = 0
    for attack_id in attack_ids:
        for metric in metrics_to_sweep:
            try:
                index["sweeps"][f"{attack_id}:{metric}"] = service.sweep(
                    attack_id=attack_id, metric=metric
                )
                sweep_count += 1
            except ServiceError:
                continue
    print(f"Sweeps: {sweep_count} (attack x metric combinations)")

    panels: list[tuple[str, Callable[[], dict[str, Any]]]] = [
        ("baselines", service.baselines_panel),
        ("crypto", service.crypto_panel),
        ("tcam", service.tcam_panel),
        ("lstm", service.lstm_panel),
        ("verification", service.verification_panel),
    ]
    for name, getter in panels:
        try:
            index["panels"][name] = getter()
            print(f"Panel {name}: ok")
        except ServiceError as exc:
            index["panels"][name] = {"error": str(exc)}
            print(f"Panel {name}: skipped -- {exc}")

    total = _write(out_dir / "index.json", index)
    print(f"index.json: {_kib(total)}")

    run_ids = [r["id"] for r in runs]
    for run_id in run_ids:
        run_dir = out_dir / "runs" / run_id
        try:
            size = _write(run_dir / "summary.json", service.run_summary(run_id))
        except ServiceError as exc:
            print(f"  [skip summary] {run_id}: {exc}")
            size = 0
        try:
            size2 = _write(run_dir / "series.json", service.run_series(run_id))
        except ServiceError as exc:
            print(f"  [skip series] {run_id}: {exc}")
            size2 = 0
        print(f"  {run_id}: summary {_kib(size)}, series {_kib(size2)}")

    if map_runs:
        target_map_runs = [r for r in run_ids if r in set(map_runs)]
        missing = set(map_runs) - set(target_map_runs)
        if missing:
            print(f"  [warn] --map-runs not found in catalog, skipped: {sorted(missing)}")
    elif include_map:
        target_map_runs = run_ids
    else:
        target_map_runs = []

    for run_id in target_map_runs:
        try:
            scene = service.map_scene(run_id)
        except ServiceError as exc:
            print(f"  [skip map] {run_id}: {exc}")
            continue
        size = _write(out_dir / "runs" / run_id / "map.json", scene)
        print(f"  {run_id}: map {_kib(size)} ({scene.get('event_count', 0)} events)")

    print(f"\nSnapshot written to {out_dir.resolve()}")
    print("Point the GUI at it with (PowerShell):")
    print(f'  $env:MOBIGUARD_SNAPSHOT_DIR = "{out_dir}"')
    print("  python -m uvicorn gui.backend.app:app --port 8021")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export results_routing/ into a self-contained JSON snapshot.",
    )
    parser.add_argument("--out", required=True, type=Path, help="Directory to write the snapshot into.")
    parser.add_argument(
        "--results-dir", default=None,
        help="Source results_routing/ dir; defaults to $MOBIGUARD_RESULTS_DIR / the repo default.",
    )
    parser.add_argument(
        "--include-map", action="store_true",
        help="Export a map scene for every run. Slow -- reads each run's "
             "bc_detection_log_* sidecar, some of which reach ~600MB.",
    )
    parser.add_argument(
        "--map-runs", nargs="*", default=None, metavar="RUN_ID",
        help="Export map scenes only for these run ids (fast, targeted alternative to --include-map).",
    )
    args = parser.parse_args(argv)
    export_snapshot(
        args.out,
        results_dir=args.results_dir,
        include_map=args.include_map,
        map_runs=args.map_runs,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
