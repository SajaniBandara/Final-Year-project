"""Launching and supervising ns-3 runs from the GUI.

This is what makes "online mode" mean an actual simulation rather than a replay
of a recorded one. The GUI spawns ``build/scratch/routing/routing``, watches the
metrics CSV it writes, and streams both the process log and the decoded cycle
rows to the browser as they appear.

Why the binary directly and not ``./waf --run``
-----------------------------------------------
CLAUDE.md is explicit about both halves of this:

* ``--run`` performs an implicit build check, and concurrent build checks race
  on ``build/compile_commands.json``'s post-build hook. The GUI can have several
  runs in flight, so it must not go through waf.
* Invoking the binary from a bare shell fails with ``error while loading shared
  libraries`` unless ``LD_LIBRARY_PATH`` includes ``build/lib``. That directory
  holds both profiles' ``.so`` files, so setting it is profile-agnostic --
  ``run_training_attacks.py`` does exactly this and is described there as the
  profile-safe launcher.

So: direct ``Popen``, no shell, ``LD_LIBRARY_PATH`` prepended.

Why every GUI run gets a tag
----------------------------
``write_security_metrics_csv()`` opens its output ``ios::out|ios::app``. Two
runs with the same attack/percentage/seed therefore append into *one* file, and
the parser would see a single run with a cycle counter that restarts. Every
launch here is given a unique ``--run_tag``, which ``routing.cc`` appends to
every output filename, so each run owns its files outright and concurrent runs
cannot collide.

Concurrency and shared-host etiquette
-------------------------------------
Simulations are single-threaded and want a physical core each. This host is
shared, so :class:`RunManager` caps concurrent runs (:data:`MAX_CONCURRENT`) and
refuses to start past it rather than letting a demo turn into a fork bomb.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import signal
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from . import params as P
from .catalog import REPO_ROOT

#: Where the ns-3 tree lives. Overridable because the HPC and this workstation
#: put it in different places, and the GUI is expected to run on either.
DEFAULT_NS3_DIR = Path(
    os.environ.get(
        "MOBIGUARD_NS3_DIR",
        Path.home() / "G_13" / "ns-allinone-3.35" / "ns-3.35",
    )
).expanduser()

#: Simulations are single-threaded and want a core each; this host is shared.
MAX_CONCURRENT: int = int(os.environ.get("MOBIGUARD_MAX_CONCURRENT", "4"))

#: Lines of process output kept per run. Enough to diagnose a failure without
#: letting a 300 s run's stdout become a memory leak.
LOG_RING_SIZE: int = 4000

#: Notable events kept per run. S1/S2 fire on close to every attacked packet, so
#: this ring is what stops a long run's event rail from becoming the leak the
#: log ring already guards against.
NOTABLE_RING_SIZE: int = 600

#: How long to wait after SIGTERM before SIGKILL.
TERM_GRACE_S: float = 5.0

#: Substrings that mark a line as worth surfacing in the UI's event rail.
#: These are the unconditional prints -- attack triggers, detections, DKG and
#: blockchain commits -- which stay on regardless of the DEBUG_LOG flags.
NOTABLE_MARKERS: tuple[str, ...] = (
    "TRIGGERED", "[ATTACK DELAY", "[DETECT", "[DKG", "[BLOCKCHAIN",
    "[QUARANTINE", "[FAILOVER", "[WITNESS", "[ESCALAT", "ERROR",
    "Solution not found",
)

# Attacker ground truth exists only on stdout -- no CSV carries it -- and each
# attack family announces itself in a different format. Capturing all of them is
# what lets the map reveal, after the panel has guessed, which nodes were
# actually malicious.
#
# Data-plane Selective Time Delay (Attack 2). One line per *candidate*, so the
# value matters: `= 0` lines are the majority.
#     [ATTACK2] Node 3 selective_delay_malicious = 1
ROSTER_RE = re.compile(
    r"^\[ATTACK\d*\]\s+Node\s+(?P<node>\d+)\s+"
    r"(?P<field>\w+)\s*=\s*(?P<value>[01])\s*$"
)

# Hidden Forwarding (Attacks 5-8). Only malicious nodes are printed, and the
# node may be an RSU or a vehicle acting as a relay -- both are given as logical
# ids, so no translation is needed.
#     [HF SCALE] RSU 217 marked malicious -> eavesdropper=45
#     [HF SCALE] VehicleRelay 12 marked malicious -> eavesdropper=88
HF_ROSTER_RE = re.compile(
    r"^\[HF SCALE\]\s+(?:RSU|VehicleRelay)\s+(?P<node>\d+)\s+marked\s+malicious"
)

# Control-plane ladder (Attack 1; Attack 3 uses the same ladder but prints
# nothing, being guarded on active_attack_variant == 0). This gives a *count*,
# not identities -- but the C++ compromises controllers 0..k-1 in order, so the
# identities follow, and the RSUs they own follow from the nearest-controller
# assignment. `mapview.derive_control_plane_attackers` does that expansion.
#     [ATTACK1] declare_attackers(): attack_percentage=60% -> 2 of 4 controllers compromised.
CP_ROSTER_RE = re.compile(
    r"declare_attackers\(\):\s*attack_percentage=\d+%\s*->\s*(?P<count>\d+)\s+of\s+"
    r"(?P<total>\d+)\s+controllers\s+compromised"
)

#: Its 264-line output would otherwise swamp the event rail, so roster lines are
#: routed to :attr:`RunRecord.attackers` and kept out of `notable`.
NOISE_RE = re.compile(r"^\[ATTACK\d*\]\s+Node\s+\d+\s")


class RunState(str, Enum):
    """Lifecycle of one launched simulation."""

    STARTING = "starting"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunnerError(RuntimeError):
    """The run could not be started, or the environment is not usable."""


@dataclass
class RunRecord:
    """One launched simulation and everything the UI needs to show about it."""

    run_id: str
    tag: str
    argv: list[str]
    values: dict[str, Any]
    sim_time: float
    metrics_path: Path
    started_at: float
    state: RunState = RunState.STARTING
    pid: int | None = None
    exit_code: int | None = None
    finished_at: float | None = None
    cycles_done: int = 0
    error: str | None = None
    #: False for isolated baseline runs, which write no metrics CSV -- see
    #: :func:`writes_metrics_csv`. Progress then falls back to wall time.
    emits_metrics: bool = True
    log: list[str] = field(default_factory=list)
    notable: list[str] = field(default_factory=list)
    #: Node ids ``declare_attackers()`` reported as malicious, parsed from
    #: stdout. Empty for a benign run, and empty until the simulator reaches
    #: its declaration phase a few seconds in.
    attackers: set[int] = field(default_factory=set)
    #: Controllers compromised by the Attack 1/3 ladder. Their identities are
    #: 0..n-1 by construction; the RSUs they own are derived, not printed.
    compromised_controllers: int = 0

    @property
    def elapsed_s(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    @property
    def progress(self) -> float:
        """Fraction complete, 0-1, from cycles written rather than wall time.

        Wall-clock estimates drift badly -- crypto-heavy configs run slower
        because liboqs is already optimised and does not speed up with the rest
        of the tree. Counting rows in the metrics CSV measures the real thing:
        one row per simulated second.
        """
        if self.state is RunState.FINISHED:
            return 1.0
        if not self.emits_metrics:
            # No CSV to count. Fall back to the measured wall-clock rate, which
            # is an estimate and is labelled as one rather than presented with
            # the same authority as a row count.
            expected = self.sim_time * P.WALL_S_PER_SIM_S
            return min(0.99, self.elapsed_s / expected) if expected > 0 else 0.0
        # The simulator writes a row per completed routing cycle, and the final
        # cycle does not always complete before Simulator::Stop -- a 20 s run
        # reliably lands 18 rows. A run that exited 0 is done whatever the row
        # count says, which the FINISHED branch above handles.
        if self.sim_time <= 0:
            return 0.0
        return min(1.0, self.cycles_done / self.sim_time)

    @property
    def eta_s(self) -> float | None:
        """Seconds remaining, extrapolated from this run's own observed rate."""
        if self.state != RunState.RUNNING or not self.emits_metrics:
            return None
        if self.cycles_done < 2:
            return None
        rate = self.elapsed_s / self.cycles_done  # wall-s per sim-s, measured
        return max(0.0, (self.sim_time - self.cycles_done) * rate)

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "tag": self.tag,
            "state": self.state.value,
            "pid": self.pid,
            "exit_code": self.exit_code,
            "command": " ".join(self.argv),
            "values": self.values,
            "sim_time": self.sim_time,
            "metrics_file": self.metrics_path.name,
            "metrics_path": str(self.metrics_path),
            "metrics_exists": self.metrics_path.exists(),
            "emits_metrics": self.emits_metrics,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_s": round(self.elapsed_s, 1),
            "cycles_done": self.cycles_done,
            "progress": round(self.progress, 4),
            "eta_s": None if self.eta_s is None else round(self.eta_s),
            "error": self.error,
            "notable": self.notable[-40:],
            "attackers": sorted(self.attackers),
            "compromised_controllers": self.compromised_controllers,
        }


def writes_metrics_csv(values: dict[str, Any]) -> bool:
    """Whether this configuration produces a ``MOBIGUARD_*.csv`` at all.

    ``write_security_metrics_csv()`` returns early when either the TAP baseline
    is enabled or both LRAD engines are off (routing.cc ~117890). Both are
    deliberate: an isolated baseline run must not append rows produced with
    MOBIGUARD's own detectors disabled into the file the real run writes, since
    the two would be indistinguishable afterwards.

    The consequence for the GUI is that a baseline run has no metrics CSV to
    count rows in, so progress cannot be measured the usual way. Detecting the
    case up front is better than watching a healthy run sit at 0% -- which is
    exactly what it looks like otherwise.
    """
    if values.get("enable_tap"):
        return False
    lrad_obu = values.get("enable_lrad_obu", P.PARAMS_BY_NAME["enable_lrad_obu"].default)
    lrad_rsu = values.get("enable_lrad_rsu", P.PARAMS_BY_NAME["enable_lrad_rsu"].default)
    return bool(lrad_obu or lrad_rsu)


def metrics_filename(values: dict[str, Any], tag: str) -> str:
    """Predict the metrics CSV name ``routing.cc`` will write for these values.

    Mirrors the construction at ``routing.cc`` line ~117906 exactly:
    ``MOBIGUARD_Attack<id>_<pct><delay_suffix>_seed<seed>[_<tag>].csv``.

    Two rules are easy to get wrong and are the reason this is a function rather
    than an f-string at the call site:

    * ``attack_id`` is ``active_attack_variant + 1``, and the benign baseline
      (variant -1) folds into ``Attack0`` -- not a separate ``baseline`` name.
    * ``g_delay_suffix`` is set **only** for attacks 1 and 2, and only when
      ``attack_number`` was given explicitly. For every other variant the delay
      is not injected, so the suffix would be misleading and stays empty.
    """
    def _v(name: str) -> Any:
        # Absent means "flag not passed", which means the binary uses its own
        # default -- so the prediction must use that same default, read from the
        # registry rather than repeated as a literal here. Getting this wrong
        # produces a name that does not exist, and the run then reports 0
        # cycles forever while writing a perfectly good CSV next door.
        if name in values and values[name] is not None:
            return values[name]
        return P.PARAMS_BY_NAME[name].default

    attack = int(_v("attack_number") or 0)
    pct = int(_v("attack_percentage") or 0)
    seed = int(_v("sim_seed") or 1)
    suffix = ""
    if attack in (1, 2):
        suffix = f"_d{int(float(_v('attack_delay_ms')))}ms"
    tag_part = f"_{tag}" if tag else ""
    return f"MOBIGUARD_Attack{attack}_{pct}{suffix}_seed{seed}{tag_part}.csv"


@dataclass(frozen=True)
class Environment:
    """Where the simulator and its inputs live, and whether they are usable."""

    ns3_dir: Path
    binary: Path
    results_dir: Path
    lib_dir: Path

    @property
    def ready(self) -> bool:
        return self.binary.is_file() and os.access(self.binary, os.X_OK)

    def problems(self) -> list[str]:
        """Everything that would make a launch fail, in the order to fix it.

        Checked up front because each of these fails quietly at run time: a
        missing helper aborts mid-run with "Solution not found", and a missing
        LSTM weights file makes the detector silently no-op.
        """
        out: list[str] = []
        if not self.ns3_dir.is_dir():
            out.append(f"ns-3 tree not found at {self.ns3_dir}")
            return out
        if not self.binary.is_file():
            out.append(
                f"simulator not built: {self.binary} is missing "
                f"(run ./waf build in {self.ns3_dir})"
            )
        elif not os.access(self.binary, os.X_OK):
            out.append(f"{self.binary} is not executable")
        if not self.lib_dir.is_dir():
            out.append(f"{self.lib_dir} is missing -- the binary will not link")
        if not self.results_dir.is_dir():
            out.append(f"results directory {self.results_dir} does not exist")
        for helper in ("optimization.py", "optimization_lifetime.py"):
            if not (self.ns3_dir / "scratch" / helper).is_file():
                out.append(
                    f"scratch/{helper} is missing -- runs abort mid-way with "
                    "'Solution not found'"
                )
        return out

    def build_profile(self) -> str:
        """``optimized``/``debug``/``unknown``, read from waf's config cache.

        Reported rather than enforced. CLAUDE.md is clear that ``_cache.py`` can
        disagree with the binary on disk, so this is a hint for the operator,
        not a gate -- a debug build is ~12x slower but still correct.
        """
        cache = self.ns3_dir / "build" / "c4che" / "_cache.py"
        try:
            text = cache.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "unknown"
        m = re.search(r"BUILD_PROFILE\s*=\s*'([^']+)'", text)
        return m.group(1) if m else "unknown"

    def to_json(self) -> dict[str, Any]:
        problems = self.problems()
        return {
            "ns3_dir": str(self.ns3_dir),
            "binary": str(self.binary),
            "results_dir": str(self.results_dir),
            "ready": not problems,
            "problems": problems,
            "build_profile": self.build_profile(),
            "max_concurrent": MAX_CONCURRENT,
        }


def detect_environment(ns3_dir: Path | None = None) -> Environment:
    """Locate the ns-3 tree and the paths that hang off it."""
    root = Path(ns3_dir or DEFAULT_NS3_DIR).expanduser()
    return Environment(
        ns3_dir=root,
        binary=root / "build" / "scratch" / "routing" / "routing",
        results_dir=root / "results_routing",
        lib_dir=root / "build" / "lib",
    )


class RunManager:
    """Owns every simulation this server has launched.

    One instance per process. Runs outlive the browser tab that started them --
    closing the tab must not kill a 300 s simulation -- so records stay here
    until the server exits or :meth:`clear_finished` is called.
    """

    def __init__(self, env: Environment | None = None) -> None:
        self.env = env or detect_environment()
        self._runs: dict[str, RunRecord] = {}
        self._procs: dict[str, asyncio.subprocess.Process] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()

    # -- introspection ------------------------------------------------------

    def get(self, run_id: str) -> RunRecord:
        try:
            return self._runs[run_id]
        except KeyError:
            raise RunnerError(f"no such run {run_id!r}") from None

    def list(self) -> list[RunRecord]:
        """Newest first -- the UI's list reads top-down."""
        return sorted(self._runs.values(), key=lambda r: r.started_at, reverse=True)

    @property
    def active(self) -> list[RunRecord]:
        return [r for r in self._runs.values()
                if r.state in (RunState.STARTING, RunState.RUNNING)]

    def clear_finished(self) -> int:
        """Drop finished records. Returns how many went."""
        done = [r.run_id for r in self._runs.values()
                if r.state not in (RunState.STARTING, RunState.RUNNING)]
        for run_id in done:
            self._runs.pop(run_id, None)
        return len(done)

    # -- launching ----------------------------------------------------------

    def plan(
        self,
        values: dict[str, Any],
        defences: dict[str, bool] | None = None,
        tag: str | None = None,
    ) -> dict[str, Any]:
        """Validate and render a launch without starting it.

        The UI calls this on every form change so the operator can see the exact
        command before committing to it -- which also makes the GUI a usable way
        to *compose* a command to run by hand later.
        """
        merged = P.apply_defences(P.validate(values), defences or {})
        # Precedence: explicit argument, then a tag the caller put in `values`,
        # then a generated one. A caller naming its own tag is how a scripted
        # batch keeps its output files identifiable (DEMO*, TAP*, FADE*).
        run_tag = tag or merged.get("run_tag") or _new_tag()
        merged["run_tag"] = run_tag
        argv = P.build_command(str(self.env.binary), merged)
        sim_time = float(merged.get("simTime", P.PARAMS_BY_NAME["simTime"].default))
        return {
            "command": " ".join(argv),
            "argv": argv,
            "values": merged,
            "tag": run_tag,
            "sim_time": sim_time,
            "metrics_file": metrics_filename(merged, run_tag),
            "est_wall_s": int(round(sim_time * P.WALL_S_PER_SIM_S)),
            "emits_metrics": writes_metrics_csv(merged),
            "warnings": self._warnings(merged),
        }

    def _warnings(self, values: dict[str, Any]) -> list[str]:
        """Non-fatal things worth saying before a run, not after it.

        Each corresponds to a documented silent-failure mode: a config that
        produces a file with no usable content, or a detector that no-ops.
        """
        out: list[str] = []
        if values.get("enable_detector_windows") and values.get("simTime", 0) < 90:
            out.append(
                "Detector-windows CSV needs simTime >= 90 to yield a usable "
                "number of 10 s windows; this run will emit very few."
            )
        if values.get("enable_lstm_inference"):
            weights = REPO_ROOT / "lstm_pipeline" / "lstm_weights_cpp.bin"
            if not weights.is_file():
                out.append(
                    "enable_lstm_inference is on but lstm_pipeline/"
                    "lstm_weights_cpp.bin is missing -- the LSTM will silently "
                    "no-op and flag_LSTM will stay false."
                )
        if values.get("attack_number") in (1, 2):
            delay = float(values.get("attack_delay_ms", 80.0))
            if delay <= 50.0:
                out.append(
                    f"attack_delay_ms={delay:g} is at or below the S2 threshold "
                    "of 50 ms, so S2 will not fire. Intentional only when "
                    "probing the detection boundary."
                )
        if values.get("enable_tap") and values.get("attack_number") != 2:
            out.append(
                "The TAP baseline is only comparable on Attack 2; on other "
                "variants its output is not meaningful."
            )
        if not writes_metrics_csv(values):
            out.append(
                "This is an isolated baseline configuration (TAP enabled, or "
                "both LRAD engines off), so routing.cc writes no "
                "MOBIGUARD_*.csv -- deliberately, so baseline rows cannot be "
                "confused with a real run's. Progress will be estimated from "
                "wall time, and the baseline's own output (TAP_*.csv / "
                "fade_results_*.csv) is what to look at."
            )
        if self.env.build_profile() != "optimized":
            out.append(
                f"Build profile reads '{self.env.build_profile()}', not "
                "'optimized' -- expect roughly 12x the wall time."
            )
        return out

    async def start(
        self,
        values: dict[str, Any],
        defences: dict[str, bool] | None = None,
    ) -> RunRecord:
        """Validate, spawn, and begin supervising a simulation."""
        problems = self.env.problems()
        if problems:
            raise RunnerError("; ".join(problems))

        async with self._lock:
            if len(self.active) >= MAX_CONCURRENT:
                raise RunnerError(
                    f"{len(self.active)} runs already in flight and the limit is "
                    f"{MAX_CONCURRENT}. This is a shared host -- stop one first."
                )
            plan = self.plan(values, defences)
            record = RunRecord(
                run_id=uuid.uuid4().hex[:12],
                tag=plan["tag"],
                argv=plan["argv"],
                values=plan["values"],
                sim_time=plan["sim_time"],
                metrics_path=self.env.results_dir / plan["metrics_file"],
                started_at=time.time(),
                emits_metrics=plan["emits_metrics"],
            )
            # A stale file from an earlier run with the same tag would be
            # appended to, not replaced (ios::app), and the parser would see one
            # run with a restarting cycle counter. Tags are unique per launch so
            # this should never fire; it is here because the failure it prevents
            # is silent and looks like corrupt data.
            if record.emits_metrics and record.metrics_path.exists():
                raise RunnerError(
                    f"{record.metrics_path.name} already exists; refusing to "
                    "append into it."
                )
            self._runs[record.run_id] = record

        try:
            proc = await asyncio.create_subprocess_exec(
                *record.argv,
                cwd=str(self.env.ns3_dir),
                env=self._child_env(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,   # so cancel can take the whole group
            )
        except OSError as exc:
            record.state = RunState.FAILED
            record.error = f"could not start the simulator: {exc}"
            record.finished_at = time.time()
            raise RunnerError(record.error) from exc

        record.pid = proc.pid
        record.state = RunState.RUNNING
        self._procs[record.run_id] = proc
        self._tasks[record.run_id] = asyncio.create_task(self._supervise(record, proc))
        return record

    def _child_env(self) -> dict[str, str]:
        """Environment for the simulator.

        ``build/lib`` holds both the debug and optimized ``.so`` sets, so
        prepending it resolves under either profile with no branch here.
        """
        env = dict(os.environ)
        lib = str(self.env.lib_dir)
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib}:{existing}" if existing else lib
        return env

    async def _supervise(
        self, record: RunRecord, proc: asyncio.subprocess.Process
    ) -> None:
        """Drain output, track progress, and record how the run ended."""
        assert proc.stdout is not None
        try:
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                record.log.append(line)
                if len(record.log) > LOG_RING_SIZE:
                    del record.log[: len(record.log) - LOG_RING_SIZE]
                roster = ROSTER_RE.match(line)
                hf = HF_ROSTER_RE.match(line)
                cp = CP_ROSTER_RE.search(line)
                if roster is not None:
                    if roster.group("value") == "1":
                        record.attackers.add(int(roster.group("node")))
                elif hf is not None:
                    record.attackers.add(int(hf.group("node")))
                    record.notable.append(line[:400])
                elif cp is not None:
                    record.compromised_controllers = int(cp.group("count"))
                    record.notable.append(line[:400])
                elif any(m in line for m in NOTABLE_MARKERS) \
                        and not NOISE_RE.match(line):
                    record.notable.append(line[:400])
                    if len(record.notable) > NOTABLE_RING_SIZE:
                        del record.notable[: len(record.notable) - NOTABLE_RING_SIZE]
                # Cycles come from the CSV, not from stdout: stdout volume
                # depends on which DEBUG_LOG flags were compiled in, the CSV
                # does not.
                record.cycles_done = _count_cycles(record.metrics_path)
        except asyncio.CancelledError:
            raise
        finally:
            code = await proc.wait()
            record.exit_code = code
            record.finished_at = time.time()
            record.cycles_done = _count_cycles(record.metrics_path)
            if record.state == RunState.CANCELLED:
                pass
            elif code == 0:
                record.state = RunState.FINISHED
            else:
                record.state = RunState.FAILED
                tail = " | ".join(record.log[-3:])
                record.error = f"exit code {code}. Last output: {tail}" if tail \
                    else f"exit code {code}"
            _persist_roster(record)
            self._procs.pop(record.run_id, None)
            self._tasks.pop(record.run_id, None)

    async def stop(self, run_id: str) -> RunRecord:
        """Terminate a run, escalating to SIGKILL if it does not go quietly."""
        record = self.get(run_id)
        proc = self._procs.get(run_id)
        if proc is None or record.state not in (RunState.STARTING, RunState.RUNNING):
            return record
        record.state = RunState.CANCELLED
        # Signal the whole process group: `start_new_session` put the simulator
        # in its own, and routing.cc shells out to optimization.py, which would
        # otherwise survive its parent.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            await asyncio.wait_for(proc.wait(), timeout=TERM_GRACE_S)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        return record

    async def stop_all(self) -> int:
        """Stop every in-flight run. Used on server shutdown."""
        active = list(self.active)
        for record in active:
            with contextlib.suppress(RunnerError):
                await self.stop(record.run_id)
        return len(active)

    def log_lines(self, run_id: str, since: int = 0) -> tuple[list[str], int]:
        """Log lines from index ``since``, plus the new index.

        The ring buffer means ``since`` can point before the retained window; in
        that case the caller silently gets what is left rather than an error,
        because a dropped middle of a log is not worth failing a demo over.
        """
        record = self.get(run_id)
        start = max(0, min(since, len(record.log)))
        return record.log[start:], len(record.log)


#: Sidecar holding a run's attacker roster, written beside its metrics CSV.
#: ``declare_attackers()`` prints the roster to stdout and nothing else records
#: it, so once the launching process exits the ground truth is gone. Persisting
#: it is what lets the spot-the-attacker reveal work on a run days later, and
#: what makes a GUI-launched run self-describing rather than dependent on this
#: server still being the one that started it.
ROSTER_SUFFIX = ".attackers.json"


def roster_path(metrics_path: Path) -> Path:
    """Where a run's attacker roster is stored."""
    return metrics_path.with_suffix(ROSTER_SUFFIX)


def load_roster(metrics_path: Path) -> set[int] | None:
    """Read a persisted roster, or None if this run has none.

    None means "not recorded", which is emphatically not the same as "there
    were no attackers" -- a benign run records an empty list, and the caller
    must be able to tell those apart.
    """
    path = roster_path(metrics_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    nodes = payload.get("attackers")
    if not isinstance(nodes, list):
        return None
    return {int(n) for n in nodes}


def load_roster_meta(metrics_path: Path) -> dict[str, Any] | None:
    """The whole roster sidecar, including the compromised-controller count."""
    try:
        payload = json.loads(roster_path(metrics_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _persist_roster(record: RunRecord) -> None:
    """Write the roster sidecar. Never raises -- a run must not fail over this.

    An *empty* roster is only written for a run that genuinely had no attackers,
    i.e. one at 0%. For any other run an empty roster means the parser did not
    recognise that attack family's announcement format, and recording it as
    "zero attackers, known" would be actively misleading: the reveal would then
    confidently mark every real attacker as a false alarm. Writing nothing
    leaves ground truth reported as unavailable, which is the truth.
    """
    if record.state not in (RunState.FINISHED, RunState.CANCELLED):
        return
    pct = int(record.values.get("attack_percentage", 0) or 0)
    attack = int(record.values.get("attack_number", 0) or 0)
    if not record.attackers and not record.compromised_controllers \
            and attack > 0 and pct > 0:
        return
    try:
        roster_path(record.metrics_path).write_text(
            json.dumps({
                "run_tag": record.tag,
                "attackers": sorted(record.attackers),
                "compromised_controllers": record.compromised_controllers,
                "attack_number": record.values.get("attack_number", 0),
                "attack_percentage": record.values.get("attack_percentage", 0),
                "sim_seed": record.values.get("sim_seed", 1),
                "source": "declare_attackers() stdout, captured at launch",
                "written_at": time.time(),
            }, indent=1),
            encoding="utf-8",
        )
    except OSError:
        pass


def _count_cycles(path: Path) -> int:
    """Rows in the metrics CSV, excluding the header.

    Cheap enough to call per output line: the file is one short row per
    simulated second, so even a 300 s run is 300 lines.
    """
    try:
        with path.open("rb") as fh:
            n = sum(1 for _ in fh)
    except OSError:
        return 0
    return max(0, n - 1)


def _new_tag() -> str:
    """A run tag unique per launch.

    ``GUI`` prefix plus a time-ordered suffix, so the files a demo produces sort
    chronologically in the results directory and are obviously GUI-launched --
    which matters when they sit beside the sweep launchers' output.
    """
    return "GUI" + time.strftime("%m%d%H%M%S") + uuid.uuid4().hex[:3]


def running_simulations() -> Iterator[tuple[int, str]]:
    """Every ``routing`` process on this host, GUI-launched or not.

    Shared-host etiquette: CLAUDE.md asks for a check before launching a wide
    sweep, and the operator cannot make that judgement from the GUI's own run
    list alone -- a teammate's sweep is invisible there.
    """
    proc_dir = Path("/proc")
    if not proc_dir.is_dir():  # not Linux; nothing to report
        return
    for entry in proc_dir.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                "utf-8", errors="replace"
            ).strip()
        except OSError:
            continue
        if "scratch/routing/routing" in cmdline:
            yield int(entry.name), cmdline


def host_load() -> dict[str, Any]:
    """Load average, core count and free memory, for the pre-launch check."""
    try:
        load1, load5, load15 = os.getloadavg()  # type: ignore[attr-defined]
    except (OSError, AttributeError):  # AttributeError on Windows
        load1 = load5 = load15 = 0.0
    others = list(running_simulations())
    return {
        "load1": round(load1, 2),
        "load5": round(load5, 2),
        "load15": round(load15, 2),
        "cores": os.cpu_count() or 1,
        "free_gb": _free_gb(),
        "simulations_on_host": len(others),
    }


def _free_gb() -> float | None:
    """Available memory in GB, or None where /proc/meminfo is unavailable."""
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
        m = re.search(r"^MemAvailable:\s+(\d+) kB", text, re.MULTILINE)
        return round(int(m.group(1)) / 1e6, 1) if m else None
    except OSError:
        pass
    # Windows fallback: use psutil if available, otherwise skip.
    try:
        import psutil  # type: ignore[import-untyped]
        return round(psutil.virtual_memory().available / 1e9, 1)
    except ImportError:
        pass
    return None
