"""Serves the GUI from a pre-exported JSON snapshot instead of ``results_routing/``.

Built by :mod:`gui.backend.export_snapshot`. This presents the same method
surface :mod:`gui.backend.app` calls on :class:`~gui.backend.service.ResultsService`,
so ``app.py`` can swap between the two based on ``MOBIGUARD_SNAPSHOT_DIR``
without any route changing. Every value returned here was already computed
once by ``ResultsService`` at export time -- this module does no CSV parsing
and never opens anything under ``results_routing/``.

What is unavailable in snapshot mode, and why:

* **Live tail** (``mode=live`` on the stream) -- there is no growing CSV to
  follow; only **replay** works, reconstructed from the exported per-cycle
  series.
* **Run Simulation / launch control** -- a snapshot is a frozen export with no
  simulator binary or live ``results_routing/`` beside it to write into.
* **Re-run audit** -- needs the live repo's scripts, not just their last
  output (which travels in the ``verification`` panel as exported).
* A **non-default sweep** (specific seeds, a delay filter, an ablation tag) --
  only the default (all seeds, no tag) curve per attack/metric is exported,
  to keep the export step's combinatorics bounded. Re-export with a script
  change if a demo specifically needs a filtered curve as a static asset.

Each of these raises :class:`~gui.backend.service.BadRequestError` /
:class:`~gui.backend.service.NotFoundError`, which ``app.py`` already maps to
400/404/503 -- so the frontend sees a normal error response, not a crash.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator

from . import mapview, params, schema
from .catalog import RunFile
from .service import BadRequestError, NotFoundError, SIM_ATTACK_START_S
from .stream import CYCLE_PERIOD_S, Cycle, clamp_speed


class SnapshotReplaySource:
    """Replays an exported run's series at wall-clock speed.

    Same contract as :class:`gui.backend.stream.ReplaySource` (one ``Cycle``
    per simulated second, scaled by ``speed``) but reads from the JSON
    already loaded from ``series.json`` instead of re-parsing a CSV.
    """

    source_name = "replay"

    def __init__(self, series: dict[str, Any], *, speed: float = 1.0) -> None:
        self.series = series
        self.speed = clamp_speed(speed)

    @property
    def interval(self) -> float:
        return CYCLE_PERIOD_S / self.speed

    async def __aiter__(self) -> AsyncIterator[Cycle]:
        cycles = self.series["cycles"]
        columns = self.series["columns"]
        for index, cycle in enumerate(cycles):
            if index:
                await asyncio.sleep(self.interval)
            yield Cycle(
                cycle=cycle,
                columns={name: values[index] for name, values in columns.items()},
                source=self.source_name,
            )


def _signal_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for event in events:
        out[event["signal"]] = out.get(event["signal"], 0) + 1
    return dict(sorted(out.items()))


class SnapshotService:
    """Read-only view over one exported snapshot directory."""

    def __init__(self, snapshot_dir: str | Path) -> None:
        self.snapshot_dir = Path(snapshot_dir)
        index_path = self.snapshot_dir / "index.json"
        if not index_path.is_file():
            raise FileNotFoundError(
                f"no snapshot at {self.snapshot_dir} (expected index.json) -- build one with "
                f"`python -m gui.backend.export_snapshot --out {self.snapshot_dir}`"
            )
        self._index: dict[str, Any] = json.loads(index_path.read_text(encoding="utf-8"))
        self._run_cache: dict[str, dict[str, Any]] = {}

    # --- loading --------------------------------------------------------

    def _run_json(self, run_id: str, kind: str) -> dict[str, Any]:
        key = f"{run_id}:{kind}"
        cached = self._run_cache.get(key)
        if cached is not None:
            return cached
        path = self.snapshot_dir / "runs" / run_id / f"{kind}.json"
        if not path.is_file():
            raise NotFoundError(
                f"{run_id}: no {kind}.json in this snapshot -- re-export with "
                f"export_snapshot to include it"
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        self._run_cache[key] = data
        return data

    # --- meta -------------------------------------------------------------

    def refresh(self) -> dict[str, Any]:
        """Re-read ``index.json`` in case the snapshot was regenerated in place."""
        self.__init__(self.snapshot_dir)  # type: ignore[misc]
        return self.health()

    def health(self) -> dict[str, Any]:
        health = dict(self._index["health"])
        health["results_dir"] = f"snapshot: {self.snapshot_dir}"
        return health

    def list_runs(self) -> dict[str, Any]:
        return self._index["catalog"]

    def metric_definitions(self, attack_id: int) -> dict[str, Any]:
        try:
            return self._index["metric_definitions"][str(attack_id)]
        except KeyError:
            raise NotFoundError(f"no metric definitions for attack {attack_id} in this snapshot") from None

    # --- runs ---------------------------------------------------------------

    def run_series(
        self, run_id: str, columns: list[str] | None = None, *, run_index: int = -1
    ) -> dict[str, Any]:
        if run_index != -1:
            raise BadRequestError("snapshot mode only stores each file's most recent run (run_index=-1)")
        data = self._run_json(run_id, "series")
        if not columns:
            return data
        unknown = [c for c in columns if c not in data["columns"]]
        if unknown:
            raise BadRequestError(f"unknown column(s): {', '.join(unknown)}")
        return {
            **data,
            "columns": {c: data["columns"][c] for c in columns},
            "units": {c: data["units"].get(c, "count") for c in columns},
            "caveats": {c: data["caveats"][c] for c in columns if c in data["caveats"]},
        }

    def run_summary(self, run_id: str, *, run_index: int = -1) -> dict[str, Any]:
        if run_index != -1:
            raise BadRequestError("snapshot mode only stores each file's most recent run (run_index=-1)")
        return self._run_json(run_id, "summary")

    def sweep(
        self,
        *,
        attack_id: int,
        metric: str,
        seeds: list[int] | None = None,
        delay_ms: int | None = None,
        tag: str | None = None,
    ) -> dict[str, Any]:
        if seeds is not None or delay_ms is not None or tag is not None:
            raise BadRequestError(
                "snapshot mode only serves the default (all-seed, no-tag) sweep per metric"
            )
        try:
            return self._index["sweeps"][f"{attack_id}:{metric}"]
        except KeyError:
            raise NotFoundError(f"no sweep for attack {attack_id} metric {metric!r} in this snapshot") from None

    # --- panels ---------------------------------------------------------------

    def _panel(self, name: str) -> dict[str, Any]:
        panel = self._index["panels"].get(name)
        if panel is None:
            raise NotFoundError(f"{name} panel not exported into this snapshot")
        if isinstance(panel, dict) and set(panel) == {"error"}:
            raise NotFoundError(str(panel["error"]))
        return panel

    def crypto_panel(self, run_id: str | None = None) -> dict[str, Any]:
        return self._panel("crypto")

    def tcam_panel(self, mode: str | None = None) -> dict[str, Any]:
        return self._panel("tcam")

    def lstm_panel(self) -> dict[str, Any]:
        return self._panel("lstm")

    def verification_panel(self) -> dict[str, Any]:
        return self._panel("verification")

    def baselines_panel(self) -> dict[str, Any]:
        return self._panel("baselines")

    def rerun_audit(self, *, self_test: bool = False) -> dict[str, Any]:
        raise BadRequestError("re-running the equation audit needs the live repo, not a snapshot")

    # --- live / replay streaming ---------------------------------------------

    def stream_meta(self, run_id: str, mode: str) -> dict[str, Any]:
        if mode != "replay":
            raise BadRequestError("snapshot mode only supports replay (no live CSV to tail)")
        series = self._run_json(run_id, "series")
        return {
            "type": "meta",
            "run": series["run"],
            "mode": "replay",
            "attack_start_s": SIM_ATTACK_START_S,
            "kpi_columns": list(schema.LIVE_KPI_COLUMNS),
            "event_counters": list(schema.LIVE_EVENT_COUNTERS),
            "units": series["units"],
            "caveats": series["caveats"],
        }

    def stream_source(
        self, run_id: str, *, mode: str = "replay", speed: float = 1.0, from_start: bool = True
    ) -> SnapshotReplaySource:
        if mode != "replay":
            raise BadRequestError("snapshot mode only supports replay (no live CSV to tail)")
        return SnapshotReplaySource(self._run_json(run_id, "series"), speed=speed)

    # --- run control (unavailable) --------------------------------------------

    @property
    def runs(self):  # pragma: no cover - guarded by simulator_environment()
        raise BadRequestError("Run Simulation is unavailable in snapshot mode")

    def simulator_environment(self) -> dict[str, Any]:
        # Same shape as ResultsService.simulator_environment() /
        # runner.Environment.to_json() -- the frontend reads .ready/.problems/
        # .build_profile, not ad hoc field names.
        return {
            "ready": False,
            "problems": [f"snapshot mode: serving {self.snapshot_dir}, no simulator attached"],
            "build_profile": "n/a",
            "host": {"load1": 0, "cores": 0, "free_gb": 0, "simulations_on_host": 0},
        }

    def run_options(self) -> dict[str, Any]:
        # Static parameter/attack/defence metadata -- Attack Lab's configurator
        # and defence board need this even though nothing here can actually be
        # launched, so unlike plan_run/start_run this does not raise.
        return params.describe()

    def plan_run(self, values: dict[str, object], defences: dict[str, bool] | None = None) -> dict[str, Any]:
        raise BadRequestError("Run Simulation is unavailable in snapshot mode")

    async def start_run(self, values: dict[str, object], defences: dict[str, bool] | None = None) -> dict[str, Any]:
        raise BadRequestError("Run Simulation is unavailable in snapshot mode")

    async def stop_run(self, run_uid: str) -> dict[str, Any]:
        raise NotFoundError(run_uid)

    def run_status(self, run_uid: str) -> dict[str, Any]:
        raise NotFoundError(run_uid)

    def run_log(self, run_uid: str, since: int = 0) -> dict[str, Any]:
        raise NotFoundError(run_uid)

    def launched_runs(self) -> dict[str, Any]:
        return {"runs": [], "active": 0}

    # --- map ------------------------------------------------------------------

    def _run_file_stub(self, run_id: str) -> RunFile:
        """A :class:`RunFile` good enough for the topology-only map fallback below.

        Its ``.path`` does not exist -- snapshot mode has no ``results_routing/``
        CSV to point at -- but that is fine: :func:`gui.backend.mapview.scene`
        only ever uses ``.path`` to look for sidecars beside it (correctly
        finding none, the same way a live run with no ``bc_detection_log_``
        degrades) and for an optional re-parse that is wrapped in
        ``try/except`` and made moot here anyway, since ``end`` is supplied
        from the exported series instead.
        """
        entry = next(
            (r for r in self._index["catalog"]["runs"] if r["id"] == run_id), None
        )
        if entry is None:
            raise NotFoundError(f"unknown run id: {run_id!r}")
        return RunFile(
            attack_id=entry["attack"],
            attack_percentage=entry["pct"],
            seed=entry["seed"],
            delay_ms=entry["delay_ms"],
            tag=entry["tag"],
            run_id=entry["id"],
            path=self.snapshot_dir / "runs" / run_id / "__no_csv_in_snapshot__.csv",
            size_bytes=entry["size_bytes"],
            modified=datetime.fromisoformat(entry["modified"]),
        )

    def _topology_only_scene(
        self, run_id: str, *, start: float, end: float | None, step: float
    ) -> dict[str, Any]:
        """Map fallback for a run this snapshot never exported a map.json for.

        Mirrors what the live server shows for a run with no
        ``bc_detection_log_*.csv``: real topology and vehicle movement (the
        mobility trace is a repo asset under ``mobility/``, not something
        ``results_routing/`` holds, so it is always available), just no
        accusations -- rather than a hard 404 for every run this snapshot
        hasn't caught up to yet.
        """
        run_file = self._run_file_stub(run_id)
        horizon = end
        if horizon is None:
            try:
                cycles = self._run_json(run_id, "series").get("cycles") or []
            except NotFoundError:
                cycles = []
            if cycles:
                horizon = float(cycles[-1])
        try:
            result = mapview.scene(run_file, start=start, end=horizon, step=step)
        except mapview.MapError as exc:
            raise BadRequestError(str(exc)) from exc
        result["notes"] = [
            "Built from the mobility trace only -- this snapshot has no "
            "map.json for this run yet (bc_detection_log_ not drained in). "
            "Topology and movement are real; there are no accusations to show."
        ] + list(result.get("notes") or [])
        return result

    def map_scene(
        self, run_id: str, *, start: float = 0.0, end: float | None = None, step: float = 1.0
    ) -> dict[str, Any]:
        try:
            scene = self._run_json(run_id, "map")
        except NotFoundError:
            return self._topology_only_scene(run_id, start=start, end=end, step=step)
        if start == 0.0 and end is None and step == 1.0:
            return scene
        # The snapshot stores one fixed frame set at the export-time step;
        # slicing it in memory covers a demo's "scrub to a window" case, just
        # not a genuinely different --step re-render.
        frames = [f for f in scene["frames"] if f["t"] >= start and (end is None or f["t"] <= end)]
        kept_events = sum(len(f.get("events") or []) for f in frames)
        duration = min(end, scene["duration"]) if end is not None else scene["duration"]
        return {**scene, "frames": frames, "duration": round(duration, 3), "event_count": kept_events}

    def map_node(self, run_id: str, node_id: int) -> dict[str, Any]:
        try:
            scene = self._run_json(run_id, "map")
        except NotFoundError:
            return mapview.node_detail(self._run_file_stub(run_id), node_id)
        layout = scene["layout"]
        n_vehicles, n_rsus = layout["n_vehicles"], layout["n_rsus"]
        kind = (
            "vehicle" if node_id < n_vehicles
            else "rsu" if node_id < n_vehicles + n_rsus
            else "controller"
        )
        events = [e for frame in scene["frames"] for e in frame.get("events", [])]
        against = [e for e in events if e["suspect"] == node_id]
        raised = [e for e in events if e["rsu"] == node_id]
        truth = scene["ground_truth"]
        attackers = set(truth.get("attackers") or [])
        known = bool(truth.get("known"))

        detail: dict[str, Any] = {
            "node": node_id,
            "kind": kind,
            "is_attacker": (node_id in attackers) if known else None,
            "ground_truth_known": known,
            "accused": {
                "count": len(against),
                "first_t": round(min((e["t"] for e in against), default=0.0), 3),
                "last_t": round(max((e["t"] for e in against), default=0.0), 3),
                "signals": _signal_counts(against),
                "accusers": sorted({e["rsu"] for e in against}),
            },
            "raised": {
                "count": len(raised),
                "signals": _signal_counts(raised),
                "suspects": sorted({e["suspect"] for e in raised})[:50],
            },
        }
        if kind == "rsu":
            rsu = next((r for r in layout["rsus"] if r["id"] == node_id), None)
            if rsu:
                detail["position"] = {"x": rsu["x"], "y": rsu["y"]}
                detail["grid"] = {"row": rsu["row"], "col": rsu["col"]}
                detail["controller"] = rsu["controller"]
        elif kind == "controller":
            ctrl = next((c for c in layout["controllers"] if c["id"] == node_id), None)
            if ctrl:
                detail["position"] = {"x": ctrl["x"], "y": ctrl["y"]}
        return detail

    def score_guess(self, run_id: str, guess: list[int]) -> dict[str, Any]:
        try:
            scene = self._run_json(run_id, "map")
        except NotFoundError:
            return mapview.score_guess(self._run_file_stub(run_id), guess)
        truth = scene["ground_truth"]
        if not truth.get("known"):
            return {
                "scored": False,
                "reason": truth.get("source"),
                "expected_count": truth.get("expected_count"),
                "guess": sorted(set(guess)),
            }
        picked = set(guess)
        actual = set(truth.get("attackers") or [])
        tp, fp, fn = len(picked & actual), len(picked - actual), len(actual - picked)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return {
            "scored": True, "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "actual_count": len(actual), "guess": sorted(picked),
            "correct": sorted(picked & actual), "missed": sorted(actual - picked)[:50],
            "wrong": sorted(picked - actual), "source": truth.get("source"),
        }

    # --- figures --------------------------------------------------------------

    def figures(self) -> dict[str, Any]:
        return self._index["figures"]

    def figure_path(self, relative: str) -> Path:
        # Committed, git-tracked PNGs under output/ -- small enough (34-44
        # files) that duplicating them into the snapshot isn't worth it; read
        # straight from the repo tree the snapshot was exported from.
        from .catalog import REPO_ROOT

        figures_dir = REPO_ROOT / "output"
        candidate = (figures_dir / relative).resolve()
        try:
            candidate.relative_to(figures_dir.resolve())
        except ValueError:
            raise NotFoundError(f"figure outside output/: {relative}") from None
        if not candidate.is_file() or candidate.suffix.lower() != ".png":
            raise NotFoundError(f"no such figure: {relative}")
        return candidate
