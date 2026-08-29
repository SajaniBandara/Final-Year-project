"""Application logic for the demo GUI, independent of HTTP.

Everything the API serves is built here, in plain Python, so it can be tested
without a server and reused by Phase 2's WebSocket paths. :mod:`gui.backend.app`
is a thin routing layer over this module and should stay that way.

Two responsibilities beyond assembling responses:

**Caching.** Parsing one run is cheap (~30 rows), but a sweep parses six files
and the run picker hits the same runs repeatedly. Parsed runs are cached on
``(path, mtime, size)``, so an edited or re-copied CSV invalidates its own entry
without a manual flush -- which matters here specifically because
``results_routing/`` is refreshed by hand from the HPC.

**Refusing to mislead.** Two guards are carried through into every response
rather than left to the frontend:

* ``caveat`` on any series or sweep of the inline per-node detection columns,
  which share a name with a thesis metric but are a different statistic
  (``docs/WHICH_MCC_TO_REPORT.md``).
* ``stale`` in :meth:`ResultsService.health`, because the local CSVs are copied
  by hand and a month-old copy looks exactly like a fresh one in a chart.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Sequence

from . import aggregate, schema
from .catalog import REPO_ROOT, Catalog, RunFile
from .parser import Run, SchemaError, parse_file
from .lstm import panel as lstm_panel
from .stream import make_source

#: Simulated time at which attack injection begins. Fixed at 10.0 s because the
#: S1 EWMA baseline needs ~10 s of benign traffic to converge (CLAUDE.md, "Known
#: gotchas"). The Live tab draws its "attack starts" marker here.
SIM_ATTACK_START_S: float = 10.0

#: Age beyond which the results copy is reported as stale. The CSVs are copied
#: from the HPC by hand, so drift is the normal failure mode, not the exception.
STALE_AFTER = timedelta(days=7)

#: Directory holding the committed thesis figures.
FIGURES_DIR = REPO_ROOT / "output"


class ServiceError(Exception):
    """Base class for errors the API maps onto HTTP status codes."""


class NotFoundError(ServiceError):
    """A requested run, figure, or column does not exist."""


class BadRequestError(ServiceError):
    """The request was well-formed but asks for something incoherent."""


class ResultsService:
    """Read-only view over one ``results_routing/`` directory."""

    def __init__(self, results_dir: str | os.PathLike[str] | None = None) -> None:
        self._results_dir = results_dir
        self._catalog: Catalog | None = None
        # key -> parsed runs, keyed on file identity so a re-copy self-invalidates.
        self._run_cache: dict[tuple[str, float, int], list[Run]] = {}

    # --- catalog lifecycle --------------------------------------------------

    @property
    def catalog(self) -> Catalog:
        """The current catalog, scanning on first use."""
        if self._catalog is None:
            self._catalog = Catalog.scan(self._results_dir)
        return self._catalog

    def refresh(self) -> Catalog:
        """Re-scan the results directory and drop cached parses.

        Exposed so a run finishing mid-demo can be picked up without a restart.
        """
        self._catalog = None
        self._run_cache.clear()
        return self.catalog

    def _load(self, run_file: RunFile) -> list[Run]:
        """Parse a run file, memoised on its path, mtime and size."""
        key = (str(run_file.path), run_file.modified.timestamp(), run_file.size_bytes)
        cached = self._run_cache.get(key)
        if cached is None:
            try:
                cached = parse_file(run_file.path, run_file.attack_id)
            except SchemaError as exc:
                raise BadRequestError(str(exc)) from exc
            if not cached:
                raise BadRequestError(f"{run_file.run_id}: no data rows (header only?)")
            self._run_cache[key] = cached
        return cached

    def _run_file(self, run_id: str) -> RunFile:
        try:
            return self.catalog.get(run_id)
        except KeyError as exc:
            raise NotFoundError(str(exc)) from exc

    # --- responses ----------------------------------------------------------

    def health(self) -> dict[str, object]:
        """Service and data-freshness summary, for the staleness banner."""
        newest = self.catalog.newest_modified()
        age_days = (datetime.now(timezone.utc) - newest).days if newest else None
        return {
            "results_dir": str(self.catalog.results_dir),
            "run_count": len(self.catalog),
            "newest_modified": newest.isoformat() if newest else None,
            "age_days": age_days,
            "stale": bool(newest and (datetime.now(timezone.utc) - newest) > STALE_AFTER),
            "attack_start_s": SIM_ATTACK_START_S,
        }

    def list_runs(self) -> dict[str, object]:
        """Every indexed run plus the axes the run picker needs."""
        return {
            "runs": [r.to_dict() for r in self.catalog],
            "attacks": self.catalog.attack_ids(),
            "percentages": self.catalog.percentages(),
            "seeds": self.catalog.seeds(),
        }

    def metric_definitions(self, attack_id: int) -> dict[str, object]:
        """Columns available for ``attack_id``, with units and caveats.

        Served so the frontend builds its metric picker from the schema instead
        of hardcoding a list that could drift out of step with ``routing.cc``.
        """
        columns = schema.columns_for(attack_id)
        return {
            "attack": attack_id,
            "has_tcam_columns": schema.has_tcam_columns(attack_id),
            "columns": [
                {
                    "name": name,
                    "unit": schema.METRIC_UNITS.get(name, "count"),
                    "caveat": schema.caveat_for(name),
                }
                for name in columns
            ],
        }

    def run_series(
        self,
        run_id: str,
        columns: Sequence[str] | None = None,
        *,
        run_index: int = -1,
    ) -> dict[str, object]:
        """Per-cycle series for one run.

        Args:
            columns: Column subset; all columns when omitted.
            run_index: Which appended run within the file (``-1`` = most recent).
        """
        run_file = self._run_file(run_id)
        runs = self._load(run_file)
        try:
            run = runs[run_index]
        except IndexError as exc:
            raise NotFoundError(
                f"{run_id} holds {len(runs)} run(s); no index {run_index}"
            ) from exc

        selected = list(columns) if columns else list(run.columns)
        unknown = [c for c in selected if c not in run.columns]
        if unknown:
            raise BadRequestError(
                f"unknown column(s) for attack {run.attack_id}: {', '.join(unknown)}"
            )

        return {
            "run": run_file.to_dict(),
            "run_index": run.index,
            "runs_in_file": len(runs),
            "cycles": run.cycles,
            "columns": {name: run.series(name) for name in selected},
            "units": {name: schema.METRIC_UNITS.get(name, "count") for name in selected},
            "caveats": {
                name: schema.caveat_for(name)
                for name in selected
                if schema.caveat_for(name)
            },
            "attack_start_s": SIM_ATTACK_START_S,
        }

    def run_summary(self, run_id: str, *, run_index: int = -1) -> dict[str, object]:
        """Final-cycle values, the confusion matrix, and its recomputation check.

        The recomputation is the point: MCC/DR/FPR are re-derived from raw
        TP/FP/TN/FN and reported alongside the values the simulator wrote, so a
        disagreement is visible instead of trusted. Mirrors GROUP B of
        ``scripts/functional_verification.py``.
        """
        run_file = self._run_file(run_id)
        runs = self._load(run_file)
        run = runs[run_index]
        final = run.final()

        confusion = aggregate.recompute_confusion(
            tp=final["TP"], fp=final["FP"], tn=final["TN"], fn=final["FN"]
        )
        discrepancies = aggregate.verify_reported_metrics(run)

        return {
            "run": run_file.to_dict(),
            "cycles": len(run),
            "final": final,
            "confusion": confusion.to_dict(),
            "verification": {
                "discrepancies": [d.to_dict() for d in discrepancies],
                "max_delta": max((d.delta for d in discrepancies), default=0.0),
                "note": (
                    "MCC/DR/FPR re-derived from raw TP/FP/TN/FN and compared to "
                    "the columns the simulator wrote. Deltas at 1e-5 are CSV "
                    "rounding at 6 significant figures."
                ),
            },
            "caveat": schema.PER_NODE_CAVEAT,
        }

    def sweep(
        self,
        *,
        attack_id: int,
        metric: str,
        seeds: Iterable[int] | None = None,
        delay_ms: int | None = None,
        tag: str | None = None,
    ) -> dict[str, object]:
        """A metric-vs-attack-percentage curve with 95% CIs across seeds."""
        if attack_id not in self.catalog.attack_ids():
            raise NotFoundError(
                f"no runs indexed for attack {attack_id}; "
                f"available: {self.catalog.attack_ids()}"
            )
        try:
            result = aggregate.sweep(
                self.catalog,
                attack_id=attack_id,
                metric=metric,
                seeds=list(seeds) if seeds is not None else None,
                delay_ms=delay_ms,
                tag=tag,
            )
        except KeyError as exc:
            raise BadRequestError(str(exc).strip("'")) from exc

        payload = result.to_dict()
        # A single seed cannot support an interval. Say so explicitly rather
        # than letting the frontend infer it from a null.
        payload["single_seed"] = all(n < 2 for n in payload["n"])  # type: ignore[union-attr]
        return payload

    # --- live / replay streaming -------------------------------------------

    def stream_meta(self, run_id: str, mode: str) -> dict[str, object]:
        """Opening message for a stream: what is being sent, and from where.

        Sent before any cycle so the UI can label the source honestly. The
        distinction matters in a viva -- "is this actually running?" deserves a
        straight answer, and the answer is on screen.
        """
        run_file = self._run_file(run_id)
        return {
            "type": "meta",
            "run": run_file.to_dict(),
            "mode": mode,
            "attack_start_s": SIM_ATTACK_START_S,
            "kpi_columns": list(schema.LIVE_KPI_COLUMNS),
            "event_counters": list(schema.LIVE_EVENT_COUNTERS),
            "units": {
                name: schema.METRIC_UNITS.get(name, "count")
                for name in schema.columns_for(run_file.attack_id)
            },
            "caveats": {
                name: schema.caveat_for(name)
                for name in schema.columns_for(run_file.attack_id)
                if schema.caveat_for(name)
            },
        }

    def stream_source(
        self,
        run_id: str,
        *,
        mode: str = "replay",
        speed: float = 1.0,
        from_start: bool = True,
    ):
        """Build the cycle source backing a stream.

        Raises:
            NotFoundError: unknown run id.
            BadRequestError: unknown mode.
        """
        run_file = self._run_file(run_id)
        try:
            return make_source(
                mode,
                run_file.path,
                run_file.attack_id,
                speed=speed,
                from_start=from_start,
            )
        except ValueError as exc:
            raise BadRequestError(str(exc)) from exc

    def lstm_panel(self) -> dict[str, object]:
        """Federated-LSTM results from the committed lstm_pipeline JSONs.

        Independent of ``results_routing/``: these files are git-tracked and
        current, so this panel is unaffected by the staleness of the CSV copy.
        """
        return lstm_panel()

    def figures(self) -> dict[str, object]:
        """The committed thesis figures under ``output/``, grouped by directory."""
        if not FIGURES_DIR.is_dir():
            return {"groups": []}

        groups: dict[str, list[dict[str, str]]] = {}
        for png in sorted(FIGURES_DIR.rglob("*.png")):
            group = png.parent.relative_to(FIGURES_DIR).as_posix() or "."
            groups.setdefault(group, []).append(
                {
                    "name": png.stem,
                    "path": png.relative_to(FIGURES_DIR).as_posix(),
                }
            )
        return {
            "groups": [
                {"group": name, "figures": figs} for name, figs in sorted(groups.items())
            ]
        }

    def figure_path(self, relative: str) -> Path:
        """Resolve a figure path from :meth:`figures`, refusing directory escapes.

        Args:
            relative: A ``path`` value returned by :meth:`figures`.

        Raises:
            NotFoundError: if the path escapes ``output/`` or does not exist.
        """
        candidate = (FIGURES_DIR / relative).resolve()
        try:
            candidate.relative_to(FIGURES_DIR.resolve())
        except ValueError:
            raise NotFoundError(f"figure outside output/: {relative}") from None
        if not candidate.is_file() or candidate.suffix.lower() != ".png":
            raise NotFoundError(f"no such figure: {relative}")
        return candidate
