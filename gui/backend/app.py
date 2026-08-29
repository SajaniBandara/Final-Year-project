"""FastAPI application for the MOBIGUARD demo GUI.

A thin routing layer over :mod:`gui.backend.service` -- every response is
assembled there, so the API surface stays testable without a server and Phase 2
can reuse the same logic over WebSockets.

Run it::

    python -m pip install -r gui/requirements.txt
    python -m uvicorn gui.backend.app:app --reload

Then open http://127.0.0.1:8000/ for the UI, or /docs for the generated OpenAPI
reference (useful evidence in its own right: it lists every metric the GUI can
show and the caveats attached to them).

Point it at a different results copy with ``MOBIGUARD_RESULTS_DIR``.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .catalog import REPO_ROOT
from .parser import SchemaError
from .service import BadRequestError, NotFoundError, ResultsService, ServiceError

logger = logging.getLogger(__name__)

FRONTEND_DIR = REPO_ROOT / "gui" / "frontend"

#: Single service instance for the process. Read-only over the filesystem, so
#: sharing it is safe and lets the parsed-run cache actually pay off.
_service = ResultsService()


def get_service() -> ResultsService:
    """FastAPI dependency yielding the shared service."""
    return _service


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Scan the results directory at startup.

    Done eagerly so a missing or misconfigured results directory fails when the
    server starts rather than when someone clicks a chart during the demo.
    """
    try:
        health = _service.health()
        logger.info(
            "indexed %s runs from %s", health["run_count"], health["results_dir"]
        )
        if health["stale"]:
            logger.warning(
                "results copy is %s days old (newest %s) -- charts may not reflect "
                "the current simulator",
                health["age_days"],
                health["newest_modified"],
            )
        if health["run_count"] == 0:
            logger.warning("no metrics CSVs found; the run picker will be empty")
    except FileNotFoundError as exc:
        # Not fatal: the API still starts and /api/health reports the problem,
        # which is more useful than a server that refuses to boot.
        logger.error("%s", exc)
    yield


app = FastAPI(
    title="MOBIGUARD Demo GUI",
    version="0.2.0",
    summary="Offline simulation statistics and realtime PEMs for MOBIGUARD.",
    lifespan=lifespan,
)


# --- error mapping -----------------------------------------------------------


@app.exception_handler(NotFoundError)
async def _not_found(request: Request, exc: NotFoundError) -> JSONResponse:
    return JSONResponse(status_code=404, content={"detail": str(exc)})


@app.exception_handler(BadRequestError)
async def _bad_request(request: Request, exc: BadRequestError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(FileNotFoundError)
async def _missing_results_dir(request: Request, exc: FileNotFoundError) -> JSONResponse:
    # Raised by Catalog.scan when results_routing/ is absent. 503 rather than
    # 500: the service is fine, its data is not.
    return JSONResponse(status_code=503, content={"detail": str(exc)})


@app.exception_handler(ServiceError)
async def _service_error(request: Request, exc: ServiceError) -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": str(exc)})


# --- helpers -----------------------------------------------------------------


def _split_csv(value: str | None) -> list[str] | None:
    """Parse a comma-separated query parameter into a list."""
    if value is None:
        return None
    items = [part.strip() for part in value.split(",")]
    return [item for item in items if item]


def _split_ints(value: str | None, *, field: str) -> list[int] | None:
    """Parse a comma-separated list of integers.

    Raises:
        BadRequestError: on a non-integer entry, so the caller sees a 400 rather
            than a 500 from deep inside the aggregation.
    """
    items = _split_csv(value)
    if items is None:
        return None
    try:
        return [int(item) for item in items]
    except ValueError as exc:
        raise BadRequestError(f"{field} must be comma-separated integers: {exc}") from exc


# --- routes ------------------------------------------------------------------


@app.get("/api/health", tags=["meta"])
def health(service: ResultsService = Depends(get_service)) -> dict[str, object]:
    """Service status and data freshness.

    ``stale`` drives the UI banner. The results copy is refreshed by hand from
    the HPC, so an out-of-date copy is the expected failure mode and must be
    visible rather than inferred.
    """
    return service.health()


@app.post("/api/refresh", tags=["meta"])
def refresh(service: ResultsService = Depends(get_service)) -> dict[str, object]:
    """Re-scan the results directory and drop cached parses.

    Lets a run that finished mid-demo appear without restarting the server.
    """
    service.refresh()
    return service.health()


@app.get("/api/catalog", tags=["catalog"])
def catalog(service: ResultsService = Depends(get_service)) -> dict[str, object]:
    """Every indexed run, plus the attack/percentage/seed axes for the picker."""
    return service.list_runs()


@app.get("/api/metrics/{attack_id}", tags=["catalog"])
def metrics(attack_id: int, service: ResultsService = Depends(get_service)) -> dict[str, object]:
    """Columns available for one attack, with units and mandatory caveats.

    Attacks 3, 4 and the baseline carry nine extra TCAM columns, so the metric
    picker must be built per attack rather than from one fixed list.
    """
    return service.metric_definitions(attack_id)


@app.get("/api/run/{run_id}/series", tags=["runs"])
def run_series(
    run_id: str,
    cols: str | None = Query(None, description="Comma-separated column names; all if omitted."),
    run_index: int = Query(-1, description="Which appended run in the file; -1 = most recent."),
    service: ResultsService = Depends(get_service),
) -> dict[str, object]:
    """Per-cycle series for one run, with units and any display caveats."""
    return service.run_series(run_id, _split_csv(cols), run_index=run_index)


@app.get("/api/run/{run_id}/summary", tags=["runs"])
def run_summary(
    run_id: str,
    run_index: int = Query(-1),
    service: ResultsService = Depends(get_service),
) -> dict[str, object]:
    """Final-cycle values, confusion matrix, and its independent recomputation."""
    return service.run_summary(run_id, run_index=run_index)


@app.get("/api/sweep", tags=["analysis"])
def sweep(
    attack: int = Query(..., description="Attack id; 0 is the benign baseline."),
    metric: str = Query(..., description="Column to plot against attack percentage."),
    seeds: str | None = Query(None, description="Comma-separated seeds; all if omitted."),
    delay_ms: int | None = Query(None, description="Restrict to one injected delay."),
    tag: str | None = Query(None, description="Restrict to one ablation run tag."),
    service: ResultsService = Depends(get_service),
) -> dict[str, object]:
    """A metric plotted against attack percentage, averaged across seeds.

    ``ci95`` entries are ``null`` where only one seed exists -- render that as
    "n=1, no CI", never as a zero-width error bar. ``caveat`` is non-null for the
    inline per-node detection columns and must be shown alongside the chart.
    """
    return service.sweep(
        attack_id=attack,
        metric=metric,
        seeds=_split_ints(seeds, field="seeds"),
        delay_ms=delay_ms,
        tag=tag,
    )


@app.get("/api/panels/crypto", tags=["analysis"])
def crypto_panel(
    run_id: str | None = Query(None, description="Crypto log to analyse; first run if omitted."),
    service: ResultsService = Depends(get_service),
) -> dict[str, object]:
    """Per-operation crypto overhead (M7).

    The log's ``result`` column means different things per operation, so no
    combined pass/fail rate is reported -- each row carries its own meaning.
    """
    return service.crypto_panel(run_id)


@app.get("/api/panels/lstm", tags=["analysis"])
def lstm_panel(service: ResultsService = Depends(get_service)) -> dict[str, object]:
    """Federated-LSTM detection quality, poisoning robustness and ablations.

    Degenerate MCC values are flagged rather than reported as zero, and
    rule-based (S3/S4) rows are marked so they are not read as LSTM results.
    """
    return service.lstm_panel()


@app.get("/api/verification", tags=["verification"])
def verification(service: ResultsService = Depends(get_service)) -> dict[str, object]:
    """Equation-audit and functional-verification status.

    Answers "does the code implement the thesis?" -- reported as-is, including
    failures. The audit currently does not pass.
    """
    return service.verification_panel()


@app.post("/api/verification/audit", tags=["verification"])
def rerun_audit(
    self_test: bool = Query(False, description="Also run the negative control (slower)."),
    service: ResultsService = Depends(get_service),
) -> dict[str, object]:
    """Re-run scripts/audit_equations.py and refresh its stored log.

    Takes ~14 s. Worth having live in a demo: re-running the audit in front of
    an examiner is more convincing than showing a file.
    """
    return service.rerun_audit(self_test=self_test)


@app.get("/api/figures", tags=["figures"])
def figures(service: ResultsService = Depends(get_service)) -> dict[str, object]:
    """The committed thesis figures under ``output/``, grouped by directory."""
    return service.figures()


@app.get("/api/figures/{path:path}", tags=["figures"])
def figure(path: str, service: ResultsService = Depends(get_service)) -> FileResponse:
    """Serve one figure PNG by the ``path`` returned from ``/api/figures``."""
    return FileResponse(service.figure_path(path), media_type="image/png")


# --- live / replay stream ----------------------------------------------------


@app.websocket("/ws/stream")
async def stream(
    websocket: WebSocket,
    run_id: str = Query(..., description="Run to stream."),
    mode: str = Query("replay", description="'replay' a finished run, or 'live' tail a growing one."),
    speed: float = Query(1.0, description="Replay speed multiplier; ignored when mode=live."),
    from_start: bool = Query(True, description="Live mode: include rows already written."),
    service: ResultsService = Depends(get_service),
) -> None:
    """Stream one run's cycles to the Live PEM Monitor.

    Replay and live emit an identical message sequence -- one ``meta``, then a
    ``cycle`` per routing cycle, then ``end`` -- so the UI renders them the same
    way and only the labelled ``source`` differs. HTTP exception handlers do not
    apply to WebSockets, so errors are sent as an ``error`` message before close.
    """
    await websocket.accept()

    try:
        await websocket.send_json(service.stream_meta(run_id, mode))
        source = service.stream_source(
            run_id, mode=mode, speed=speed, from_start=from_start
        )
    except ServiceError as exc:
        await websocket.send_json({"type": "error", "detail": str(exc)})
        await websocket.close()
        return

    try:
        async for cycle in source:
            await websocket.send_json(cycle.to_message())
        # Only replay terminates on its own; a live tail runs until disconnect.
        await websocket.send_json({"type": "end", "reason": "complete"})
    except WebSocketDisconnect:
        return
    except (FileNotFoundError, SchemaError) as exc:
        await websocket.send_json({"type": "error", "detail": str(exc)})
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("stream failed for %s", run_id)
        await websocket.send_json({"type": "error", "detail": str(exc)})

    try:
        await websocket.close()
    except RuntimeError:
        pass  # already closed by the client


# --- static frontend ---------------------------------------------------------

# Mounted last: it is a catch-all and would otherwise shadow /api/*.
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
else:  # pragma: no cover - only until Phase 1b lands
    logger.warning("frontend directory not found at %s; serving API only", FRONTEND_DIR)
