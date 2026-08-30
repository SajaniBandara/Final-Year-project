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

from fastapi import Body, Depends, FastAPI, Query, Request, WebSocket, WebSocketDisconnect
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


@app.get("/api/panels/tcam", tags=["analysis"])
def tcam_panel(
    mode: str | None = Query(None, description="Occupancy log to analyse; first if omitted."),
    service: ResultsService = Depends(get_service),
) -> dict[str, object]:
    """TCAM occupancy over time plus per-RSU grid frames.

    Cells are RSUs only: the CSV's ``rsu_id`` is a simulation node index over
    all 268 nodes, so vehicles and controllers are sliced out.
    """
    return service.tcam_panel(mode)


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


# --- simulation control ------------------------------------------------------
#
# These are the only routes that change anything on the host: they start a
# process. Everything else in this API is read-only over the filesystem.

@app.get("/api/sim/environment", tags=["simulation"])
def sim_environment(service: ResultsService = Depends(get_service)) -> dict:
    """Whether this machine can run a simulation, and what it is doing now.

    The GUI is expected to run both on the workstation beside the ns-3 tree and
    on a laptop with no simulator at all. This route is how the frontend decides
    whether to offer run control or hide it, so it always answers rather than
    erroring when the tree is absent.
    """
    return service.simulator_environment()


@app.get("/api/sim/options", tags=["simulation"])
def sim_options(service: ResultsService = Depends(get_service)) -> dict:
    """Parameter registry, attack variants, defence layers and presets."""
    return service.run_options()


@app.post("/api/sim/plan", tags=["simulation"])
def sim_plan(
    body: dict = Body(..., description="{'values': {...}, 'defences': {...}}"),
    service: ResultsService = Depends(get_service),
) -> dict:
    """Validate a configuration and show the command it would run.

    Called on every form change, so the operator sees the exact command line
    before committing to it -- which also makes the GUI a way to compose a
    command to run by hand later.
    """
    return service.plan_run(body.get("values") or {}, body.get("defences") or {})


@app.post("/api/sim/start", tags=["simulation"])
async def sim_start(
    body: dict = Body(..., description="{'values': {...}, 'defences': {...}}"),
    service: ResultsService = Depends(get_service),
) -> dict:
    """Launch a simulation. Returns immediately with the run record."""
    return await service.start_run(
        body.get("values") or {}, body.get("defences") or {}
    )


@app.post("/api/sim/{run_uid}/stop", tags=["simulation"])
async def sim_stop(
    run_uid: str, service: ResultsService = Depends(get_service)
) -> dict:
    """Terminate a running simulation."""
    return await service.stop_run(run_uid)


@app.get("/api/sim/runs", tags=["simulation"])
def sim_runs(service: ResultsService = Depends(get_service)) -> dict:
    """Every run this server has launched, newest first."""
    return service.launched_runs()


@app.get("/api/sim/{run_uid}", tags=["simulation"])
def sim_status(
    run_uid: str, service: ResultsService = Depends(get_service)
) -> dict:
    """Progress, state and captured attacker roster for one launched run."""
    return service.run_status(run_uid)


@app.get("/api/sim/{run_uid}/log", tags=["simulation"])
def sim_log(
    run_uid: str,
    since: int = Query(0, ge=0, description="Resume from this line index."),
    service: ResultsService = Depends(get_service),
) -> dict:
    """Incremental process output. Poll with the returned cursor."""
    return service.run_log(run_uid, since)


# --- map ---------------------------------------------------------------------

@app.get("/api/map/{run_id}", tags=["map"])
def map_scene(
    run_id: str,
    start: float = Query(0.0, ge=0.0),
    end: float | None = Query(None, description="Sim seconds; default is the run's own horizon."),
    step: float = Query(1.0, gt=0.0, le=10.0),
    service: ResultsService = Depends(get_service),
) -> dict:
    """Topology, vehicle movement and detection events for one run."""
    return service.map_scene(run_id, start=start, end=end, step=step)


@app.get("/api/map/{run_id}/node/{node_id}", tags=["map"])
def map_node(
    run_id: str, node_id: int, service: ResultsService = Depends(get_service)
) -> dict:
    """One node's detection history, for the click-through inspector."""
    return service.map_node(run_id, node_id)


@app.post("/api/map/{run_id}/guess", tags=["map"])
def map_guess(
    run_id: str,
    body: dict = Body(..., description="{'guess': [node ids]}"),
    service: ResultsService = Depends(get_service),
) -> dict:
    """Score a spot-the-attacker guess against the run's attacker roster.

    Answers with the same confusion matrix the detectors are judged by, so a
    guess and MOBIGUARD's own answer are directly comparable.
    """
    return service.score_guess(run_id, list(body.get("guess") or []))


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
