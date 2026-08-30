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

@app.get("/api/map/demo", tags=["map"])
def map_demo_scene() -> dict:
    """Synthetic demo scene — no results_routing/ CSVs needed.

    Generates 30 vehicles moving on plausible road paths across the LA map,
    the full 8x8 RSU grid, 4 controllers, 60 frames of animation, and
    detection events from second 10 onward so the accusation overlay
    and car-rotation code can all be exercised without any real data.
    """
    import math as _math
    import random as _rnd

    _rnd.seed(42)

    # --- static layout (same constants as topology.py) -----------------------
    N_V, N_RSU, N_CTRL = 30, 64, 4
    MAP_W, MAP_H = 2061.0, 2137.0
    RSU_MIN_X, RSU_MIN_Y = 100.0, 100.0
    RSU_DX, RSU_DY = 260.0, 270.0
    RSU_GRID_W = 8
    CTRL_POS = [(515.0, 534.0), (1545.0, 534.0), (515.0, 1602.0), (1545.0, 1602.0)]

    rsus = []
    for r in range(N_RSU):
        col, row = r % RSU_GRID_W, r // RSU_GRID_W
        x, y = RSU_MIN_X + RSU_DX * col, RSU_MIN_Y + RSU_DY * row
        best_c = min(range(N_CTRL), key=lambda c: (x - CTRL_POS[c][0])**2 + (y - CTRL_POS[c][1])**2)
        rsus.append({"id": N_V + r, "index": r, "row": row, "col": col,
                     "x": x, "y": y, "controller": best_c})

    controllers = [{"id": N_V + N_RSU + c, "index": c, "x": cx, "y": cy}
                   for c, (cx, cy) in enumerate(CTRL_POS)]

    layout = {
        "map": {"width": MAP_W, "height": MAP_H},
        "rsus": rsus,
        "controllers": controllers,
        "n_vehicles": N_V, "n_rsus": N_RSU, "n_controllers": N_CTRL,
        "coverage_radius": 180.0, "grid_width": RSU_GRID_W,
        "id_ranges": {
            "vehicles":    [0,          N_V - 1],
            "rsus":        [N_V,        N_V + N_RSU - 1],
            "controllers": [N_V + N_RSU, N_V + N_RSU + N_CTRL - 1],
        },
    }

    # --- vehicle routes: straight lines across the map -----------------------
    # Each vehicle gets a start point and a bearing so it drifts naturally.
    SPEED = 14.0  # m/s ≈ 50 km/h
    routes = []
    for i in range(N_V):
        angle = _rnd.uniform(0, 2 * _math.pi)
        x0 = _rnd.uniform(100, MAP_W - 100)
        y0 = _rnd.uniform(100, MAP_H - 100)
        routes.append((x0, y0, _math.cos(angle) * SPEED, _math.sin(angle) * SPEED))

    # 5 malicious vehicles — ids 3, 7, 12, 18, 25
    ATTACKERS = {3, 7, 12, 18, 25}
    ATTACK_START = 10   # second at which detection events begin
    SIGNALS = ["S1", "S2", "S3", "S4", "S5"]
    N_FRAMES = 60

    # --- build frames ---------------------------------------------------------
    frames = []
    all_events: list[dict] = []

    for fi in range(N_FRAMES):
        t = float(fi)
        vehicles = []
        for vid, (x0, y0, vx, vy) in enumerate(routes):
            x = (x0 + vx * t) % MAP_W
            y = (y0 + vy * t) % MAP_H
            vehicles.append({"id": vid, "x": round(x, 1), "y": round(y, 1)})

        frame_events = []
        if fi >= ATTACK_START:
            # Each malicious vehicle may generate 0-2 accusations per frame
            for att in ATTACKERS:
                if _rnd.random() < 0.45:
                    rsu_idx = _rnd.randint(0, N_RSU - 1)
                    rsu_id  = N_V + rsu_idx
                    signal  = _rnd.choice(SIGNALS)
                    ev = {"rsu": rsu_id, "suspect": att, "signal": signal,
                          "t": round(t + _rnd.uniform(0, 0.9), 2)}
                    frame_events.append(ev)
                    all_events.append(ev)

        frames.append({
            "t": t,
            "vehicles": vehicles,
            "events": frame_events,
            "density": {str(N_V + r): _rnd.randint(1, 6) for r in range(N_RSU)},
        })

    return {
        "run_id": "demo",
        "attack_id": 2,
        "attack_percentage": 20,
        "seed": 1,
        "layout": layout,
        "frames": frames,
        "frame_step": 1.0,
        "duration": float(N_FRAMES - 1),
        "event_count": len(all_events),
        "events_truncated": False,
        "ground_truth": {
            "attackers": sorted(ATTACKERS),
            "expected_count": len(ATTACKERS),
            "known": True,
            "source": "synthetic demo — not a real run",
        },
        "suspects": [
            {"suspect": a, "count": sum(1 for e in all_events if e["suspect"] == a),
             "first_t": ATTACK_START, "last_t": N_FRAMES - 1,
             "signals": {s: 1 for s in SIGNALS}, "accusers": [N_V]}
            for a in sorted(ATTACKERS)
        ],
        "sources": {"detection_log": None, "density": None, "mobility": "synthetic"},
        "notes": ["⚠ Demo mode — synthetic data, not a real simulation run."],
    }


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


@app.get("/api/panels/baselines", tags=["analysis"])
def baselines_panel(service: ResultsService = Depends(get_service)) -> dict:
    """SOTA comparators (B1 TAP, B2 SFTO, B3 eFADE) and the ablation summary."""
    return service.baselines_panel()


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
