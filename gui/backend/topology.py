"""Network geometry and per-second node state: the data behind the map.

The implementation plan filed the topology view as "Phase 3b, needs a
``routing.cc`` change" on the grounds that no per-node detection state was
emitted. That turned out to be wrong. Everything the map needs is already on
disk or derivable:

============================  =========================================
What                          Where it comes from
============================  =========================================
RSU positions                 Computed. ``routing.cc`` places them with a
                              ``GridPositionAllocator``; the parameters are
                              constants, so the layout is reproducible
                              exactly without reading anything.
Controller positions          Computed. Four fixed quadrant positions,
                              likewise constants in the C++.
Vehicle positions over time   ``mobility/mobility_urban_150_seed<S>.tcl``,
                              the same ns-2 trace ns-3 itself replays.
Who accused whom, and when    ``bc_detection_log_*.csv``:
                              ``rsu_id, suspect_node, signal_idx,
                              timestamp_ms``.
Vehicles per RSU per second   ``rsu_density_*.csv``.
RSU TCAM occupancy per sec    ``tcam_occupancy_*.csv``.
Who was actually malicious    Only stdout, from ``declare_attackers()`` --
                              see :mod:`.runner`, which captures it live.
============================  =========================================

So the map works for a finished run (scrub through it) and for a running one
(the same overlays, tailed), with no simulator change.

Reconstructing vehicle positions
--------------------------------
The trace is ns-2 ``setdest`` format, which is a *movement* description, not a
position table::

    $node_(0) set X_ 1521.72              # initial position
    $ns_ at 12.0 "$node_(0) setdest 1600 500 13.89"

``setdest x y speed`` means "from now, head toward (x, y) at speed m/s, and stop
on arrival". Position at an arbitrary time therefore has to be integrated
forward through the events, which is what :class:`MobilityTrace` does -- the
same thing ``Ns2MobilityHelper`` does inside ns-3, so the map shows where the
vehicles actually were, not an approximation of it.
"""

from __future__ import annotations

import math
import re
import xml.etree.ElementTree as ET
from bisect import bisect_right
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Iterator

from .catalog import REPO_ROOT

# --------------------------------------------------------------------------
# Geometry constants, quoted from routing.cc. These are not tuning knobs -- if
# the C++ layout changes, these must change with it, and tests/test_topology.py
# re-reads the allocator arguments from the source to catch that.
# --------------------------------------------------------------------------

#: ``RSU_mobility.SetPositionAllocator("ns3::GridPositionAllocator", ...)`` in
#: the ``use_sumo_mobility`` branch (routing.cc ~143050). RowFirst layout.
RSU_MIN_X, RSU_MIN_Y = 100.0, 100.0
RSU_DELTA_X, RSU_DELTA_Y = 260.0, 270.0
RSU_GRID_WIDTH = 8

#: The four SDVN controllers, one per quadrant (routing.cc ~143224).
CONTROLLER_POSITIONS: tuple[tuple[float, float], ...] = (
    (515.0, 534.0),    # c1: SW
    (1545.0, 534.0),   # c2: SE
    (515.0, 1602.0),   # c3: NW
    (1545.0, 1602.0),  # c4: NE
)

#: Extent of the SUMO-derived Los Angeles map, from the comment on the RSU
#: allocator: "the new 2061m x 2137m LA map".
MAP_WIDTH, MAP_HEIGHT = 2061.0, 2137.0

#: Nominal RSU radio reach, for drawing coverage. Illustrative: the simulation's
#: actual association is by nearest-RSU, not by a hard radius, so this circle is
#: a visual aid and the UI labels it as one.
RSU_COVERAGE_R = 180.0

#: Signature index -> label, as written to ``bc_detection_log``'s
#: ``signal_idx`` column. S1..S8 are the eight MOBIGUARD signatures.
SIGNAL_LABELS: dict[int, str] = {
    0: "S1", 1: "S2", 2: "S3", 3: "S4",
    4: "S5", 5: "S6", 6: "S7", 7: "S8",
}


class TopologyError(RuntimeError):
    """A topology input is missing or unreadable."""


# --------------------------------------------------------------------------
# Static layout
# --------------------------------------------------------------------------

def rsu_position(index: int) -> tuple[float, float]:
    """Position of RSU ``index`` (0-based), from the grid allocator.

    RowFirst means the index advances along X first, wrapping every
    ``GridGridWidth`` units into the next row -- so index 8 is directly above
    index 0, not to the right of index 7.
    """
    col = index % RSU_GRID_WIDTH
    row = index // RSU_GRID_WIDTH
    return (RSU_MIN_X + RSU_DELTA_X * col, RSU_MIN_Y + RSU_DELTA_Y * row)


def nearest_controller(x: float, y: float) -> int:
    """Index of the closest controller, matching the C++ assignment rule.

    ``routing.cc`` assigns each RSU to ``argmin_ci d(r_k, ci)`` over trusted
    controllers. Reproduced here so the map can draw the control-plane edges
    without the simulator having to emit them.
    """
    best, best_d = 0, math.inf
    for i, (cx, cy) in enumerate(CONTROLLER_POSITIONS):
        d = (x - cx) ** 2 + (y - cy) ** 2
        if d < best_d:
            best, best_d = i, d
    return best


def _real_net_xml() -> Path | None:
    """Find the SUMO road network ``osm.net.xml``, coping with a degraded checkout.

    ``sumo_sim/seed<1-5>/osm.net.xml`` are symlinks to one shared network file
    (all seeds drive on the same roads; only traffic/routes differ). On a
    checkout without symlink support (this Windows tree, confirmed
    2026-09-01) each one degraded into a plain ~110-byte text file holding the
    *original* machine's absolute path rather than a working link -- so this
    tries the working-symlink case first, then salvages the repo-relative
    tail of that leftover text.
    """
    base = REPO_ROOT / "sumo_sim"
    if not base.is_dir():
        return None
    candidates = sorted(base.glob("*/osm.net.xml"))

    def _big_enough(p: Path) -> bool:
        try:
            return p.is_file() and p.stat().st_size > 1_000_000
        except OSError:
            return False

    for candidate in candidates:
        target = candidate.resolve() if candidate.is_symlink() else candidate
        if _big_enough(target):
            return target

    for candidate in candidates:
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            continue
        if "\n" in text or len(text) > 400:
            continue  # not a small pointer file
        normalised = text.replace("\\", "/")
        idx = normalised.find("sumo_sim/")
        if idx == -1:
            continue
        resolved = (REPO_ROOT / normalised[idx:]).resolve()
        if _big_enough(resolved):
            return resolved
    return None


#: SUMO/OSM ``edge type`` -> the class the frontend styles it as, matching
#: SUMO-GUI's own default network colouring (grey asphalt for motor traffic,
#: tan footways, red-brown cycleways, dashed dark rail) rather than one
#: undifferentiated line for every road.
_NON_MOTOR_TYPES = frozenset({
    "highway.footway", "highway.pedestrian", "highway.steps", "highway.path",
})


def _road_class(edge_type: str | None) -> str:
    if not edge_type:
        return "road"
    if edge_type.startswith("railway."):
        return "rail"
    if edge_type in _NON_MOTOR_TYPES:
        return "foot"
    if edge_type == "highway.cycleway":
        return "cycle"
    return "road"


@lru_cache(maxsize=1)
def road_network() -> list[dict[str, Any]] | None:
    """Road centrelines, in the same coordinate space as everything else on the map.

    ``osm.net.xml``'s ``<location convBoundary="0.00,0.00,2061.77,2137.46">``
    matches :data:`MAP_WIDTH`/:data:`MAP_HEIGHT` exactly (both derive from the
    same SUMO->ns-2 export), so these polylines need no reprojection -- they
    draw in the identical coordinate system RSU and vehicle positions already
    use. Skips SUMO's internal junction-connector edges (the ``:``-prefixed
    ids), which are stubs a few metres long and not roads a reader would
    recognise.

    Each entry carries ``lanes`` (the edge's real lane count, so the frontend
    can draw a 4-lane arterial thicker than a service alley) and ``class``
    (:func:`_road_class`, so it can colour motor roads, footways, cycleways
    and rail differently -- the point of "standard SUMO colours"). The
    centreline is the *middle* lane's shape rather than the first: on a
    multi-lane edge the first lane is offset a full lane width from the
    road's true centre, which reads as visibly off-alignment once the road is
    drawn with real width.

    Cached for the process lifetime: parsing the ~8MB network XML takes a
    moment, and the network is identical for every run.
    """
    path = _real_net_xml()
    if path is None:
        return None
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None

    roads: list[dict[str, Any]] = []
    for edge in root.iter("edge"):
        if edge.get("function") == "internal":
            continue
        lanes = edge.findall("lane")
        if not lanes:
            continue
        shape = lanes[len(lanes) // 2].get("shape")
        if not shape:
            continue
        points: list[tuple[float, float]] = []
        for pair in shape.split():
            x_str, _, y_str = pair.partition(",")
            try:
                points.append((round(float(x_str), 1), round(float(y_str), 1)))
            except ValueError:
                break
        if len(points) < 2:
            continue
        roads.append({
            "points": points,
            "lanes": len(lanes),
            "class": _road_class(edge.get("type")),
        })
    return roads


def layout(n_vehicles: int = 200, n_rsus: int = 64, n_controllers: int = 4) -> dict[str, Any]:
    """The static scene: every fixed node, its logical id, and its position.

    Logical ids follow the convention every CSV and every header uses -- and
    which is *not* the ns-3 node id: vehicles occupy ``0 .. N_Vehicles-1``,
    RSUs ``N_Vehicles .. N_Vehicles+N_RSUs-1``, controllers after that. Getting
    this wrong silently mislabels every detection event on the map, because
    ``suspect_node`` in the detection log is a logical id.
    """
    rsus = []
    for r in range(n_rsus):
        x, y = rsu_position(r)
        rsus.append({
            "id": n_vehicles + r,
            "index": r,
            "row": r // RSU_GRID_WIDTH,
            "col": r % RSU_GRID_WIDTH,
            "x": x, "y": y,
            "controller": nearest_controller(x, y),
        })
    controllers = [
        {"id": n_vehicles + n_rsus + c, "index": c, "x": x, "y": y}
        for c, (x, y) in enumerate(CONTROLLER_POSITIONS[:n_controllers])
    ]
    return {
        "map": {"width": MAP_WIDTH, "height": MAP_HEIGHT},
        "roads": road_network(),
        "rsus": rsus,
        "controllers": controllers,
        "vehicle_ids": [0, max(0, n_vehicles - 1)],
        "n_vehicles": n_vehicles,
        "n_rsus": n_rsus,
        "n_controllers": n_controllers,
        "coverage_radius": RSU_COVERAGE_R,
        "grid_width": RSU_GRID_WIDTH,
        "id_ranges": {
            "vehicles": [0, n_vehicles - 1],
            "rsus": [n_vehicles, n_vehicles + n_rsus - 1],
            "controllers": [n_vehicles + n_rsus,
                            n_vehicles + n_rsus + n_controllers - 1],
        },
    }


# --------------------------------------------------------------------------
# Vehicle mobility
# --------------------------------------------------------------------------

_INIT_RE = re.compile(
    r"^\$node_\((?P<node>\d+)\)\s+set\s+(?P<axis>[XYZ])_\s+(?P<value>-?[\d.eE+-]+)"
)
_DEST_RE = re.compile(
    r'^\$ns_\s+at\s+(?P<t>[\d.eE+-]+)\s+"\$node_\((?P<node>\d+)\)\s+setdest\s+'
    r"(?P<x>-?[\d.eE+-]+)\s+(?P<y>-?[\d.eE+-]+)\s+(?P<speed>-?[\d.eE+-]+)"
)


@dataclass
class _Waypoint:
    """One ``setdest``: head for (x, y) at ``speed`` m/s from time ``t``."""

    t: float
    x: float
    y: float
    speed: float


class MobilityTrace:
    """Vehicle positions over time, integrated from an ns-2 ``setdest`` trace.

    Sampling is the hot path -- the map asks for every vehicle's position at
    each of several hundred timesteps -- so positions are integrated once, at
    a fixed cadence, into a dense table, and sampling is then an index lookup.
    Integrating on demand per query would repeat the same forward walk for
    every frame.
    """

    def __init__(self, path: Path, *, step: float = 1.0, until: float | None = None):
        self.path = path
        self.step = step
        self._start: dict[int, tuple[float, float]] = {}
        self._waypoints: dict[int, list[_Waypoint]] = {}
        self._parse()
        self.duration = until if until is not None else self._trace_end()
        self._times: list[float] = []
        self._frames: list[dict[int, tuple[float, float]]] = []
        self._integrate()

    # -- parsing ------------------------------------------------------------

    def _parse(self) -> None:
        try:
            with self.path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    m = _DEST_RE.match(line)
                    if m is not None:
                        node = int(m.group("node"))
                        self._waypoints.setdefault(node, []).append(
                            _Waypoint(float(m.group("t")), float(m.group("x")),
                                      float(m.group("y")), float(m.group("speed")))
                        )
                        continue
                    m = _INIT_RE.match(line)
                    if m is not None:
                        node = int(m.group("node"))
                        axis = m.group("axis")
                        if axis == "Z":       # planar simulation; Z is always 0
                            continue
                        value = float(m.group("value"))
                        x, y = self._start.get(node, (0.0, 0.0))
                        self._start[node] = (value, y) if axis == "X" else (x, value)
        except OSError as exc:
            raise TopologyError(f"cannot read mobility trace {self.path}: {exc}") from exc
        if not self._start:
            raise TopologyError(f"{self.path} contains no node positions")
        for waypoints in self._waypoints.values():
            waypoints.sort(key=lambda w: w.t)

    def _trace_end(self) -> float:
        return max(
            (w[-1].t for w in self._waypoints.values() if w),
            default=0.0,
        )

    # -- integration --------------------------------------------------------

    def _integrate(self) -> None:
        """Walk every node forward through its waypoints at ``self.step``.

        Between waypoints a node moves toward its current target at its current
        speed and **stops on arrival** -- it does not overshoot and does not
        drift. That stop-on-arrival rule is why a plain linear interpolation
        between consecutive waypoints would be wrong: a node that reaches its
        destination early sits still for the remainder of the interval, and on
        this trace that is common.
        """
        n_frames = int(self.duration / self.step) + 1
        state: dict[int, tuple[float, float]] = dict(self._start)
        target: dict[int, _Waypoint | None] = {n: None for n in self._start}
        cursor: dict[int, int] = {n: 0 for n in self._start}

        for frame in range(n_frames):
            t = frame * self.step
            for node, pos in state.items():
                waypoints = self._waypoints.get(node, ())
                # Adopt every waypoint whose time has arrived; the last one wins.
                i = cursor[node]
                while i < len(waypoints) and waypoints[i].t <= t:
                    target[node] = waypoints[i]
                    i += 1
                cursor[node] = i

                dest = target[node]
                if dest is None or dest.speed <= 0:
                    continue
                x, y = pos
                dx, dy = dest.x - x, dest.y - y
                dist = math.hypot(dx, dy)
                if dist <= 1e-9:
                    continue
                travel = dest.speed * self.step
                if travel >= dist:          # arrives within this step, and stops
                    state[node] = (dest.x, dest.y)
                else:
                    state[node] = (x + dx / dist * travel, y + dy / dist * travel)
            self._times.append(t)
            self._frames.append(dict(state))

    # -- sampling -----------------------------------------------------------

    @property
    def nodes(self) -> list[int]:
        return sorted(self._start)

    def positions_at(self, t: float) -> dict[int, tuple[float, float]]:
        """Every node's position at the frame at or before ``t``."""
        if not self._frames:
            return {}
        i = max(0, min(len(self._frames) - 1, bisect_right(self._times, t) - 1))
        return self._frames[i]

    def frame_times(self) -> list[float]:
        return list(self._times)


def trace_path(seed: int, maxspeed: int = 150) -> Path:
    """The mobility trace ``routing.cc`` loads for ``--sim_seed=seed`` and ``--maxspeed=maxspeed``.

    Seeds 1-5 select separately generated SUMO runs for speed 150; maxspeed 0..60 selects
    specific speed limit family traces (mobility_urban_<maxspeed>.tcl).
    """
    base = REPO_ROOT / "mobility"
    if maxspeed != 150:
        candidate = base / f"mobility_urban_{maxspeed}.tcl"
        if candidate.is_file():
            return candidate
    if 1 <= seed <= 5:
        candidate = base / f"mobility_urban_150_seed{seed}.tcl"
        if candidate.is_file():
            return candidate
    return base / "mobility_urban_150.tcl"


@lru_cache(maxsize=12)
def load_trace(seed: int, maxspeed: int = 150, step: float = 1.0, until: float | None = None) -> MobilityTrace:
    """Cached trace load. Integration takes a moment; the result is immutable."""
    path = trace_path(seed, maxspeed=maxspeed)
    if not path.is_file():
        raise TopologyError(
            f"mobility trace for seed {seed} and maxspeed {maxspeed} not found at {path}."
        )
    return MobilityTrace(path, step=step, until=until)


# --------------------------------------------------------------------------
# Detection overlay
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class DetectionEvent:
    """One accusation: an RSU naming a suspect, at a time, via a signature."""

    t: float
    rsu_id: int
    suspect: int
    signal: int

    @property
    def signal_label(self) -> str:
        return SIGNAL_LABELS.get(self.signal, f"sig{self.signal}")


def read_detection_log(
    path: Path, *, limit: int | None = None, until_s: float | None = None
) -> list[DetectionEvent]:
    """Parse ``bc_detection_log_*.csv``, skipping its signature column.

    These files reach hundreds of megabytes -- 33 MB for a 15 s run here, and
    the plan records 600 MB files on the HPC -- almost entirely because
    ``rsu_sig`` is a multi-kilobyte ML-DSA-87 signature per row. Reading is
    therefore line-oriented with an early field split: the signature is never
    materialised, only counted past. Do not switch this to ``csv.DictReader``
    without measuring, which builds a dict per row and holds the signature.
    """
    events: list[DetectionEvent] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            header = fh.readline()
            if not header.startswith("rsu_id"):
                raise TopologyError(f"{path.name}: unexpected header {header[:60]!r}")
            for line in fh:
                # Only the first four fields matter; the fifth is the signature.
                parts = line.split(",", 4)
                if len(parts) < 4:
                    continue
                try:
                    rsu_id = int(parts[0])
                    suspect = int(parts[1])
                    signal = int(parts[2])
                    t = int(parts[3]) / 1000.0
                except ValueError:
                    continue
                if until_s is not None and t > until_s:
                    break
                events.append(DetectionEvent(t, rsu_id, suspect, signal))
                if limit is not None and len(events) >= limit:
                    break
    except OSError as exc:
        raise TopologyError(f"cannot read {path}: {exc}") from exc
    return events


def read_rsu_density(path: Path) -> dict[int, dict[int, tuple[int, float]]]:
    """``{second: {rsu_id: (vehicle_count, mean_speed)}}`` from ``rsu_density_*``."""
    out: dict[int, dict[int, tuple[int, float]]] = {}
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            header = fh.readline()
            if not header.startswith("t,rsu_id"):
                raise TopologyError(f"{path.name}: unexpected header {header[:60]!r}")
            for line in fh:
                parts = line.rstrip("\n").split(",")
                if len(parts) < 4:
                    continue
                try:
                    t, rsu_id, rho, v_bar = (
                        int(parts[0]), int(parts[1]), int(parts[2]), float(parts[3])
                    )
                except ValueError:
                    continue
                out.setdefault(t, {})[rsu_id] = (rho, v_bar)
    except OSError as exc:
        raise TopologyError(f"cannot read {path}: {exc}") from exc
    return out


def bucket_events(
    events: Iterable[DetectionEvent], *, step: float = 1.0
) -> dict[int, list[DetectionEvent]]:
    """Group events into ``step``-second buckets keyed by bucket index.

    The map advances one frame per simulated second, matching the routing
    cycle, so this is what turns a flat event list into per-frame overlays.
    """
    out: dict[int, list[DetectionEvent]] = {}
    for event in events:
        out.setdefault(int(event.t / step), []).append(event)
    return out


def suspect_summary(events: Iterable[DetectionEvent]) -> dict[int, dict[str, Any]]:
    """Per-suspect accusation totals: how often, by whom, via which signatures.

    This is what the node inspector and the spot-the-attacker reveal both read:
    a node's whole detection story, rather than one event at one instant.
    """
    out: dict[int, dict[str, Any]] = {}
    for event in events:
        entry = out.setdefault(event.suspect, {
            "suspect": event.suspect, "count": 0, "first_t": event.t,
            "last_t": event.t, "signals": {}, "accusers": set(),
        })
        entry["count"] += 1
        entry["first_t"] = min(entry["first_t"], event.t)
        entry["last_t"] = max(entry["last_t"], event.t)
        entry["signals"][event.signal_label] = \
            entry["signals"].get(event.signal_label, 0) + 1
        entry["accusers"].add(event.rsu_id)
    for entry in out.values():
        entry["accusers"] = sorted(entry["accusers"])
    return out


def iter_frames(
    trace: MobilityTrace,
    events_by_frame: dict[int, list[DetectionEvent]],
    density: dict[int, dict[int, tuple[int, float]]],
    *,
    n_vehicles: int,
    n_rsus: int,
    start: float = 0.0,
    end: float | None = None,
    step: float = 1.0,
) -> Iterator[dict[str, Any]]:
    """Yield one map frame per simulated second.

    A frame carries only what changes: vehicle positions, the accusations made
    during that second, and each RSU's load. The static layout is sent once, by
    :func:`layout`, rather than repeated per frame -- 64 RSU positions times
    300 frames is pure waste on the wire.
    """
    end = trace.duration if end is None else end
    t = start
    while t <= end:
        index = int(t / step)
        positions = trace.positions_at(t)
        frame_events = events_by_frame.get(index, [])
        yield {
            "t": round(t, 3),
            "vehicles": [
                {"id": node, "x": round(x, 1), "y": round(y, 1)}
                for node, (x, y) in sorted(positions.items())
                if node < n_vehicles
            ],
            "events": [
                {"rsu": e.rsu_id, "suspect": e.suspect, "signal": e.signal_label,
                 "t": round(e.t, 3)}
                for e in frame_events
            ],
            "density": {
                str(rsu): count
                for rsu, (count, _v) in density.get(index, {}).items()
            },
        }
        t += step
