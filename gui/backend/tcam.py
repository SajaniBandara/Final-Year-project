"""TCAM occupancy and the RSU grid, from ``tcam_occupancy_*.csv``.

Schema (``scratch/tcam_attack_helper.h:634``)::

    t, rsu_id, total_rule_count, cum_rejections, counted_rule_count

Three things here are easy to get wrong, and each would produce a plausible but
incorrect picture.

**1. ``rsu_id`` is a simulation node index, not an RSU index.**
Despite the column name it ranges over all 268 nodes -- 200 vehicles, then 64
RSUs, then 4 controllers (``routing.cc:112``, ``const int total_size = 268``).
Measured: every occupancy file has ids 0..267, of which only 200..263 are RSUs.
Rendering an 8x8 grid straight from ``rsu_id`` would plot vehicles.

**2. ``counted_rule_count`` is the capacity-occupying count, not
``total_rule_count``.** From the writer's own comment
(``tcam_attack_helper.h:668``): ``total_rule_count`` is the raw table including
passive ip-hook observations, while ``counted_rule_count`` is
``g_tcam_rule_count``, "the authoritative data-plane rule count the S3/S4
detector reads". Utilisation computed from ``total`` would overstate occupancy.

**3. The grid is row-major, 8 wide.** ``routing.cc:143049`` allocates RSU
positions with ``GridPositionAllocator``, ``GridWidth=8``,
``LayoutType="RowFirst"``, ``DeltaX=260``, ``DeltaY=270`` from ``(100, 100)``.
So RSU ``r`` sits at column ``r % 8``, row ``r // 8``. A column-major render
would look entirely reasonable and be wrong.
"""

from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .catalog import DEFAULT_RESULTS_DIR

#: Single canonical TCAM size (``routing.cc:117842``).
TCAM_CAPACITY = 1500

#: S4's occupancy gate -- benign 99th percentile, recalibrated 2026-08-08.
#: The detector fires above this (``routing.cc``, ComputeTcamDetection call).
S4_UTIL_THRESHOLD = 0.216667

N_RSUS_DEFAULT = 64
N_CONTROLLERS_DEFAULT = 4

#: RSU grid layout (``routing.cc:143049``).
GRID_WIDTH = 8
GRID_MIN_X, GRID_MIN_Y = 100.0, 100.0
GRID_DELTA_X, GRID_DELTA_Y = 260.0, 270.0

TCAM_FILENAME_RE = re.compile(
    r"^tcam_occupancy_attack(?P<attack>\d+)(?P<suffix>_[A-Za-z0-9]+)?\.csv$"
)


@dataclass(frozen=True)
class TcamFile:
    """One occupancy log."""

    mode: str
    path: Path
    attack_id: int
    suffix: str | None

    @property
    def label(self) -> str:
        return f"Attack {self.attack_id}" + (f" ({self.suffix})" if self.suffix else "")

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.mode,
            "label": self.label,
            "attack": self.attack_id,
            "suffix": self.suffix,
        }


def parse_tcam_filename(name: str) -> dict[str, object] | None:
    """Parse an occupancy filename into attack id and sweep suffix.

    The suffix (``_pct40``, ``_n120``, …) is carried through verbatim rather
    than interpreted: the sweep files are distinct runs, but what the ``_nXX``
    parameter varies is not recorded in the data, and every such file still has
    200 vehicles.
    """
    match = TCAM_FILENAME_RE.match(name)
    if match is None:
        return None
    suffix = match.group("suffix")
    return {
        "attack_id": int(match.group("attack")),
        "suffix": suffix[1:] if suffix else None,
    }


def scan(results_dir: str | os.PathLike[str] | None = None) -> list[TcamFile]:
    """Index the TCAM occupancy logs in ``results_dir``."""
    base = Path(results_dir or os.environ.get("MOBIGUARD_RESULTS_DIR") or DEFAULT_RESULTS_DIR)
    if not base.is_dir():
        return []
    found: list[TcamFile] = []
    for entry in sorted(base.glob("tcam_occupancy_*.csv")):
        parts = parse_tcam_filename(entry.name)
        if parts is None:
            continue
        found.append(
            TcamFile(
                mode=entry.stem.replace("tcam_occupancy_", ""),
                path=entry,
                attack_id=int(parts["attack_id"]),
                suffix=parts["suffix"],  # type: ignore[arg-type]
            )
        )
    return sorted(found, key=lambda f: (f.attack_id, f.suffix or ""))


def rsu_range(max_node_id: int, n_rsus: int = N_RSUS_DEFAULT,
              n_controllers: int = N_CONTROLLERS_DEFAULT) -> tuple[int, int]:
    """Half-open ``[start, end)`` of node ids that are RSUs.

    Derived from the highest node id rather than a hardcoded 200, so a run with
    a different vehicle count still slices correctly. Node order is
    vehicles, then RSUs, then controllers.
    """
    total = max_node_id + 1
    start = total - n_controllers - n_rsus
    return max(0, start), max(0, total - n_controllers)


def grid_position(rsu_local: int) -> dict[str, float]:
    """Row/column and world position of an RSU, row-major, 8 wide."""
    row, col = divmod(rsu_local, GRID_WIDTH)
    return {
        "row": row,
        "col": col,
        "x": GRID_MIN_X + GRID_DELTA_X * col,
        "y": GRID_MIN_Y + GRID_DELTA_Y * row,
    }


def analyse(path: str | os.PathLike[str], *, n_rsus: int = N_RSUS_DEFAULT) -> dict[str, object]:
    """Aggregate one occupancy log into a time series plus per-RSU grid frames."""
    rows: list[tuple[int, int, int, int, int]] = []
    max_node = 0

    with Path(path).open("r", encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            try:
                t = int(float(row["t"]))
                node = int(float(row["rsu_id"]))
                total = int(float(row["total_rule_count"]))
                rejects = int(float(row["cum_rejections"]))
                counted = int(float(row["counted_rule_count"]))
            except (KeyError, TypeError, ValueError):
                continue
            rows.append((t, node, total, rejects, counted))
            max_node = max(max_node, node)

    if not rows:
        return {"available": False}

    start, end = rsu_range(max_node, n_rsus=n_rsus)

    # Per timestep: only RSU nodes contribute to occupancy.
    per_t: dict[int, dict[int, tuple[int, int, int]]] = {}
    for t, node, total, rejects, counted in rows:
        if start <= node < end:
            per_t.setdefault(t, {})[node - start] = (counted, total, rejects)

    timesteps = sorted(per_t)
    series = []
    frames = []
    for t in timesteps:
        cells = per_t[t]
        counts = [cells.get(r, (0, 0, 0))[0] for r in range(n_rsus)]
        utils = [c / TCAM_CAPACITY for c in counts]
        rejects_total = sum(v[2] for v in cells.values())
        leaked = sum(v[1] - v[0] for v in cells.values())
        series.append(
            {
                "t": t,
                "mean_util": sum(utils) / n_rsus,
                "max_util": max(utils),
                "occupied_rsus": sum(1 for c in counts if c > 0),
                "over_threshold": sum(1 for u in utils if u > S4_UTIL_THRESHOLD),
                "cum_rejections": rejects_total,
                # total - counted is the passive ip-hook delta, surfaced so the
                # two accountings can be reconciled rather than conflated.
                "iphook_delta": leaked,
            }
        )
        frames.append({"t": t, "counts": counts})

    peak = max(series, key=lambda s: s["max_util"])
    return {
        "available": True,
        "capacity": TCAM_CAPACITY,
        "s4_threshold": S4_UTIL_THRESHOLD,
        "n_rsus": n_rsus,
        "grid_width": GRID_WIDTH,
        "rsu_node_range": [start, end],
        "max_node_id": max_node,
        "timesteps": timesteps,
        "series": series,
        "frames": frames,
        "peak": peak,
        "grid": [grid_position(r) for r in range(n_rsus)],
        "note": (
            "Utilisation is counted_rule_count / TCAM_CAPACITY. "
            "counted_rule_count is the authoritative data-plane count the S3/S4 "
            "detector reads; total_rule_count additionally includes passive "
            "ip-hook observations."
        ),
    }


def panel(mode: str | None = None,
          results_dir: str | os.PathLike[str] | None = None) -> dict[str, object]:
    """TCAM panel: the mode list plus one analysed run."""
    files = scan(results_dir)
    if not files:
        return {"available": False, "runs": []}
    selected = next((f for f in files if f.mode == mode), files[0])
    analysis = analyse(selected.path)
    return {
        "available": analysis.get("available", False),
        "runs": [f.to_dict() for f in files],
        "selected": selected.to_dict(),
        "analysis": analysis,
    }
