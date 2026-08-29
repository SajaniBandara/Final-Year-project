"""TCAM occupancy / RSU grid tests.

Run with::

    python -m unittest gui.tests.test_tcam -v

Three traps in this dataset would each yield a plausible but wrong picture, and
each has a test here:

  1. ``rsu_id`` is a simulation node index over all 268 nodes, not an RSU index.
  2. Utilisation must use ``counted_rule_count`` (capacity-occupying, read by
     S3/S4), not ``total_rule_count`` (includes passive ip-hook entries).
  3. The grid is row-major, 8 wide. Column-major would look fine and be wrong.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from gui.backend import tcam
from gui.backend.app import app

HEADER = "t,rsu_id,total_rule_count,cum_rejections,counted_rule_count\n"


def _write(directory: Path, name: str, rows: list[tuple[int, int, int, int, int]]) -> Path:
    path = directory / name
    path.write_text(
        HEADER + "".join(f"{t},{n},{tot},{rej},{cnt}\n" for t, n, tot, rej, cnt in rows),
        encoding="utf-8",
    )
    return path


class TestRsuRange(unittest.TestCase):
    """Trap 1: the RSU slice must be derived, not hardcoded at 200."""

    def test_standard_268_node_topology(self):
        start, end = tcam.rsu_range(267)
        self.assertEqual((start, end), (200, 264))

    def test_smaller_vehicle_count_shifts_the_window(self):
        # 40 vehicles + 64 RSUs + 4 controllers = 108 nodes, ids 0..107.
        start, end = tcam.rsu_range(107)
        self.assertEqual((start, end), (40, 104))
        self.assertEqual(end - start, 64)

    def test_window_is_always_the_rsu_count_wide(self):
        for max_id in (107, 167, 267, 367):
            start, end = tcam.rsu_range(max_id)
            self.assertEqual(end - start, 64, max_id)


class TestGridPosition(unittest.TestCase):
    """Trap 3: row-major, GridWidth 8 (routing.cc:143049)."""

    def test_origin(self):
        self.assertEqual(tcam.grid_position(0)["row"], 0)
        self.assertEqual(tcam.grid_position(0)["col"], 0)
        self.assertEqual(tcam.grid_position(0)["x"], 100.0)

    def test_row_major_wrap(self):
        # RSU 7 ends row 0; RSU 8 starts row 1. Column-major would give col 1.
        self.assertEqual(tcam.grid_position(7), {"row": 0, "col": 7, "x": 100.0 + 260.0 * 7, "y": 100.0})
        eight = tcam.grid_position(8)
        self.assertEqual((eight["row"], eight["col"]), (1, 0))

    def test_known_cell(self):
        nine = tcam.grid_position(9)
        self.assertEqual((nine["row"], nine["col"]), (1, 1))
        self.assertEqual((nine["x"], nine["y"]), (360.0, 370.0))

    def test_last_cell(self):
        last = tcam.grid_position(63)
        self.assertEqual((last["row"], last["col"]), (7, 7))


class TestAnalyse(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _standard_rows(self, counted: int) -> list[tuple[int, int, int, int, int]]:
        """One timestep over a full 268-node topology; RSUs carry `counted`."""
        rows = [(2, v, 5, 0, 5) for v in range(200)]              # vehicles
        rows += [(2, 200 + r, counted + 1, 0, counted) for r in range(64)]  # RSUs
        rows += [(2, 264 + c, 0, 0, 0) for c in range(4)]          # controllers
        return rows

    def test_vehicles_and_controllers_are_excluded(self):
        """Trap 1 end to end: vehicle rules must not inflate RSU occupancy."""
        path = _write(self.dir, "tcam_occupancy_attack3.csv", self._standard_rows(150))
        a = tcam.analyse(path)
        self.assertEqual(a["rsu_node_range"], [200, 264])
        # 150/1500 = 0.1 for every RSU; the 200 vehicles at 5 rules are ignored.
        self.assertAlmostEqual(a["series"][0]["mean_util"], 0.1)
        self.assertAlmostEqual(a["series"][0]["max_util"], 0.1)
        self.assertEqual(a["series"][0]["occupied_rsus"], 64)

    def test_utilisation_uses_counted_not_total(self):
        """Trap 2: total includes ip-hook entries and would overstate occupancy."""
        rows = [(2, 200 + r, 1500, 0, 150) for r in range(64)]
        rows += [(2, 264 + c, 0, 0, 0) for c in range(4)]
        rows += [(2, v, 0, 0, 0) for v in range(200)]
        a = tcam.analyse(_write(self.dir, "tcam_occupancy_attack3.csv", rows))
        # counted=150 -> 0.10.  total=1500 would have read as 1.00.
        self.assertAlmostEqual(a["series"][0]["max_util"], 0.1)
        self.assertEqual(a["series"][0]["iphook_delta"], (1500 - 150) * 64)

    def test_s4_threshold_crossing_is_counted(self):
        below = tcam.analyse(_write(self.dir, "tcam_occupancy_attack3.csv",
                                    self._standard_rows(300)))   # 0.20 < gate
        above = tcam.analyse(_write(self.dir, "tcam_occupancy_attack4.csv",
                                    self._standard_rows(400)))   # 0.267 > gate
        self.assertEqual(below["series"][0]["over_threshold"], 0)
        self.assertEqual(above["series"][0]["over_threshold"], 64)

    def test_frames_have_one_count_per_rsu(self):
        a = tcam.analyse(_write(self.dir, "tcam_occupancy_attack3.csv", self._standard_rows(10)))
        self.assertEqual(len(a["frames"][0]["counts"]), 64)

    def test_missing_rsus_read_as_zero_not_dropped(self):
        """A grid must always have 64 cells, even when an RSU logged nothing."""
        rows = [(2, 200, 10, 0, 10), (2, 267, 0, 0, 0)]
        a = tcam.analyse(_write(self.dir, "tcam_occupancy_attack3.csv", rows))
        counts = a["frames"][0]["counts"]
        self.assertEqual(len(counts), 64)
        self.assertEqual(counts[0], 10)
        self.assertEqual(counts[1], 0)

    def test_empty_file_is_unavailable(self):
        path = _write(self.dir, "tcam_occupancy_attack3.csv", [])
        self.assertFalse(tcam.analyse(path)["available"])

    def test_peak_is_the_highest_timestep(self):
        rows = self._standard_rows(100)
        rows += [(3, 200 + r, 401, 0, 400) for r in range(64)]
        a = tcam.analyse(_write(self.dir, "tcam_occupancy_attack3.csv", rows))
        self.assertEqual(a["peak"]["t"], 3)


class TestFilenamesAndPanel(unittest.TestCase):
    def test_parses_plain_and_suffixed_modes(self):
        self.assertEqual(tcam.parse_tcam_filename("tcam_occupancy_attack4.csv"),
                         {"attack_id": 4, "suffix": None})
        self.assertEqual(tcam.parse_tcam_filename("tcam_occupancy_attack3_pct40.csv"),
                         {"attack_id": 3, "suffix": "pct40"})
        self.assertEqual(tcam.parse_tcam_filename("tcam_occupancy_attack4_n120.csv"),
                         {"attack_id": 4, "suffix": "n120"})

    def test_ignores_other_tcam_files(self):
        self.assertIsNone(tcam.parse_tcam_filename("tcam_snapshots_attack3.csv"))
        self.assertIsNone(tcam.parse_tcam_filename("MOBIGUARD_Attack3_40_seed1.csv"))

    def test_panel_unavailable_without_data(self):
        panel = tcam.panel(results_dir=Path("no") / "such" / "dir")
        self.assertFalse(panel["available"])


class TestTcamRoute(unittest.TestCase):
    def test_route_serves(self):
        response = TestClient(app).get("/api/panels/tcam")
        self.assertEqual(response.status_code, 200)
        self.assertIn("available", response.json())


if __name__ == "__main__":
    unittest.main()
