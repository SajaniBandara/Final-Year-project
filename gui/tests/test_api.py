"""API-layer tests for the demo GUI.

Run with::

    python -m unittest gui.tests.test_api -v

These build a synthetic ``results_routing/`` in a temp directory and inject it
via FastAPI's dependency override, so they are deterministic and run in a fresh
clone where ``results_routing/*.csv`` (gitignored) is absent. The real-data
checks live in ``test_phase0``.

Two seeds are written for attack 1 specifically so the confidence-interval path
is exercised -- the local results copy has only seed 1, so ``n>=2`` would
otherwise never be tested.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from gui.backend import schema
from gui.backend.app import app, get_service
from gui.backend.service import ResultsService

# Known-consistent confusion matrix, from MOBIGUARD_Attack1_40_d80ms_seed1.csv
# cycle 1. Using real values keeps the recomputation check meaningful.
_TP, _FP, _TN, _FN = 13.0, 20.0, 216.0, 19.0
_MCC, _DR, _FPR = 0.317268, 40.625, 8.47458


def _row(attack_id: int, cycle: int, **overrides: float) -> str:
    """Build one valid CSV row for ``attack_id``."""
    values = {name: 0.0 for name in schema.columns_for(attack_id)}
    values["cycle"] = float(cycle)
    values.update(
        {"TP": _TP, "FP": _FP, "TN": _TN, "FN": _FN,
         "cur_MCC": _MCC, "cur_DR": _DR, "cur_FPR": _FPR,
         "avg_MCC": _MCC, "avg_DR": _DR, "avg_FPR": _FPR}
    )
    values.update(overrides)
    return ", ".join(
        f"{values[name]:g}" if name != "cycle" else str(cycle)
        for name in schema.columns_for(attack_id)
    )


def _write_run(directory: Path, filename: str, attack_id: int, cycles: int = 5, **overrides: float) -> None:
    """Write a metrics CSV with the single-line header format."""
    header = "# " + ", ".join(schema.columns_for(attack_id))
    rows = [_row(attack_id, c, **overrides) for c in range(1, cycles + 1)]
    (directory / filename).write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")


class ApiTestCase(unittest.TestCase):
    """Base class wiring a synthetic results directory into the app."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)

        # Attack 1 (narrow, 52 cols) at two percentages and two seeds -> real CIs.
        for pct in (20, 40):
            for seed in (1, 2):
                _write_run(
                    base, f"MOBIGUARD_Attack1_{pct}_d80ms_seed{seed}.csv", 1,
                    avg_PDR=70.0 + seed,
                )
        # Attack 3 (wide, 61 cols) to exercise the TCAM columns.
        _write_run(base, "MOBIGUARD_Attack3_40_seed1.csv", 3, avg_tcam_util=0.085)
        # A non-metrics file the catalog must ignore.
        (base / "bc_anchor_log_Attack1_40_d80ms.csv").write_text("noise\n", encoding="utf-8")

        self.service = ResultsService(base)
        app.dependency_overrides[get_service] = lambda: self.service
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()
        self._tmp.cleanup()


class TestMeta(ApiTestCase):
    def test_health_reports_counts_and_freshness(self):
        body = self.client.get("/api/health").json()
        self.assertEqual(body["run_count"], 5)
        self.assertFalse(body["stale"])  # just written
        self.assertEqual(body["attack_start_s"], 10.0)
        self.assertIsNotNone(body["newest_modified"])

    def test_refresh_picks_up_a_new_run(self):
        base = Path(self._tmp.name)
        self.assertEqual(self.client.get("/api/health").json()["run_count"], 5)
        _write_run(base, "MOBIGUARD_Attack1_60_d80ms_seed1.csv", 1)
        # Not visible until the catalog is re-scanned...
        self.assertEqual(self.client.get("/api/health").json()["run_count"], 5)
        self.assertEqual(self.client.post("/api/refresh").json()["run_count"], 6)

    def test_openapi_schema_builds(self):
        """A broken route signature shows up here before it shows up in a demo."""
        self.assertEqual(self.client.get("/openapi.json").status_code, 200)


class TestCatalogRoutes(ApiTestCase):
    def test_catalog_lists_runs_and_axes(self):
        body = self.client.get("/api/catalog").json()
        self.assertEqual(len(body["runs"]), 5)
        self.assertEqual(body["attacks"], [1, 3])
        self.assertEqual(body["percentages"], [20, 40])
        self.assertEqual(body["seeds"], [1, 2])

    def test_metrics_differ_between_narrow_and_wide_attacks(self):
        narrow = self.client.get("/api/metrics/1").json()
        wide = self.client.get("/api/metrics/3").json()
        self.assertFalse(narrow["has_tcam_columns"])
        self.assertTrue(wide["has_tcam_columns"])
        self.assertEqual(len(narrow["columns"]), 52)
        self.assertEqual(len(wide["columns"]), 61)

    def test_metric_definitions_carry_units_and_caveats(self):
        columns = {c["name"]: c for c in self.client.get("/api/metrics/1").json()["columns"]}
        self.assertEqual(columns["cur_PDR"]["unit"], "percent")
        self.assertEqual(columns["cur_MCC"]["unit"], "fraction")
        self.assertIsNotNone(columns["cur_MCC"]["caveat"])
        self.assertIsNone(columns["cur_PDR"]["caveat"])


class TestRunRoutes(ApiTestCase):
    def test_series_returns_all_columns_by_default(self):
        body = self.client.get("/api/run/MOBIGUARD_Attack1_40_d80ms_seed1/series").json()
        self.assertEqual(body["cycles"], [1, 2, 3, 4, 5])
        self.assertEqual(len(body["columns"]), 52)
        self.assertEqual(body["runs_in_file"], 1)

    def test_series_column_subset(self):
        body = self.client.get(
            "/api/run/MOBIGUARD_Attack1_40_d80ms_seed1/series", params={"cols": "cur_MCC,cur_PDR"}
        ).json()
        self.assertEqual(sorted(body["columns"]), ["cur_MCC", "cur_PDR"])

    def test_series_attaches_caveat_for_diagnostic_columns(self):
        body = self.client.get(
            "/api/run/MOBIGUARD_Attack1_40_d80ms_seed1/series", params={"cols": "cur_MCC,cur_PDR"}
        ).json()
        self.assertIn("cur_MCC", body["caveats"])
        self.assertNotIn("cur_PDR", body["caveats"])
        self.assertIn("detector_windows.csv", body["caveats"]["cur_MCC"])

    def test_unknown_run_is_404(self):
        response = self.client.get("/api/run/nope/series")
        self.assertEqual(response.status_code, 404)
        self.assertIn("nope", response.json()["detail"])

    def test_unknown_column_is_400(self):
        response = self.client.get(
            "/api/run/MOBIGUARD_Attack1_40_d80ms_seed1/series", params={"cols": "not_a_column"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("not_a_column", response.json()["detail"])

    def test_tcam_column_rejected_on_narrow_attack(self):
        response = self.client.get(
            "/api/run/MOBIGUARD_Attack1_40_d80ms_seed1/series", params={"cols": "max_tcam_util"}
        )
        self.assertEqual(response.status_code, 400)

    def test_summary_recomputes_the_confusion_matrix(self):
        body = self.client.get("/api/run/MOBIGUARD_Attack1_40_d80ms_seed1/summary").json()
        self.assertEqual(body["confusion"]["TP"], _TP)
        self.assertAlmostEqual(body["confusion"]["MCC"], _MCC, places=5)
        self.assertAlmostEqual(body["confusion"]["DR"], _DR, places=4)
        # Written from real values, so reported and recomputed must agree.
        self.assertLess(body["verification"]["max_delta"], 1e-3)
        self.assertIn("detector_windows.csv", body["caveat"])


class TestSweepRoute(ApiTestCase):
    def test_sweep_returns_curve_with_confidence_intervals(self):
        body = self.client.get("/api/sweep", params={"attack": 1, "metric": "avg_PDR"}).json()
        self.assertEqual(body["pct"], [20, 40])
        self.assertEqual(body["n"], [2, 2])          # two seeds each
        self.assertFalse(body["single_seed"])
        self.assertTrue(all(ci is not None for ci in body["ci95"]))
        self.assertAlmostEqual(body["mean"][0], 71.5)  # seeds wrote 71.0 and 72.0

    def test_single_seed_reports_null_ci(self):
        body = self.client.get("/api/sweep", params={"attack": 3, "metric": "avg_tcam_util"}).json()
        self.assertEqual(body["n"], [1])
        self.assertTrue(body["single_seed"])
        self.assertIsNone(body["ci95"][0])

    def test_sweep_carries_the_caveat_for_detection_metrics(self):
        body = self.client.get("/api/sweep", params={"attack": 1, "metric": "avg_MCC"}).json()
        self.assertIsNotNone(body["caveat"])
        self.assertIn("eq:eval_dedup", body["caveat"])

    def test_sweep_of_a_safe_metric_has_no_caveat(self):
        body = self.client.get("/api/sweep", params={"attack": 1, "metric": "avg_PDR"}).json()
        self.assertIsNone(body["caveat"])

    def test_seed_filter(self):
        body = self.client.get(
            "/api/sweep", params={"attack": 1, "metric": "avg_PDR", "seeds": "1"}
        ).json()
        self.assertEqual(body["n"], [1, 1])

    def test_unindexed_attack_is_404(self):
        response = self.client.get("/api/sweep", params={"attack": 7, "metric": "avg_MCC"})
        self.assertEqual(response.status_code, 404)

    def test_metric_absent_from_schema_is_400(self):
        response = self.client.get("/api/sweep", params={"attack": 1, "metric": "max_tcam_util"})
        self.assertEqual(response.status_code, 400)

    def test_malformed_seeds_is_400_not_500(self):
        response = self.client.get(
            "/api/sweep", params={"attack": 1, "metric": "avg_PDR", "seeds": "one,two"}
        )
        self.assertEqual(response.status_code, 400)


class TestFigureRoutes(ApiTestCase):
    def test_figures_are_grouped(self):
        body = self.client.get("/api/figures").json()
        self.assertIn("groups", body)
        for group in body["groups"]:
            self.assertIn("group", group)
            self.assertTrue(all("path" in f for f in group["figures"]))

    def test_directory_traversal_is_refused(self):
        for attempt in ("../CLAUDE.md", "../../etc/passwd", "..%2FCLAUDE.md"):
            response = self.client.get(f"/api/figures/{attempt}")
            self.assertIn(response.status_code, (404, 400), attempt)

    def test_known_figure_is_served_when_present(self):
        body = self.client.get("/api/figures").json()
        paths = [f["path"] for g in body["groups"] for f in g["figures"]]
        if not paths:
            self.skipTest("no committed figures under output/")
        response = self.client.get(f"/api/figures/{paths[0]}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "image/png")


class TestMissingResultsDirectory(unittest.TestCase):
    """A missing results copy must degrade to 503, not crash the server."""

    def setUp(self) -> None:
        app.dependency_overrides[get_service] = lambda: ResultsService(
            Path("no") / "such" / "results" / "dir"
        )
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()

    def test_health_reports_503(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertIn("results directory not found", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
