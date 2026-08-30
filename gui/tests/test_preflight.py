"""Preflight tests.

Run with::

    python -m unittest gui.tests.test_preflight -v

The point of preflight is that a missing dataset is reported *before* the demo
rather than appearing as a blank panel during it, so these tests are mostly
about the absent cases being described correctly, with the command that fixes
them.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gui.backend import preflight, schema


def _write_metrics(directory: Path, name: str, attack_id: int, cycles: int = 3) -> None:
    columns = schema.columns_for(attack_id)
    header = "# " + ", ".join(columns)
    rows = []
    for c in range(1, cycles + 1):
        values = {n: 0.0 for n in columns}
        values["cycle"] = float(c)
        rows.append(", ".join(str(c) if n == "cycle" else "0" for n in columns))
    (directory / name).write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")


def _find(report: preflight.Report, name: str) -> preflight.Check:
    return next(c for c in report.checks if c.name.strip() == name)


class TestEmptyResultsDirectory(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_no_metrics_is_a_warning_not_a_failure(self):
        """The server starts fine without results; those tabs are just empty.

        FAIL is reserved for things that stop the process starting, so that a
        blocking problem is never confused with a missing dataset.
        """
        report, _ = preflight.run(self.dir)
        check = _find(report, "metrics CSVs")
        self.assertEqual(check.status, preflight.WARN)
        self.assertIn("empty", check.detail)
        self.assertEqual(report.failed, [])

    def test_missing_directory_warns_with_a_fix(self):
        report, _ = preflight.run(self.dir / "nope")
        check = _find(report, "results dir")
        self.assertEqual(check.status, preflight.WARN)
        self.assertIn("MOBIGUARD_RESULTS_DIR", check.fix)

    def test_absent_panels_are_warnings_not_failures(self):
        report, _ = preflight.run(self.dir)
        for name in ("tab: TCAM Grid", "tab: Crypto Overhead"):
            check = _find(report, name)
            self.assertEqual(check.status, preflight.WARN, name)
            self.assertIsNotNone(check.fix, name)

    def test_detector_windows_absence_is_reported(self):
        """The only source of the paper's M1 -- its absence must be explicit."""
        report, _ = preflight.run(self.dir)
        check = _find(report, "paper M1 (detector_windows)")
        self.assertEqual(check.status, preflight.WARN)
        self.assertIn("enable_detector_windows", check.fix)


class TestPopulatedResultsDirectory(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_single_seed_warns_about_confidence_intervals(self):
        _write_metrics(self.dir, "MOBIGUARD_Attack1_40_seed1.csv", 1)
        report, ok = preflight.run(self.dir)
        self.assertEqual(_find(report, "metrics CSVs").status, preflight.OK)
        ci = _find(report, "confidence intervals")
        self.assertEqual(ci.status, preflight.WARN)
        self.assertIn("n=1", ci.detail)
        self.assertTrue(ok)

    def test_multiple_seeds_clear_the_confidence_warning(self):
        for seed in (1, 2, 3):
            _write_metrics(self.dir, f"MOBIGUARD_Attack1_40_seed{seed}.csv", 1)
        report, _ = preflight.run(self.dir)
        self.assertEqual(_find(report, "confidence intervals").status, preflight.OK)

    def test_fresh_files_are_not_flagged_stale(self):
        _write_metrics(self.dir, "MOBIGUARD_Attack1_40_seed1.csv", 1)
        self.assertEqual(_find(preflight.run(self.dir)[0], "metrics CSVs").status, preflight.OK)

    def test_detector_windows_presence_is_recognised(self):
        _write_metrics(self.dir, "MOBIGUARD_Attack1_40_seed1.csv", 1)
        (self.dir / "detector_windows_Attack1_40_seed1.csv").write_text("x\n", encoding="utf-8")
        check = _find(preflight.run(self.dir)[0], "paper M1 (detector_windows)")
        self.assertEqual(check.status, preflight.OK)


class TestRuntimeChecks(unittest.TestCase):
    def test_fastapi_and_uvicorn_are_checked(self):
        report, _ = preflight.run(Path(tempfile.gettempdir()))
        for name in ("python", "fastapi", "uvicorn"):
            self.assertEqual(_find(report, name).status, preflight.OK, name)


class TestRendering(unittest.TestCase):
    def test_render_is_ascii_only(self):
        """The Windows console is cp1252 and mangles non-ASCII output."""
        report, _ = preflight.run(Path(tempfile.gettempdir()))
        text = report.render()
        text.encode("ascii")  # raises if any non-ASCII slipped in

    def test_fix_lines_appear_only_for_non_ok_checks(self):
        report = preflight.Report()
        report.add("fine", preflight.OK, "all good", "should not appear")
        report.add("broken", preflight.FAIL, "bad", "do this")
        rendered = report.render()
        self.assertNotIn("should not appear", rendered)
        self.assertIn("do this", rendered)

    def test_main_returns_an_exit_code(self):
        # No metrics there, but the LSTM and figures panels still populate from
        # git-tracked files, so this environment is usable -> 0.
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(preflight.main(["--results-dir", tmp]), 0)


if __name__ == "__main__":
    unittest.main()
