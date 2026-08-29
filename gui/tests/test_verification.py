"""Verification-tab tests.

Run with::

    python -m unittest gui.tests.test_verification -v

The parser is tested against a synthetic log so it runs anywhere, plus the real
``docs/task8_verification/equation_audit.log`` when present.

The audit currently **fails** (3 checks), and these tests assert the parser
reports that faithfully. A tab that rounded a failing audit up to "all good"
would be worse than no tab.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from gui.backend import verification as ver
from gui.backend.app import app

SYNTHETIC_LOG = """\
==============================================================================
MOBIGUARD -- EQUATION & ALGORITHM PRESENCE AUDIT
reference   : docs/main.tex
==============================================================================
==============================================================================
SECTION 0. STRUCTURAL CONSTANTS (recomputed from source vs paper)
==============================================================================
  [PASS] eq:rsu_endorsement          BFT quorum f+1
         exp=22 got=22
  [FAIL] eq:ewma_variance            S1 EWMA forgetting factor beta
         exp=0.8 got=0.95
==============================================================================
SECTION Y. COVERAGE SELF-CHECK (every main.tex label must be audited)
==============================================================================
  [FAIL] eq: 3 label(s) in main.tex with no audit entry
         eq:eval_dedup, eq:lstm_gate, eq:theta_adapt
  [INFO] eq: 6 audit entr(ies) with no main.tex label (stale?)
         eq:aoei, eq:density_x

==============================================================================
AUDIT SUMMARY
==============================================================================
  paper set        : 87 equations + 6 algorithms in docs/main.tex
  checks executed  : 114
  result           : 1 PASS, 2 FAIL, 0 INFO (paper-only, by declaration)
==============================================================================
"""


class TestParseAudit(unittest.TestCase):
    def setUp(self) -> None:
        self.parsed = ver.parse_audit(SYNTHETIC_LOG)

    def test_extracts_sections(self):
        ids = [s["id"] for s in self.parsed["sections"]]
        self.assertIn("0", ids)
        self.assertIn("Y", ids)

    def test_extracts_checks_with_details(self):
        labels = [c["label"] for c in self.parsed["checks"]]
        self.assertIn("eq:rsu_endorsement", labels)
        ewma = next(c for c in self.parsed["checks"] if c["label"] == "eq:ewma_variance")
        self.assertEqual(ewma["status"], "FAIL")
        self.assertIn("exp=0.8 got=0.95", ewma["details"])
        # Checks must carry the section they were found under, so the UI can
        # group them and a failure can be located in the audit output.
        self.assertIn("STRUCTURAL CONSTANTS", ewma["section"])

    def test_failures_are_collected(self):
        failures = self.parsed["failures"]
        self.assertEqual(len(failures), 2)
        self.assertTrue(all(f["status"] == "FAIL" for f in failures))

    def test_coverage_failure_names_the_missing_labels(self):
        coverage = next(f for f in self.parsed["failures"] if f["label"] == "eq:")
        self.assertIn("eq:eval_dedup", coverage["details"][0])

    def test_summary_fields_are_parsed(self):
        summary = self.parsed["summary"]
        self.assertIn("paper set", summary)
        self.assertIn("87 equations", summary["paper set"])

    def test_reported_counts_are_read(self):
        self.assertEqual(self.parsed["counts_reported"], {"PASS": 1, "FAIL": 2, "INFO": 0})

    def test_failing_audit_is_not_reported_as_passed(self):
        """The property this module exists to preserve."""
        self.assertFalse(self.parsed["passed"])

    def test_passing_audit_is_reported_as_passed(self):
        clean = SYNTHETIC_LOG.replace(
            "result           : 1 PASS, 2 FAIL, 0 INFO",
            "result           : 3 PASS, 0 FAIL, 0 INFO",
        )
        self.assertTrue(ver.parse_audit(clean)["passed"])

    def test_info_count_mismatch_does_not_trip_the_cross_check(self):
        """The script's INFO tally excludes coverage INFOs by design.

        Comparing INFO would flag every healthy run, so only PASS/FAIL are
        cross-checked against the script's own tally.
        """
        self.assertTrue(self.parsed["counts_agree"])
        self.assertNotEqual(
            self.parsed["counts_parsed"]["INFO"], self.parsed["counts_reported"]["INFO"]
        )

    def test_parsed_pass_fail_must_match_the_script_tally(self):
        tampered = SYNTHETIC_LOG.replace(
            "result           : 1 PASS, 2 FAIL, 0 INFO",
            "result           : 9 PASS, 0 FAIL, 0 INFO",
        )
        self.assertFalse(ver.parse_audit(tampered)["counts_agree"])


class TestMissingLogs(unittest.TestCase):
    def test_absent_audit_log_reports_the_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(ver, "AUDIT_LOG", Path(tmp) / "nope.log"):
                result = ver.read_audit()
        self.assertFalse(result["available"])
        self.assertIn("audit_equations.py", result["command"])

    def test_absent_functional_log_explains_why_it_cannot_be_run_here(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(ver, "FUNCTIONAL_LOG", Path(tmp) / "nope.log"):
                result = ver.read_functional()
        self.assertFalse(result["available"])
        self.assertIn("functional_verification.py", result["command"])
        self.assertIn("finished run", result["note"])


class TestRealAuditLog(unittest.TestCase):
    """Against the checked-in log, when it has been generated."""

    def setUp(self) -> None:
        if not ver.AUDIT_LOG.is_file():
            self.skipTest("equation_audit.log not generated yet")
        self.parsed = ver.read_audit()

    def test_pass_fail_agree_with_the_script(self):
        self.assertTrue(
            self.parsed["counts_agree"],
            f"parsed {self.parsed['counts_parsed']} vs reported {self.parsed['counts_reported']}",
        )

    def test_every_check_has_a_section(self):
        self.assertTrue(all(c["section"] for c in self.parsed["checks"]))

    def test_reports_the_real_state_including_failure(self):
        # Documented state as of 2026-08-29: 103 PASS / 3 FAIL.
        self.assertGreater(self.parsed["counts_reported"]["PASS"], 50)
        self.assertEqual(self.parsed["passed"], self.parsed["counts_reported"]["FAIL"] == 0)


class TestVerificationRoute(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_route_serves_the_panel(self):
        response = self.client.get("/api/verification")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("audit", body)
        self.assertIn("functional", body)
        self.assertTrue(body["script_present"])


if __name__ == "__main__":
    unittest.main()
