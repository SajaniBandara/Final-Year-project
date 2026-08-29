"""Federated-LSTM panel tests.

Run with::

    python -m unittest gui.tests.test_lstm -v

Unlike the CSV-backed tests, these run against the **real committed**
``lstm_pipeline/*.json`` -- those files are git-tracked, so they are present in a
fresh clone and are the current results rather than a stale copy.

The behaviour under test is mostly refusal-to-mislead: an MCC of 0.0 that is
really undefined, and rows whose numbers belong to the S3/S4 rules rather than
to the model.
"""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from gui.backend import lstm
from gui.backend.app import app

_HAS_PIPELINE = (lstm.PIPELINE_DIR / "evaluation_results.json").is_file()
_requires_pipeline = unittest.skipUnless(
    _HAS_PIPELINE, "lstm_pipeline/evaluation_results.json not present"
)


class TestMccStatus(unittest.TestCase):
    """MCC is undefined, not zero, when its denominator has a zero factor."""

    def test_healthy_matrix_is_defined(self):
        defined, note = lstm.mcc_status(tp=930, tn=6231, fp=53, fn=2770)
        self.assertTrue(defined)
        self.assertIsNone(note)

    def test_no_true_negatives_is_undefined(self):
        # A6 DP-ActiveHF: TN = FP = 0, yet DR is 86%. Reporting MCC 0.0 here
        # reads as a failed detector; it is an uncomputable statistic.
        defined, note = lstm.mcc_status(tp=7175, tn=0, fp=0, fn=1145)
        self.assertFalse(defined)
        self.assertIn("no true negatives", note)

    def test_no_positives_is_undefined(self):
        # The Benign row: nothing to detect, so MCC has no meaning.
        defined, note = lstm.mcc_status(tp=0, tn=1626, fp=38, fn=0)
        self.assertFalse(defined)
        self.assertIn("no positives", note)

    def test_nothing_predicted_negative_is_undefined(self):
        defined, note = lstm.mcc_status(tp=5, tn=0, fp=3, fn=0)
        self.assertFalse(defined)

    def test_missing_counts_are_trusted(self):
        """Rule-based rows report no counts; their MCC must not be second-guessed."""
        defined, note = lstm.mcc_status(None, None, None, None)
        self.assertTrue(defined)
        self.assertIsNone(note)


@_requires_pipeline
class TestEvaluation(unittest.TestCase):
    def setUp(self) -> None:
        self.panel = lstm.panel()
        self.variants = {v["name"]: v for v in self.panel["evaluation"]["variants"]}

    def test_panel_is_available(self):
        self.assertTrue(self.panel["available"])

    def test_hidden_forwarding_variants_are_flagged_not_zeroed(self):
        """The finding this panel exists to communicate honestly."""
        flagged = [
            name for name, v in self.variants.items() if not v["mcc_defined"]
        ]
        # Benign plus the three HF variants with no true negatives.
        self.assertIn("A6 DP-ActiveHF", flagged)
        a6 = self.variants["A6 DP-ActiveHF"]
        self.assertFalse(a6["mcc_defined"])
        self.assertGreater(a6["dr"], 0.8)  # detects 86% despite "MCC 0.0"
        self.assertIn("no true negatives", a6["mcc_note"])

    def test_tcam_variants_are_marked_rule_based(self):
        """A3/A4 are caught by S3/S4, not the model -- do not credit the LSTM."""
        for name in ("A3 CP-TCAM", "A4 DP-TCAM"):
            self.assertEqual(self.variants[name]["source"], "rule_based", name)
            self.assertIsNotNone(self.variants[name]["reference_only"], name)

    def test_lstm_variants_are_marked_lstm(self):
        for name in ("A1 CP-SelectiveDelay", "A2 DP-SelectiveDelay", "A8 DP-PassiveHF"):
            self.assertEqual(self.variants[name]["source"], "lstm", name)

    def test_overall_row_is_marked(self):
        overall = [v for v in self.variants.values() if v["is_overall"]]
        self.assertEqual(len(overall), 1)

    def test_note_points_at_the_mcc_convention(self):
        self.assertIn("WHICH_MCC_TO_REPORT", self.panel["evaluation"]["note"])


@_requires_pipeline
class TestFederationAndPoisoning(unittest.TestCase):
    def setUp(self) -> None:
        self.panel = lstm.panel()

    def test_rejection_breakdown_is_a_true_part_to_whole(self):
        """A stacked bar is only honest if the parts sum to the whole."""
        federation = self.panel["federation"]
        total = sum(item["count"] for item in federation["breakdown"])
        self.assertEqual(total, federation["n_total"])

    def test_poisoning_grid_has_clean_and_poisoned_pairs(self):
        poisoning = self.panel["poisoning"]
        self.assertGreater(len(poisoning["grid"]), 0)
        for point in poisoning["grid"]:
            for key in ("gamma", "t_min", "mcc_clean", "mcc_poisoned", "delta_poison"):
                self.assertIn(key, point)
        self.assertIsNotNone(poisoning["selected"])

    def test_ablations_pair_both_arms_per_variant(self):
        for key in ("ab2", "ab3"):
            ablation = self.panel["ablations"][key]
            self.assertIsNotNone(ablation, key)
            self.assertTrue(ablation["arm_a"] and ablation["arm_b"])
            for row in ablation["rows"]:
                self.assertIn("a", row)
                self.assertIn("b", row)

    def test_mobility_empty_bins_stay_null(self):
        """An absent mobility combination must not render as MCC 0."""
        mobility = self.panel["mobility"]
        self.assertGreater(len(mobility["cells"]), 0)
        nulls = [c for c in mobility["cells"] if c["mcc"] is None]
        self.assertGreater(len(nulls), 0, "expected some unpopulated bins")
        self.assertIn("not zero MCC", mobility["note"])


class TestLstmRoute(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_route_serves_the_panel(self):
        response = self.client.get("/api/panels/lstm")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn("available", body)
        if body["available"]:
            self.assertIn("variants", body["evaluation"])


if __name__ == "__main__":
    unittest.main()
