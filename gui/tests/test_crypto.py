"""Crypto overhead panel tests.

Run with::

    python -m unittest gui.tests.test_crypto -v

The behaviour under test is again refusal-to-mislead. ``crypto_timing_log``'s
``result`` column is overloaded: aggregated naively across operations it reads
"85% failed", when in fact most of those rows are broadcast overhears that never
attempted cryptography, and detector rows where "ok" means the detector fired.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from gui.backend import crypto
from gui.backend.app import app

HEADER = "sim_time_s,op,node_id,pkt_id,flow_id,wall_us,result\n"


def _write_log(directory: Path, name: str, rows: list[tuple[str, float, str]]) -> Path:
    path = directory / name
    body = "".join(
        f"1.0,{op},1,1,1,{wall},{result}\n" for op, wall, result in rows
    )
    path.write_text(HEADER + body, encoding="utf-8")
    return path


class TestFilenameParsing(unittest.TestCase):
    def test_variant_is_zero_based_and_maps_to_attack_id(self):
        """V0 is Attack 1. Off by one here would mislabel every panel."""
        parts = crypto.parse_crypto_filename("crypto_timing_log_V0_pct40_s1.csv")
        self.assertEqual(parts["attack_id"], 1)
        self.assertEqual(parts["attack_percentage"], 40)
        self.assertEqual(parts["seed"], 1)
        self.assertIsNone(parts["delay_ms"])

        last = crypto.parse_crypto_filename("crypto_timing_log_V7_pct100_s3_d80ms.csv")
        self.assertEqual(last["attack_id"], 8)
        self.assertEqual(last["delay_ms"], 80)

    def test_ignores_other_files(self):
        for name in ("MOBIGUARD_Attack1_40_seed1.csv", "bc_anchor_log_Attack1_40.csv"):
            self.assertIsNone(crypto.parse_crypto_filename(name))


class TestAnalyseRun(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_latency_statistics(self):
        path = _write_log(self.dir, "crypto_timing_log_V0_pct0_s1.csv",
                          [("sign", 10.0, "ok"), ("sign", 20.0, "ok"), ("sign", 30.0, "ok")])
        ops = {o["op"]: o for o in crypto.analyse_run(path)["operations"]}
        self.assertEqual(ops["sign"]["count"], 3)
        self.assertAlmostEqual(ops["sign"]["mean_us"], 20.0)
        self.assertAlmostEqual(ops["sign"]["median_us"], 20.0)
        self.assertAlmostEqual(ops["sign"]["max_us"], 30.0)

    def test_broadcast_overhears_report_no_rate(self):
        """100% 'fail' on an op where no crypto ran is not a failure rate."""
        path = _write_log(self.dir, "crypto_timing_log_V0_pct0_s1.csv",
                          [("verify_skip_broadcast", 1.0, "fail")] * 5)
        ops = {o["op"]: o for o in crypto.analyse_run(path)["operations"]}
        row = ops["verify_skip_broadcast"]
        self.assertEqual(row["kind"], "not_applicable")
        self.assertIsNone(row["ok_rate"])
        self.assertIsNone(row["rate_meaning"])
        self.assertIn("never attempt cryptography", row["note"])

    def test_detector_rows_say_ok_means_fired(self):
        path = _write_log(self.dir, "crypto_timing_log_V0_pct0_s1.csv",
                          [("lrad_obu", 5.0, "fail"), ("lrad_obu", 5.0, "ok")])
        ops = {o["op"]: o for o in crypto.analyse_run(path)["operations"]}
        self.assertEqual(ops["lrad_obu"]["kind"], "detector")
        self.assertEqual(ops["lrad_obu"]["rate_meaning"], "detector fired")
        self.assertIn("FIRED", ops["lrad_obu"]["note"])

    def test_signature_verification_uses_only_the_verify_op(self):
        """The one op whose boolean genuinely encodes pass/fail."""
        path = _write_log(self.dir, "crypto_timing_log_V0_pct0_s1.csv",
                          [("verify", 60.0, "ok")] * 9
                          + [("verify", 60.0, "fail")]
                          + [("verify_skip_broadcast", 1.0, "fail")] * 500)
        result = crypto.analyse_run(path)["signature_verification"]
        self.assertEqual(result["attempts"], 10)      # overhears excluded
        self.assertEqual(result["failed"], 1)
        self.assertAlmostEqual(result["fail_rate"], 0.1)

    def test_stark_caveat_fires_when_counts_match_the_overhear_population(self):
        """The finding: stark_hop's fail count IS the overhear count."""
        path = _write_log(self.dir, "crypto_timing_log_V0_pct0_s1.csv",
                          [("verify", 60.0, "ok")] * 3
                          + [("verify_skip_broadcast", 1.0, "fail")] * 7
                          + [("stark_hop", 1.0, "ok")] * 3
                          + [("stark_hop", 1.0, "fail")] * 7)
        caveat = crypto.analyse_run(path)["stark_hop_caveat"]
        self.assertTrue(caveat["counts_line_up"])
        self.assertAlmostEqual(caveat["raw_fail_rate"], 0.7)
        self.assertIn("measures overhearing", caveat["explanation"])

    def test_stark_caveat_does_not_fire_on_genuine_failures(self):
        path = _write_log(self.dir, "crypto_timing_log_V0_pct0_s1.csv",
                          [("verify", 60.0, "ok")] * 3
                          + [("verify_skip_broadcast", 1.0, "fail")] * 7
                          + [("stark_hop", 1.0, "ok")] * 5
                          + [("stark_hop", 1.0, "fail")] * 5)
        caveat = crypto.analyse_run(path)["stark_hop_caveat"]
        self.assertFalse(caveat["counts_line_up"])
        self.assertIn("may reflect genuine", caveat["explanation"])

    def test_stark_hop_reports_no_rate(self):
        path = _write_log(self.dir, "crypto_timing_log_V0_pct0_s1.csv",
                          [("stark_hop", 1.0, "fail")] * 3)
        ops = {o["op"]: o for o in crypto.analyse_run(path)["operations"]}
        self.assertIsNone(ops["stark_hop"]["ok_rate"])
        self.assertIn("dominated by them", ops["stark_hop"]["note"])


class TestScanAndPanel(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        for variant, pct in ((0, 20), (2, 40)):
            _write_log(self.dir, f"crypto_timing_log_V{variant}_pct{pct}_s1.csv",
                       [("sign", 100.0, "ok")])

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_scan_sorts_by_attack(self):
        found = crypto.scan(self.dir)
        self.assertEqual([f.attack_id for f in found], [1, 3])

    def test_panel_selects_the_first_run_by_default(self):
        panel = crypto.panel(results_dir=self.dir)
        self.assertTrue(panel["available"])
        self.assertEqual(panel["selected"]["attack"], 1)

    def test_panel_honours_a_run_id(self):
        target = crypto.scan(self.dir)[1].run_id
        panel = crypto.panel(target, results_dir=self.dir)
        self.assertEqual(panel["selected"]["id"], target)

    def test_missing_directory_is_unavailable_not_an_error(self):
        panel = crypto.panel(results_dir=Path("no") / "such" / "dir")
        self.assertFalse(panel["available"])
        self.assertEqual(panel["runs"], [])


class TestCryptoRoute(unittest.TestCase):
    def test_route_serves(self):
        response = TestClient(app).get("/api/panels/crypto")
        self.assertEqual(response.status_code, 200)
        self.assertIn("available", response.json())


if __name__ == "__main__":
    unittest.main()
