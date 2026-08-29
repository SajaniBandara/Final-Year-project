"""Phase 0 tests: schema, parser, catalog, aggregation.

Run with::

    python -m unittest gui.tests.test_phase0 -v

Two kinds of test live here:

* **Synthetic** -- built from temporary files, so they run in a fresh clone and
  pin the behaviour that must not regress (the 52-vs-61 column split, both
  header formats, the append-produces-two-runs case).

* **Real-data** -- run against ``results_routing/``, which is gitignored, so
  these skip cleanly when the CSVs have not been copied from the HPC. They are
  the ones that would catch a schema drift in ``routing.cc``, so a skip is worth
  noticing rather than ignoring.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gui.backend import aggregate, catalog, parser, schema

# Real data is optional: results_routing/*.csv is gitignored.
try:
    _CATALOG: catalog.Catalog | None = catalog.Catalog.scan()
except FileNotFoundError:
    _CATALOG = None

_HAS_REAL_DATA = _CATALOG is not None and len(_CATALOG) > 0
_requires_real_data = unittest.skipUnless(
    _HAS_REAL_DATA,
    "results_routing/ has no metrics CSVs (they are gitignored; copy from the HPC)",
)


def _row(width: int, cycle: int = 1) -> str:
    """A syntactically valid data row of ``width`` fields, space-padded."""
    return ", ".join([str(cycle)] + ["1"] * (width - 1))


class TestSchema(unittest.TestCase):
    """The column layout mirrors write_security_metrics_csv() in routing.cc."""

    def test_widths_match_measured_files(self):
        # Measured on disk: Attack1/Attack5 -> 52 fields, Attack3 -> 61.
        self.assertEqual(schema.NARROW_WIDTH, 52)
        self.assertEqual(schema.WIDE_WIDTH, 61)
        self.assertEqual(len(schema.columns_for(1)), 52)
        self.assertEqual(len(schema.columns_for(5)), 52)
        self.assertEqual(len(schema.columns_for(3)), 61)

    def test_tcam_attacks_are_3_4_and_baseline(self):
        # active_attack_variant 2, 3, -1 -> attack ids 3, 4, 0.
        self.assertEqual(schema.TCAM_ATTACK_IDS, frozenset({0, 3, 4}))
        for attack_id in (0, 3, 4):
            self.assertTrue(schema.has_tcam_columns(attack_id))
        for attack_id in (1, 2, 5, 6, 7, 8):
            self.assertFalse(schema.has_tcam_columns(attack_id))

    def test_tcam_block_is_inserted_mid_row_not_appended(self):
        """The regression this whole module exists to prevent."""
        narrow = schema.columns_for(1)
        wide = schema.columns_for(3)
        head = len(schema.BASE_HEAD)

        # Identical up to the insertion point...
        self.assertEqual(narrow[:head], wide[:head])
        # ...then the wide schema diverges, and TP has MOVED.
        self.assertEqual(wide[head], "max_tcam_util")
        self.assertNotEqual(narrow.index("TP"), -1)
        self.assertEqual(narrow.index("TP"), wide.index("TP"))  # TP is inside BASE_HEAD
        # The tail fields are the ones that shift.
        self.assertEqual(
            wide.index("sig_valid_rate") - narrow.index("sig_valid_rate"),
            len(schema.TCAM_BLOCK),
        )

    def test_column_names_are_unique(self):
        for attack_id in (0, 1, 3):
            columns = schema.columns_for(attack_id)
            self.assertEqual(len(columns), len(set(columns)))


class TestRowDecoder(unittest.TestCase):
    """Hazards 1, 2, 3 and 5 from the plan."""

    def test_skips_both_header_formats_and_blank_lines(self):
        decoder = parser.RowDecoder(1)
        # Old multi-line header (4 lines) and the new single-line one both start '#'.
        self.assertIsNone(decoder.decode("# cycle, cur_PDR, avg_PDR,"))
        self.assertIsNone(decoder.decode("# TP, FP, TN, FN,"))
        self.assertIsNone(decoder.decode(""))
        self.assertIsNone(decoder.decode("   \n"))

    def test_strips_space_padded_fields(self):
        decoder = parser.RowDecoder(1)
        cycle, row = decoder.decode(_row(52, cycle=7))
        self.assertEqual(cycle, 7)
        self.assertEqual(row["cycle"], 7.0)
        self.assertEqual(row["cur_PDR"], 1.0)

    def test_parses_scientific_notation(self):
        decoder = parser.RowDecoder(1)
        fields = ["1"] * 52
        fields[schema.columns_for(1).index("t_stark_ms_avg")] = "9.14657e-05"
        _, row = decoder.decode(", ".join(fields))
        self.assertAlmostEqual(row["t_stark_ms_avg"], 9.14657e-05)

    def test_tolerates_trailing_comma(self):
        decoder = parser.RowDecoder(1)
        cycle, _ = decoder.decode(_row(52) + ",")
        self.assertEqual(cycle, 1)

    def test_wide_row_under_narrow_schema_raises(self):
        """A 61-field row read as attack 1 must fail loudly, not shift columns."""
        decoder = parser.RowDecoder(1)
        with self.assertRaises(parser.SchemaError) as ctx:
            decoder.decode(_row(61), line_no=5)
        self.assertIn("expects 52", str(ctx.exception))
        self.assertIn("line 5", str(ctx.exception))

    def test_narrow_row_under_wide_schema_raises(self):
        decoder = parser.RowDecoder(3)
        with self.assertRaises(parser.SchemaError):
            decoder.decode(_row(52))

    def test_non_numeric_field_raises(self):
        decoder = parser.RowDecoder(1)
        with self.assertRaises(parser.SchemaError):
            decoder.decode(_row(52).replace("1", "nope", 1))


class TestParseRuns(unittest.TestCase):
    """Hazard 4: ios::app means one file can hold several runs."""

    def test_single_run(self):
        lines = ["# header,"] + [_row(52, c) for c in range(1, 6)]
        runs = parser.parse_lines(lines, attack_id=1)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].cycles, [1, 2, 3, 4, 5])

    def test_appended_second_run_splits_on_cycle_reset(self):
        lines = [_row(52, c) for c in (1, 2, 3)] + [_row(52, c) for c in (1, 2)]
        runs = parser.parse_lines(lines, attack_id=1)
        self.assertEqual(len(runs), 2)
        self.assertEqual(runs[0].cycles, [1, 2, 3])
        self.assertEqual(runs[1].cycles, [1, 2])
        self.assertEqual([r.index for r in runs], [0, 1])

    def test_repeated_cycle_also_splits(self):
        """Non-increasing, not merely decreasing -- a stalled cycle is a new run."""
        runs = parser.parse_lines([_row(52, c) for c in (1, 2, 2, 3)], attack_id=1)
        self.assertEqual(len(runs), 2)

    def test_load_run_defaults_to_most_recent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "MOBIGUARD_Attack1_40_seed1.csv"
            path.write_text(
                "\n".join([_row(52, c) for c in (1, 2, 3)] + [_row(52, c) for c in (1, 2)]),
                encoding="utf-8",
            )
            self.assertEqual(parser.load_run(path, 1).cycles, [1, 2])
            self.assertEqual(parser.load_run(path, 1, index=0).cycles, [1, 2, 3])

    def test_header_only_file_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.csv"
            path.write_text("# cycle, cur_PDR,\n", encoding="utf-8")
            with self.assertRaises(parser.SchemaError):
                parser.load_run(path, 1)

    def test_series_rejects_wrong_schema_column(self):
        run = parser.parse_lines([_row(52, 1)], attack_id=1)[0]
        with self.assertRaises(KeyError):
            run.series("max_tcam_util")


class TestCatalog(unittest.TestCase):
    """Both filename shapes present in results_routing/ today."""

    def test_parses_filename_without_delay(self):
        parts = catalog.parse_metrics_filename("MOBIGUARD_Attack5_40_seed1.csv")
        self.assertEqual(parts["attack_id"], 5)
        self.assertEqual(parts["attack_percentage"], 40)
        self.assertIsNone(parts["delay_ms"])
        self.assertEqual(parts["seed"], 1)
        self.assertIsNone(parts["tag"])

    def test_parses_filename_with_delay(self):
        parts = catalog.parse_metrics_filename("MOBIGUARD_Attack1_40_d80ms_seed1.csv")
        self.assertEqual(parts["attack_id"], 1)
        self.assertEqual(parts["delay_ms"], 80)

    def test_parses_ablation_tag(self):
        parts = catalog.parse_metrics_filename("MOBIGUARD_Attack2_60_d80ms_seed3_AB1A.csv")
        self.assertEqual(parts["tag"], "AB1A")
        self.assertEqual(parts["seed"], 3)

    def test_ignores_other_result_families(self):
        for name in (
            "bc_anchor_log_Attack1_40_d80ms.csv",
            "crypto_timing_log_200_40_1.csv",
            "tcam_occupancy_attack3_40.csv",
            "fade_results_200_40_1.csv",
            "notes.txt",
        ):
            self.assertIsNone(catalog.parse_metrics_filename(name), name)

    def test_scan_indexes_and_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for name in (
                "MOBIGUARD_Attack1_20_d80ms_seed1.csv",
                "MOBIGUARD_Attack1_40_d80ms_seed1.csv",
                "MOBIGUARD_Attack3_40_seed2.csv",
                "bc_anchor_log_Attack1_40_d80ms.csv",
            ):
                (base / name).write_text(_row(52), encoding="utf-8")

            cat = catalog.Catalog.scan(base)
            self.assertEqual(len(cat), 3)  # bc_* ignored
            self.assertEqual(cat.attack_ids(), [1, 3])
            self.assertEqual(cat.percentages(attack_id=1), [20, 40])
            self.assertEqual(cat.seeds(), [1, 2])
            self.assertEqual(len(cat.filter(attack_id=1)), 2)
            self.assertEqual(len(cat.filter(attack_id=1, attack_percentage=40)), 1)
            self.assertEqual(len(cat.filter(seeds=[2])), 1)
            self.assertIsNotNone(cat.newest_modified())

    def test_scan_missing_directory_raises(self):
        with self.assertRaises(FileNotFoundError):
            catalog.Catalog.scan(Path("no") / "such" / "dir")

    def test_get_unknown_run_id_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(KeyError):
                catalog.Catalog.scan(Path(tmp)).get("nope")

    def test_baseline_labelled_distinctly(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "MOBIGUARD_Attack0_0_seed1.csv").write_text(_row(61), encoding="utf-8")
            run_file = catalog.Catalog.scan(base).runs[0]
            self.assertTrue(run_file.is_baseline)
            self.assertIn("Baseline", run_file.label)


class TestDiagnosticCaveats(unittest.TestCase):
    """docs/WHICH_MCC_TO_REPORT.md is a binding convention, not advice.

    The inline detection columns are a per-node statistic that shares a name
    with the thesis metric. Plotting one unlabelled as M1 is the specific
    mistake that doc exists to prevent.
    """

    def test_inline_detection_columns_carry_a_caveat(self):
        for metric in ("cur_MCC", "avg_MCC", "cur_DR", "avg_DR", "cur_FPR", "avg_FPR"):
            self.assertIsNotNone(schema.caveat_for(metric), metric)
            self.assertIn("detector_windows.csv", schema.caveat_for(metric))

    def test_non_detection_columns_have_no_caveat(self):
        for metric in ("cur_PDR", "avg_lat_ms", "rsu_chain_len", "avg_tcam_util"):
            self.assertIsNone(schema.caveat_for(metric), metric)

    def test_sweep_propagates_the_caveat_to_the_api(self):
        sweep = aggregate.Sweep(attack_id=1, metric="avg_MCC", unit="fraction", points=())
        self.assertIsNotNone(sweep.caveat)
        self.assertIsNotNone(sweep.to_dict()["caveat"])

    def test_sweep_of_a_safe_metric_has_no_caveat(self):
        sweep = aggregate.Sweep(attack_id=1, metric="avg_PDR", unit="percent", points=())
        self.assertIsNone(sweep.to_dict()["caveat"])


class TestStatistics(unittest.TestCase):
    """CI method must match scripts/plot_hf_results.py."""

    def test_t_table_matches_published_values(self):
        self.assertAlmostEqual(aggregate.t_critical_95(1), 12.706, places=3)
        self.assertAlmostEqual(aggregate.t_critical_95(2), 4.303, places=3)
        self.assertAlmostEqual(aggregate.t_critical_95(4), 2.776, places=3)
        self.assertAlmostEqual(aggregate.t_critical_95(29), 2.045, places=3)
        # Beyond the table, fall back to the normal approximation.
        self.assertAlmostEqual(aggregate.t_critical_95(500), 1.960, places=3)

    def test_t_critical_rejects_zero_df(self):
        with self.assertRaises(ValueError):
            aggregate.t_critical_95(0)

    def test_single_seed_has_no_ci(self):
        """n=1 must report None, not a zero-width bar implying perfect precision."""
        est = aggregate.mean_ci95([0.42])
        self.assertEqual(est.n, 1)
        self.assertIsNone(est.ci95)
        self.assertAlmostEqual(est.mean, 0.42)

    def test_ci_formula(self):
        est = aggregate.mean_ci95([1.0, 2.0, 3.0])
        # sd = 1.0, n = 3, t(df=2) = 4.303  ->  ci = 4.303 * 1 / sqrt(3)
        self.assertAlmostEqual(est.mean, 2.0)
        self.assertAlmostEqual(est.ci95, 4.303 / (3 ** 0.5), places=6)

    def test_empty_sample_raises(self):
        with self.assertRaises(ValueError):
            aggregate.mean_ci95([])


class TestConfusionRecomputation(unittest.TestCase):
    """Mirrors functional_verification.py GROUP B."""

    def test_known_values_from_attack1_cycle1(self):
        # MOBIGUARD_Attack1_40_d80ms_seed1.csv cycle 1.
        m = aggregate.recompute_confusion(tp=13, fp=20, tn=216, fn=19)
        self.assertAlmostEqual(m.mcc, 0.317268, places=5)   # fraction
        self.assertAlmostEqual(m.dr, 40.625, places=4)      # percent
        self.assertAlmostEqual(m.fpr, 8.47458, places=4)    # percent

    def test_degenerate_denominators_yield_zero_not_nan(self):
        m = aggregate.recompute_confusion(tp=0, fp=0, tn=0, fn=0)
        self.assertEqual((m.mcc, m.dr, m.fpr), (0.0, 0.0, 0.0))

    def test_perfect_classifier(self):
        m = aggregate.recompute_confusion(tp=10, fp=0, tn=10, fn=0)
        self.assertAlmostEqual(m.mcc, 1.0)
        self.assertAlmostEqual(m.dr, 100.0)
        self.assertAlmostEqual(m.fpr, 0.0)


@_requires_real_data
class TestAgainstRealResults(unittest.TestCase):
    """These are what would catch a schema drift in routing.cc."""

    def setUp(self):
        assert _CATALOG is not None
        self.catalog = _CATALOG

    def test_every_indexed_run_decodes(self):
        """No file in results_routing/ may fail the width assertion."""
        failures = []
        for run_file in self.catalog:
            try:
                runs = parser.parse_file(run_file.path, run_file.attack_id)
                self.assertGreater(len(runs), 0, run_file.run_id)
            except parser.SchemaError as exc:
                failures.append(f"{run_file.run_id}: {exc}")
        self.assertEqual(failures, [], "files failed to decode:\n" + "\n".join(failures))

    def test_narrow_and_wide_files_both_present_and_decoded(self):
        """Guards against the test passing because only one width was exercised."""
        widths = set()
        for run_file in self.catalog:
            run = parser.load_run(run_file.path, run_file.attack_id)
            widths.add(len(run.columns))
        self.assertIn(52, widths)
        self.assertIn(61, widths)

    def test_reported_metrics_match_recomputation(self):
        """MCC/DR/FPR are re-derived from TP/FP/TN/FN and must agree."""
        worst = 0.0
        worst_desc = ""
        for run_file in self.catalog:
            run = parser.load_run(run_file.path, run_file.attack_id)
            for d in aggregate.verify_reported_metrics(run):
                if d.delta > worst:
                    worst, worst_desc = d.delta, f"{run_file.run_id} {d.metric} cycle {d.cycle}"
        self.assertLess(worst, 1e-3, f"largest discrepancy {worst} at {worst_desc}")

    def test_sweep_over_real_catalog(self):
        attack_id = self.catalog.attack_ids()[-1]
        result = aggregate.sweep(self.catalog, attack_id=attack_id, metric="avg_MCC")
        self.assertGreater(len(result.points), 0)
        self.assertEqual(result.unit, "fraction")
        self.assertEqual(
            [p.attack_percentage for p in result.points],
            self.catalog.percentages(attack_id),
        )

    def test_sweep_rejects_column_absent_from_schema(self):
        non_tcam = [a for a in self.catalog.attack_ids() if a not in schema.TCAM_ATTACK_IDS]
        if not non_tcam:
            self.skipTest("no non-TCAM attacks indexed")
        with self.assertRaises(KeyError):
            aggregate.sweep(self.catalog, attack_id=non_tcam[0], metric="max_tcam_util")


if __name__ == "__main__":
    unittest.main()
