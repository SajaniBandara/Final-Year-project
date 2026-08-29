"""Column layout of ``results_routing/MOBIGUARD_Attack<N>_<pct>[_d<X>ms]_seed<S>.csv``.

This module is the single source of truth for the metrics-CSV field order. It
mirrors ``write_security_metrics_csv()`` in ``scratch/routing.cc`` (the header
block around line 117895 and the row emission around line 117971). If that
writer's column list ever changes, change it here in the same commit.

Why this needs its own module
-----------------------------
The writer emits **two different row widths**, and the wider one inserts its
extra fields *in the middle* of the row rather than appending them:

    if (active_attack_variant == 2 || active_attack_variant == 3
        || active_attack_variant == -1)
        fout << ", max_tcam_util, avg_tcam_util, ...";   // 9 fields, mid-row

``active_attack_variant`` is the legacy 0-based selector; the filename carries
``attack_id = active_attack_variant + 1``, with the benign baseline (-1) folded
into ``Attack0``. So the wide rows belong to **attacks 3, 4 and 0**.

Measured on the files currently in ``results_routing/``:

    MOBIGUARD_Attack1_40_d80ms_seed1.csv -> 52 data fields
    MOBIGUARD_Attack5_40_seed1.csv       -> 52 data fields
    MOBIGUARD_Attack3_40_seed1.csv       -> 61 data fields

Reading a wide row with the narrow layout silently shifts every field after
index 20 -- TP would be read from ``max_tcam_util``, and the resulting MCC would
be wrong but entirely plausible. ``routing.cc``'s own header comment flags this
same hazard for the positional ``COL_TP``/``COL_FP`` reads in
``scripts/run_q1q6_ablation.py``. Hence :func:`columns_for` and the width
assertion in ``parser.decode_row``.

Units, which are not uniform across the metric columns
------------------------------------------------------
``cur_MCC``/``avg_MCC`` are **fractions** in [-1, 1]; ``cur_DR``/``cur_FPR`` and
their averages are **percentages** in [0, 100]. See :data:`METRIC_UNITS` -- the
confusion-matrix recomputation in ``aggregate`` depends on getting this right.
"""

from __future__ import annotations

from typing import Final

# --- Field groups, in emission order ----------------------------------------

#: Fields 0-20. Present in every row regardless of attack variant.
BASE_HEAD: Final[tuple[str, ...]] = (
    "cycle",
    "cur_PDR",
    "avg_PDR",
    "cur_lat_ms",
    "avg_lat_ms",
    "cur_MCC",
    "avg_MCC",
    "cur_DR",
    "avg_DR",
    "cur_FPR",
    "avg_FPR",
    "cur_mit_ms",
    "avg_mit_ms",
    "TP",
    "FP",
    "TN",
    "FN",
    "cur_TVR",
    "avg_TVR",
    "cur_UCR",
    "avg_UCR",
)

#: Inserted after :data:`BASE_HEAD` for TCAM variants and the benign baseline
#: only. This is the block that makes the row width vary.
TCAM_BLOCK: Final[tuple[str, ...]] = (
    "max_tcam_util",
    "avg_tcam_util",
    "total_lambda_fm",
    "total_lambda_pi",
    "total_malicious",
    "s3_fired_count",
    "s4_fired_count",
    "any_s3",
    "any_s4",
)

#: Crypto, blockchain, witness, failover and time-reference fields. Always last.
BASE_TAIL: Final[tuple[str, ...]] = (
    "sig_valid_rate",
    "avg_trust_score",
    "stark_timing_fail_count",
    "stark_hop_fail_count",
    "flowmod_endorsement_rate",
    "rsu_chain_len",
    "global_chain_len",
    "witness_da_count",
    "witness_nfa_count",
    "d_obu_count",
    "d_rsu_count",
    "escalation_count",
    "ctrl_failover_max_ms",
    "ctrl_failover_events",
    "ctrl_failover_reassigned",
    "o_crypto_bytes_pkt",
    "t_batch_ms_avg",
    "batch_B_avg",
    "t_consensus_ms_avg",
    "t_stark_ms_avg",
    "witness_TP_W",
    "witness_FP_W",
    "witness_FN_W",
    "WAP_precision",
    "WAP_recall",
    "eps_ref_s",
    "avg_eps_ref_s",
    "time_ref_f_bad",
    "ufcr_unauth_total",
    "ufcr_blocked",
    "UFCR",
)

#: Attack ids whose rows carry :data:`TCAM_BLOCK`. 3 and 4 are the TCAM
#: exhaustion variants (``active_attack_variant`` 2 and 3); 0 is the benign
#: baseline (``active_attack_variant == -1``).
TCAM_ATTACK_IDS: Final[frozenset[int]] = frozenset({0, 3, 4})

NARROW_WIDTH: Final[int] = len(BASE_HEAD) + len(BASE_TAIL)  # 52
WIDE_WIDTH: Final[int] = NARROW_WIDTH + len(TCAM_BLOCK)  # 61


def columns_for(attack_id: int) -> tuple[str, ...]:
    """Return the field names, in order, for a run of ``attack_id``.

    ``attack_id`` is the number in the filename (0 = benign baseline, 1-8 = the
    attack variants), *not* the legacy 0-based ``active_attack_variant``.
    """
    if attack_id in TCAM_ATTACK_IDS:
        return BASE_HEAD + TCAM_BLOCK + BASE_TAIL
    return BASE_HEAD + BASE_TAIL


def width_for(attack_id: int) -> int:
    """Return the expected number of data fields per row for ``attack_id``."""
    return WIDE_WIDTH if attack_id in TCAM_ATTACK_IDS else NARROW_WIDTH


def has_tcam_columns(attack_id: int) -> bool:
    """True if this attack's rows carry the S3/S4 TCAM block."""
    return attack_id in TCAM_ATTACK_IDS


# --- Units ------------------------------------------------------------------

#: Unit of each metric column, for axis labels and for the confusion-matrix
#: cross-check. Columns absent here are counts, rates in [0, 1], byte totals, or
#: raw seconds, and are passed through unscaled.
#:
#: Verified against MOBIGUARD_Attack1_40_d80ms_seed1.csv cycle 1
#: (TP=13, FP=20, TN=216, FN=19):
#:     MCC = 0.317268  -> fraction   (TP*TN-FP*FN)/sqrt(...) = 0.31727
#:     DR  = 40.625    -> percent    TP/(TP+FN) = 0.40625
#:     FPR = 8.47458   -> percent    FP/(FP+TN) = 0.084746
METRIC_UNITS: Final[dict[str, str]] = {
    "cur_PDR": "percent",
    "avg_PDR": "percent",
    "cur_lat_ms": "ms",
    "avg_lat_ms": "ms",
    "cur_MCC": "fraction",
    "avg_MCC": "fraction",
    "cur_DR": "percent",
    "avg_DR": "percent",
    "cur_FPR": "percent",
    "avg_FPR": "percent",
    "cur_mit_ms": "ms",
    "avg_mit_ms": "ms",
    "cur_TVR": "percent",
    "avg_TVR": "percent",
    "cur_UCR": "percent",
    "avg_UCR": "percent",
    "UFCR": "percent",
    # Rates and utilisations already expressed in [0, 1].
    "max_tcam_util": "fraction",
    "avg_tcam_util": "fraction",
    "sig_valid_rate": "fraction",
    "flowmod_endorsement_rate": "fraction",
    "avg_trust_score": "fraction",
    "WAP_precision": "fraction",
    "WAP_recall": "fraction",
    "eps_ref_s": "s",
    "avg_eps_ref_s": "s",
    "o_crypto_bytes_pkt": "bytes",
    "t_batch_ms_avg": "ms",
    "t_consensus_ms_avg": "ms",
    "t_stark_ms_avg": "ms",
}

# --- Diagnostic-only columns -------------------------------------------------

#: Why the inline detection columns must never be presented as the thesis metric.
#: See ``docs/WHICH_MCC_TO_REPORT.md`` (binding convention, 2026-08-07).
PER_NODE_CAVEAT: Final[str] = (
    "Per-node diagnostic, NOT the thesis metric. The paper's M1/DR/FPR are "
    "computed per-RSU over non-overlapping 10 s blocks (eq:eval_dedup) from "
    "detector_windows.csv. This column is the inline per-node confusion matrix "
    "in routing.cc: 268 nodes, sticky latches, whole-run. The two are not "
    "comparable -- measured 2026-08-06 on one Q6 config, 0.264 per-node vs "
    "~0.895 per-window. See docs/WHICH_MCC_TO_REPORT.md."
)

#: Columns that share a name with a thesis metric but are a different statistic.
#: Any surface that plots one of these MUST render the caveat alongside it;
#: :class:`gui.backend.aggregate.Sweep` carries it through for that reason.
DIAGNOSTIC_ONLY_COLUMNS: Final[dict[str, str]] = {
    "cur_MCC": PER_NODE_CAVEAT,
    "avg_MCC": PER_NODE_CAVEAT,
    "cur_DR": PER_NODE_CAVEAT,
    "avg_DR": PER_NODE_CAVEAT,
    "cur_FPR": PER_NODE_CAVEAT,
    "avg_FPR": PER_NODE_CAVEAT,
}


def caveat_for(metric: str) -> str | None:
    """Return the mandatory caveat for ``metric``, or ``None`` if it has none."""
    return DIAGNOSTIC_ONLY_COLUMNS.get(metric)


#: Columns the Live PEM Monitor puts on its KPI tiles (plan §4, Tab 1).
#: ``cur_MCC``/``cur_DR``/``cur_FPR`` are here as *live diagnostics* -- legitimate
#: for watching the detector react in real time, but they carry
#: :data:`PER_NODE_CAVEAT` and must be labelled as diagnostics on the tile.
LIVE_KPI_COLUMNS: Final[tuple[str, ...]] = (
    "cur_MCC",
    "cur_DR",
    "cur_FPR",
    "cur_PDR",
    "cur_lat_ms",
    "cur_mit_ms",
    "avg_trust_score",
    "UFCR",
)

#: Counters whose per-cycle *delta* drives the live detection-event feed.
LIVE_EVENT_COUNTERS: Final[tuple[str, ...]] = (
    "d_obu_count",
    "d_rsu_count",
    "escalation_count",
)
