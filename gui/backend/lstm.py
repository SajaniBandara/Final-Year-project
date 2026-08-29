"""Federated-LSTM results, read from the committed ``lstm_pipeline/*.json``.

Unlike ``results_routing/``, these files are **git-tracked and current** (dated
2026-08-29 at the time of writing, against a month-stale CSV copy), so this
panel works in a fresh clone and is the one part of the GUI not subject to the
staleness banner.

Three things in the raw JSON would mislead a reader if rendered literally, and
this module normalises all three rather than leaving it to the frontend:

**1. MCC 0.0 that is really "undefined".**
``evaluation_results.json`` stores 0.0 for variants whose confusion matrix has a
zero denominator. A6 DP-ActiveHF reads ``MCC 0.0`` beside ``DR 86.24%`` -- not a
failed detector, but an evaluation set with **no true negatives** (TN = FP = 0),
so MCC is not defined. Benign is the same case from the other side (TP = FN = 0).
Plotting those as zero would understate the detector and invite exactly the
wrong question in a viva. :func:`mcc_status` marks them.

**2. Rows that are not the LSTM at all.**
A3/A4 carry ``is_rule_based: true`` and ``source: "rule_based_S3_S4"`` with null
counts -- the TCAM variants are caught by the S3/S4 rules, not the model. Their
headline MCC belongs to the rule, and presenting it inside an "LSTM detection
quality" chart without a marker would claim credit the model has not earned.

**3. ``lstm_clf_reference_only``.**
A3/A4 also carry what the LSTM classifier *would* have scored. It is explicitly
reference-only and is surfaced as such, never as the headline number.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .catalog import REPO_ROOT

#: Where the pipeline writes its result JSONs.
PIPELINE_DIR = REPO_ROOT / "lstm_pipeline"

#: Key in ``evaluation_results.json`` holding the aggregate row rather than a
#: single variant.
OVERALL_PREFIX = "Overall"


def _load(name: str) -> Any | None:
    """Read one pipeline JSON, or ``None`` if it has not been produced."""
    path = PIPELINE_DIR / name
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def mcc_status(tp: Any, tn: Any, fp: Any, fn: Any) -> tuple[bool, str | None]:
    """Is MCC defined for this confusion matrix, and if not, why not?

    MCC's denominator is ``(TP+FP)(TP+FN)(TN+FP)(TN+FN)``. Any zero factor makes
    it undefined, and the pipeline stores 0.0 in that case -- which reads as "the
    detector scored zero" rather than "this cannot be computed".

    Returns:
        ``(defined, reason)``; ``reason`` is ``None`` when defined.
    """
    if None in (tp, tn, fp, fn):
        return True, None  # counts not reported (rule-based rows); trust the value
    if (tn + fp) == 0:
        return False, "no true negatives in the evaluation set (TN = FP = 0)"
    if (tp + fn) == 0:
        return False, "no positives in the evaluation set (TP = FN = 0)"
    if (tp + fp) == 0:
        return False, "nothing was predicted positive (TP = FP = 0)"
    if (tn + fn) == 0:
        return False, "nothing was predicted negative (TN = FN = 0)"
    return True, None


@dataclass(frozen=True)
class VariantResult:
    """Detection quality for one attack variant."""

    name: str
    mcc: float
    dr: float
    fpr: float
    tp: int | None
    tn: int | None
    fp: int | None
    fn: int | None
    source: str
    mcc_defined: bool
    mcc_note: str | None
    is_overall: bool
    reference_only: dict[str, float] | None = field(default=None)

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "mcc": self.mcc,
            "dr": self.dr,
            "fpr": self.fpr,
            "tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn,
            "source": self.source,
            "mcc_defined": self.mcc_defined,
            "mcc_note": self.mcc_note,
            "is_overall": self.is_overall,
            "reference_only": self.reference_only,
        }


def load_evaluation() -> dict[str, object] | None:
    """Per-variant detection quality, with degenerate MCC and rule-based rows marked."""
    raw = _load("evaluation_results.json")
    if raw is None:
        return None

    variants: list[VariantResult] = []
    for name, entry in raw.items():
        tp, tn = entry.get("TP"), entry.get("TN")
        fp, fn = entry.get("FP"), entry.get("FN")
        defined, note = mcc_status(tp, tn, fp, fn)
        variants.append(
            VariantResult(
                name=name,
                mcc=entry.get("M1_MCC", 0.0),
                dr=entry.get("M2_DR", 0.0),
                fpr=entry.get("M3_FPR", 0.0),
                tp=tp, tn=tn, fp=fp, fn=fn,
                source="rule_based" if entry.get("is_rule_based") else "lstm",
                mcc_defined=defined,
                mcc_note=note,
                is_overall=name.startswith(OVERALL_PREFIX),
                reference_only=entry.get("lstm_clf_reference_only"),
            )
        )

    return {
        "variants": [v.to_dict() for v in variants],
        "note": (
            "Window-level evaluation from the federated pipeline's own evaluator "
            "(W=10 s, stride 5 s). This is a different statistic from the "
            "simulator's inline per-node MCC; see docs/WHICH_MCC_TO_REPORT.md."
        ),
    }


def load_poisoning() -> dict[str, object] | None:
    """BRFA-v2 robustness under sign-flip poisoning (M8)."""
    raw = _load("brfa_param_sweep_results.json")
    if raw is None:
        return None
    return {
        "poison_mode": raw.get("poison_mode"),
        "malicious_fraction": raw.get("rho_ab5"),
        "grid": raw.get("grid", []),
        "selected": raw.get("selected"),
        "note": (
            "delta_poison is the MCC lost when a fraction of RSU updates are "
            "sign-flipped. Zero means the aggregator rejected every poisoned "
            "update before averaging."
        ),
    }


def load_federation() -> dict[str, object] | None:
    """Federated round outcome and the Byzantine-rejection breakdown."""
    raw = _load("fed_summary.json")
    if raw is None:
        return None

    n_total = raw.get("n_total", 0)
    accepted = raw.get("accepted_rsus", []) or []
    rejections = {
        "trust": len(raw.get("trust_rejected", []) or []),
        "hash": len(raw.get("hash_rejected", []) or []),
        "krum": len(raw.get("krum_rejected", []) or []),
    }
    return {
        "n_total": n_total,
        "byzantine_bound_f": raw.get("f"),
        "selected_rounds": raw.get("selected_R"),
        "round_grid": raw.get("round_grid", []),
        "global_theta": raw.get("global_theta"),
        "accepted": len(accepted),
        "rejections": rejections,
        # Part-to-whole over the 64 RSUs, so the four counts must sum to n_total.
        "breakdown": [
            {"label": "Accepted", "count": len(accepted)},
            {"label": "Rejected: trust", "count": rejections["trust"]},
            {"label": "Rejected: Krum", "count": rejections["krum"]},
            {"label": "Rejected: hash", "count": rejections["hash"]},
        ],
        "round_log": raw.get("round_log", []),
    }


def _ablation(name: str, arms: dict[str, str]) -> dict[str, object] | None:
    """Load a two-arm ablation into a per-variant before/after shape."""
    raw = _load(name)
    if raw is None:
        return None

    arm_keys = list(arms)
    if not all(key in raw for key in arm_keys):
        return None

    variants = sorted(set(raw[arm_keys[0]]) | set(raw[arm_keys[1]]))
    rows = []
    for variant in variants:
        a = raw[arm_keys[0]].get(variant, {})
        b = raw[arm_keys[1]].get(variant, {})
        rows.append(
            {
                "variant": variant,
                "a": {"mcc": a.get("MCC"), "dr": a.get("DR"), "fpr": a.get("FPR")},
                "b": {"mcc": b.get("MCC"), "dr": b.get("DR"), "fpr": b.get("FPR")},
            }
        )
    return {
        "arm_a": arms[arm_keys[0]],
        "arm_b": arms[arm_keys[1]],
        "rows": rows,
    }


def load_ablations() -> dict[str, object]:
    """AB2 (centralised vs federated) and AB3 (5- vs 7-feature)."""
    return {
        "ab2": _ablation(
            "ab2_centralized_vs_federated_results.json",
            {"AB2_A_centralized": "Centralised", "AB2_B_federated": "Federated"},
        ),
        "ab3": _ablation(
            "ab3_feature_ablation_results.json",
            {"AB3_A_5feature": "5 features", "AB3_B_7feature": "7 features"},
        ),
    }


def load_mobility() -> dict[str, object] | None:
    """MCC stratified by RSU density and mean speed (eq:mcc_mobility)."""
    raw = _load("mobility_stratified_results.json")
    if raw is None:
        return None

    rho_labels = raw.get("rho_labels", [])
    vbar_labels = raw.get("vbar_labels", [])
    cells = []
    for variant, bins in (raw.get("per_variant") or {}).items():
        for bin_name, value in bins.items():
            # Empty bins are null: that mobility combination never occurred in
            # the trace. Rendered as a gap, never as MCC 0.
            cells.append(
                {
                    "variant": variant,
                    "bin": bin_name,
                    "mcc": None if value is None else value.get("MCC"),
                    "n": None if value is None else value.get("n"),
                }
            )
    return {
        "rho_labels": rho_labels,
        "vbar_labels": vbar_labels,
        "bins": [f"rho={r},v_bar={v}" for r in rho_labels for v in vbar_labels],
        "variants": sorted((raw.get("per_variant") or {})),
        "cells": cells,
        "note": "Empty bins are mobility combinations absent from the trace, not zero MCC.",
    }


def panel() -> dict[str, object]:
    """Everything the Federated LSTM tab needs, in one response."""
    evaluation = load_evaluation()
    return {
        "available": evaluation is not None,
        "source_dir": str(PIPELINE_DIR),
        "evaluation": evaluation,
        "poisoning": load_poisoning(),
        "federation": load_federation(),
        "ablations": load_ablations(),
        "mobility": load_mobility(),
    }
