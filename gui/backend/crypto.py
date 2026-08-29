"""Crypto and integrity overhead (M7), from ``crypto_timing_log_*.csv``.

Schema (``scratch/crypto_event_log.h``)::

    sim_time_s, op, node_id, pkt_id, flow_id, wall_us, result

Filenames are ``crypto_timing_log_V<variant>_pct<pct>_s<seed>[_d<X>ms].csv``,
where ``<variant>`` is the **0-based** ``active_attack_variant`` -- so ``V0`` is
Attack 1. Getting that off by one would mislabel every panel.

The ``result`` column is overloaded
-----------------------------------
``crypto_log_event(op, ..., bool result)`` writes ``"ok"``/``"fail"``, but what
the boolean *means* depends entirely on the call site, so aggregating it across
ops is meaningless. Measured on one run, a naive aggregate reads **85% failed**.
Grounded in the source:

===========================  ===============================================
``verify``                   genuine ML-DSA-87 outcome (``sig_ok``).
                             routing.cc:122163
``verify_skip_broadcast``    a broadcast **overhear**: no cryptography ran, so
                             ``sig_ok`` is false by construction. 100% "fail"
                             and none of them are failures. routing.cc:122163
``stark_hop``                ``stark_verify_hop`` outcome -- but logged outside
                             the broadcast branch, so overhears land here too.
                             routing.cc:122167. See the caveat below.
``lrad_obu`` / ``lrad_rsu``  the **detector's decision** (``flags.D_OBU`` /
                             ``flags.D_RSU``): "ok" means the signature FIRED.
                             lrad.h:809 / lrad.h:614
``sign``                     ``mldsa87_sign`` outcome.
``batch_verify``,            timing records; observed always "ok".
``consensus``,
``escalate_to_rsu``
===========================  ===============================================

``routing.cc:122152-122162`` records that ``verify`` was already fixed for this
exact problem -- overhears used to be logged as ``verify`` failures, making the
fail rate "meaningless (mostly benign overhears, not real signature failures)",
so they were split into their own op. **That fix was never applied to
``stark_hop``**, and the arithmetic shows it: on one run ``stark_hop`` has
exactly 3,873 "ok" against ``verify``'s 3,873 total, and exactly 28,501 "fail"
against ``verify_skip_broadcast``'s 28,501. So its 88% fail rate is the same
overhear population, not proof failures. :func:`analyse_run` flags it rather
than reporting the raw rate.
"""

from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Iterable

from .catalog import DEFAULT_RESULTS_DIR

CRYPTO_FILENAME_RE = re.compile(
    r"^crypto_timing_log_V(?P<variant>\d+)_pct(?P<pct>\d+)_s(?P<seed>\d+)"
    r"(?:_d(?P<delay>\d+)ms)?\.csv$"
)

#: What ``result`` means for each op, and whether its rate is worth reporting.
#: ``rate_meaning`` is None where a pass/fail rate is not a meaningful statistic.
OP_SEMANTICS: dict[str, dict[str, object]] = {
    "sign": {
        "kind": "crypto",
        "label": "ML-DSA-87 sign",
        "rate_meaning": "signing succeeded",
    },
    "verify": {
        "kind": "crypto",
        "label": "ML-DSA-87 verify",
        "rate_meaning": "signature verified",
    },
    "batch_verify": {
        "kind": "crypto",
        "label": "Batch verify",
        "rate_meaning": "batch verified",
    },
    "verify_skip_broadcast": {
        "kind": "not_applicable",
        "label": "Broadcast overhear (no crypto run)",
        "rate_meaning": None,
        "note": (
            "Every neighbour overhears every packet; only the intended next hop "
            "verifies. These never attempt cryptography, so their 'fail' is "
            "structural, not a rejection."
        ),
    },
    "stark_hop": {
        "kind": "crypto",
        "label": "STARK hop proof",
        "rate_meaning": None,
        "note": (
            "Logged outside the broadcast-skip branch, so broadcast overhears "
            "are counted here too and the raw fail rate is dominated by them "
            "(see module docstring). Report the latency, not the rate."
        ),
    },
    "consensus": {
        "kind": "consensus",
        "label": "Blockchain consensus",
        "rate_meaning": "consensus reached",
    },
    "escalate_to_rsu": {
        "kind": "detector",
        "label": "Escalation OBU to RSU",
        "rate_meaning": "escalated",
    },
    "lrad_obu": {
        "kind": "detector",
        "label": "LRAD OBU signature",
        "rate_meaning": "detector fired",
        "note": "'ok' means the detector FIRED. Most packets are benign, so a low rate is expected.",
    },
    "lrad_rsu": {
        "kind": "detector",
        "label": "LRAD RSU signature",
        "rate_meaning": "detector fired",
        "note": "'ok' means the detector FIRED, not that a check passed.",
    },
}

#: Ops that make up the post-quantum crypto overhead headline (M7).
HEADLINE_OPS = ("sign", "verify", "batch_verify", "consensus")


@dataclass(frozen=True)
class CryptoFile:
    """One crypto timing log, identified from its filename."""

    run_id: str
    path: Path
    attack_id: int
    attack_percentage: int
    seed: int
    delay_ms: int | None

    @property
    def label(self) -> str:
        base = "Baseline" if self.attack_id == 0 else f"Attack {self.attack_id}"
        extra = f", {self.delay_ms}ms" if self.delay_ms is not None else ""
        return f"{base} @ {self.attack_percentage}% (seed {self.seed}{extra})"

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.run_id,
            "label": self.label,
            "attack": self.attack_id,
            "pct": self.attack_percentage,
            "seed": self.seed,
            "delay_ms": self.delay_ms,
        }


def parse_crypto_filename(name: str) -> dict[str, object] | None:
    """Parse a crypto log filename.

    The ``V`` field is the 0-based ``active_attack_variant``; the attack id used
    everywhere else in the GUI is ``variant + 1``.
    """
    match = CRYPTO_FILENAME_RE.match(name)
    if match is None:
        return None
    delay = match.group("delay")
    return {
        "attack_id": int(match.group("variant")) + 1,
        "attack_percentage": int(match.group("pct")),
        "seed": int(match.group("seed")),
        "delay_ms": int(delay) if delay is not None else None,
    }


def scan(results_dir: str | os.PathLike[str] | None = None) -> list[CryptoFile]:
    """Index the crypto timing logs in ``results_dir``."""
    base = Path(results_dir or os.environ.get("MOBIGUARD_RESULTS_DIR") or DEFAULT_RESULTS_DIR)
    if not base.is_dir():
        return []
    found: list[CryptoFile] = []
    for entry in sorted(base.glob("crypto_timing_log_*.csv")):
        parts = parse_crypto_filename(entry.name)
        if parts is None:
            continue
        found.append(
            CryptoFile(
                run_id=entry.stem,
                path=entry,
                attack_id=int(parts["attack_id"]),
                attack_percentage=int(parts["attack_percentage"]),
                seed=int(parts["seed"]),
                delay_ms=parts["delay_ms"],  # type: ignore[arg-type]
            )
        )
    return sorted(found, key=lambda f: (f.attack_id, f.attack_percentage, f.seed))


def _percentile(sorted_values: list[float], q: float) -> float:
    """Nearest-rank percentile of an already-sorted list."""
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, max(0, int(round(q * (len(sorted_values) - 1)))))
    return sorted_values[index]


def analyse_run(path: str | os.PathLike[str]) -> dict[str, object]:
    """Aggregate one crypto timing log into per-operation statistics.

    Returns latency statistics for every op, plus ``ok``/``fail`` counts
    annotated with what those actually mean for that op.
    """
    durations: dict[str, list[float]] = {}
    outcomes: dict[str, dict[str, int]] = {}
    total_rows = 0

    with Path(path).open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            op = (row.get("op") or "").strip()
            if not op:
                continue
            try:
                wall = float(row.get("wall_us") or 0.0)
            except ValueError:
                continue
            total_rows += 1
            durations.setdefault(op, []).append(wall)
            bucket = outcomes.setdefault(op, {"ok": 0, "fail": 0})
            bucket["ok" if (row.get("result") or "").strip() == "ok" else "fail"] += 1

    operations = []
    for op, values in durations.items():
        values.sort()
        counts = outcomes[op]
        semantics = OP_SEMANTICS.get(
            op, {"kind": "other", "label": op, "rate_meaning": None}
        )
        n = len(values)
        operations.append(
            {
                "op": op,
                "label": semantics["label"],
                "kind": semantics["kind"],
                "count": n,
                "mean_us": sum(values) / n,
                "median_us": median(values),
                "p95_us": _percentile(values, 0.95),
                "max_us": values[-1],
                "total_ms": sum(values) / 1000.0,
                "ok": counts["ok"],
                "fail": counts["fail"],
                # Only meaningful where the boolean encodes a pass/fail.
                "rate_meaning": semantics.get("rate_meaning"),
                "ok_rate": (counts["ok"] / n) if semantics.get("rate_meaning") else None,
                "note": semantics.get("note"),
            }
        )

    operations.sort(key=lambda o: o["mean_us"], reverse=True)

    by_op = {o["op"]: o for o in operations}
    verify = by_op.get("verify")

    return {
        "total_events": total_rows,
        "operations": operations,
        "headline": [by_op[op] for op in HEADLINE_OPS if op in by_op],
        # The genuine signature-verification failure rate, from the one op whose
        # boolean actually encodes that. Never aggregate across ops.
        "signature_verification": (
            {
                "attempts": verify["count"],
                "passed": verify["ok"],
                "failed": verify["fail"],
                "fail_rate": verify["fail"] / verify["count"] if verify["count"] else 0.0,
            }
            if verify
            else None
        ),
        "stark_hop_caveat": _stark_caveat(by_op),
        "note": (
            "The result column means different things per operation, so a "
            "combined pass/fail rate is not a statistic. See each row."
        ),
    }


def _stark_caveat(by_op: dict[str, dict[str, object]]) -> dict[str, object] | None:
    """Detect stark_hop's fail count being the broadcast-overhear population.

    ``verify`` was split from ``verify_skip_broadcast`` precisely so overhears
    would stop inflating its failure rate (routing.cc:122152-122162).
    ``stark_hop`` is logged outside that branch, so the same contamination
    remains. When the counts line up exactly, say so rather than presenting an
    88% failure rate as a finding.
    """
    stark = by_op.get("stark_hop")
    verify = by_op.get("verify")
    skipped = by_op.get("verify_skip_broadcast")
    if not (stark and verify and skipped):
        return None

    matches = stark["ok"] == verify["count"] and stark["fail"] == skipped["count"]
    return {
        "stark_ok": stark["ok"],
        "stark_fail": stark["fail"],
        "verify_total": verify["count"],
        "broadcast_overhears": skipped["count"],
        "counts_line_up": matches,
        "raw_fail_rate": stark["fail"] / stark["count"] if stark["count"] else 0.0,
        "explanation": (
            "stark_hop's 'fail' count equals the broadcast-overhear count exactly, "
            "and its 'ok' count equals the number of genuine verifications. It is "
            "logged outside the broadcast-skip branch, so its raw fail rate "
            "measures overhearing, not proof failures. Report its latency instead."
            if matches
            else "stark_hop counts do not line up with the overhear population; "
            "its fail rate may reflect genuine proof outcomes."
        ),
    }


def panel(run_id: str | None = None, results_dir: str | os.PathLike[str] | None = None) -> dict[str, object]:
    """Crypto overhead panel: the run list plus one analysed run."""
    files = scan(results_dir)
    if not files:
        return {"available": False, "runs": []}

    selected = next((f for f in files if f.run_id == run_id), files[0])
    return {
        "available": True,
        "runs": [f.to_dict() for f in files],
        "selected": selected.to_dict(),
        "analysis": analyse_run(selected.path),
    }
