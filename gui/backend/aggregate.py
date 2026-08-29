"""Sweep curves, 95% confidence intervals, and confusion-matrix recomputation.

Stdlib only. The data is small enough (48 files x ~30 rows) that ``statistics``
and a hardcoded t-table replace pandas/numpy/scipy outright, which keeps the
demo's install step at ``pip install fastapi uvicorn``.

Two things here must agree with work that already exists, or the GUI will
quietly contradict the thesis:

* **The CI method** mirrors ``scripts/plot_hf_results.py`` -- a two-sided
  Student-t interval at alpha=0.05 with ``df = n - 1``, ``ci = t * sd / sqrt(n)``.
  That script gets its critical value from ``scipy.stats.t``; :data:`T_CRITICAL_95`
  is the same table inlined. ``test_phase0`` pins several entries against
  published values.

* **The confusion-matrix recomputation** mirrors ``functional_verification.py``
  GROUP B, which re-derives MCC/DR/FPR from the raw TP/FP/TN/FN columns instead
  of trusting the reported ones. :func:`verify_reported_metrics` carries that
  same check into the UI so a mismatch is *shown*, not hidden.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from statistics import fmean, stdev
from typing import Sequence

from . import schema
from .catalog import Catalog, RunFile
from .parser import Run, load_run

#: Two-sided Student-t critical values at alpha = 0.05, indexed by degrees of
#: freedom. Sourced to match ``scipy.stats.t.ppf(0.975, df)`` as used by
#: ``scripts/plot_hf_results.py``. df > 30 falls back to the normal
#: approximation, which is within 0.5% there and never reached by these sweeps
#: (seeds number at most a handful).
T_CRITICAL_95: dict[int, float] = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
    16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}

NORMAL_CRITICAL_95: float = 1.960


def t_critical_95(df: int) -> float:
    """Two-sided t critical value at 95% for ``df`` degrees of freedom."""
    if df < 1:
        raise ValueError(f"degrees of freedom must be >= 1, got {df}")
    return T_CRITICAL_95.get(df, NORMAL_CRITICAL_95)


@dataclass(frozen=True)
class Estimate:
    """A point estimate with its 95% CI half-width and sample size.

    ``ci95`` is ``None`` when ``n < 2``: a single seed carries no information
    about spread. The UI must render that as "n=1, no CI" rather than as a
    zero-width error bar, which would read as perfect precision.
    """

    mean: float
    ci95: float | None
    n: int
    values: tuple[float, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {"mean": self.mean, "ci95": self.ci95, "n": self.n}


def mean_ci95(values: Sequence[float]) -> Estimate:
    """Mean and 95% CI half-width over ``values``.

    Raises:
        ValueError: if ``values`` is empty.
    """
    if not values:
        raise ValueError("cannot summarise an empty sample")
    n = len(values)
    mean = fmean(values)
    if n < 2:
        return Estimate(mean=mean, ci95=None, n=n, values=tuple(values))
    sd = stdev(values)
    ci = t_critical_95(n - 1) * sd / math.sqrt(n)
    return Estimate(mean=mean, ci95=ci, n=n, values=tuple(values))


# --- Confusion matrix --------------------------------------------------------


@dataclass(frozen=True)
class ConfusionMetrics:
    """MCC/DR/FPR derived from raw counts.

    Units follow the CSV's own convention (see :data:`schema.METRIC_UNITS`):
    :attr:`mcc` is a fraction in [-1, 1]; :attr:`dr` and :attr:`fpr` are
    percentages in [0, 100]. Matching those units is what lets
    :func:`verify_reported_metrics` compare against the reported columns
    directly.
    """

    tp: float
    fp: float
    tn: float
    fn: float
    mcc: float
    dr: float
    fpr: float

    def to_dict(self) -> dict[str, float]:
        return {
            "TP": self.tp, "FP": self.fp, "TN": self.tn, "FN": self.fn,
            "MCC": self.mcc, "DR": self.dr, "FPR": self.fpr,
        }


def recompute_confusion(tp: float, fp: float, tn: float, fn: float) -> ConfusionMetrics:
    """Re-derive MCC, DR and FPR from raw counts.

    A zero denominator yields 0.0 for the affected metric, matching the
    degenerate-case convention used elsewhere in the project (a classifier that
    never had the opportunity to be right or wrong scores 0, not NaN).
    """
    mcc_den_sq = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    mcc = ((tp * tn) - (fp * fn)) / math.sqrt(mcc_den_sq) if mcc_den_sq > 0 else 0.0

    dr = 100.0 * tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = 100.0 * fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return ConfusionMetrics(tp=tp, fp=fp, tn=tn, fn=fn, mcc=mcc, dr=dr, fpr=fpr)


@dataclass(frozen=True)
class MetricDiscrepancy:
    """Largest per-cycle gap between a reported column and its recomputation."""

    metric: str
    reported: float
    recomputed: float
    cycle: int

    @property
    def delta(self) -> float:
        return abs(self.reported - self.recomputed)

    def to_dict(self) -> dict[str, object]:
        return {
            "metric": self.metric,
            "reported": self.reported,
            "recomputed": self.recomputed,
            "cycle": self.cycle,
            "delta": self.delta,
        }


def verify_reported_metrics(run: Run) -> list[MetricDiscrepancy]:
    """Recompute MCC/DR/FPR per cycle and report the worst gap for each.

    Mirrors ``functional_verification.py`` GROUP B: the reported columns are
    checked against the raw confusion matrix rather than believed. Returns one
    entry per metric, describing the cycle where the two disagreed most; a
    healthy run yields deltas at floating-point noise level.
    """
    pairs = (("MCC", "cur_MCC"), ("DR", "cur_DR"), ("FPR", "cur_FPR"))
    worst: dict[str, MetricDiscrepancy] = {}

    for i, cycle in enumerate(run.cycles):
        recomputed = recompute_confusion(
            run.series("TP")[i], run.series("FP")[i],
            run.series("TN")[i], run.series("FN")[i],
        )
        for key, column in pairs:
            candidate = MetricDiscrepancy(
                metric=column,
                reported=run.series(column)[i],
                recomputed=getattr(recomputed, key.lower()),
                cycle=cycle,
            )
            if key not in worst or candidate.delta > worst[key].delta:
                worst[key] = candidate

    return [worst[k] for k, _ in pairs if k in worst]


# --- Sweeps ------------------------------------------------------------------


@dataclass(frozen=True)
class SweepPoint:
    """One attack-percentage point on a sweep curve."""

    attack_percentage: int
    estimate: Estimate
    run_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "pct": self.attack_percentage,
            **self.estimate.to_dict(),
            "run_ids": list(self.run_ids),
        }


@dataclass(frozen=True)
class Sweep:
    """A metric plotted against attack percentage, averaged across seeds."""

    attack_id: int
    metric: str
    unit: str
    points: tuple[SweepPoint, ...]

    @property
    def caveat(self) -> str | None:
        """Mandatory display caveat, or ``None``.

        Non-``None`` for the inline per-node detection columns, which share a
        name with a thesis metric but are a different statistic. The UI must
        render this next to the chart -- see ``docs/WHICH_MCC_TO_REPORT.md``.
        """
        return schema.caveat_for(self.metric)

    def to_dict(self) -> dict[str, object]:
        return {
            "attack": self.attack_id,
            "metric": self.metric,
            "unit": self.unit,
            "caveat": self.caveat,
            "pct": [p.attack_percentage for p in self.points],
            "mean": [p.estimate.mean for p in self.points],
            "ci95": [p.estimate.ci95 for p in self.points],
            "n": [p.estimate.n for p in self.points],
            "run_ids": [list(p.run_ids) for p in self.points],
        }


def run_level_value(run_file: RunFile, metric: str) -> float:
    """The whole-run value of ``metric`` for one CSV.

    Takes the metric from the run's final cycle. For the cumulative ``avg_*``
    columns that is the whole-run average by construction, which is the quantity
    the sweep curves in ``output/`` plot.
    """
    run = load_run(run_file.path, run_file.attack_id)
    return run.final()[metric]


def sweep(
    catalog: Catalog,
    *,
    attack_id: int,
    metric: str,
    seeds: Sequence[int] | None = None,
    delay_ms: int | None = None,
    tag: str | None = None,
) -> Sweep:
    """Build a metric-vs-attack-percentage curve with 95% CIs across seeds.

    Raises:
        KeyError: if ``metric`` is not a column of this attack's schema --
            asking for a TCAM column on attack 5, say, fails here rather than
            producing an empty chart.
    """
    if metric not in schema.columns_for(attack_id):
        raise KeyError(
            f"{metric!r} is not a column for attack {attack_id}. "
            f"TCAM columns exist only for attacks {sorted(schema.TCAM_ATTACK_IDS)}."
        )

    points: list[SweepPoint] = []
    for pct in catalog.percentages(attack_id):
        run_files = catalog.filter(
            attack_id=attack_id,
            attack_percentage=pct,
            seeds=seeds,
            delay_ms=delay_ms,
            tag=tag,
        )
        if not run_files:
            continue
        values = [run_level_value(rf, metric) for rf in run_files]
        points.append(
            SweepPoint(
                attack_percentage=pct,
                estimate=mean_ci95(values),
                run_ids=tuple(rf.run_id for rf in run_files),
            )
        )

    return Sweep(
        attack_id=attack_id,
        metric=metric,
        unit=schema.METRIC_UNITS.get(metric, "count"),
        points=tuple(points),
    )
