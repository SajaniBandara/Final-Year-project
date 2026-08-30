"""Baseline comparators (B1/B2/B3) and the ablation summary.

The offline half of what the demo has to answer: *how does MOBIGUARD compare to
prior work, and how much does each of its layers contribute?* Two different
questions with two different kinds of evidence.

Comparators
-----------

======  ==========================================  ==============================
Label   What                                        Where its numbers live
======  ==========================================  ==============================
B1      TAP (Arsalan & Rehman, FIT 2018)            ``TAP_Attack<N>_*.csv``
B2      SFTO                                        ``sfto_pipeline/results/*/metrics.json``
B3      eFADE                                       ``fade_results_*.csv``
======  ==========================================  ==============================

Each covers a different slice and **none covers all eight variants**, which is
itself a finding worth stating rather than papering over: TAP is only comparable
on Attack 2 (its detector keys on safety-critical flow delay), eFADE is scoped
to the four Hidden Forwarding variants by construction, and SFTO's published
pipeline covers the two TCAM variants. A single "MOBIGUARD vs. baselines" bar
chart across all eight would be inventing coverage that does not exist.

Why these files were empty until now
------------------------------------
``docs/GUI_IMPLEMENTATION_PLAN.md`` recorded B1 and B3 as "BLOCKED on the HPC --
TAP produced no local output, all 48 ``fade_results_*.csv`` are header-only".
The diagnosis was wrong. Both are gated on a flag combination that had never
been run: eFADE needs ``!enable_lrad_obu && !enable_lrad_rsu`` (routing.cc
~144745) and TAP needs ``--enable_tap=1`` with the same isolation. Every
existing run had LRAD on, so eFADE's detection loop never armed and wrote its
header and nothing else. ``scripts/gui_demo_runs.py`` collects both properly.

Comparability, and where it stops
---------------------------------
TAP's writer emits the same leading 19 columns as MOBIGUARD's, deliberately, so
MCC/DR/FPR and the raw confusion counts line up 1:1 and can be put side by side
honestly. SFTO cannot: its numbers come from an offline classifier over a
feature matrix, scored per sample rather than per routing cycle, on a few dozen
samples. So SFTO's sample size travels with its metrics everywhere in this
module -- an MCC of 1.000 over 22 samples and an MCC of 1.000 over ten thousand
windows are not the same claim, and only one of them survives a panel asking.
"""

from __future__ import annotations

import json
import re
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import schema
from .catalog import REPO_ROOT, Catalog, RunFile
from .parser import parse_file

#: Where SFTO's offline pipeline writes its evaluation.
SFTO_RESULTS = REPO_ROOT / "sfto_pipeline" / "results"

#: SFTO result directory -> which attack variant it evaluated. Taken from the
#: directory names the pipeline itself uses; anything unmapped is reported
#: without a variant rather than guessed into one.
SFTO_VARIANTS: dict[str, int] = {
    "routing_attack3": 3,
    "routing_attack4": 4,
}

#: Which variants each comparator can speak to at all.
COVERAGE: dict[str, tuple[int, ...]] = {
    "B1": (2,),
    "B2": (3, 4),
    "B3": (5, 6, 7, 8),
}

BASELINE_NAMES: dict[str, str] = {
    "B1": "TAP (Arsalan & Rehman, FIT 2018)",
    "B2": "SFTO",
    "B3": "eFADE",
}

#: Ablation tag -> what it removes. Parsed from the run tag suffix (AB1A, AB4C).
#: The letters are arms of one ablation, not separate ablations.
ABLATION_LABELS: dict[str, str] = {
    "AB1": "LRAD rule engines",
    "AB2": "Post-quantum crypto",
    "AB3": "Federated LSTM",
    "AB4": "STARK timing & hop proofs",
    "AB5": "Blockchain anchoring",
    "AB6": "Witness / BFT alerts",
    "AB7": "Trust & quarantine",
    "AB8": "FlowMod endorsement",
    "AB9": "Controller failover",
    "AB10": "Key management",
    "AB11": "DKG key rotation",
}

ABLATION_RE = re.compile(r"^(AB\d+)([A-Z]?)$")

#: Metrics compared across baselines and ablations. All are per-node inline
#: diagnostics rather than the thesis's per-RSU-window M1 -- carried through
#: from schema.py so the caveat travels with the number.
COMPARE_COLUMNS = ("avg_MCC", "avg_DR", "avg_FPR")


class BaselineError(RuntimeError):
    """A baseline source could not be read."""


# --------------------------------------------------------------------------
# TAP (B1)
# --------------------------------------------------------------------------

def _final_row(path: Path, attack_id: int) -> dict[str, float] | None:
    """Last cycle of a metrics-shaped CSV, or None when it has no data rows."""
    try:
        runs = parse_file(path, attack_id)
    except Exception:  # noqa: BLE001 - a malformed baseline must not break the tab
        return None
    run = runs[-1] if runs else None
    if run is None or not run.cycles:
        return None
    # Run stores columns as parallel lists, so the final cycle is the last
    # element of each. The avg_* columns are cumulative, which is why the last
    # row is the run's summary rather than an arbitrary sample of it.
    return {name: values[-1] for name, values in run.columns.items() if values}


def tap_records(results_dir: Path) -> list[dict[str, Any]]:
    """Every ``TAP_Attack*.csv`` on disk, decoded to its final cycle.

    TAP's writer emits MOBIGUARD's leading 19 columns verbatim, so the narrow
    schema decodes it directly -- and that column alignment is the whole reason
    a like-for-like comparison is possible.
    """
    out: list[dict[str, Any]] = []
    for path in sorted(results_dir.glob("TAP_Attack*.csv")):
        m = re.match(
            r"TAP_Attack(\d+)_(\d+)(?:_d(\d+)ms)?_seed(\d+)(?:_(.+))?\.csv$",
            path.name,
        )
        if m is None:
            continue
        attack_id = int(m.group(1))
        final = _final_row(path, attack_id)
        if final is None:
            continue
        out.append({
            "file": path.name,
            "attack_id": attack_id,
            "attack_percentage": int(m.group(2)),
            "delay_ms": int(m.group(3)) if m.group(3) else None,
            "seed": int(m.group(4)),
            "tag": m.group(5),
            "metrics": {c: final.get(c) for c in COMPARE_COLUMNS},
            "confusion": {c: final.get(c) for c in ("TP", "FP", "TN", "FN")},
        })
    return out


# --------------------------------------------------------------------------
# eFADE (B3)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class FadeSummary:
    """eFADE's per-flow verdicts for one run, reduced to a detection rate."""

    file: str
    attack_id: int
    attack_percentage: int
    seed: int
    tag: str | None
    flows: int
    detected: int
    localised: int
    mean_detection_time: float | None

    @property
    def detection_rate(self) -> float | None:
        return (self.detected / self.flows) if self.flows else None

    def to_json(self) -> dict[str, Any]:
        return {
            "file": self.file, "attack_id": self.attack_id,
            "attack_percentage": self.attack_percentage, "seed": self.seed,
            "tag": self.tag, "flows": self.flows, "detected": self.detected,
            "localised": self.localised,
            "detection_rate": self.detection_rate,
            "mean_detection_time_s": self.mean_detection_time,
        }


def fade_records(results_dir: Path) -> list[FadeSummary]:
    """Parse ``fade_results_*.csv``, skipping the header-only ones.

    A header-only file is the normal state for a run made before the isolation
    flags were understood: eFADE's detection loop is inert unless both LRAD
    engines are off, so it wrote its header and nothing else. Those are dropped
    here and counted by :func:`panel`, which reports how many were found -- the
    count is the evidence for why the baseline was thought to be broken.
    """
    out: list[FadeSummary] = []
    for path in sorted(results_dir.glob("fade_results_Attack*.csv")):
        m = re.match(
            r"fade_results_Attack(\d+)_(\d+)(?:_d\d+ms)?_seed(\d+)(?:_(.+))?\.csv$",
            path.name,
        )
        if m is None:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rows = [ln for ln in lines[1:] if ln.strip()]
        if not rows:
            continue
        detected = 0
        localised = 0
        times: list[float] = []
        for row in rows:
            parts = [p.strip() for p in row.split(",")]
            if len(parts) < 7:
                continue
            is_detected = parts[2] in ("1", "true", "True")
            if is_detected:
                detected += 1
                try:
                    times.append(float(parts[3]))
                except ValueError:
                    pass
            # Localisation means eFADE named the duplicating node, not merely
            # that something was wrong -- its headline claim over plain anomaly
            # detection, so it is counted separately.
            #
            # Undetected rows carry the sentinel 50000 in all three node
            # columns, not an empty field, so they must be excluded explicitly
            # or every flow counts as localised and the metric reads 100%.
            if is_detected and parts[6] not in ("", "-1", "50000", "none", "None"):
                localised += 1
        out.append(FadeSummary(
            file=path.name, attack_id=int(m.group(1)),
            attack_percentage=int(m.group(2)), seed=int(m.group(3)),
            tag=m.group(4), flows=len(rows), detected=detected,
            localised=localised,
            mean_detection_time=statistics.fmean(times) if times else None,
        ))
    return out


def count_empty_fade(results_dir: Path) -> int:
    """Header-only eFADE files: runs where its detection loop never armed."""
    total = 0
    for path in results_dir.glob("fade_results_Attack*.csv"):
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.readline()
                if not any(line.strip() for line in fh):
                    total += 1
        except OSError:
            continue
    return total


# --------------------------------------------------------------------------
# SFTO (B2)
# --------------------------------------------------------------------------

def sfto_records(root: Path = SFTO_RESULTS) -> list[dict[str, Any]]:
    """SFTO's offline evaluation, with its sample size attached.

    The sample size is not decoration. These runs report MCC 1.000, which reads
    as "perfect" until you see it was over 22 samples. Reporting the metric
    without ``n`` would be the single most misleading number this GUI could
    show, so ``n`` travels with it and :func:`panel` marks small samples.
    """
    out: list[dict[str, Any]] = []
    if not root.is_dir():
        return out
    for directory in sorted(p for p in root.iterdir() if p.is_dir()):
        metrics_path = directory / "metrics.json"
        if not metrics_path.is_file():
            continue
        try:
            payload = json.loads(metrics_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        counts = {k: payload.get(k) for k in ("TP", "FP", "TN", "FN")}
        n = sum(v for v in counts.values() if isinstance(v, int))
        if payload.get("mcc") is None:
            continue
        out.append({
            "dataset": directory.name,
            "attack_id": SFTO_VARIANTS.get(directory.name),
            "metrics": {
                # SFTO reports fractions; MOBIGUARD's DR/FPR columns are
                # percentages. Scaled here so a side-by-side table compares
                # like with like rather than looking 100x better.
                "avg_MCC": payload.get("mcc"),
                "avg_DR": _scale(payload.get("recall")),
                "avg_FPR": _scale(payload.get("fpr")),
            },
            "confusion": counts,
            "n": n,
            "small_sample": n < 100,
            "features": payload.get("selected_features"),
        })
    return out


def _scale(fraction: float | None) -> float | None:
    return None if fraction is None else fraction * 100.0


# --------------------------------------------------------------------------
# Ablations
# --------------------------------------------------------------------------

def ablation_records(catalog: Catalog) -> list[dict[str, Any]]:
    """Every AB-tagged run, grouped by the ablation it belongs to."""
    out: list[dict[str, Any]] = []
    for run_file in catalog:
        tag = run_file.tag or ""
        m = ABLATION_RE.match(tag)
        if m is None:
            continue
        family, arm = m.group(1), m.group(2)
        final = _final_row(run_file.path, run_file.attack_id)
        if final is None:
            continue
        out.append({
            "run_id": run_file.run_id,
            "ablation": family,
            "arm": arm or "-",
            "label": ABLATION_LABELS.get(family, family),
            "attack_id": run_file.attack_id,
            "attack_percentage": run_file.attack_percentage,
            "seed": run_file.seed,
            "metrics": {c: final.get(c) for c in COMPARE_COLUMNS},
            "confusion": {c: final.get(c) for c in ("TP", "FP", "TN", "FN")},
        })
    return out


def mobiguard_reference(
    catalog: Catalog, attack_id: int, pct: int | None = None
) -> dict[str, Any] | None:
    """The full-stack run to compare an ablation or baseline against.

    Prefers an untagged run -- the plain sweep output -- then a DEMO run, and
    never an AB/TAP/FADE one: comparing an ablation against another ablation
    would silently answer a different question than the one asked.
    """
    candidates = [
        r for r in catalog
        if r.attack_id == attack_id
        and (pct is None or r.attack_percentage == pct)
        and not ABLATION_RE.match(r.tag or "")
        and not (r.tag or "").startswith(("TAP", "FADE"))
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda r: (bool(r.tag), -r.size_bytes))
    chosen = candidates[0]
    final = _final_row(chosen.path, chosen.attack_id)
    if final is None:
        return None
    return {
        "run_id": chosen.run_id,
        "attack_id": chosen.attack_id,
        "attack_percentage": chosen.attack_percentage,
        "metrics": {c: final.get(c) for c in COMPARE_COLUMNS},
        "confusion": {c: final.get(c) for c in ("TP", "FP", "TN", "FN")},
    }


# --------------------------------------------------------------------------
# Panel assembly
# --------------------------------------------------------------------------

def panel(catalog: Catalog) -> dict[str, Any]:
    """Everything the Baselines & Ablations tab renders."""
    results_dir = catalog.results_dir
    tap = tap_records(results_dir)
    fade = [f.to_json() for f in fade_records(results_dir)]
    sfto = sfto_records()
    ablations = ablation_records(catalog)

    comparisons: list[dict[str, Any]] = []

    for record in tap:
        reference = mobiguard_reference(
            catalog, record["attack_id"], record["attack_percentage"]
        )
        comparisons.append({
            "baseline": "B1", "name": BASELINE_NAMES["B1"],
            "attack_id": record["attack_id"],
            "attack_percentage": record["attack_percentage"],
            "baseline_metrics": record["metrics"],
            "baseline_confusion": record["confusion"],
            "mobiguard": reference,
            "comparable": True,
            "basis": "Same 19 leading columns, same runs' cycle cadence.",
        })

    for record in sfto:
        if record["attack_id"] is None:
            continue
        reference = mobiguard_reference(catalog, record["attack_id"])
        comparisons.append({
            "baseline": "B2", "name": BASELINE_NAMES["B2"],
            "attack_id": record["attack_id"],
            "attack_percentage": None,
            "baseline_metrics": record["metrics"],
            "baseline_confusion": record["confusion"],
            "mobiguard": reference,
            "comparable": False,
            "n": record["n"],
            "basis": (
                f"Not directly comparable: SFTO scores {record['n']} offline "
                "samples from a feature matrix, MOBIGUARD scores per routing "
                "cycle. Read the confusion counts, not the ratio."
            ),
        })

    return {
        "baselines": [
            {"key": key, "name": BASELINE_NAMES[key], "covers": list(COVERAGE[key])}
            for key in ("B1", "B2", "B3")
        ],
        "tap": tap,
        "fade": fade,
        "fade_empty_files": count_empty_fade(results_dir),
        "sfto": sfto,
        "comparisons": comparisons,
        "ablations": ablations,
        "ablation_families": sorted(
            {a["ablation"] for a in ablations},
            key=lambda t: int(t[2:]),
        ),
        "compare_columns": list(COMPARE_COLUMNS),
        "caveats": {
            column: schema.caveat_for(column)
            for column in COMPARE_COLUMNS
            if schema.caveat_for(column)
        },
        "notes": _notes(tap, fade, sfto, ablations, count_empty_fade(results_dir)),
    }


def _notes(
    tap: list[dict[str, Any]],
    fade: list[dict[str, Any]],
    sfto: list[dict[str, Any]],
    ablations: list[dict[str, Any]],
    empty_fade: int,
) -> list[str]:
    """What is missing and why, stated rather than left as an empty chart."""
    notes: list[str] = []
    if not tap:
        notes.append(
            "B1 TAP: no TAP_Attack*.csv on disk. TAP needs --enable_tap=1 with "
            "both LRAD engines off; run scripts/gui_demo_runs.py --batch "
            "baselines to collect it."
        )
    if not fade:
        notes.append(
            f"B3 eFADE: {empty_fade} result file(s) present but all header-only. "
            "eFADE's detection loop only arms when both LRAD engines are off "
            "(routing.cc ~144745), so runs with the full stack produce a header "
            "and nothing else. This is a configuration gap, not missing data."
        )
    elif empty_fade:
        notes.append(
            f"{empty_fade} eFADE file(s) are header-only -- runs made with LRAD "
            "on, where its detection loop never armed. They are excluded here."
        )
    if not sfto:
        notes.append("B2 SFTO: no metrics.json under sfto_pipeline/results/.")
    else:
        small = [s for s in sfto if s["small_sample"]]
        if small:
            notes.append(
                f"{len(small)} SFTO result(s) are scored over fewer than 100 "
                "samples. An MCC of 1.000 over a few dozen samples is not "
                "comparable to one over thousands of windows; the sample size "
                "is shown beside every SFTO figure for that reason."
            )
    if not ablations:
        notes.append("No AB-tagged runs found in the results directory.")
    notes.append(
        "No baseline covers all eight variants: TAP is comparable on Attack 2 "
        "only, eFADE is scoped to the four Hidden Forwarding variants by "
        "construction, and SFTO's published pipeline covers the TCAM pair. A "
        "single chart across all eight would imply coverage that does not exist."
    )
    return notes
