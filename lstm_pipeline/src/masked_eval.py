"""
masked_eval.py — traffic-floor masked evaluation (2026-08-30).

WHY THIS EXISTS
---------------
17 of the 64 RSUs sit on the 8x8 grid perimeter and carry ~160x less traffic
than the interior in EVERY config, benign included (measured 2026-08-30:
mean lambda_PI 0.04 vs 6.73 on Attack0, and the same ratio on A5/A6/A8). They
are compromised like any other RSU at high attack_percentage, but routing
paths never traverse them, so they never forward a packet, never schedule a
hidden duplicate, and never trigger S5. hf_send_gt = 0 is the CORRECT label
for them -- this is not a labelling defect and must not be "fixed" in the
injector.

What it IS, is an evaluation subsidy. Those windows are trivially-classifiable
negatives: 26.7% of the test split carries literally zero traffic, and they
make up 36.9% of the entire negative class. Every RSU-level specificity/FPR
number is inflated by that free mass without it being visible in the reported
figure.

So this script reports M1-M3 BOTH WAYS -- all windows, and traffic-carrying
windows only -- the same convention item7_persistence_sweep.py uses for the
dedup question: print both rather than silently pick one.

THE MASK IS NOT A TUNED THRESHOLD. Per-RSU benign traffic is continuous, with
no bimodal break (checked: the sorted per-RSU benign means rise smoothly from
0.0000 to 31.76), so any "low traffic" cutoff would be arbitrary. The rule
used here is the non-arbitrary one: a window is excluded iff the RSU carried
ZERO traffic across all W cycles of that window. Nothing to detect, nothing to
false-alarm on. Traffic is read from the raw per-cycle lambda_PI column, which
is a model INPUT feature -- the mask therefore conditions on inputs only,
never on labels or scores, so it cannot leak.

Mirrors evaluator.py's DETECTOR pipeline exactly (per-RSU theta -> hf_theta
override -> warm-up adaptation -> Q19 dedup). The warm-up step keeps using
test_y, exactly as evaluator.py does, so the detector side is byte-identical;
only the EVALUATION label differs, see below.

WHICH LABEL. Defaults to y_indep, NOT test_y. test_y is 100% positive for
A5/A6/A7 (0 negatives, measured on the test split) and 96.2% positive for A8,
so a per-variant confusion matrix over test_y has tn=fp=0 and both MCC and FPR
are undefined -- sklearn returns 0.0 for MCC and the FPR expression collapses
to 0/0. Those are not measurements. evaluator.py already acknowledges this as
"A5-A7's unmeasurable FPR" (see load_hf_theta's docstring). y_indep is the
leak-free window label and carries real negatives for every variant (28-43%
positive), which is what makes MCC/FPR meaningful here. Pass --label y to
reproduce evaluator.py's degenerate columns.
"""
import sys, os, csv, json, argparse
from pathlib import Path
import numpy as np

SRC = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))

from evaluator import (load_global_model, load_hf_theta, predict_test,
                       compute_adaptive_theta, compute_clf_metrics,
                       ATTACK_NAMES, PRE, RESULTS)
from preprocessor import WINDOW

TRAIN = RESULTS / "lstm_training"


def window_traffic(meta: np.ndarray, seed_suffix_delay=(1, 2)) -> np.ndarray:
    """Total raw lambda_PI over each window's W cycles, from the source CSVs.

    Joined on meta's full key (rsu, attack_v, pct, seed, start_cycle), so it
    lines up row-for-row with the preprocessed arrays.
    """
    cache = {}
    out = np.full(len(meta), np.nan)
    for i in range(len(meta)):
        rsu, av, pct, seed, c0 = (int(x) for x in meta[i])
        key = (rsu, av, pct, seed)
        d = cache.get(key)
        if d is None:
            suf = "_d100ms" if av in seed_suffix_delay else ""
            p = TRAIN / f"RSU_{rsu}" / f"Attack{av}_{pct}{suf}_seed{seed}.csv"
            d = {}
            if p.exists():
                with open(p) as fh:
                    for x in csv.DictReader(fh):
                        d[int(float(x["cycle"]))] = float(x["lambda_PI"])
            cache[key] = d
        out[i] = sum(d.get(c, 0.0) for c in range(c0, c0 + WINDOW)) if d else np.nan
    return out


def dedup_with(y_true, y_pred, meta, extra):
    """evaluator.deduplicate_windows(), also collapsing `extra` by max()."""
    block = meta[:, 4] // WINDOW
    keys = np.stack([meta[:, 0], meta[:, 1], meta[:, 2], meta[:, 3], block], axis=1)
    _, gi = np.unique(keys, axis=0, return_inverse=True)
    n = gi.max() + 1
    yt = np.zeros(n, dtype=np.int8); yp = np.zeros(n, dtype=np.int8)
    ex = np.zeros(n, dtype=float)
    np.maximum.at(yt, gi, y_true)
    np.maximum.at(yp, gi, y_pred)
    np.maximum.at(ex, gi, extra)          # block carries traffic if ANY window did
    gm = np.zeros((n, meta.shape[1]), dtype=meta.dtype); gm[gi] = meta
    return yt, yp, gm, ex


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variants", default="5,6,7,8",
                    help="comma-separated attack_v to report (default A5-A8)")
    ap.add_argument("--json", default=None, help="optional output path")
    ap.add_argument("--label", default="y_indep", choices=["y_indep", "y"],
                    help="evaluation label (default y_indep; 'y' is degenerate for A5-A7)")
    args = ap.parse_args()
    want = [int(v) for v in args.variants.split(",")]

    model, per_rsu_theta, global_theta = load_global_model()
    hf_theta = load_hf_theta()
    y_true, y_pred, scores, meta = predict_test(model, per_rsu_theta, global_theta, hf_theta)

    # Warm-up adaptation uses test_y, exactly as evaluator.py does -- the
    # detector side stays identical regardless of --label.
    theta_ad, keep, n_ad, n_runs = compute_adaptive_theta(
        scores, meta, y_true, per_rsu_theta, global_theta, hf_theta)
    y_pred = (scores > theta_ad).astype(np.int8)
    if args.label == "y_indep":
        y_true = np.load(PRE / "test_y_indep.npy")
    y_true, y_pred, scores, meta = y_true[keep], y_pred[keep], scores[keep], meta[keep]
    print(f"evaluation label: {args.label}   warm-up adapted {n_ad}/{n_runs} runs")

    traf = window_traffic(meta)
    unresolved = int(np.isnan(traf).sum())
    traf = np.nan_to_num(traf, nan=0.0)

    y_true, y_pred, meta, traf = dedup_with(y_true, y_pred, meta, traf)
    carries = traf > 0

    print(f"blocks after dedup: {len(y_true)}   unresolved-traffic windows: {unresolved}")
    print(f"zero-traffic blocks: {(~carries).sum()} ({(~carries).mean()*100:.1f}%)")
    neg = y_true == 0
    print(f"share of NEGATIVE class that is zero-traffic: "
          f"{(neg & ~carries).sum()/max(neg.sum(),1)*100:.1f}%\n")

    hdr = (f"{'variant':<22}{'MCC':>8}{'DR':>9}{'FPR':>9}   |"
           f"{'MCC':>8}{'DR':>9}{'FPR':>9}{'dropped':>9}")
    print(f"{'':<22}{'--- all windows ---':^26}   |{'--- traffic-carrying only ---':^35}")
    print(hdr); print("-" * len(hdr))
    out = {}
    for av in want:
        m = meta[:, 1] == av
        if m.sum() == 0:
            continue
        a = compute_clf_metrics(y_true[m], y_pred[m])
        mm = m & carries
        b = compute_clf_metrics(y_true[mm], y_pred[mm])
        drop = 100 * (1 - mm.sum() / m.sum())
        print(f"{ATTACK_NAMES.get(av, f'A{av}'):<22}"
              f"{a['M1_MCC']:>8.4f}{a['M2_DR']*100:>8.2f}%{a['M3_FPR']*100:>8.2f}%   |"
              f"{b['M1_MCC']:>8.4f}{b['M2_DR']*100:>8.2f}%{b['M3_FPR']*100:>8.2f}%{drop:>8.1f}%")
        out[ATTACK_NAMES.get(av, f"A{av}")] = {"all_windows": a,
                                               "traffic_carrying": b,
                                               "pct_windows_dropped": round(drop, 2)}
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
