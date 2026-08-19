"""
evaluator.py — MOBIGUARD M1–M8 metrics (§Primary Performance Metrics)

M1  MCC      Matthews Correlation Coefficient
M2  DR       Detection Rate = TPR = TP/(TP+FN)
M3  FPR      False Positive Rate = FP/(FP+TN)
M4  L_mit    Mitigation latency — from simulation CSV avg_mit column
M5  PDR      Packet Delivery Ratio — from simulation CSV avg_PDR column
M6  L_e2e    End-to-End Latency — from simulation CSV avg_lat column
M7  TVR      Threshold Violation Rate — from simulation CSV avg_TVR% column
M8  UCR      Unauthorized Copy Rate — from simulation CSV avg_UCR% column

LSTM-based metrics (M1–M3) use the federated global model to predict on
the test split; rule-based metrics (M4–M8) are read from MOBIGUARD result CSVs.
"""

import os, json, argparse
import numpy as np
import torch
import pandas as pd
from pathlib import Path
from sklearn.metrics import matthews_corrcoef, confusion_matrix

from lstm_model import LSTMAutoencoder, N_FEATURES
from preprocessor import WINDOW
from fed_aggregator import Z_ALPHA

REPO      = Path(__file__).resolve().parents[2]
PRE       = REPO / "lstm_pipeline" / "preprocessed"
MODEL_DIR = REPO / "lstm_pipeline" / "models"
RESULTS   = Path(os.environ.get("HOME", "/home/nipuni")) / \
            "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
DEVICE    = "cuda" if torch.cuda.is_available() else "cpu"

# 5-8 match main.tex's own attack titles: Attack 5 "Active Hidden Forward
# Attack: Control Plane", Attack 6 "...: Data Plane", Attack 7 "Passive
# Hidden Forward Attack: Control Plane", Attack 8 "...: Data Plane"
# (main.tex sec:Overview of the four Hidden Forwarding Attacks, S5-S8).
ATTACK_NAMES = {
    0: "Benign",
    1: "A1 CP-SelectiveDelay",
    2: "A2 DP-SelectiveDelay",
    3: "A3 CP-TCAM",
    4: "A4 DP-TCAM",
    5: "A5 CP-ActiveHF",
    6: "A6 DP-ActiveHF",
    7: "A7 CP-PassiveHF",
    8: "A8 DP-PassiveHF",
}


# ── LSTM-based prediction ─────────────────────────────────────────────────────

def load_global_model() -> tuple:
    # weights_only=False: PyTorch >=2.6 safe loader rejects numpy scalars in
    # our own checkpoints.
    ckpt = torch.load(MODEL_DIR / "global.pt", map_location=DEVICE,
                      weights_only=False)
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEVICE)
    model.load_state_dict(ckpt["weights"])
    model.eval()
    with open(REPO / "lstm_pipeline" / "fed_summary.json") as fh:
        fed = json.load(fh)
    # eq:lstm_threshold/eq:lstm_detection: theta^(k) is explicitly PER-RSU
    # ("ensuring that each RSU applies a locally calibrated decision
    # boundary rather than a global threshold that would fail to account
    # for RSU-specific traffic distributions" — main.tex's own words).
    # This function used to return only the single scalar global_theta
    # (the mean across all 64 per-RSU thetas) and predict_test() applied
    # THAT ONE VALUE to every RSU's test windows — silently ignoring the
    # per-RSU calibration entirely. With per-RSU thetas ranging from ~0.7
    # to ~2200 (found 2026-07-18), that mean is dominated by whichever
    # RSUs happen to have inflated individual thetas, making the effective
    # cutoff far too conservative for every other RSU. Now returns the
    # full per-RSU dict; global_theta is kept only as the fallback for an
    # RSU id absent from fed_summary.json (e.g. skipped for <MIN_BENIGN
    # windows during training).
    per_rsu_theta = {int(k): float(v["theta"]) for k, v in fed["per_rsu"].items()}
    return model, per_rsu_theta, float(fed["global_theta"])


HF_THETA_PATH = REPO / "lstm_pipeline" / "hf_theta.json"


def load_hf_theta() -> dict | None:
    """Variant-aware theta for A5-A8 (2026-08-20, calibrate_hf_theta.py).

    The standard per-RSU theta is calibrated on a pool that's 94% A1-A4
    traffic -- structurally different from HF traffic, and the actual cause
    of A8's 56% FPR / A5-A7's unmeasurable FPR (not a z_alpha problem, a
    calibration-population problem; see calibrate_hf_theta.py's docstring).
    hf_theta.json holds a single shared threshold computed on pooled
    HF-context quiet windows (A5-A8 combined -- per-RSU HF sample sizes are
    too sparse, 87 windows / 64 RSUs, to calibrate individually). Returns
    None if the file doesn't exist, so callers that haven't run the
    calibration step yet fall back to standard per-RSU theta unchanged.
    """
    if not HF_THETA_PATH.exists():
        return None
    with open(HF_THETA_PATH) as fh:
        return json.load(fh)


def predict_test(model: LSTMAutoencoder, per_rsu_theta: dict, global_theta: float,
                  hf_theta: dict | None = None) -> tuple:
    X    = np.load(PRE / "test_X.npy")
    y    = np.load(PRE / "test_y.npy")
    meta = np.load(PRE / "test_meta.npy")
    bs   = 512
    scores = []
    with torch.no_grad():
        for i in range(0, len(X), bs):
            xb = torch.from_numpy(X[i:i+bs]).float().to(DEVICE)
            scores.append(model.anomaly_score(xb).cpu().numpy())
    scores = np.concatenate(scores)
    rsu_ids = meta[:, 0].astype(int)
    theta_arr = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_ids])
    if hf_theta is not None:
        # Only overrides rows belonging to the variants hf_theta.json was
        # calibrated for (A5-A8) -- A1-A4 keep their standard per-RSU theta
        # untouched, same scoping validated in test_stratified_theta_a8.py.
        av_ids = meta[:, 1].astype(int)
        hf_mask = np.isin(av_ids, hf_theta["applies_to_variants"])
        theta_arr = np.where(hf_mask, hf_theta["theta_hf"], theta_arr)
    y_pred = (scores > theta_arr).astype(np.int8)
    return y, y_pred, scores, meta


# ── Online threshold warm-up adaptation (Eq.~theta_adapt, A2 diagnostic) ────────

WARMUP_CYCLES = 30       # matches Eq.~theta_adapt's 30s warm-up window
MIN_WARMUP_WINDOWS = 2   # skip adaptation if too few benign warm-up samples


def compute_adaptive_theta(scores: np.ndarray, meta: np.ndarray, y_true: np.ndarray,
                            per_rsu_theta: dict, global_theta: float,
                            hf_theta: dict | None = None) -> tuple:
    """
    Q2/A2 diagnostic (2026-07-31): seed-to-seed mobility variance at
    interior RSUs means theta calibrated on training seeds underestimates
    the benign tail on a fresh test seed. Each (rsu, attack_v, pct, seed)
    run uses its OWN first-30s benign-labeled (y_true==0) windows to adapt
    theta online: theta_adapted = max(base_theta, mu_warmup + Z_ALPHA *
    sigma_warmup). Only ever WIDENS the threshold relative to the
    training-seed baseline (never narrows it, so a thin/noisy warm-up
    sample can't make things worse) -- an approximation of main.tex's
    Eq.~theta_adapt (pct99(A_benign U A_warmup)); we don't have the raw
    A_benign calibration population saved (only mu/sigma/theta in
    fed_summary.json), so this reuses the same Gaussian formula as the
    rest of the pipeline instead of a raw percentile.

    Verified on the test split (a2_warmup_adaptation_eval.py, 2026-07-31):
    A2 FPR 1.6%->1.0% (real reduction) for a 1.8pt DR cost (86.7%->84.9%) --
    a much better trade than the interior-RSU z-widening attempt (Q27-narrow,
    reverted: 8-12pt DR cost for a smaller FPR gain). A1 also improved
    slightly; A5-A8 (no seed-variance problem) essentially unchanged.

    Returns (theta_arr, keep_mask) -- keep_mask excludes warm-up windows
    themselves from evaluation (they calibrate, they aren't scored).
    """
    rsu_ids, av_ids, pct_ids, seed_ids, start_cycle = (
        meta[:, 0], meta[:, 1], meta[:, 2], meta[:, 3], meta[:, 4]
    )
    is_warmup = start_cycle < WARMUP_CYCLES
    keys = np.stack([rsu_ids, av_ids, pct_ids, seed_ids], axis=1)
    _, run_idx = np.unique(keys, axis=0, return_inverse=True)
    n_runs = run_idx.max() + 1

    theta_arr = np.array([per_rsu_theta.get(r, global_theta) for r in rsu_ids], dtype=float)
    if hf_theta is not None:
        # Same scoping as predict_test(): only A5-A8 rows get the pooled
        # HF-context base theta. Applied BEFORE the warm-up loop below so
        # "base_theta" (what warm-up compares theta_w against, and only
        # overrides if it exceeds) is the correct starting point for HF
        # runs too -- otherwise this function would silently rebuild
        # theta_arr from per_rsu_theta alone and discard the HF override
        # predict_test() applied upstream.
        hf_row_mask = np.isin(av_ids, hf_theta["applies_to_variants"])
        theta_arr = np.where(hf_row_mask, hf_theta["theta_hf"], theta_arr)
    n_adapted = 0
    for run in range(n_runs):
        run_mask = run_idx == run
        warm_mask = run_mask & is_warmup & (y_true == 0)
        if warm_mask.sum() < MIN_WARMUP_WINDOWS:
            continue
        warm_scores = scores[warm_mask]
        mu_w, sig_w = float(warm_scores.mean()), float(warm_scores.std())
        theta_w = mu_w + Z_ALPHA * sig_w
        rsu_this_run = int(rsu_ids[run_mask][0])
        av_this_run = int(av_ids[run_mask][0])
        if hf_theta is not None and av_this_run in hf_theta["applies_to_variants"]:
            base_theta = hf_theta["theta_hf"]
        else:
            base_theta = per_rsu_theta.get(rsu_this_run, global_theta)
        if theta_w > base_theta:
            theta_arr[run_mask] = theta_w
            n_adapted += 1

    keep = ~is_warmup
    return theta_arr, keep, n_adapted, n_runs


# ── Window deduplication (Q19) ───────────────────────────────────────────────

def deduplicate_windows(y_true: np.ndarray, y_pred: np.ndarray,
                         meta: np.ndarray) -> tuple:
    """
    W=10/stride=5 windows overlap 50%, so a single anomalous span can be
    flagged by two consecutive windows and get double-counted as two
    independent FP/TP events in a raw per-window confusion matrix (up to
    ~2x FPR inflation). Apply non-maximum suppression: group windows by
    (rsu, attack_v, pct, seed, non-overlapping 10s block) using meta's
    start_cycle (col 4) // WINDOW, and collapse each block to a single
    true/pred label via max() -- a block counts as positive if ANY window
    inside it was flagged, matching "at most one FP per RSU per 10-second
    non-overlapping block" from the diagnostic spec.
    """
    block = meta[:, 4] // WINDOW
    keys  = np.stack([meta[:, 0], meta[:, 1], meta[:, 2], meta[:, 3], block], axis=1)
    _, group_idx = np.unique(keys, axis=0, return_inverse=True)
    n_groups = group_idx.max() + 1
    yt = np.zeros(n_groups, dtype=np.int8)
    yp = np.zeros(n_groups, dtype=np.int8)
    np.maximum.at(yt, group_idx, y_true)
    np.maximum.at(yp, group_idx, y_pred)
    # meta collapsed to one row per group (first window's meta, block-truncated
    # start_cycle) so callers can still slice by attack_v/pct/seed downstream.
    group_meta = np.zeros((n_groups, meta.shape[1]), dtype=meta.dtype)
    group_meta[group_idx] = meta
    return yt, yp, group_meta


# ── Metric computation ────────────────────────────────────────────────────────

def compute_clf_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    mcc = matthews_corrcoef(y_true, y_pred)
    dr  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {"TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn),
            "M1_MCC": round(mcc, 4),
            "M2_DR":  round(dr,  4),
            "M3_FPR": round(fpr, 4)}


def load_sim_csv(attack_v: int, pct: int) -> pd.DataFrame | None:
    """
    Load MOBIGUARD result CSV(s) for a given attack variant and percentage.

    write_security_metrics_csv() (routing.cc) names files
    MOBIGUARD_Attack<N>_<pct>[_d<D>ms][_seed<S>].csv — never
    "MOBIGUARD_V<v>_pct<p>_*" (that pattern never matched anything, so this
    sim_metrics block was silently empty on every prior run). N here is the
    attack NUMBER (1-8), same as attack_v — ATTACK_NAMES below maps them
    1:1. glob picks up every delay/seed suffix variant.

    The file's own header is 4 lines, each prefixed with "#" (see
    write_security_metrics_csv()'s header write), so there is no valid
    single-line CSV header for pandas to parse — comment="#" strips all 4
    lines and pandas then silently promotes the first DATA row to column
    names instead. Read with header=None and pull columns by fixed
    position instead (see extract_sim_metrics()).
    """
    files = sorted(RESULTS.glob(f"MOBIGUARD_Attack{attack_v}_{pct}*.csv"))
    if not files:
        return None
    dfs = [pd.read_csv(f, comment="#", header=None) for f in files]
    return pd.concat(dfs, ignore_index=True)


# Fixed column positions in write_security_metrics_csv()'s row layout
# (routing.cc) — matches scripts/plot_fade_results.py's MOB_COL_* map.
# All 5 sit before the variant-conditional TCAM block (only present for
# A3/A4/benign, appended after avg_UCR), so these positions are stable
# across every attack variant.
SIM_COL_MAP = {
    "M4_L_mit_ms": 12,   # avg_mit_ms
    "M5_PDR":       2,   # avg_PDR
    "M6_L_e2e_ms":  4,   # avg_lat_ms
    "M7_TVR_pct":  18,   # avg_TVR
    "M8_UCR_pct":  20,   # avg_UCR
}


def extract_sim_metrics(df: pd.DataFrame) -> dict:
    out = {}
    for metric, col in SIM_COL_MAP.items():
        if col < df.shape[1]:
            out[metric] = round(float(df[col].mean()), 4)
        else:
            out[metric] = None
    return out


# Rule-based-only detection columns (avg_MCC, avg_DR%, avg_FPR%) — same
# fixed-position CSV layout as SIM_COL_MAP. TCAM_RULE_BASED_VARIANTS use
# these instead of the LSTM confusion matrix (see rule_based_clf_metrics()).
RULE_COL_MAP = {"mcc": 6, "dr_pct": 8, "fpr_pct": 10}
TCAM_RULE_BASED_VARIANTS = {3, 4}
# pct=0 (zero attackers) excluded: DR/MCC are trivially 0 there (no
# positives to detect at all).
TCAM_PCTS = [20, 40, 60, 80, 100]


def rule_based_clf_metrics(attack_v: int) -> dict | None:
    """
    A3/A4 (TCAM) already have a dedicated, spec-correct rule-based detector
    (S3: blockchain endorsement / f_unauth, S4: TCAM-utilization threshold
    -- tcam_detection.h's ComputeTcamDetection(), independent of the LSTM).
    Those runs have --enable_lstm_inference=0 (verified: crypto_layer.h's
    default and run_training_attacks.py never sets it), so avg_MCC/avg_DR/
    avg_FPR in the MOBIGUARD CSVs already reflect S1-S8 rule-based
    detection ONLY, with zero LSTM contribution.

    Filename convention (routing.cc's write_security_metrics_csv(),
    verified 2026-08-09 against the current binary at line ~117801):
    "MOBIGUARD_Attack<N>_<pct>[_d<X>ms]_seed<S>.csv", opened in APPEND
    mode -- every run at a given (attack, pct, seed) accumulates into the
    SAME file across all past invocations at that exact combination. This
    superseded an older no-seed-suffix convention this function was
    originally written against (found 2026-07-30); that convention no
    longer exists on disk at all as of the 2026-08-08/09 full data
    recollection, which is why this function silently returned None for
    every call before this fix -- evaluator.py's main() masked the
    failure by falling back to the LSTM's own confusion matrix while
    still printing the "[rule-based]" tag (see the has_rule_data check in
    main() below, added in the same fix).
    Take the LAST row of EACH matching (attack, pct, seed) file (the most
    recently completed run's final converged cumulative average for that
    file) rather than a mean over the whole file, which spans multiple
    runs' distinct onset transients -- then average across all matching
    files.
    """
    last_rows = []
    for pct in TCAM_PCTS:
        for f in sorted(RESULTS.glob(f"MOBIGUARD_Attack{attack_v}_{pct}_*seed*.csv")):
            df = pd.read_csv(f, comment="#", header=None)
            if len(df) > 0:
                last_rows.append(df.iloc[-1])
    if not last_rows:
        return None
    last_df = pd.DataFrame(last_rows)
    mcc = float(last_df[RULE_COL_MAP["mcc"]].mean())
    dr  = float(last_df[RULE_COL_MAP["dr_pct"]].mean())  / 100.0
    fpr = float(last_df[RULE_COL_MAP["fpr_pct"]].mean()) / 100.0
    return {"TP": None, "TN": None, "FP": None, "FN": None,
            "M1_MCC": round(mcc, 4), "M2_DR": round(dr, 4), "M3_FPR": round(fpr, 4),
            "n_runs": len(last_rows), "source": "rule_based_S3_S4"}


# ── Main ──────────────────────────────────────────────────────────────────────

def main(args):
    print(f"Loading global federated model …")
    model, per_rsu_theta, global_theta = load_global_model()
    theta_vals = list(per_rsu_theta.values())
    print(f"  Per-RSU θ: n={len(theta_vals)} min={min(theta_vals):.4f} "
          f"median={sorted(theta_vals)[len(theta_vals)//2]:.4f} max={max(theta_vals):.4f}")
    print(f"  Global θ (fallback only) = {global_theta:.6f}")

    hf_theta = load_hf_theta()
    if hf_theta is not None:
        print(f"  HF θ (A5-A8, calibrate_hf_theta.py) = {hf_theta['theta_hf']:.6f} "
              f"(n={hf_theta['n_calibration_windows']} pooled quiet windows)")
    else:
        print("  hf_theta.json not found -- A5-A8 using standard per-RSU theta")

    print("Running inference on test split …")
    y_true, y_pred, scores, meta = predict_test(model, per_rsu_theta, global_theta, hf_theta)

    # Online threshold warm-up adaptation (A2 diagnostic, see
    # compute_adaptive_theta() docstring) -- recompute y_pred with the
    # adapted per-run theta, then drop warm-up windows from evaluation.
    theta_adapted, keep_mask, n_adapted, n_runs = compute_adaptive_theta(
        scores, meta, y_true, per_rsu_theta, global_theta, hf_theta)
    print(f"  Warm-up adaptation: {n_adapted}/{n_runs} runs raised theta "
          f"above the base per-RSU value")
    y_pred = (scores > theta_adapted).astype(np.int8)
    y_true, y_pred, scores, meta = y_true[keep_mask], y_pred[keep_mask], scores[keep_mask], meta[keep_mask]

    n_raw = len(y_true)
    y_true, y_pred, meta = deduplicate_windows(y_true, y_pred, meta)
    print(f"  Q19 dedup: {n_raw} overlapping windows -> {len(y_true)} "
          f"non-overlapping 10s blocks ({100*(1-len(y_true)/n_raw):.1f}% collapsed)")

    all_results = {}

    # Per-attack-variant breakdown
    attack_variants = sorted(set(meta[:, 1]))
    for av in attack_variants:
        mask = meta[:, 1] == av
        if mask.sum() == 0:
            continue
        lstm_clf = compute_clf_metrics(y_true[mask], y_pred[mask])

        # A3/A4 (TCAM): report the dedicated rule-based S3/S4 detector
        # instead of the LSTM's own confusion matrix -- see
        # rule_based_clf_metrics() docstring. Falls back to the LSTM clf
        # if the rule-based CSVs aren't available for some reason -- but
        # that fallback must be visible, not silent: this function used to
        # print "[rule-based]" purely based on `av in
        # TCAM_RULE_BASED_VARIANTS`, so when rule_based_clf_metrics()
        # returned None (as it silently did for every call before the
        # 2026-08-09 filename-convention fix, since the MOBIGUARD CSVs had
        # switched to a seed-suffixed naming this function didn't know
        # about) the printed A3/A4 rows were actually the LSTM's own
        # confusion matrix mislabeled as rule-based.
        has_rule_data = False
        if av in TCAM_RULE_BASED_VARIANTS:
            rule_clf = rule_based_clf_metrics(av)
            has_rule_data = rule_clf is not None
            if not has_rule_data:
                print(f"  WARNING: no rule-based S3/S4 CSVs found for "
                      f"{ATTACK_NAMES.get(av, f'A{av}')} -- falling back to "
                      f"the LSTM's own confusion matrix (NOT tagged "
                      f"[rule-based] below).")
            clf = rule_clf if has_rule_data else lstm_clf
        else:
            clf = lstm_clf

        # Rule-based metrics from simulation CSV (use any pct available)
        sim_metrics = {}
        for pct in [20, 40, 60, 80]:
            df = load_sim_csv(av, pct)
            if df is not None:
                sim_metrics[f"pct{pct}"] = extract_sim_metrics(df)

        result = {**clf, "sim_metrics": sim_metrics}
        if av in TCAM_RULE_BASED_VARIANTS:
            result["lstm_clf_reference_only"] = lstm_clf
            result["is_rule_based"] = has_rule_data
        all_results[ATTACK_NAMES.get(av, f"A{av}")] = result

        print(f"\n  {ATTACK_NAMES.get(av, f'A{av}'):30s}"
              f"  MCC={clf['M1_MCC']:+.3f}"
              f"  DR={clf['M2_DR']:.3f}"
              f"  FPR={clf['M3_FPR']:.3f}"
              f"  n={int(mask.sum())}"
              f"{'  [rule-based]' if has_rule_data else '  [LSTM fallback]' if av in TCAM_RULE_BASED_VARIANTS else ''}")

    # Overall (all LSTM-scored variants combined, excluding benign AND
    # A3/A4 -- those are reported via the rule-based detector above, not
    # the LSTM, so folding their windows into an "LSTM overall" average
    # would mix two different detectors into one number).
    attack_mask = (meta[:, 1] > 0) & (~np.isin(meta[:, 1], list(TCAM_RULE_BASED_VARIANTS))) & (y_true >= 0)
    if attack_mask.sum() > 0:
        overall = compute_clf_metrics(y_true[attack_mask], y_pred[attack_mask])
        all_results["Overall (LSTM: attacks 1,2,5-8)"] = overall
        print(f"\n  {'Overall (LSTM: attacks 1,2,5-8)':30s}"
              f"  MCC={overall['M1_MCC']:+.3f}"
              f"  DR={overall['M2_DR']:.3f}"
              f"  FPR={overall['M3_FPR']:.3f}")

    out_path = REPO / "lstm_pipeline" / "evaluation_results.json"
    with open(out_path, "w") as fh:
        json.dump(all_results, fh, indent=2)
    print(f"\nFull results → {out_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    main(ap.parse_args())
