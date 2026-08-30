"""
calibrate_hf_theta_pervariant.py — per-variant, per-RSU HF threshold (2026-08-30).

Supervisor's construction, replacing the single pooled theta_hf:

  1. Compute mu and sigma SEPARATELY per variant per RSU. Never pool A5-A8
     quiet windows together before fitting -- pooling averages A6's real noise
     floor away, which is what produced its 78% FPR (A6 median score 1.452 vs
     a pooled threshold of 0.790).
  2. theta_v,k = mu_v,k + Z_ALPHA * sigma_v,k
  3. theta_HF^(k) = max over v in {5,6,7,8} of theta_v,k

Variant-AWARE in construction, variant-BLIND in application: no attack label
ever reaches the detector at inference. Each RSU gets ONE number; taking the max
just means the worst-behaved variant's noise floor is properly represented at
that RSU instead of averaged away.

Quiet windows are defined by the LATCHED label (--latched, default on), because
the label switch and the recalibration must land together: scoring a new ground
truth against a stale calibration is the artefact class this whole exercise has
been chasing.

Reports, per the supervisor's ask:
  - which variant BINDS the max at each RSU (not assumed to always be A6)
  - FPR/DR/MCC for all four variants under the single combined threshold
    (this is what the deployed system achieves)
  - per-variant thresholds as a separate, clearly-labelled diagnostic table
    (this is the LSTM's ceiling per attack type -- never the deployed number)
"""
import sys, os, csv, json, argparse, math
from pathlib import Path
import numpy as np, torch

SRC = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))
from evaluator import load_global_model, PRE, RESULTS
from fed_aggregator import Z_ALPHA
from preprocessor import WINDOW

HF = [5, 6, 7, 8]
TRAIN = RESULTS / "lstm_training"
MIN_CELL = 10          # below this a (variant,RSU) cell cannot be fitted


def scores_for(model, split):
    X = np.load(PRE / f"{split}_X.npy")
    out = []
    with torch.no_grad():
        for i in range(0, len(X), 512):
            out.append(model.anomaly_score(torch.from_numpy(X[i:i+512]).float()).cpu().numpy())
    return np.concatenate(out), np.load(PRE / f"{split}_meta.npy"), np.load(PRE / f"{split}_y_indep.npy")


def latched(meta, y_indep):
    """Latched HF label, derived offline from hf_send_gt (no re-run needed)."""
    cache, out = {}, y_indep.copy()
    for i in np.where(np.isin(meta[:, 1], HF))[0]:
        rsu, av, pct, seed, c0 = (int(x) for x in meta[i])
        k = (rsu, av, pct, seed)
        d = cache.get(k)
        if d is None:
            p = TRAIN / f"RSU_{rsu}" / f"Attack{av}_{pct}_seed{seed}.csv"
            d = {}
            if p.exists():
                with open(p) as fh:
                    for x in csv.DictReader(fh):
                        d[int(float(x["cycle"]))] = float(x["hf_send_gt"])
            cache[k] = d
        out[i] = 1 if any(v > 0 for c, v in d.items() if c <= c0 + WINDOW - 1) else 0
    return out


def cm(yt, yp):
    tp = int(((yt == 1) & (yp == 1)).sum()); fp = int(((yt == 0) & (yp == 1)).sum())
    fn = int(((yt == 1) & (yp == 0)).sum()); tn = int(((yt == 0) & (yp == 0)).sum())
    den = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)) or 1
    return (tp/max(tp+fn,1)*100, fp/max(fp+tn,1)*100, (tp*tn-fp*fn)/den, tp, fp, fn, tn)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--latched", type=int, default=1)
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    model, per_rsu_theta, global_theta = load_global_model()
    sv, mv, yiv = scores_for(model, "val")
    st, mt, yit = scores_for(model, "test")
    if a.latched:
        yv, yt = latched(mv, yiv), latched(mt, yit)
        print(f"label: LATCHED   (val pos {yv[np.isin(mv[:,1],HF)].mean()*100:.1f}%, "
              f"test pos {yt[np.isin(mt[:,1],HF)].mean()*100:.1f}%)")
    else:
        yv, yt = yiv, yit
        print("label: per-event y_indep")

    rsus = sorted({int(r) for r in mv[:, 0]})
    theta_vk, thin = {}, []
    for v in HF:
        for k in rsus:
            q = (mv[:, 1] == v) & (mv[:, 0] == k) & (yv == 0)
            n = int(q.sum())
            if n < MIN_CELL:
                thin.append((v, k, n)); continue
            e = sv[q]
            theta_vk[(v, k)] = float(e.mean() + Z_ALPHA * e.std())

    print(f"\nper-(variant,RSU) cells fitted: {len(theta_vk)} / {len(HF)*len(rsus)}"
          f"   too thin (<{MIN_CELL} quiet windows): {len(thin)}")

    # theta_HF^(k) = max over variants; record which variant binds
    theta_k, binder = {}, {}
    for k in rsus:
        cand = {v: theta_vk[(v, k)] for v in HF if (v, k) in theta_vk}
        if not cand:
            theta_k[k] = per_rsu_theta.get(k, global_theta); binder[k] = None; continue
        v = max(cand, key=cand.get); theta_k[k] = cand[v]; binder[k] = v

    from collections import Counter
    bc = Counter(binder.values())
    print("\nWHICH VARIANT BINDS theta_HF^(k):")
    for v, c in sorted(bc.items(), key=lambda x: -x[1]):
        lbl = f"A{v}" if v is not None else "fallback (no cell)"
        print(f"    {lbl:<20} binds at {c:2d}/{len(rsus)} RSUs")

    th_t = np.array([theta_k.get(int(r), global_theta) for r in mt[:, 0]])
    print("\n=== DEPLOYED: single combined threshold theta_HF^(k), variant-blind ===")
    print(f"{'variant':<8}{'DR':>9}{'FPR':>9}{'MCC':>9}{'TP':>8}{'FP':>8}{'FN':>8}{'TN':>8}")
    res = {}
    for v in HF:
        m = mt[:, 1] == v
        r = cm(yt[m].astype(int), (st[m] > th_t[m]).astype(int))
        print(f"A{v:<7}{r[0]:>8.1f}%{r[1]:>8.1f}%{r[2]:>9.3f}{r[3]:>8d}{r[4]:>8d}{r[5]:>8d}{r[6]:>8d}")
        res[f"A{v}"] = {"DR": round(r[0],2), "FPR": round(r[1],2), "MCC": round(r[2],4)}

    print("\n=== DIAGNOSTIC ONLY: each variant under its OWN threshold ===")
    print("    (the LSTM's ceiling per attack type -- NOT what the deployed system achieves)")
    print(f"{'variant':<8}{'DR':>9}{'FPR':>9}{'MCC':>9}")
    diag = {}
    for v in HF:
        m = mt[:, 1] == v
        tv = np.array([theta_vk.get((v, int(r)), theta_k.get(int(r), global_theta)) for r in mt[m][:, 0]])
        r = cm(yt[m].astype(int), (st[m] > tv).astype(int))
        print(f"A{v:<7}{r[0]:>8.1f}%{r[1]:>8.1f}%{r[2]:>9.3f}")
        diag[f"A{v}"] = {"DR": round(r[0],2), "FPR": round(r[1],2), "MCC": round(r[2],4)}

    if a.json:
        json.dump({"z_alpha": Z_ALPHA, "latched": bool(a.latched),
                   "theta_per_rsu": {str(k): theta_k[k] for k in theta_k},
                   "binding_variant": {str(k): binder[k] for k in binder},
                   "deployed": res, "diagnostic_per_variant": diag},
                  open(a.json, "w"), indent=2)
        print(f"\nwrote {a.json}")


if __name__ == "__main__":
    main()
