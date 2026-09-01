"""
train_cls_head.py -- Supervisor Fix 2 (2026-08-20): train the classification
head (fc_cls) with the LSTM encoder frozen.

Encoder weights are frozen, so every window's latent is CONSTANT across
epochs -- we encode the split once up front and then train the small MLP head
on cached latents. Identical maths to running the encoder every batch, ~2
orders of magnitude faster.

--labels selects the training target:
  supervisor : A5-A8 <- (r_anom > 0), A1/A2 <- (delta_t_exceeded)
               EXACTLY as specified in the 2026-08-20 message. Both of these
               are themselves INPUT FEATURES (index 9 and 10), so the head can
               satisfy them by echoing one input -- measured agreement between
               label and a one-line rule on that same feature is 100.00%
               (MCC 1.0000). Kept selectable so the inflation is measurable
               rather than argued about.
  indep      : A5-A8 <- hf_send_gt window label (y_indep, produced by
               preprocessor.py). hf_send_gt is a send-side attack-injection
               counter deliberately excluded from FEATURES for this exact
               reason. A1/A2 keep the delay-exceedance target (no independent
               alternative exists in the collected data) -- the reported
               trivial-rule baseline shows what it is worth on its own.
"""
import argparse, json
import numpy as np, torch, torch.nn as nn
from pathlib import Path
from lstm_model import LSTMAutoencoder, N_FEATURES

REPO = Path(__file__).resolve().parents[2]
PRE  = REPO / "lstm_pipeline" / "preprocessed"
MODELS = REPO / "lstm_pipeline" / "models"
DEV = "cuda" if torch.cuda.is_available() else "cpu"
HF = [5, 6, 7, 8]; TIMING = [1, 2]
R_ANOM_IDX, DT_EXC_IDX = 9, 10


def build_labels(X, meta, y_indep, mode, timing_labels="indep"):
    av = meta[:, 1].astype(int)
    y = np.zeros(len(X), dtype=np.int8)
    hf_m, tm_m = np.isin(av, HF), np.isin(av, TIMING)
    if mode == "supervisor":
        y[hf_m] = (X[hf_m][:, :, R_ANOM_IDX] > 0).any(axis=1)
    else:
        y[hf_m] = y_indep[hf_m]
    # A1/A2 target. The delta_t_exceeded form is a LABEL LEAK: DT_EXC_IDX is
    # FEATURES index 10, an input the head can read, so it can satisfy the
    # label by echoing one column -- the same defect this file already
    # documents for --labels supervisor on r_anom.
    #
    # The docstring's justification ("no independent alternative exists in the
    # collected data") was true when written on 2026-08-20 and became FALSE on
    # 2026-08-27: std_send_gt, A1/A2's send-side injection counter, is now
    # collected and is deliberately excluded from FEATURES. preprocessor.py
    # folds it into y_indep (make_windows, `_inj = max(_hf, stdgt, tcamgt)`),
    # so y_indep now carries a leak-free A1/A2 label, not just an HF one.
    # Verified 2026-08-31: std_send_gt present on all 3840 A1/A2 files.
    #
    # Default is the leak-free form. The legacy form stays selectable so the
    # inflation stays measurable rather than argued about.
    if timing_labels == "dt_exceeded":
        y[tm_m] = (X[tm_m][:, :, DT_EXC_IDX] > 0).any(axis=1)
    else:
        y[tm_m] = y_indep[tm_m]
    return y


def latents(model, X, bs=1024):
    out = []
    model.eval()
    with torch.no_grad():
        for i in range(0, len(X), bs):
            xb = torch.from_numpy(X[i:i+bs]).float().to(DEV)
            out.append(model.encode(xb).cpu())
    return torch.cat(out)


def metrics(yt, yp):
    tp=int(((yt==1)&(yp==1)).sum()); fp=int(((yt==0)&(yp==1)).sum())
    fn=int(((yt==1)&(yp==0)).sum()); tn=int(((yt==0)&(yp==0)).sum())
    d=np.sqrt(float(tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    return dict(TP=tp,FP=fp,FN=fn,TN=tn,
                MCC=0.0 if d==0 else (tp*tn-fp*fn)/d,
                DR=tp/(tp+fn) if tp+fn else float('nan'),
                FPR=fp/(fp+tn) if fp+tn else float('nan'))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", choices=["supervisor","indep"], default="indep")
    # A1/A2 target form. "indep" uses std_send_gt via y_indep (leak-free,
    # available since 2026-08-27); "dt_exceeded" is the legacy form that reads
    # FEATURES index 10 and is therefore a label leak -- kept only so the
    # inflation can be measured. See build_labels().
    ap.add_argument("--timing-labels", choices=["indep","dt_exceeded"],
                    default="indep")
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--fpr-target", type=float, default=0.01)
    # Deviates from the 2026-08-20 spec ("Do not touch the encoder") on
    # purpose: with the encoder frozen the head is capped well below a
    # one-line threshold rule on the raw feature, so this measures
    # whether the reconstruction-trained latent is the binding
    # constraint rather than the head's capacity.
    ap.add_argument("--unfreeze", action="store_true")
    a = ap.parse_args()

    ck = torch.load(MODELS/"global.pt", map_location=DEV, weights_only=False)
    model = LSTMAutoencoder(n_features=N_FEATURES).to(DEV)
    model.load_state_dict(ck["weights"])
    for n_, p_ in model.named_parameters():
        p_.requires_grad = n_.startswith("fc_cls") or a.unfreeze
    print(f"[{a.labels}] trainable: {[n for n,p in model.named_parameters() if p.requires_grad]}")

    d = {}
    for sp in ("train","val","test"):
        d[sp] = (np.load(PRE/f"{sp}_X.npy"), np.load(PRE/f"{sp}_meta.npy"),
                 np.load(PRE/f"{sp}_y_indep.npy"))
    y = {sp: build_labels(*d[sp], a.labels, a.timing_labels) for sp in d}
    print(f"positive fraction: " + "  ".join(f"{s}={y[s].mean():.3f}" for s in y))

    if not a.unfreeze:
        print("encoding (frozen encoder -> latents cached once) …")
        Z = {sp: latents(model, d[sp][0]) for sp in d}

    pos = float(y["train"].mean())
    w = torch.tensor([1.0/max(pos,1e-6)], device=DEV)  # class-weighted BCE
    lossf = nn.BCELoss(reduction="none")
    opt = torch.optim.Adam(model.fc_cls.parameters(), lr=1e-3)
    ytr = torch.from_numpy(y["train"]).float().to(DEV)
    if a.unfreeze:
        Xtr = torch.from_numpy(d["train"][0]).float()
        opt = torch.optim.Adam([p for p in model.parameters() if p.requires_grad], lr=1e-3)
        n = len(Xtr); bs = 512
    else:
        Ztr = Z["train"].to(DEV); n = len(Ztr); bs = 512
    for ep in range(1, a.epochs+1):
        model.train() if a.unfreeze else model.fc_cls.train(); perm = torch.randperm(n, device=DEV); tot=0.0
        for i in range(0, n, bs):
            b = perm[i:i+bs]
            opt.zero_grad()
            if a.unfreeze:
                p = model.fc_cls(model.encode(Xtr[b.cpu()].to(DEV))).squeeze(-1).clamp(1e-7, 1-1e-7)
            else:
                p = model.fc_cls(Ztr[b]).squeeze(-1).clamp(1e-7, 1-1e-7)
            wt = torch.where(ytr[b] > 0.5, w, torch.ones_like(w))
            loss = (lossf(p, ytr[b]) * wt).mean()
            loss.backward(); opt.step(); tot += loss.item()*len(b)
        if ep % 5 == 0 or ep == 1:
            print(f"  epoch {ep:2d}/{a.epochs}  loss={tot/n:.5f}")

    model.eval()
    if a.unfreeze:
        Z = {sp: latents(model, d[sp][0]) for sp in d}
    P = {}
    with torch.no_grad():
        for sp in d:
            P[sp] = model.fc_cls(Z[sp].to(DEV)).squeeze(-1).cpu().numpy()

    # per-RSU threshold: highest DR subject to FPR <= target, swept on VAL
    rsu_v, rsu_t = d["val"][1][:,0].astype(int), d["test"][1][:,0].astype(int)
    grid = np.linspace(0.01, 0.99, 99)
    thr = {}
    for r in np.unique(rsu_v):
        m = rsu_v == r
        yv, pv = y["val"][m], P["val"][m]
        best, bdr = 0.5, -1.0
        for t in grid:
            mm = metrics(yv, (pv > t).astype(int))
            if mm["FPR"] <= a.fpr_target and (mm["DR"] or 0) > bdr:
                bdr, best = mm["DR"], t
        thr[int(r)] = best
    gthr = float(np.median(list(thr.values())))
    tarr = np.array([thr.get(int(r), gthr) for r in rsu_t])
    yp = (P["test"] > tarr).astype(int)

    av = d["test"][1][:,1].astype(int)
    print(f"\n=== TEST, per-RSU calibrated (FPR<={a.fpr_target:.0%}), labels={a.labels} ===")
    mccs = []
    for v in [1,2,5,6,7,8]:
        m = av == v
        if not m.sum(): continue
        mm = metrics(y["test"][m], yp[m]); mccs.append(mm["MCC"])
        print(f"  A{v}: MCC={mm['MCC']:+.4f} DR={mm['DR']:.4f} FPR={mm['FPR']:.4f} "
              f"(TP={mm['TP']} FP={mm['FP']} FN={mm['FN']} TN={mm['TN']})")
    print(f"  macro-MCC (A1,A2,A5-A8) = {np.mean(mccs):.4f}")
    torch.save({"weights": model.state_dict(), "labels": a.labels,
                "per_rsu_threshold": thr},
               MODELS/f"global_clshead_{a.labels}{'_e2e' if a.unfreeze else ''}.pt")
    print(f"saved -> models/global_clshead_{a.labels}{'_e2e' if a.unfreeze else ''}.pt")


if __name__ == "__main__":
    main()
