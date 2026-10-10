"""train_cls_event.py -- the classification head, trained on the EVENT / STATE labels (supervisor 2026-10-10, answer 4).

The paper's rule: the classification head P(attack) with a PER-RSU benign quantile threshold, alpha = 0.01, floor = 0.05:
    theta_k = max(0.05, Quantile_{1-alpha}( P(attack) over the benign validation windows of RSU k )).
The encoder (the federated autoencoder, models/global.pt) is FROZEN, so the reconstruction path and its bar are untouched; only fc_cls is trained,
with weighted BCE on the training-seed windows (seeds 6, 7, 8: benign + A1..A8 at p in {20,40,60}) labelled by the preprocessor's y_indep, i.e. the
simulator's ev_label (action label for A1/A2/A5-A8, state label for A3/A4). Validation seeds are 2 and 3; test seed is 1; seed 1 never decides.
Then HEAD vs BAR on pooled MCC over the validation seeds:
  head  : P(attack) >= theta_k
  bar   : reconstruction error > LSTM_HC_THETA (the high-confidence tier, 386.744)
  recon : reconstruction error > the per-RSU theta of fed_summary.json (the autoencoder's ordinary rule)
Outputs: cls_theta.json (per_rsu_threshold), cls_event_results.json, models/global.pt gets the trained head (the old one is kept as global_recon_only.pt).
"""
import json, math, os, sys
import numpy as np, torch, torch.nn as nn
from pathlib import Path
sys.path.insert(0, os.getcwd())
from lstm_model import LSTMAutoencoder, N_FEATURES, seed_everything

REPO = Path(__file__).resolve().parents[2]; PRE = REPO / "lstm_pipeline" / "preprocessed"; MODELS = REPO / "lstm_pipeline" / "models"
DEV = "cuda" if torch.cuda.is_available() else "cpu"
ALPHA, FLOOR, HC_BAR = 0.01, 0.05, float(json.load(open(REPO / "lstm_pipeline" / "hc_theta.json"))["theta_hc"])
seed_everything(int(os.environ.get("MOBIGUARD_TRAIN_SEED", "1")))

def mcc(tp, fp, fn, tn):
    d = math.sqrt(float(tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return 0.0 if d == 0 else (tp * tn - fp * fn) / d
def counts(y, p):
    return int(((y == 1) & (p == 1)).sum()), int(((y == 0) & (p == 1)).sum()), int(((y == 1) & (p == 0)).sum()), int(((y == 0) & (p == 0)).sum())

ck = torch.load(MODELS / "global.pt", map_location=DEV, weights_only=False)
model = LSTMAutoencoder(n_features=N_FEATURES).to(DEV); model.load_state_dict(ck["weights"]); model.eval()
if not (MODELS / "global_recon_only.pt").exists(): torch.save(ck, MODELS / "global_recon_only.pt")
fed = json.load(open(REPO / "lstm_pipeline" / "fed_summary.json")); gth = fed.get("global_theta", 0.0)
per = {int(k): v["theta"] for k, v in fed.get("per_rsu", {}).items() if isinstance(v, dict) and "theta" in v}

D = {s: dict(X=np.load(PRE / f"{s}_X.npy"), y=np.load(PRE / f"{s}_y_indep.npy").astype(np.float32), m=np.load(PRE / f"{s}_meta.npy")) for s in ("train", "val", "test")}
tr = D["train"]; ntr, pos = len(tr["y"]), float(tr["y"].mean())
print(f"train windows {ntr}, positive rate {pos:.3f}  (attack windows must be present: run the seed 6-8 attack collection first)")
if pos == 0.0: raise SystemExit("no positive training windows: collect A1-A8 on seeds 6-8 and run preprocessor.py")
for p in model.parameters(): p.requires_grad = False
for p in model.fc_cls.parameters(): p.requires_grad = True
opt = torch.optim.Adam(model.fc_cls.parameters(), lr=1e-3); lf = nn.BCELoss(reduction="none")
w = torch.tensor([(1 - pos) / max(pos, 1e-6)], device=DEV)
Xtr = torch.from_numpy(tr["X"]).float(); ytr = torch.from_numpy(tr["y"]).float().to(DEV)
with torch.no_grad():
    Ztr = torch.cat([model.encode(Xtr[i:i + 2048].to(DEV)) for i in range(0, ntr, 2048)])
for ep in range(1, 41):
    perm = torch.randperm(ntr, device=DEV); tot = 0.0; model.fc_cls.train()
    for i in range(0, ntr, 512):
        b = perm[i:i + 512]; opt.zero_grad()
        p = model.fc_cls(Ztr[b]).squeeze(-1).clamp(1e-7, 1 - 1e-7)
        wt = torch.where(ytr[b] > 0.5, w, torch.ones_like(w))
        l = (lf(p, ytr[b]) * wt).mean(); l.backward(); opt.step(); tot += l.item() * len(b)
    if ep % 10 == 0: print(f"  epoch {ep}/40 loss {tot / ntr:.5f}")
model.eval()
def score(s):
    X = torch.from_numpy(D[s]["X"]).float(); P, R = [], []
    with torch.no_grad():
        for i in range(0, len(X), 2048):
            xb = X[i:i + 2048].to(DEV); P.append(model.fc_cls(model.encode(xb)).squeeze(-1).cpu().numpy()); R.append(model.anomaly_score(xb).cpu().numpy())
    return np.concatenate(P), np.concatenate(R)
S = {s: score(s) for s in D}
rv = D["val"]["m"][:, 0].astype(int); yv = D["val"]["y"].astype(int); Pv, Rv = S["val"]
theta = {}
for r in range(64):
    m = (rv == r) & (yv == 0)
    q = float(np.quantile(Pv[m], 1.0 - ALPHA)) if m.sum() >= 20 else FLOOR
    theta[r] = max(FLOOR, q)
json.dump(dict(per_rsu_threshold={str(k): v for k, v in theta.items()}, alpha=ALPHA, floor=FLOOR,
               rule="theta_k = max(floor, quantile_{1-alpha}(P(attack) over benign validation windows of RSU k)); validation seeds 2,3; label = ev_label",
               generated="train_cls_event.py"), open(REPO / "lstm_pipeline" / "cls_theta.json", "w"), indent=1)
def decide(s, kind):
    m = D[s]["m"]; r = m[:, 0].astype(int); P, R = S[s]
    if kind == "head": return (P >= np.array([theta[x] for x in r])).astype(int)
    if kind == "bar": return (R > HC_BAR).astype(int)
    return (R > np.array([per.get(x, gth) for x in r])).astype(int)
res = {}
for s in ("val", "test"):
    y = D[s]["y"].astype(int); av = D[s]["m"][:, 1].astype(int); res[s] = {}
    for kind in ("head", "bar", "recon"):
        p = decide(s, kind); out = {}
        for name, sel in (("pooled_A1A2A5-8+benign", np.isin(av, [0, 1, 2, 5, 6, 7, 8])), ("pooled_all8+benign", np.ones(len(av), bool))):
            tp, fp, fn, tn = counts(y[sel], p[sel]); out[name] = dict(MCC=mcc(tp, fp, fn, tn), DR=tp / max(1, tp + fn), FPR=fp / max(1, fp + tn))
        for a in range(1, 9):
            sel = np.isin(av, [0, a]); tp, fp, fn, tn = counts(y[sel], p[sel]); out[f"A{a}"] = dict(MCC=mcc(tp, fp, fn, tn), DR=tp / max(1, tp + fn), FPR=fp / max(1, fp + tn))
        res[s][kind] = out
best = max(("head", "bar"), key=lambda k: res["val"][k]["pooled_A1A2A5-8+benign"]["MCC"])
res["choice"] = dict(rule="better pooled MCC (A1,A2,A5-A8 + benign) on validation seeds 2,3", chosen=best, hc_bar=HC_BAR, alpha=ALPHA, floor=FLOOR)
json.dump(res, open(REPO / "lstm_pipeline" / "cls_event_results.json", "w"), indent=1)
ck["weights"] = model.state_dict(); torch.save(ck, MODELS / "global.pt")
for s in ("val", "test"):
    print(f"--- {s}")
    for kind in ("head", "bar", "recon"):
        o = res[s][kind]["pooled_A1A2A5-8+benign"]; print(f"  {kind:5s} pooled MCC {o['MCC']:.3f}  DR {o['DR']:.3f}  FPR {o['FPR']:.4f}")
print("chosen:", best)
