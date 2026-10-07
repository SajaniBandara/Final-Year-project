#!/usr/bin/env python3
"""AB5 figure from lstm_pipeline/poison_sweep_results.json (50x scale attack): M8 poisoning
impact (primary), poisoned RSUs rejected by each method, and MCC as a reference."""
import json, os
from pathlib import Path
os.environ.setdefault("MPLCONFIGDIR", "/tmp/mplcfg")
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
REPO = Path(__file__).resolve().parent.parent
d = json.load(open(REPO / "lstm_pipeline/poison_sweep_results.json"))
rhos = [0.0, 0.1, 0.2, 0.3, 0.4]
def rejected(m, r):
    e = d[m][f"rho_{r}"]; return len(set(e["poisoned_rsus"]) - set(e["accepted_rsus"])), len(e["poisoned_rsus"])
plt.rcParams.update({"font.size": 9, "axes.grid": True, "grid.alpha": 0.3})
B, F = "#1f77b4", "#d62728"
fig, ax = plt.subplots(1, 3, figsize=(11, 3.3))
for m, c, lab in (("brfa", B, "BRFA-v2"), ("fedavg", F, "naive FedAvg")):
    ax[0].plot(rhos, [d[m][f"rho_{r}"]["delta_poison"] for r in rhos], "o-", color=c, label=lab)
    ax[1].plot(rhos, [rejected(m, r)[0] for r in rhos], "o-", color=c, label=lab)
    ax[2].plot(rhos, [d[m][f"rho_{r}"]["MCC"] for r in rhos], "o-", color=c, label=lab)
ax[1].plot(rhos, [rejected("brfa", r)[1] for r in rhos], "k--", lw=1, label="poisoned RSUs present")
for a in ax: a.axvline(1/3, color="gray", ls=":", lw=1); a.set_xlabel("poisoned RSU fraction")
ax[0].set(ylabel="M8 poisoning impact (MCC loss vs clean)", title="(a) Poisoning impact")
ax[1].set(ylabel="poisoned RSUs rejected (count)", title="(b) Poisoned updates rejected")
ax[2].set(ylabel="M1 global model MCC (reference)", title="(c) Detection (reference)")
for a in ax: a.legend(fontsize=7)
fig.tight_layout(); fig.savefig(REPO / "docs/phantom_exp23/ab5_poison.png", dpi=170)
for r in rhos: print(r, "BRFA rejected/poisoned", rejected("brfa", r), "FedAvg", rejected("fedavg", r))
