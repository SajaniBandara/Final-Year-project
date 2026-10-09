#!/usr/bin/env python3
"""rematch_analysis.py -- with the LSTM ON: LRAD's full benign false-alarm rate per RSU node-cycle (seeds 2, 3, after the 45 s warm-up), then the
TAP margin and SFTO theta that give the same rate (supervisor 2026-10-09). The target excludes the baselines' own alarm sources and the witness bit."""
import glob, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import event_scorer as es
RES = Path.home() / "ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
NV, NR, T, W = 200, 64, 180, int(es.WARMUP_S)
BASE_BITS = (1 << 14) | (1 << 15) | (1 << 16)
def load(tag):
    p = glob.glob(str(RES / f"events_Attack*_{tag}.csv")); return es.parse(p[0]) if p else None
def main():
    lrad = [load(f"rm_lrad_s{s}") for s in (2, 3)]; tap = [load(f"rm_tap_s{s}") for s in (2, 3)]
    if not all(lrad) or not all(tap): print("runs missing"); return 1
    ncy = NR * (T - W) * 2
    def lrad_rate(bits_mask):
        n = 0
        for ev in lrad:
            a = {(nd, c) for nd, l in ev["alm"].items() for (c, w, m) in l if c >= W and (m & bits_mask)}
            n += len(a)
        return n / ncy
    allm = 0xFFFFFFFF & ~es.WITNESS_BITS & ~BASE_BITS
    out = dict(cfg=lrad[0]["cfg"], LRAD_full_FPR_per_nodecycle=lrad_rate(allm), by_source={})
    names = es.FLAG_NAMES
    for b, nm in enumerate(names):
        if (1 << b) & allm:
            r = lrad_rate(1 << b)
            if r: out["by_source"][nm] = r
    target = out["LRAD_full_FPR_per_nodecycle"]
    rows = []
    for e in range(-320, 41):
        m = 10 ** (e / 40.0)
        nc = sum(1 for ev in tap for (c, n), u in ev["uv"].items() if c >= W and NV <= n < NV + NR and u[2] > m)
        rows.append((m, nc / ncy))
    mb = min(rows, key=lambda r: abs(r[1] - target)); out["TAP"] = dict(margin_s=mb[0], FPR=mb[1], FPR_at_current_5_623ms=min(rows, key=lambda r: abs(r[0] - 5.623e-3))[1])
    rows = []
    for i in range(1, 100):
        th = round(0.01 * i, 3)
        nc = sum(1 for ev in lrad for (c, n), u in ev["uv"].items() if c >= W and NV <= n < NV + NR and u[1] >= th)
        rows.append((th, nc / ncy))
    tb = min(rows, key=lambda r: abs(r[1] - target)); out["SFTO"] = dict(theta=tb[0], FPR=tb[1], FPR_at_current_0_59=next(r for r in rows if abs(r[0] - 0.59) < 1e-9)[1], max_achievable=max(r[1] for r in rows))
    out["quarantines_benign_lrad"] = [len({n for n in ev["qua"] if n < NV + NR}) for ev in lrad]
    Path(__file__).resolve().parent.parent.joinpath("docs/calibration/rematch_lstm_on.json").write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps(out, indent=1, default=str)); return 0
if __name__ == "__main__": raise SystemExit(main())
