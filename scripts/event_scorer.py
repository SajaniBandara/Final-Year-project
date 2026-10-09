#!/usr/bin/env python3
"""event_scorer.py -- event-based per-cycle scoring (supervisor 2026-10-08). Reads NO latched state.

Input : results_routing/events_<run>.csv written by scratch/event_log.h (rows cycle,node,kind,value).
Unit  : scored node = RSU (node id N_V..N_V+N_R-1) x routing cycle (1 s).
Rules (supervisor 2026-10-08, amended 2026-10-09: rule 4 DROPPED -- every node is scored in every cycle; A3/A4 use a STATE label):
  positive      node performed an attack action in the cycle that reached an honest node (kind ACT), even if
                blocked afterwards; actions aborted by quarantine enforcement are never logged.
  flagged       any detector alarm on the node. An alarm with window w raised at cycle c covers cycles
                c-w+1..c; every covered cycle in which the node attacked is a TP. If the node did not attack
                anywhere in the window, the alarm is an FP in cycle c.
  quarantine    (rule 4 dropped) every node is scored in every cycle; false quarantines are a separate count.
                `stop_after_quarantine=True` only reproduces the superseded rule for diagnostics.
  state label   A3/A4 (variants 2/3): a node is positive from its first attacker-injected TCAM entry until the last
                such entry has aged out or been removed (STATE rows); alarms inside that interval are true.
  per-cycle counts TP FP FN TN sum to the scored nodes every cycle.
Headline M1 = MCC of counts summed over cycles >= warm-up. CI from per-cycle MCC values (cycles where MCC is
undefined are skipped and counted).
"""
import argparse, csv, math, sys
from collections import defaultdict

FLAG_NAMES = ["S1","S2","S3","S4","S5","S6","S7","S8","LSTM","WIT_DA","WIT_NFA","BTMM_PKT","QUAR","R_ANOM","TAP","SFTO","FADE"]
WARMUP_S = 45.0   # one warm-up for all runs: after the last vehicle start (44 s in the N=200 trace)
WITNESS_BITS = (1 << 9) | (1 << 10)   # witness alerts are logged as alarms from their own source; excluded unless asked


def mcc(tp, fp, fn, tn):
    """nan = undefined (a class is absent: no positives or no negatives, e.g. p=0 / p=100).
    0.0 when both classes exist but the detector flags nothing or everything (standard MCC convention)."""
    if (tp + fn) == 0 or (tn + fp) == 0:
        return float("nan")
    d = (tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)
    return (tp*tn - fp*fn)/math.sqrt(d) if d > 0 else 0.0


def parse(path):
    ev = dict(act=defaultdict(int), alm=defaultdict(list), qua={}, fire=defaultdict(lambda: defaultdict(int)),
              wit=defaultdict(int), atk=set(), commit="", last_cycle=0, qua_events=defaultdict(list),
              state=defaultdict(int), dec=defaultdict(lambda: defaultdict(int)), variant=-1, uv={}, m4={}, quax={}, td={}, rev={}, ctrlc={}, cfg={})
    for line in open(path):
        line = line.strip()
        if line.startswith("# commit="):
            ev["commit"] = line.split("=", 1)[1]; continue
        if line.startswith("# cfg "):
            ev["cfg"] = dict(kv.split("=", 1) for kv in line[6:].split() if "=" in kv); continue
        if line.startswith("# variant="):
            ev["variant"] = int(line.split("=", 1)[1]); continue
        if not line or line.startswith("#") or line.startswith("cycle,"):
            continue
        c, n, kind, val = line.split(",", 3)
        c, n = int(c), int(n)
        ev["last_cycle"] = max(ev["last_cycle"], c)
        if kind == "ACT":   ev["act"][(c, n)] += int(val)
        elif kind == "ALM1":  ev["alm"][n].append((c, 1, int(val)))
        elif kind == "ALM10": ev["alm"][n].append((c, 10, int(val)))
        elif kind == "QUA":
            ev["qua_events"][c].append(n)
            if n not in ev["qua"] or c < ev["qua"][n]: ev["qua"][n] = c
        elif kind == "FIRE":
            b, k = val.split(":"); ev["fire"][c][int(b)] += int(k)
        elif kind == "WIT":
            t, k = val.split(":"); ev["wit"][(c, int(t))] += int(k)
        elif kind == "ATK": ev["atk"].add(n)
        elif kind == "STATE": ev["state"][(c, n)] = int(val)
        elif kind == "UTIL":
            u, sf, td = val.split(":"); ev["uv"][(c, n)] = (float(u), float(sf), float(td))
        elif kind == "QUAX":
            f = val.split(":"); ev["quax"][n] = dict(cycle=c, type=int(f[0]), t=float(f[1]), trust=float(f[2]), dec=[int(x) for x in f[3:11]])
        elif kind == "TD":
            f = val.split(":"); ev["td"][n] = dict(type=int(f[0]), dec=[int(x) for x in f[1:9]])
        elif kind == "REV": ev["rev"][n] = float(val)
        elif kind == "CTRLC": ev["ctrlc"][n] = int(val)
        elif kind == "M4":
            a, b, d = val.split(":"); ev["m4"][n] = (float(a), float(b), float(d))
        elif kind == "DEC":
            b, k = val.split(":"); ev["dec"][c][int(b)] += int(k)
    return ev


def score(ev, n_veh, n_rsu, total_cycles=None, warmup=WARMUP_S, stop_after_quarantine=False, alarm_mask=None):
    T = total_cycles if total_cycles is not None else ev["last_cycle"] + 1
    if alarm_mask is None:
        alarm_mask = ~WITNESS_BITS & 0xFFFFFFFF   # witness alerts are not alarms unless asked for
    nodes = range(n_veh, n_veh + n_rsu)
    rows = []
    per = [dict(c=c, scored=0, TP=0, FP=0, FN=0, TN=0) for c in range(T)]
    for n in nodes:
        q = ev["qua"].get(n, None) if stop_after_quarantine else None   # scored through cycle q inclusive
        if ev.get("variant", -1) in (2, 3):     # A3/A4: STATE label (S3/S4 test table state)
            sc = [c for (c, nn) in ev["state"] if nn == n]
            acts = set(range(min(sc), max(sc) + 1)) if sc else set()
        else:                                    # A1, A2, A5-A8 and benign: ACTION label
            acts = {c for (c, nn) in ev["act"] if nn == n}
        covered, fp_cycles = set(), {}
        for (c, w, mask) in ev["alm"].get(n, []):
            if alarm_mask is not None and not (mask & alarm_mask):
                continue          # score only the chosen detector(s), e.g. SFTO alone
            win = range(max(0, c - w + 1), c + 1)
            if any(x in acts for x in win):
                covered.update(win)
            else:
                fp_cycles[c] = fp_cycles.get(c, 0) | mask
        for c in range(T):
            if q is not None and c > q:
                continue                         # not scored from the cycle after quarantine
            p = per[c]; p["scored"] += 1
            if c in acts:
                p["TP" if c in covered else "FN"] += 1
            else:
                if c in fp_cycles:
                    p["FP"] += 1
                    for b, nm in enumerate(FLAG_NAMES):
                        if fp_cycles[c] >> b & 1: p["fpsrc_" + nm] = p.get("fpsrc_" + nm, 0) + 1
                else:
                    p["TN"] += 1
    for p in per:
        c = p["c"]
        p["MCC"] = mcc(p["TP"], p["FP"], p["FN"], p["TN"])
        p["quar_events"] = sum(1 for n in ev["qua_events"].get(c, []) if n_veh <= n < n_veh + n_rsu)
        for b, nm in enumerate(FLAG_NAMES):
            p["fire_" + nm] = ev["fire"].get(c, {}).get(b, 0)
        p["wit_DA"] = ev["wit"].get((c, 0), 0); p["wit_NFA"] = ev["wit"].get((c, 1), 0)
        p["ACT"] = sum(v for (cc, nn), v in ev["act"].items() if cc == c)
    post = [p for p in per if p["c"] >= warmup]
    tp, fp, fn, tn = (sum(p[k] for p in post) for k in ("TP", "FP", "FN", "TN"))
    vals = [p["MCC"] for p in post if not math.isnan(p["MCC"])]
    m = sum(vals)/len(vals) if vals else float("nan")
    sd = math.sqrt(sum((v-m)**2 for v in vals)/(len(vals)-1)) if len(vals) > 1 else float("nan")
    # false quarantines: benign RSUs (never attacked up to and including the quarantine cycle) and benign vehicles
    false_q = 0; true_q = 0
    for n, c in ev["qua"].items():
        if n_veh <= n < n_veh + n_rsu:
            attacked = any(cc <= c and nn == n for (cc, nn) in ev["act"])
        elif n < n_veh:
            attacked = n in ev["atk"]
        else:
            attacked = False
        if attacked: true_q += 1
        else: false_q += 1
    dec_tot = defaultdict(int)
    for cc, d in ev["dec"].items():
        if cc >= warmup:
            for b, k in d.items(): dec_tot[FLAG_NAMES[b] if b < len(FLAG_NAMES) else str(b)] += k
    summ = dict(commit=ev["commit"], variant=ev.get("variant", -1), decisions=dict(dec_tot), TPFN=tp + fn, cycles=T, warmup=warmup, TP=tp, FP=fp, FN=fn, TN=tn,
                M1=mcc(tp, fp, fn, tn), DR=(tp/(tp+fn) if tp+fn else float("nan")),
                FPR=(fp/(fp+tn) if fp+tn else float("nan")),
                mcc_cycle_mean=m, mcc_cycle_ci95=(1.96*sd/math.sqrt(len(vals)) if len(vals) > 1 else float("nan")),
                mcc_cycles_defined=len(vals), mcc_cycles_undefined=len(post)-len(vals),
                quarantined_true=true_q, quarantined_false=false_q,
                fire_totals={nm: sum(p["fire_"+nm] for p in post) for nm in FLAG_NAMES},
                fp_by_src={nm: sum(p.get("fpsrc_"+nm, 0) for p in post) for nm in FLAG_NAMES if sum(p.get("fpsrc_"+nm, 0) for p in post)})
    return per, summ


def check_same_positives(named_scores):
    """named_scores: {arm_name: summary}. Flags any two arms whose TP+FN differ: their M1 must not be compared."""
    ref_name, ref = next(iter(named_scores.items()))
    bad = [(n, s["TPFN"]) for n, s in named_scores.items() if s["TPFN"] != ref["TPFN"]]
    return (len(bad) == 0), dict(reference=(ref_name, ref["TPFN"]), differing=bad)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("events"); ap.add_argument("--n-veh", type=int, default=200); ap.add_argument("--n-rsu", type=int, default=64)
    ap.add_argument("--cycles", type=int, default=None); ap.add_argument("--warmup", type=float, default=WARMUP_S)
    ap.add_argument("--out", default=None, help="write per-cycle CSV here")
    ap.add_argument("--quarantine-stop", action="store_true",
                    help="superseded rule 4 (stop scoring a node after its quarantine); diagnostic only")
    ap.add_argument("--include-witness", action="store_true", help="count witness alerts as alarms")
    a = ap.parse_args()
    per, s = score(parse(a.events), a.n_veh, a.n_rsu, a.cycles, a.warmup, a.quarantine_stop, 0xFFFFFFFF if a.include_witness else None)
    if a.out:
        with open(a.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(per[0].keys())); w.writeheader(); w.writerows(per)
    for k, v in s.items(): print(f"{k}: {v}")


if __name__ == "__main__":
    main()
