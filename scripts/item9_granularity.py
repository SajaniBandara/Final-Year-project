#!/usr/bin/env python3
"""
item9_granularity.py — item 9's open follow-up (session README, 2026-08-29).

Item 9 repointed the A5-A8 window activity gate from g_ranom_flag_last
(receive-side) to the hf_send_gt delta (send-side). That fixed the wrong-signal
failure, but nodes 220/225/233 still fire in 58/58 windows, leaving 19-24
residual FP each. The open question:

  "does g_lstm_hf_sendgt_count's increment granularity actually match how
   often S5's own firing condition is true for these high-activity nodes?"

This answers it directly, per cycle, for the three nodes:

  gate   = hf_send_gt > 0 in that cycle   (lstm_training CSV; the column is
           already the PER-CYCLE DELTA of g_lstm_hf_sendgt_count, see
           lstm_logger.h:900 -- not the cumulative counter)
  fired  = an S5 detection event landed in that cycle
           (bc_detection_log, signal_idx==5, timestamp_ms -> cycle;
            the 4 surviving columns after the 2026-08-29 strip are enough)

The diagnostic cell is (fired=1, gate=0): S5 fired while the window-truth gate
called the node dormant. Those are the scored-FP cycles. If that cell is large,
the two signals disagree at cycle granularity and the gate -- not S5 -- is what
still needs work.
"""
import csv, glob, os, sys
from collections import defaultdict

R = os.path.expanduser("~/ns3_g13/ns-allinone-3.35/ns-3.35/results_routing")
NODES = [220, 225, 233]
N_VEH = 200          # sim node id = N_Vehicles + local RSU index


def _resolve(pattern, what):
    """Exactly one file, or refuse. A loose glob here silently POOLS runs --
    measured 2026-08-29: `*60_seed1*` matched 10 different runs (Q1..Q6, fix2,
    prim, susp, d4test) and summed their S5 events into one bogus total. The
    per-run answer is the only meaningful one, so fail loudly instead."""
    hits = sorted(glob.glob(pattern))
    if len(hits) == 1:
        return hits[0]
    if not hits:
        print(f"  no {what} matched: {pattern}")
    else:
        print(f"  AMBIGUOUS -- {len(hits)} {what} files matched {pattern}; "
              f"narrow the tag. Pooling them would be meaningless:")
        for h in hits:
            print(f"      {os.path.basename(h)}")
    return None


def s5_events_by_cycle(tag):
    """{sim_node_id: {cycle: n_S5_events}} from the on-chain detection log."""
    out = defaultdict(lambda: defaultdict(int))
    one = _resolve(f"{R}/bc_detection_log_Attack5_*{tag}*.csv", "bc_detection_log")
    if one is None:
        return out
    for p in [one]:
        with open(p) as f:
            for r in csv.DictReader(f):
                try:
                    if int(r["signal_idx"]) != 5:
                        continue
                    node = int(r["suspect_node"])
                    cyc = int(float(r["timestamp_ms"]) / 1000.0)
                except (ValueError, KeyError, TypeError):
                    continue
                out[node][cyc] += 1
    return out


def gate_by_cycle(tag):
    """{sim_node_id: {cycle: hf_send_gt}} from the per-RSU training CSVs."""
    out = defaultdict(dict)
    for p in glob.glob(f"{R}/lstm_training/RSU_*/Attack5_*{tag}*.csv"):
        with open(p) as f:
            for r in csv.DictReader(f):
                try:
                    node = N_VEH + int(r["rsu_id"])
                    out[node][int(r["cycle"])] = float(r["hf_send_gt"])
                except (ValueError, KeyError, TypeError):
                    continue
    return out


def main(tag=""):
    s5, gate = s5_events_by_cycle(tag), gate_by_cycle(tag)
    if not s5:
        print(f"no bc_detection_log_Attack5_*{tag}* found under {R}"); return
    print("=" * 72)
    print("ITEM 9 — does the hf_send_gt gate agree with S5 at cycle granularity?")
    print("=" * 72)
    print(f"\n{'node':>6}{'cycles':>8}{'S5 fired':>10}{'gate>0':>9}"
          f"{'fired&gate':>12}{'FIRED&!GATE':>13}{'agree%':>9}")
    print("-" * 72)
    for n in NODES:
        cycles = sorted(gate.get(n, {}))
        if not cycles:
            print(f"{n:>6}{'(no gate rows)':>8}"); continue
        f_g = f_ng = ng_g = both0 = 0
        for c in cycles:
            fired = s5.get(n, {}).get(c, 0) > 0
            g = gate[n].get(c, 0) > 0
            if fired and g: f_g += 1
            elif fired and not g: f_ng += 1
            elif not fired and g: ng_g += 1
            else: both0 += 1
        tot = len(cycles)
        agree = 100.0 * (f_g + both0) / tot if tot else 0.0
        print(f"{n:>6}{tot:>8}{f_g+f_ng:>10}{f_g+ng_g:>9}{f_g:>12}{f_ng:>13}{agree:>8.1f}%")
    print("\nFIRED&!GATE is the residual-FP mechanism: S5 fired, the gate called the")
    print("node dormant, so window truth was 0 and a correct detection scored as FP.")

    # Supervisor decision 4 (2026-08-29): "rerun A5 in full to confirm no
    # similar residuals surface ELSEWHERE". The three known nodes are not the
    # question -- the question is whether any OTHER node shows the same
    # signature. Scan every node that fired S5 at all.
    print("\n" + "=" * 72)
    print("SWEEP — every node with S5 activity, not just the three known ones")
    print("=" * 72)
    rows = []
    for n in sorted(set(s5) | set(gate)):
        cycles = sorted(gate.get(n, {}))
        if not cycles:
            continue
        fired = sum(1 for c in cycles if s5.get(n, {}).get(c, 0) > 0)
        if fired == 0:
            continue
        f_ng = sum(1 for c in cycles
                   if s5.get(n, {}).get(c, 0) > 0 and not gate[n].get(c, 0) > 0)
        rows.append((f_ng, fired, len(cycles), n))
    rows.sort(reverse=True)
    if not rows:
        print("  no node shows S5 activity in this run.")
        return
    print(f"\n{'node':>6}{'cycles':>8}{'S5 fired':>10}{'FIRED&!GATE':>13}{'residual%':>11}")
    print("-" * 50)
    for f_ng, fired, tot, n in rows[:25]:
        mark = "  <-- known" if n in NODES else ""
        print(f"{n:>6}{tot:>8}{fired:>10}{f_ng:>13}{100.0*f_ng/fired:>10.1f}%{mark}")
    others = [r for r in rows if r[3] not in NODES and r[0] > 0]
    print(f"\nNodes with residual FIRED&!GATE cycles: {sum(1 for r in rows if r[0] > 0)} total, "
          f"of which {len(others)} are NOT the three known ones.")
    if others:
        print("  -> the residual is NOT confined to 220/225/233; it is systemic.")
    else:
        print("  -> residual confined to the three known nodes.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "")
