#!/usr/bin/env python3
"""
primary_detector_table.py -- supervisor's primary-detector ablation table
(2026-08-20 spec).

Each variant is scored ONLY by its assigned primary detector, per-window
(eq:eval_dedup: non-overlapping 10s blocks, max-pooled), from the
detector_windows.csv snapshot taken for each Q-config.

  A1, A2  -> LSTM (classification head)
  A3, A4  -> rule engine S3/S4
  A5, A6  -> crypto layer (BatchVerify + S5/S6)
  A7, A8  -> witness mechanism

A cell is only defined where that variant's primary detector is actually
ENABLED in that Q-config. The Q-config flag matrix (run_q1q6_ablation.py):

           S1/S2  S3/S4  S5/S6  S7/S8  LSTM  witness
    Q1      on     on     off    off    off    off
    Q2      off    off    on     on     off    off
    Q3      off    off    off    off    ON     off
    Q4      off    off    off    off    off    ON
    Q5      on     on     on     on     off    off
    Q6      on     on     on     on     ON     ON

so e.g. A1/A2 (primary = LSTM) exist only at Q3 and Q6; A7/A8 (primary =
witness) only at Q4 and Q6. Undefined cells are printed as "--" rather
than filled with the OR-combined number, which would be a different
quantity.
"""
import csv, glob, math, sys
from collections import defaultdict
from pathlib import Path

PRIMARY = {1:"LSTM",2:"LSTM",3:"S3/S4",4:"S3/S4",
           5:"crypto",6:"crypto",7:"witness",8:"witness"}
ENABLED = {   # Q-config -> which primary-detector families are live
    "Q1": {"S3/S4"},
    "Q2": {"crypto"},
    "Q3": {"LSTM"},
    "Q4": {"witness"},
    "Q5": {"S3/S4","crypto"},
    "Q6": {"S3/S4","crypto","LSTM","witness"},
}

def mcc(tp,fp,fn,tn):
    d=math.sqrt(float(tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    return 0.0 if d==0 else (tp*tn-fp*fn)/d

def score(path, variant):
    """Per-window MCC after eq:eval_dedup block max-pooling. RSU rows only
    (WHICH_MCC_TO_REPORT.md sec 3: OBU rows have no coherent ground truth)."""
    blocks=defaultdict(lambda:[0,0])
    try: rows=list(csv.DictReader(open(path)))
    except OSError: return None
    for r in rows:
        if int(r["variant"])!=variant or r.get("mode")!="RSU": continue
        b=int(float(r["w_start"])//10)
        k=(r["node"],b); v=blocks[k]
        v[0]=max(v[0],int(r.get("truth",0) or 0))
        v[1]=max(v[1],1 if float(r["score"])>0.5 else 0)
    if not blocks: return None
    tp=sum(1 for t,p in blocks.values() if t==1 and p==1)
    fp=sum(1 for t,p in blocks.values() if t==0 and p==1)
    fn=sum(1 for t,p in blocks.values() if t==1 and p==0)
    tn=sum(1 for t,p in blocks.values() if t==0 and p==0)
    return dict(MCC=mcc(tp,fp,fn,tn),
                DR=tp/(tp+fn) if tp+fn else float('nan'),
                FPR=fp/(fp+tn) if fp+tn else float('nan'),
                TP=tp,FP=fp,FN=fn,TN=tn)

def main(snap_root):
    cfgs=["Q1","Q3","Q4","Q5","Q6"]
    print(f"{'variant':<9}{'primary':<10}" + "".join(f"{c:>10}" for c in cfgs))
    print("-"*(19+10*len(cfgs)))
    col=defaultdict(list)
    for v in range(1,9):
        row=f"A{v:<8}{PRIMARY[v]:<10}"
        for c in cfgs:
            if PRIMARY[v] not in ENABLED[c]:
                row+=f"{'--':>10}"; continue
            f=glob.glob(str(Path(snap_root)/c/f"detector_windows_Attack{v}_*.csv"))
            m=score(f[0],v) if f else None
            if m is None: row+=f"{'n/a':>10}"
            else:
                row+=f"{m['MCC']:>10.4f}"; col[c].append(m['MCC'])
        print(row)
    print("-"*(19+10*len(cfgs)))
    line=f"{'macro':<9}{'':<10}"
    for c in cfgs:
        line+= f"{sum(col[c])/len(col[c]):>10.4f}" if col[c] else f"{'--':>10}"
    print(line)
    print("\nmacro = mean over the variants whose primary detector is live in "
          "that config,\nso the columns average different variant sets and are "
          "NOT comparable across Q.")

if __name__=="__main__":
    main(sys.argv[1] if len(sys.argv)>1 else ".")
