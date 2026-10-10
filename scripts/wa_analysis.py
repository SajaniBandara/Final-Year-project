import sys,glob
sys.path.insert(0,'scripts'); import event_scorer as es
from pathlib import Path
R=Path.home()/"ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
print("arm      A s | witness-in-score |  TP    FP   FN    TN |  M1    DR    FPR | witness alarms (WIT_DA fires)")
for a in (7,8):
  for s in (2,3):
    for arm in ("code","paper","ab6off"):
      f=glob.glob(str(R/f"events_Attack{a}_40_*wa_{arm}_A{a}_s{s}.csv"))
      if not f: print(arm,a,s,"missing"); continue
      ev=es.parse(f[0])
      for wit in (0,1):
        per,sm=es.score(ev,200,64,181,45.0,False,0xFFFFFFFF if wit else None)
        print(f"{arm:7s} A{a} s{s} | {'incl' if wit else 'excl'}             | {sm['TP']:5d} {sm['FP']:5d} {sm['FN']:5d} {sm['TN']:5d} | {sm['M1']:.3f} {sm['DR']:.3f} {sm['FPR']:.3f} | {sm['fire_totals']['WIT_DA']}")
