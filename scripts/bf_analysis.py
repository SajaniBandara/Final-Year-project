import glob, sys, subprocess, re, collections
from pathlib import Path
R = Path.home()/"ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
for a in range(1,9):
  for s in (2,3):
    for bf in (1,0):
        tag=f"bio{bf}_A{a}_s{s}"; f=glob.glob(str(R/f"events_Attack*_{tag}.csv"))
        if not f: print(tag,"missing"); continue
        atk=set(); hq=aq=0; cause=collections.Counter()
        for l in open(f[0]):
            p=l.strip().split(',',3)
            if len(p)<4: continue
            if p[2]=='ATK': atk.add(int(p[1]))
        for l in open(f[0]):
            p=l.strip().split(',',3)
            if len(p)<4 or p[2]!='QUAX': continue
            n=int(p[1]); fl=p[3].split(':')
            if n in atk: aq+=1
            else:
                hq+=1
                for i,v in enumerate(fl[3:11]): cause[i]+=int(v)
        o=subprocess.run(["python3","scripts/event_scorer.py",f[0]],capture_output=True,text=True).stdout
        m=lambda k: re.search(k+r": ([\d.]+)",o).group(1)
        print(f"{tag}: atk_q={aq}/{len(atk)} honest_q={hq} causes(B,H,D,..)={dict(cause)} M1={float(m('M1')):.3f} DR={float(m('DR')):.3f} FPR={float(m('FPR')):.4f}")
