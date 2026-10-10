import glob
from pathlib import Path
R = Path.home()/"ns3_g13/ns-allinone-3.35/ns-3.35/results_routing"
for a in range(1,5):
  for s in (2,3):
    for b in (0,2):
        tag=(f"cl{b}_A{a}_s{s}" if b<2 else f"clw_A{a}_s{s}"); f=glob.glob(str(R/f"events_Attack*_{tag}.csv"))
        if not f: print(tag,"missing"); continue
        atk=set(); m4={}; q=set()
        for l in open(f[0]):
            p=l.strip().split(',',3)
            if len(p)<4: continue
            if p[2]=='ATK': atk.add(int(p[1]))
            elif p[2]=='M4': m4[int(p[1])]=[float(x) for x in p[3].split(':')]
            elif p[2]=='QUAX': q.add(int(p[1]))
        acted=[n for n,v in m4.items() if v[0]>0]
        cq=sum(1 for n,v in m4.items() if v[1]>0); cr=sum(1 for n,v in m4.items() if v[2]>0)
        cont=sum(1 for n,v in m4.items() if v[1]>0 or v[2]>0)
        hq=len([n for n in q if n not in atk]); hon=264-len(atk)
        print(f"{tag}: attackers={len(atk)} acted={len(acted)} contained={cont} (quar {cq}, revoc {cr}) honest_quarantined={hq}/{hon} = {100*hq/hon:.1f}%")
