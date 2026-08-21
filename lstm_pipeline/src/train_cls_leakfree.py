import sys,os; sys.path.insert(0,os.getcwd())
import numpy as np, torch, torch.nn as nn, glob, csv, math, re
from pathlib import Path
from lstm_model import LSTMAutoencoder, N_FEATURES
PRE=Path('../preprocessed'); MODELS=Path('../models')
DEV="cuda" if torch.cuda.is_available() else "cpu"
BASE=Path.home()/"ns3_g13/ns-allinone-3.35/ns-3.35/results_routing/lstm_training"
def nodemap(seeds):
    m={}
    for p in glob.glob(str(BASE/"RSU_*"/"A*_seed*.csv")):
        f=Path(p); rsu=int(f.parent.name[4:])
        g=re.match(r"^Attack(\d+)_(\d+)(?:_d\d+ms)?_seed(\d+)$",f.stem)
        if not g or int(g.group(3)) not in seeds: continue
        av,pct,sd=int(g.group(1)),int(g.group(2)),int(g.group(3))
        with open(p) as fh:
            rd=csv.reader(fh); next(rd,None)
            for r in rd:
                if len(r)>=14:
                    try: m[(rsu,av,pct,sd,int(r[0]))]=int(r[13])
                    except ValueError: pass
    return m
def labels(split,seeds):
    """LEAK-FREE per standing rule: A5-A8 <- hf_send_gt window label (y_indep);
       A1/A2 <- is_malicious_node node label (CSV col14). Neither is a FEATURES column."""
    meta=np.load(PRE/f'{split}_meta.npy'); yi=np.load(PRE/f'{split}_y_indep.npy')
    av=meta[:,1].astype(int); y=np.zeros(len(meta),np.int8)
    y[np.isin(av,[5,6,7,8])]=yi[np.isin(av,[5,6,7,8])]
    nm=nodemap(seeds); tm=np.isin(av,[1,2])
    for i in np.where(tm)[0]:
        rsu,a,pct,sd,sc=meta[i]
        v=[nm.get((int(rsu),int(a),int(pct),int(sd),int(sc)+k)) for k in range(10)]
        v=[x for x in v if x is not None]
        if v: y[i]=1 if max(v)>0 else 0
    return y
def met(yt,yp):
    tp=int(((yt==1)&(yp==1)).sum());fp=int(((yt==0)&(yp==1)).sum())
    fn=int(((yt==1)&(yp==0)).sum());tn=int(((yt==0)&(yp==0)).sum())
    d=math.sqrt(float(tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    return (0.0 if d==0 else (tp*tn-fp*fn)/d, tp/(tp+fn) if tp+fn else float('nan'),
            fp/(fp+tn) if fp+tn else float('nan'))
print("building leak-free labels …")
Y={s:labels(s,st) for s,st in [('train',{1,2,3}),('val',{4}),('test',{5})]}
for s in Y: print(f"  {s}: pos rate {Y[s].mean():.3f}")
ck=torch.load(MODELS/'global.pt',map_location=DEV,weights_only=False)
model=LSTMAutoencoder(n_features=N_FEATURES).to(DEV); model.load_state_dict(ck['weights'])
X={s:np.load(PRE/f'{s}_X.npy') for s in Y}
opt=torch.optim.Adam(model.parameters(),lr=1e-3)   # unfrozen: continue fine-tune
lf=nn.BCELoss(reduction='none')
pos=float(Y['train'].mean()); w=torch.tensor([1.0/max(pos,1e-6)],device=DEV)
Xtr=torch.from_numpy(X['train']).float(); ytr=torch.from_numpy(Y['train']).float().to(DEV); n=len(Xtr)
print("fine-tuning from current weights (encoder unfrozen, 20 epochs) …")
for ep in range(1,21):
    model.train(); perm=torch.randperm(n); tot=0.
    for i in range(0,n,512):
        b=perm[i:i+512]; opt.zero_grad()
        p=model.fc_cls(model.encode(Xtr[b].to(DEV))).squeeze(-1).clamp(1e-7,1-1e-7)
        wt=torch.where(ytr[b.to(DEV)]>0.5,w,torch.ones_like(w))
        l=(lf(p,ytr[b.to(DEV)])*wt).mean(); l.backward(); opt.step(); tot+=l.item()*len(b)
    if ep%10==0: print(f"  epoch {ep}/20 loss={tot/n:.5f}")
model.eval(); P={}
with torch.no_grad():
    for s in X:
        o=[]
        for i in range(0,len(X[s]),1024):
            o.append(model.fc_cls(model.encode(torch.from_numpy(X[s][i:i+1024]).float().to(DEV))).squeeze(-1).cpu().numpy())
        P[s]=np.concatenate(o)
mv=np.load(PRE/'val_meta.npy'); mt=np.load(PRE/'test_meta.npy')
rv,rt=mv[:,0].astype(int),mt[:,0].astype(int); thr={}
for r in np.unique(rv):
    m=rv==r; best,bdr=0.5,-1
    for t in np.linspace(0.01,0.99,99):
        mm=met(Y['val'][m],(P['val'][m]>t).astype(int))
        if mm[2]<=0.01 and (mm[1] or 0)>bdr: bdr,best=mm[1],t
    thr[int(r)]=best
g=float(np.median(list(thr.values())))
yp=(P['test']>np.array([thr.get(int(r),g) for r in rt])).astype(int)
av=mt[:,1].astype(int); ms=[]
print("\n=== DECISION 1: leak-free labels, encoder unfrozen, per-RSU FPR<=1% ===")
for v in [1,2,5,6,7,8]:
    m=av==v; a,d,f=met(Y['test'][m],yp[m]); ms.append(a)
    print(f"  A{v}: MCC={a:+.4f}  DR={d:.3f}  FPR={f:.3f}")
print(f"  macro-MCC = {sum(ms)/len(ms):.4f}")
torch.save({"weights":model.state_dict(),"labels":"leakfree","per_rsu_threshold":thr},
           MODELS/"global_clshead_leakfree.pt")
print("  saved -> models/global_clshead_leakfree.pt")
