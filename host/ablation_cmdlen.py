import numpy as np, pandas as pd, json
import revised_experiments as R
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, roc_auc_score
R.DATA='/mnt/user-data/uploads/sysmon-lab/host/dataset'
raw,extra=R.load()
f,m,_=R.aggregate(raw)
y=m.label.values; g=m.lineage.values
out={}
for name,cols in [('all32',list(f.columns)),('no_cmd',[c for c in f.columns if c not in ('cmd_len','pcmd_len')])]:
    X=f[cols].values; f1s=[];aucs=[]
    for rep in range(5):
        for tr,te in StratifiedGroupKFold(5,shuffle=True,random_state=rep).split(X,y,g):
            sc=StandardScaler().fit(X[tr]); rf=dict(R.supervised())['Random Forest']
            rf.fit(sc.transform(X[tr]),y[tr]); B=sc.transform(X[te])
            f1s.append(f1_score(y[te],rf.predict(B))); aucs.append(roc_auc_score(y[te],rf.predict_proba(B)[:,1]))
    out[name]=dict(n=len(cols),F1='%.3f±%.3f'%(np.mean(f1s),np.std(f1s,ddof=1)),AUC='%.3f±%.3f'%(np.mean(aucs),np.std(aucs,ddof=1)))
med=f.groupby(y)[['cmd_len','pcmd_len']].median()
out['median_cmd_len']={'label0':float(med.loc[0,'cmd_len']),'label1':float(med.loc[1,'cmd_len'])}
out['median_pcmd_len']={'label0':float(med.loc[0,'pcmd_len']),'label1':float(med.loc[1,'pcmd_len'])}
print(json.dumps(out,indent=1)); json.dump(out,open('results/ablation_cmdlen.json','w'),indent=1)
