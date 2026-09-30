from pathlib import Path
import json, sys, re, ast, math
import pandas as pd
import numpy as np
from pypdf import PdfReader
from docx import Document

ROOT=Path('S:/Jr.Project(Real)/sysmon-lab')
OUT=ROOT/'tmp/paper_nccy_review'
raw=pd.read_csv(ROOT/'host/dataset/merged_dataset.csv',low_memory=False)
stats={'rows':len(raw),'columns':len(raw.columns),'column_names':list(raw.columns),'labels':raw.groupby(['platform','label']).size().to_dict(),
    'events':raw.EventID.value_counts().sort_index().to_dict(), 'sessions':raw.groupby(['platform','session']).size().to_dict(),
    'processes':raw.ProcessGuid.nunique(),'missing_process_guid':int(raw.ProcessGuid.isna().sum()),
    'guid_multiple_runs':int((raw.groupby('ProcessGuid').run_id.nunique()>1).sum()) if 'run_id' in raw else None,
    'guid_multiple_platforms':int((raw.groupby('ProcessGuid').platform.nunique()>1).sum()),
    'proc_labels':raw.groupby('ProcessGuid').label.max().value_counts().to_dict()}
source=(ROOT/'host/ml_train.py').read_text(encoding='utf-8')
tree=ast.parse(source)
scope={'pd':pd,'np':np}
for node in tree.body:
    if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('PROC_EVENT_IDS','DERIVED_DROP','SEED') for t in node.targets):
        exec(compile(ast.Module(body=[node],type_ignores=[]),'ml_train_constants','exec'),scope)
    if isinstance(node,ast.FunctionDef) and node.name=='aggregate_processes':
        exec(compile(ast.Module(body=[node],type_ignores=[]),'ml_train_aggregate','exec'),scope)
f,meta=scope['aggregate_processes'](raw)
stats['features']=list(f.columns)
stats['derived_removed']=[n for n in f if n in scope['DERIVED_DROP']]
stats['remaining_features']=[n for n in f if n not in scope['DERIVED_DROP']]
stats['proc_by_platform_label']=meta.groupby(['platform','label']).size().to_dict()
groups,ids=np.unique(meta.proc.values,return_inverse=True)
permutation=np.random.RandomState(scope['SEED']).permutation(len(groups))
ntest=math.ceil(.3*len(groups))
te=np.flatnonzero(np.isin(ids,permutation[:ntest]))
tr=np.flatnonzero(np.isin(ids,permutation[ntest:]))
stats['split']={'train':len(tr),'test':len(te),'train_mal':int(meta.label.iloc[tr].sum()),'test_mal':int(meta.label.iloc[te].sum()),'process_overlap':len(set(meta.proc.iloc[tr]) & set(meta.proc.iloc[te]))}
loso=pd.read_csv(ROOT/'reference/ml_loso.csv')
base=loso[loso.Algorithm.str.startswith('[baseline]')].set_index('HeldOut').F1
stats['loso']={model:{'f1_mean':float(g.F1.mean()),'auc_mean':float(g.AUC.mean()),'wins':int((g.set_index('HeldOut').F1>base).sum()),'n':len(g)} for model,g in loso[~loso.Algorithm.str.startswith('[baseline]')].groupby('Algorithm')}
nlme=pd.read_csv(ROOT/'reference/NLME.csv',low_memory=False)
stats['nlme']={'rows':len(nlme),'columns':len(nlme.columns),'column_names':list(nlme.columns),'events':nlme.EventID.value_counts().sort_index().to_dict()}
stats['uncited_refs']=sorted(set(range(1,23))-set(int(m) for p in Document(ROOT/'docs/paper_draft_NCCY_v2.docx').paragraphs if not re.match(r'^\[\d+\]',p.text) for m in re.findall(r'\[(\d+)\]',p.text)))
fonts={}
for label in ['template_NCCY_full_thai','paper_draft_NCCY_v2']:
    fonts[label]=sorted({str(font.get_object().get('/BaseFont')) for p in PdfReader(OUT/'native_render'/label/f'{label}.pdf').pages for font in p['/Resources'].get('/Font',{}).values()})
stats['pdf_fonts']=fonts
serial={k:({str(kk):vv for kk,vv in v.items()} if isinstance(v,dict) else v) for k,v in stats.items()}
(OUT/'results_evidence.json').write_text(json.dumps(serial,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
for k,v in stats.items():
    if k not in ('column_names','sessions'):
        print(k,v)
