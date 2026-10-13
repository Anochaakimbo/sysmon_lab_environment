"""Export the verified RF configuration with provenance and a separate holdout demo."""
from pathlib import Path
import argparse, hashlib, json, platform, sys
import joblib, numpy as np, pandas as pd, sklearn
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
import model_web as web
import feature_processing as features
from uploaded_model import load_trusted_model, run_uploaded

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--csv',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    a=ap.parse_args()
    if a.out.exists() and any(a.out.iterdir()): raise ValueError('Output folder must be empty')
    a.out.mkdir(parents=True,exist_ok=True)
    raw=a.csv.read_bytes()
    d,x,meta,audit=web.read_events(raw)
    if not meta.truth_known.all(): raise ValueError('Training data must have complete labels')
    repo=Path(__file__).resolve().parents[1]
    prior=json.loads((repo/'reference/revised_by_os/manifest.json').read_text(encoding='utf-8-sig'))
    if digest(a.csv)!=prior['dataset_sha256']: raise ValueError('Dataset differs from evaluated dataset; compare models again before selecting a winner')
    table=pd.read_csv(repo/'reference/revised_by_os/p1_summary_by_os.csv')
    ranking=table[(table.Type=='Supervised')&(table.OS=='ALL')].sort_values('F1_mean',ascending=False)
    if ranking.iloc[0].Model!='Random Forest': raise ValueError('RF is no longer the highest F1 model')
    ranking.to_csv(a.out/'model_selection.csv',index=False)
    def new_model(): return make_pipeline(StandardScaler(),dict(features.supervised())['Random Forest'])
    split=StratifiedGroupKFold(n_splits=5,shuffle=True,random_state=0)
    tr,te=next(split.split(x,meta.label,groups=meta.lineage))
    assert not set(meta.lineage.iloc[tr]) & set(meta.lineage.iloc[te])
    holdout=new_model().fit(x.iloc[tr],meta.label.iloc[tr])
    expected=holdout.predict(x.iloc[te])
    probs=holdout.predict_proba(x.iloc[te])[:,1]
    metrics=features.scores(meta.label.iloc[te].to_numpy(),expected,probs)
    common=dict(dataset=str(a.csv.resolve()),dataset_sha256=digest(a.csv),input_events=audit['input_events'],
        dropped_events=audit['dropped_events'],processes=len(x),features=list(x),versions={'python':platform.python_version(),'sklearn':sklearn.__version__,'numpy':np.__version__,'pandas':pd.__version__,'joblib':joblib.__version__},
        feature_code_sha256=digest(Path(features.__file__)),selection_basis='Highest mean F1 among supervised models in existing lineage-grouped 5-fold x 5 repeated CV; same dataset hash.',
        previous_cv=ranking.iloc[0].to_dict(),threshold='estimator.predict default; no threshold search',
        caveat='Simulated attacks, same lab; not evidence of real-malware or cross-OS transfer accuracy.')
    artifacts={}
    for name,model,ids in [('sysmon_random_forest_holdout.pkl',holdout,tr),
                           ('sysmon_random_forest_full.pkl',new_model().fit(x,meta.label),np.arange(len(x)))]:
        info=dict(common,train_processes=len(ids),purpose='full-data model for new inputs' if len(ids)==len(x) else 'holdout demo model, excludes supplied test CSV',
                  evaluation='No independent score for full-data refit' if len(ids)==len(x) else 'Fixed first fold, seed 0; not selected by best test score')
        file=a.out/name
        joblib.dump({'model':model,'columns':list(x),'metadata':info},file,compress=3)
        loaded=load_trusted_model(file.read_bytes(),file.name,True)
        np.testing.assert_array_equal(loaded['model'].predict(x.iloc[te]),model.predict(x.iloc[te]))
        artifacts[name]={'sha256':digest(file),'train_processes':len(ids)}
    test=x.iloc[te].copy()
    test['label']=meta.label.iloc[te].to_numpy()
    test['platform']=meta.platform.iloc[te].to_numpy()
    test['run_id']=meta.run.iloc[te].to_numpy()
    test['ProcessGuid']=meta.ProcessGuid.iloc[te].to_numpy()
    test.to_csv(a.out/'test_features_for_holdout.csv',index=False,encoding='utf-8-sig')
    test_data=(a.out/'test_features_for_holdout.csv').read_bytes()
    loaded=load_trusted_model((a.out/'sysmon_random_forest_holdout.pkl').read_bytes(),'sysmon_random_forest_holdout.pkl',True)
    report,rows=run_uploaded(loaded,test_data,'test_features_for_holdout.csv',{},web.read_events,web.metric_block,web.MAX_ROWS)
    ordered=rows.set_index('process_key').reindex(['row:'+str(i+1) for i in range(len(te))])
    np.testing.assert_array_equal(ordered.prediction,expected)
    np.testing.assert_allclose(ordered.score,probs)
    meta.assign(split=np.where(meta.index.isin(meta.index[te]),'test','train')).to_csv(a.out/'holdout_split_manifest.csv',encoding='utf-8-sig')
    rows.to_csv(a.out/'expected_holdout_predictions.csv',index=False,encoding='utf-8-sig')
    (a.out/'holdout_metrics.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    summary=dict(common,artifacts=artifacts,holdout_train=len(tr),holdout_test=len(te),holdout_metrics=report['metrics'],by_os=report['by_os'])
    (a.out/'manifest.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'events':len(pd.read_csv(a.csv,low_memory=False)),'processes':len(x),'features':len(x.columns),'train':len(tr),'test':len(te),'metrics':report['metrics'],'out':str(a.out)},ensure_ascii=False))

if __name__=='__main__': main()
