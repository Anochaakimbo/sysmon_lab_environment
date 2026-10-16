"""export_model.py - train the paper's Random Forest (32 process-level features, Table 3 settings) and an
attack-type classifier (scenario of label=1 processes) per OS, and save one .pkl per OS for model_web
(Sysmon Event mode).

usage: python host/export_model.py [--dataset CSV] [--out-dir models]
       CSV default data/FINAL_DATASET_50runs.csv.gz (all 50 runs, host/build_dataset50.py);
       data/FINAL_DATASET_fixed.csv.gz gives the model of the paper's 12 runs
       writes <out-dir>/paper_rf_linux.pkl and paper_rf_windows.pkl
"""
import argparse, datetime, os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import revised_experiments as R

ap = argparse.ArgumentParser()
ap.add_argument("--dataset", default=os.path.join(os.path.dirname(R._HERE), "data", "FINAL_DATASET_50runs.csv.gz"))
ap.add_argument("--out-dir", default=os.path.join(os.path.dirname(R._HERE), "models"))
a = ap.parse_args()
raw = pd.read_csv(a.dataset, low_memory=False)
f, m, _ = R.aggregate(raw)
os.makedirs(a.out_dir, exist_ok=True)
for p in ("linux", "windows"):
    on = (m.platform == p).values
    rf = dict(R.supervised())["Random Forest"].fit(f.values[on], m.label.values[on])
    mal = on & (m.label == 1).values
    typer = RandomForestClassifier(200, random_state=R.SEED, n_jobs=-1, class_weight="balanced",
                                   min_samples_leaf=3).fit(f.values[mal], m.scenario.values[mal])
    out = os.path.join(a.out_dir, "paper_rf_%s.pkl" % p)
    joblib.dump(dict(model=rf, columns=list(f.columns), typer=typer, platform=p,
                     metadata=dict(created=datetime.date.today().isoformat(), train_processes=int(on.sum()),
                                   train_label1_share=float(m.label[on].mean()), train_runs=int(m.run[on].nunique()),
                                   training_data="%s, %s runs" % (os.path.basename(a.dataset), p))), out)
    print("%-7s %d runs, %d processes (label=1 %.1f%%), types %s -> %s"
          % (p, m.run[on].nunique(), on.sum(), 100 * m.label[on].mean(), list(typer.classes_), out))
