"""export_model.py - train the paper's Random Forest (32 process-level features, Table 3 settings) per OS,
plus an attack-type classifier per OS (scenario of label=1 processes), and save one .pkl for eval_web.py.

usage: python host/export_model.py [--data DIR] [--out models/paper_rf.pkl]
       DIR holds merged_dataset.csv and the two new-run CSVs (see REPRODUCE.md); default host/dataset
"""
import argparse, datetime, os
import joblib
from sklearn.ensemble import RandomForestClassifier
import revised_experiments as R

ap = argparse.ArgumentParser()
ap.add_argument("--data", default=R.DATA)
ap.add_argument("--out", default=os.path.join(os.path.dirname(R._HERE), "models", "paper_rf.pkl"))
a = ap.parse_args()
R.DATA = a.data
raw, _ = R.load()
f, m, _ = R.aggregate(raw)
detectors, typers = {}, {}
for p in ("linux", "windows"):
    on = (m.platform == p).values
    detectors[p] = dict(R.supervised())["Random Forest"].fit(f.values[on], m.label.values[on])
    mal = on & (m.label == 1).values
    typers[p] = RandomForestClassifier(200, random_state=R.SEED, n_jobs=-1, class_weight="balanced",
                                       min_samples_leaf=3).fit(f.values[mal], m.scenario.values[mal])
    print("%-7s detector %d processes (label=1 %.1f%%), type model %d processes, types %s"
          % (p, on.sum(), 100 * m.label[on].mean(), mal.sum(), list(typers[p].classes_)))
os.makedirs(os.path.dirname(a.out), exist_ok=True)
joblib.dump(dict(features=list(f.columns), detectors=detectors, typers=typers,
                 created=datetime.date.today().isoformat()), a.out)
print("->", a.out)
