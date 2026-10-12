"""feature_importance.py - Random Forest feature importance (paper Table 6): impurity and permutation
(F1 drop when the feature is shuffled in the test set), first fold of the lineage-grouped split.
usage: python host/feature_importance.py [dataset_dir] [output_dir]
"""
import os, sys
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.model_selection import StratifiedGroupKFold
import revised_experiments as R
if len(sys.argv) > 1: R.DATA = sys.argv[1]   # default: host/dataset (see REPRODUCE.md)
if len(sys.argv) > 2: R.OUT = sys.argv[2]    # default: reference/revised_results

raw, _ = R.load()
f, m, _ = R.aggregate(raw)
X, y, g = f.values, m.label.values, m.lineage.values
tr, te = next(StratifiedGroupKFold(5, shuffle=True, random_state=0).split(X, y, g))
rf = dict(R.supervised())["Random Forest"].fit(X[tr], y[tr])
pi = permutation_importance(rf, X[te], y[te], scoring="f1", n_repeats=5, random_state=0, n_jobs=-1)
out = pd.DataFrame({"impurity": rf.feature_importances_, "permutation_f1_drop": pi.importances_mean}, index=f.columns)
out = out.sort_values("permutation_f1_drop", ascending=False)
print(out.head(8).round(3).to_string())
os.makedirs(R.OUT, exist_ok=True)
out.round(4).to_csv(os.path.join(R.OUT, "feature_importance.csv"))
