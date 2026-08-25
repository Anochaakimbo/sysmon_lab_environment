# -*- coding: utf-8 -*-
"""
ml_feature_study.py - พิสูจน์ว่าจำนวน feature ที่ใช้ควรเป็นเท่าไหร่

ทำไมต้องมี: จำนวน feature ที่ใช้อยู่ (event 48 / process 35) ไม่ได้มาจากการวัด
  - 48 = "ทุกคอลัมน์ที่เหลือหลัง preprocessing ตามเปเปอร์" ไม่ใช่การเลือก
  - 35 = จำนวนที่ผู้เขียนสคริปต์ออกแบบเอง (11 EventID x 2 + 13 ตัวรวม)
ธีสิสอ้างตัวเลขพวกนี้ไม่ได้ถ้าไม่มีหลักฐานว่าทำไมไม่ใช่ 10 หรือ 20

สคริปต์นี้วัด 3 อย่าง ทุกอย่างเลือกจาก **validation ที่แยกจาก test** ไม่ใช่จาก test:

  1. PCA sweep n=1..N          -> ตามที่เปเปอร์ทำ (Table 9 "Number of features")
  2. ranking ความสำคัญ         -> permutation importance บน validation
  3. greedy backward elimination -> ตัดตัวที่สำคัญน้อยสุดทีละตัว
                                   หา "ชุดเล็กที่สุดที่ยังอยู่ใน 1% ของค่าดีที่สุด"

    python host/ml_feature_study.py --level process
    python host/ml_feature_study.py --level event --split process
    python host/ml_feature_study.py --level process --out reference/feature_study_process.csv
"""
import os as _os
import sys as _sys

_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
_os.environ.setdefault("PYTHONUTF8", "1")
for _s in (_sys.stdout, _sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

import argparse
import os
import warnings

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)
from ml_train import DERIVED_DROP, SysmonEncoder, load, make_split  # noqa: E402

SEED = 0
RF = dict(n_estimators=100, random_state=SEED, n_jobs=-1, class_weight="balanced")


def rf_f1(Xtr, ytr, Xte, yte):
    m = RandomForestClassifier(**RF).fit(Xtr, ytr)
    return f1_score(yte, m.predict(Xte), zero_division=0), m


def lof_auc(Xtr, ytr, Xte, yte):
    """unsupervised: เทรน benign อย่างเดียว วัดด้วย AUC (ไม่ขึ้นกับ threshold)"""
    ab = Xtr[ytr == 0]
    if len(ab) < 30 or len(np.unique(yte)) < 2:
        return np.nan
    m = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(ab)
    return roc_auc_score(yte, -m.score_samples(Xte))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(_HERE, "dataset", "merged_dataset.csv"))
    ap.add_argument("--level", choices=["event", "process"], default="process")
    ap.add_argument("--split", choices=["process", "run", "scenario"], default="process")
    ap.add_argument("--drop-derived", action="store_true",
                    help="ตัด feature ที่เป็น artifact ของ pipeline")
    ap.add_argument("--max-rows", type=int, default=0,
                    help="สุ่มลดจำนวนแถวก่อนวัด (0 = ใช้ทั้งหมด) - event-level ช้ามาก")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    feats, meta = load(a.csv, a.level)
    if a.drop_derived:
        feats = feats.drop(columns=[c for c in feats.columns if c in DERIVED_DROP])
    if a.max_rows and len(feats) > a.max_rows:
        keep = np.random.RandomState(SEED).choice(len(feats), a.max_rows, replace=False)
        keep.sort()
        feats = feats.iloc[keep].reset_index(drop=True)
        meta = meta.iloc[keep].reset_index(drop=True)
        print("  สุ่มลดเหลือ %d แถว" % len(feats))
    y = meta["label"].values
    tr, te = make_split(a.split, meta)

    if a.level == "event":
        enc = SysmonEncoder().fit(feats.iloc[tr])
        Xtr_df, Xte_df = enc.transform(feats.iloc[tr]), enc.transform(feats.iloc[te])
        names = list(enc.features_)
    else:
        Xtr_df, Xte_df = feats.iloc[tr], feats.iloc[te]
        names = list(feats.columns)

    sc = StandardScaler().fit(Xtr_df)
    Xtr, Xte = sc.transform(Xtr_df), sc.transform(Xte_df)
    ytr, yte = y[tr], y[te]

    # validation แยกจาก test - ทุกการเลือกเกิดที่นี่ ห้ามดู test
    gtr = meta["proc"].values[tr]
    i_fit, i_val = next(GroupShuffleSplit(1, test_size=.25,
                                          random_state=SEED).split(Xtr, ytr, groups=gtr))
    print("=" * 78)
    print("level=%s  split=%s  feature ตั้งต้น %d ตัว" % (a.level, a.split, len(names)))
    print("  fit %d / validation %d / test %d" % (len(i_fit), len(i_val), len(yte)))
    print("=" * 78)

    rows = []

    # ---------------------------------------------------------------- 1) PCA sweep
    print("\n[1] PCA sweep n=1..%d  (เลือกจาก validation)" % min(len(names), 30))
    print("     n | val F1  | test F1 | val LOF AUC | explained var")
    best = (-1, None)
    for n in range(1, min(len(names), 30) + 1):
        p = PCA(n_components=n, random_state=SEED).fit(Xtr[i_fit])
        A, V, T = p.transform(Xtr[i_fit]), p.transform(Xtr[i_val]), p.transform(Xte)
        vf1, _ = rf_f1(A, ytr[i_fit], V, ytr[i_val])
        tf1, _ = rf_f1(A, ytr[i_fit], T, yte)
        auc = lof_auc(A, ytr[i_fit], V, ytr[i_val])
        evr = p.explained_variance_ratio_.sum()
        rows.append(dict(step="pca", n=n, val_f1=vf1, test_f1=tf1,
                         val_lof_auc=auc, evr=evr))
        if vf1 > best[0]:
            best = (vf1, n)
        if n <= 12 or n % 3 == 0 or n == min(len(names), 30):
            print("    %3d | %.4f | %.4f  |    %.4f   | %.3f" % (n, vf1, tf1, auc, evr))
    print("  -> PCA ที่ดีสุดบน validation: n=%d (val F1 %.4f)" % (best[1], best[0]))

    p = PCA(n_components=best[1], random_state=SEED).fit(Xtr)
    tf1_pca, _ = rf_f1(p.transform(Xtr), ytr, p.transform(Xte), yte)
    tf1_all, m_all = rf_f1(Xtr, ytr, Xte, yte)
    auc_pca = lof_auc(p.transform(Xtr), ytr, p.transform(Xte), yte)
    auc_all = lof_auc(Xtr, ytr, Xte, yte)
    print("  เทียบบน test:  PCA n=%d -> RF F1 %.4f / LOF AUC %.4f" % (best[1], tf1_pca, auc_pca))
    print("                 ไม่ใช้ PCA (%d) -> RF F1 %.4f / LOF AUC %.4f"
          % (len(names), tf1_all, auc_all))

    # ---------------------------------------------------------------- 2) importance
    print("\n[2] permutation importance บน validation (RF, 5 รอบ)")
    m = RandomForestClassifier(**RF).fit(Xtr[i_fit], ytr[i_fit])
    pi = permutation_importance(m, Xtr[i_val], ytr[i_val], n_repeats=5,
                                random_state=SEED, scoring="f1", n_jobs=-1)
    imp = pd.Series(pi.importances_mean, index=names).sort_values(ascending=False)
    for k, v in imp.head(15).items():
        print("    %-12s %.4f" % (k, v))
    n_zero = int((imp <= 0).sum())
    print("    ... feature ที่ importance <= 0 : %d ตัว" % n_zero)
    for k, v in imp.items():
        rows.append(dict(step="importance", feature=k, importance=v))

    # ---------------------------------------------------- 3) backward elimination
    print("\n[3] greedy backward elimination (ตัดตัวท้ายสุดทีละตัว วัดบน validation)")
    order = list(imp.index)
    keep = list(order)
    curve = []
    while len(keep) >= 1:
        idx = [names.index(c) for c in keep]
        vf1, _ = rf_f1(Xtr[np.ix_(i_fit, idx)], ytr[i_fit],
                       Xtr[np.ix_(i_val, idx)], ytr[i_val])
        tf1, _ = rf_f1(Xtr[:, idx], ytr, Xte[:, idx], yte)
        auc = lof_auc(Xtr[np.ix_(i_fit, idx)], ytr[i_fit], Xtr[np.ix_(i_val, idx)], ytr[i_val])
        curve.append((len(keep), vf1, tf1, auc, list(keep)))
        rows.append(dict(step="elim", n=len(keep), val_f1=vf1, test_f1=tf1,
                         val_lof_auc=auc, dropped=keep[-1]))
        keep = keep[:-1]

    curve.reverse()
    print("     k | val F1  | test F1 | val LOF AUC | ตัวที่เพิ่มเข้ามา")
    prev = set()
    for k, vf1, tf1, auc, ks in curve:
        added = [c for c in ks if c not in prev]
        prev = set(ks)
        if k <= 10 or k % 5 == 0 or k == len(names):
            print("    %3d | %.4f | %.4f  |    %.4f   | %s"
                  % (k, vf1, tf1, auc, ", ".join(added[:3])))

    bestv = max(c[1] for c in curve)
    tol = bestv * 0.99
    minimal = min((c for c in curve if c[1] >= tol), key=lambda c: c[0])
    print("\n  val F1 ดีสุด = %.4f (ที่ k=%d)"
          % (bestv, next(c[0] for c in curve if c[1] == bestv)))
    print("  ชุดเล็กสุดที่ยังอยู่ใน 1%% ของค่าดีสุด: **k=%d** (val F1 %.4f, test F1 %.4f)"
          % (minimal[0], minimal[1], minimal[2]))
    print("  feature ชุดนั้น: %s" % ", ".join(minimal[4]))

    # ---------------------------------------------------------------- สรุป
    print("\n" + "=" * 78)
    print("สรุปสำหรับเขียนธีสิส (level=%s, split=%s)" % (a.level, a.split))
    print("=" * 78)
    print("  ใช้ทั้งหมด %d ตัว      -> test RF F1 %.4f / LOF AUC %.4f"
          % (len(names), tf1_all, auc_all))
    print("  PCA n=%d (เลือกจาก val) -> test RF F1 %.4f / LOF AUC %.4f"
          % (best[1], tf1_pca, auc_pca))
    print("  เลือก %d ตัว (เลือกจาก val) -> test RF F1 %.4f" % (minimal[0], minimal[2]))
    print("  -> ตัดได้ %d ตัวโดยเสีย F1 ไม่ถึง 1%%" % (len(names) - minimal[0]))

    if a.out:
        d = os.path.dirname(os.path.abspath(a.out))
        if d:
            os.makedirs(d, exist_ok=True)
        pd.DataFrame(rows).to_csv(a.out, index=False)
        print("\nเขียน %s" % a.out)


if __name__ == "__main__":
    main()
