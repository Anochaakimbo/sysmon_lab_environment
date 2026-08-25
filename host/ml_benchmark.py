# -*- coding: utf-8 -*-
"""
ml_benchmark.py - วัดผล ML บน merged_dataset.csv ด้วยโปรโตคอลที่ถูกต้อง 4 แบบ

ทำไมต้องมีไฟล์นี้: ตัวเลข F1/Accuracy ของงานแบบนี้เปลี่ยนได้ 40 จุด
โดยที่ข้อมูลเหมือนเดิมทุกแถว ขึ้นกับ "วิธีแบ่ง train/test" กับ "วิธีเทรน unsupervised"
เท่านั้น ถ้าไม่ระบุโปรโตคอลในธีสิส ตัวเลขจะไม่มีความหมาย

    python host/ml_benchmark.py                       # ครบทุกโปรโตคอล (event-level)
    python host/ml_benchmark.py --level process       # รวม event เป็น process ก่อน
    python host/ml_benchmark.py --protocol paper      # เฉพาะโปรโตคอลของเปเปอร์
    python host/ml_benchmark.py --out reference/bench.csv

--- โปรโตคอล ---
random    แบ่งแถวสุ่ม               -> ตัวเลขสูงสุด แต่ **ปลอม**: event หลายแถวมาจาก
                                      process เดียวกัน สุ่มแล้วไปอยู่ทั้ง train และ test
process   GroupSplit ตาม ProcessGuid -> in-distribution ที่ซื่อสัตย์ ใช้เป็นตัวเลขหลัก
scenario  Leave-scenario-out        -> โมเดลไม่เคยเห็นการโจมตีชนิดนั้นมาก่อน (zero-day)
                                      ตัวเลขต่ำสุดเสมอ และ **ไม่ได้แปลว่าข้อมูลไม่ดี**
paper     ตาม Fig.4 ของเปเปอร์       -> unsupervised: เทรนด้วย benign อย่างเดียว
                                      เทสด้วย benign ที่กันไว้ + malware ทั้งหมด
                                      WARNING: test set เป็น malware ~83% การ "ทายว่า
                                      ผิดปกติทุกแถว" จึงได้ F1 สูงถึง 0.908 อยู่แล้ว
                                      -> ต้องรายงาน AUC คู่กันเสมอ ไม่งั้นอ่านผลผิด
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
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC, OneClassSVM
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore")

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)
from paper_encoding import prepare  # noqa: E402

DEFAULT_CSV = os.path.join(_HERE, "dataset", "merged_dataset.csv")
SEED = 0


# ---------------------------------------------------------------- process-level
def aggregate_processes(df):
    """รวม event ของ process เดียวกันเป็น 1 แถว

    เหตุผล: ที่ระดับ event ตัว event เดี่ยวๆ ของมัลแวร์หน้าตาเหมือน benign มาก
    (powershell เปิดไฟล์ 1 ครั้ง) สิ่งที่แยกได้จริงคือ *รูปแบบรวม* ของ process
    เช่น เขียนไฟล์ 400 ไฟล์ใน 3 วินาที หรือต่อ IP เดิมซ้ำ 30 รอบ
    """
    df = df[df["ProcessGuid"].notna()].copy()
    df["_ts"] = pd.to_datetime(df["UtcTime"], errors="coerce")
    df["_scen"] = df["platform"].astype(str) + "|" + df["session"].astype(str)
    g = df.groupby("ProcessGuid", sort=True)

    f = pd.DataFrame(index=g.size().index)
    f["n_events"] = g.size()
    eids = sorted(int(e) for e in df["EventID"].dropna().unique())
    counts = (df.pivot_table(index="ProcessGuid", columns="EventID",
                             values="_ts", aggfunc="size")
                .reindex(f.index).fillna(0))
    for e in eids:
        f["ev_%d" % e] = counts[e] if e in counts.columns else 0
        f["frac_%d" % e] = f["ev_%d" % e] / f["n_events"]
    f["n_files"] = g["TargetFilename"].nunique()
    f["n_dst_ip"] = g["DestinationIp"].nunique()
    f["n_dst_port"] = g["DestinationPort"].nunique()
    f["n_regobj"] = g["TargetObject"].nunique()
    f["n_device"] = g["Device"].nunique()
    f["dur_s"] = (g["_ts"].max() - g["_ts"].min()).dt.total_seconds()
    f["rate"] = f["n_events"] / f["dur_s"].fillna(0).clip(lower=1)
    f["cmd_len"] = g["CommandLine"].first().astype(str).str.len()
    f["img_len"] = g["Image"].first().astype(str).str.len()
    f["pcmd_len"] = g["ParentCommandLine"].first().astype(str).str.len()
    f["depth"] = g["ancestor_depth"].max()
    f["enriched"] = g["enriched"].max()
    f = f.fillna(0).replace([np.inf, -np.inf], 0)

    y = g["label"].max().reindex(f.index).astype(int).values
    scen = g["_scen"].first().reindex(f.index).values
    proc = f.index.to_numpy()
    return f, y, scen, proc


# ---------------------------------------------------------------- splits
def make_split(kind, y, grp_proc, grp_scen, seed=SEED):
    idx = np.arange(len(y))
    if kind == "random":
        return train_test_split(idx, test_size=.3, random_state=seed, stratify=y)
    g = grp_proc if kind == "process" else grp_scen
    gss = GroupShuffleSplit(n_splits=1, test_size=.3, random_state=seed)
    return next(gss.split(idx, y, groups=g))


def paper_split(y, seed=SEED, train_frac=0.9):
    """Fig.4 ของเปเปอร์: เทรนด้วย benign อย่างเดียว, เทส = benign ที่เหลือ + malware ทั้งหมด"""
    rs = np.random.RandomState(seed)
    ben = np.where(y == 0)[0].copy()
    rs.shuffle(ben)
    n = int(len(ben) * train_frac)
    return ben[:n], np.concatenate([ben[n:], np.where(y == 1)[0]])


def transform(Xtr, Xte, n_pca):
    s = StandardScaler().fit(Xtr)
    a, b = s.transform(Xtr), s.transform(Xte)
    if n_pca:
        p = PCA(n_components=min(n_pca, a.shape[1]), random_state=SEED).fit(a)
        return p.transform(a), p.transform(b), float(p.explained_variance_ratio_.sum())
    return a, b, 1.0


def score(yte, pred, sc=None):
    r = dict(acc=accuracy_score(yte, pred),
             prec=precision_score(yte, pred, zero_division=0),
             rec=recall_score(yte, pred, zero_division=0),
             f1=f1_score(yte, pred, zero_division=0),
             flag_rate=float(np.mean(pred)))
    r["auc"] = roc_auc_score(yte, sc) if sc is not None and len(set(yte)) > 1 else np.nan
    return r


# ---------------------------------------------------------------- runners
def run_supervised(A, B, ytr, yte, tag, rows):
    models = [
        ("Naive Bayes", GaussianNB()),
        ("Decision Tree", DecisionTreeClassifier(random_state=SEED)),
        ("Random Forest", RandomForestClassifier(n_estimators=150, random_state=SEED, n_jobs=-1)),
        ("Linear SVM", LinearSVC(dual=False, max_iter=3000, random_state=SEED)),
    ]
    for name, m in models:
        m.fit(A, ytr)
        pred = m.predict(B)
        sc = m.predict_proba(B)[:, 1] if hasattr(m, "predict_proba") else m.decision_function(B)
        rows.append(dict(learning="Supervised", model=name, **tag, **score(yte, pred, sc)))


def run_unsupervised(A, ytr, B, yte, tag, rows, contamination=0.1):
    """เทรนเฉพาะแถว benign ของ train เสมอ (novelty detection ที่ถูกต้องตามนิยาม)"""
    Ab = A[ytr == 0] if ytr is not None else A
    rs = np.random.RandomState(SEED)
    sub = Ab[rs.choice(len(Ab), min(6000, len(Ab)), replace=False)]
    models = [
        ("Isolation Forest", IsolationForest(n_estimators=200, contamination=contamination,
                                             random_state=SEED, n_jobs=-1).fit(Ab)),
        ("Local Outlier Factor", LocalOutlierFactor(n_neighbors=20, novelty=True,
                                                    contamination=contamination).fit(Ab)),
        ("One-Class SVM", OneClassSVM(kernel="rbf", gamma="scale", nu=contamination).fit(sub)),
    ]
    for name, m in models:
        pred = (m.predict(B) == -1).astype(int)
        rows.append(dict(learning="Unsupervised", model=name, **tag,
                         **score(yte, pred, -m.score_samples(B))))
    # ฐานอ้างอิงที่ต้องพิมพ์คู่กันเสมอ - ถ้าโมเดลไม่ชนะบรรทัดนี้ แปลว่าไม่ได้ตรวจจับอะไรเลย
    rows.append(dict(learning="Unsupervised", model="[baseline] flag-everything", **tag,
                     **score(yte, np.ones_like(yte), None)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default=DEFAULT_CSV)
    ap.add_argument("--level", choices=["event", "process"], default="event")
    ap.add_argument("--protocol", choices=["all", "random", "process", "scenario", "paper"],
                    default="all")
    ap.add_argument("--pca", type=int, default=9, help="0 = ไม่ใช้ PCA")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    print("อ่าน %s  (level=%s, pca=%s)" % (a.csv, a.level, a.pca or "off"))
    if a.level == "event":
        X, y, _, df, _ = prepare([a.csv], verbose=True)
        y = y.values
        grp_proc = df["ProcessGuid"].fillna("NA").astype(str).values
        grp_scen = (df["platform"].astype(str) + "|" + df["session"].astype(str)).values
        X = X.values
    else:
        df = pd.read_csv(a.csv, low_memory=False)
        Xdf, y, grp_scen, grp_proc = aggregate_processes(df)
        X = Xdf.values
        print("  รวมเป็น process-level: %d process, %d feature" % (X.shape[0], X.shape[1]))

    print("  %d แถว x %d feature  malicious=%.3f\n" % (X.shape[0], X.shape[1], y.mean()))

    protos = ["random", "process", "scenario", "paper"] if a.protocol == "all" else [a.protocol]
    rows = []
    for proto in protos:
        if proto == "paper":
            tr, te = paper_split(y)
        else:
            tr, te = make_split(proto, y, grp_proc, grp_scen)
        ytr, yte = y[tr], y[te]
        A, B, evr = transform(X[tr], X[te], a.pca)
        tag = dict(protocol=proto, level=a.level,
                   n_feat=X.shape[1], pca=a.pca, evr=round(evr, 3),
                   test_mal=round(float(yte.mean()), 4))
        print("--- %s: train %d / test %d  test malicious=%.3f  majority-acc=%.3f"
              % (proto, len(tr), len(te), yte.mean(), max(yte.mean(), 1 - yte.mean())))
        if proto != "paper":     # paper protocol ไม่มี malware ใน train เทรน supervised ไม่ได้
            run_supervised(A, B, ytr, yte, tag, rows)
        run_unsupervised(A, ytr if proto != "paper" else None, B, yte, tag, rows)

    res = pd.DataFrame(rows)[["learning", "protocol", "level", "model", "n_feat", "pca",
                              "test_mal", "acc", "prec", "rec", "f1", "auc", "flag_rate"]]
    pd.set_option("display.width", 200)
    print("\n" + res.round(4).to_string(index=False))
    if a.out:
        d = os.path.dirname(os.path.abspath(a.out))
        if d:
            os.makedirs(d, exist_ok=True)
        res.to_csv(a.out, index=False)
        print("\nเขียน %s" % a.out)


if __name__ == "__main__":
    main()
