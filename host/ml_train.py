# -*- coding: utf-8 -*-
"""
ml_train.py - เทรนโมเดลตามเปเปอร์ (Achmad et al. 2025) แบบที่โปรโตคอลถูกต้อง
              แล้วเซฟเป็น .pkl ไปใช้กับ CSV ที่ไม่ได้อยู่ในชุด train

ต่างจากโค้ดรอบแรกตรงไหน (ดู docs/ml_results_review.md):
  1. unsupervised เทรนด้วย **benign อย่างเดียว** ตาม Fig. 4 ของเปเปอร์
     (เทรนด้วยข้อมูลผสม -> Isolation Forest ได้ AUC 0.44 แย่กว่าโยนเหรียญ)
  2. แบ่ง train/test แบบ **GroupSplit** ไม่ใช่สุ่มแถว
     (event หลายแถวมาจาก process เดียวกัน สุ่มแล้วรั่วข้าม train/test -> F1 ปลอม)
  3. encoder **fit จาก train เท่านั้น** แล้วเซฟลง pkl
     (ของเดิม factorize ทั้ง dataset = ข้อมูล test รั่วเข้า encoder และเอาไป deploy ไม่ได้)
  4. รวม event เป็น **process-level** ได้ (--level process) ซึ่งได้ผลดีกว่ามาก
  5. ทุกตาราง unsupervised พิมพ์ baseline "flag ทุกแถว" คู่เสมอ + รายงาน AUC
  6. เลือกจำนวน PCA component จาก **validation set ที่แยกจาก test** ไม่ใช่จาก test

ใช้งาน
------
    # ตัวเลขหลักที่ควรใส่ธีสิส
    python host/ml_train.py --level process --split process --pca-search

    # เทียบกับเปเปอร์ตรงๆ (unsupervised: เทรน benign ล้วน, เทส benign+malware)
    python host/ml_train.py --level event --split paper

    # เคส zero-day: ไม่เคยเห็นการโจมตีชนิดที่เอามาเทส
    python host/ml_train.py --level process --split scenario

    # เพิ่มโมเดลบอกว่าเป็นมัลแวร์ตระกูลไหน (miner/ransomware/trojan/botnet/exploit)
    python host/ml_train.py --level process --split process --family

ผลลัพธ์
------
    reference/ml_results.csv       ตารางผล (schema เดิม + AUC + Protocol)
    models/<level>_<split>.pkl     โมเดล + encoder + scaler + pca -> ใช้กับ ml_predict.py
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

import joblib
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC, OneClassSVM
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings("ignore")

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
SEED = 0

DEFAULT_CSV = os.path.join(_HERE, "dataset", "merged_dataset.csv")

# --------------------------------------------------------------------------
# คอลัมน์ที่ห้ามเป็น feature
#   PAPER_DROP  = เปเปอร์ตัดเอง (Image ตัดเพราะ "direct association with label")
#   OURS_DROP   = bookkeeping ของ pipeline เรา ถ้าใส่เข้าไปคือรั่ว label ตรงๆ
# --------------------------------------------------------------------------
PAPER_DROP = ["Image", "ProcessId", "ProcessGuid", "ParentProcessGuid",
              "UtcTime", "computer", "host_ip", "recv_timestamp"]
OURS_DROP = ["record_id", "session", "run_id", "platform", "label", "label_method",
             "is_seed", "enrich_method", "root_image", "LogonGuid",
             "CreationUtcTime", "family"]
DROP = set(PAPER_DROP) | set(OURS_DROP)

# --------------------------------------------------------------------------
# feature ที่ "ไม่ใช่พฤติกรรมของ process แต่เป็นผลพลอยได้ของ pipeline เราเอง"
#   ancestor_depth / depth : คำนวณจาก lineage tree ตัวเดียวกับที่ใช้ตัดสิน label
#                            วัดแล้ว depth >= 6 -> malicious 100%, depth = -1 -> benign 99.3%
#   enriched / parent_known: บอกว่า enrichment หา parent เจอไหม ไม่ใช่พฤติกรรม
#   img_len                : ความยาวของ Image ซึ่งเปเปอร์ตัดทิ้งเองเพราะ
#                            "direct association with the target variable"
#   CurrentDirectory       : 🚨 รั่วตรงๆ - `/tmp/lab_sandbox/exploit` = malicious 100%,
#                            `C:\lab_sandbox\` = 99.9% เพราะนี่คือ **seed directory
#                            ที่ lineage labeler ใช้ตัดสิน label** ไม่ใช่พฤติกรรม
# ใส่ --drop-derived เพื่อตัดออก แล้วรายงานตัวเลขทั้งสองแบบในธีสิส
# --------------------------------------------------------------------------
DERIVED_DROP = ["ancestor_depth", "depth", "enriched", "parent_known", "img_len",
                "CurrentDirectory"]

CARDINALITY_THRESHOLD = 21   # ตามเปเปอร์: < 21 ค่า -> label encoding, >= 21 -> ความยาวสตริง

# hyperparameter ที่เปเปอร์หาได้จาก random search (หัวข้อ 4.3) ใช้เป็นค่าตั้งต้น
PAPER_HP = {
    "Naive Bayes": dict(var_smoothing=1e-8),
    "Decision Tree": dict(criterion="entropy", max_depth=17, min_samples_split=14,
                          min_samples_leaf=5, max_features="log2"),
    "Random Forest": dict(criterion="gini", n_estimators=70, max_depth=None,
                          min_samples_split=2, min_samples_leaf=9,
                          max_features="sqrt", bootstrap=False),
    "SVM": dict(C=10, gamma="scale", kernel="rbf"),
}


# ==========================================================================
# encoder ที่ fit ได้/เซฟได้ (ของเดิม factorize ทั้ง dataset เลยเอาไป deploy ไม่ได้)
# ==========================================================================
def _is_numeric(s):
    """เช็คด้วย API ของ pandas ไม่ใช่เทียบชื่อ dtype

    ⚠️ เคยพลาดมาแล้ว: pandas 3 เปลี่ยน dtype ของคอลัมน์ข้อความจาก `object` เป็น `str`
    โค้ดที่เทียบ `dtype != object` จึงมองคอลัมน์ข้อความเป็นตัวเลข แล้ว to_numeric
    ทำให้ทั้งคอลัมน์กลายเป็น -1 เงียบๆ 27 คอลัมน์ (CommandLine, User, TargetObject ...)
    โมเดลยังเทรนผ่าน ยังได้ตัวเลขออกมา แค่ต่ำลงเฉยๆ - ไม่มีอะไรฟ้อง
    """
    return (pd.api.types.is_numeric_dtype(s)
            or pd.api.types.is_bool_dtype(s)
            or pd.api.types.is_datetime64_any_dtype(s))


def assert_matrix_sane(X, names, where=""):
    """throw ถ้าคอลัมน์กลายเป็นค่าคงที่เยอะผิดปกติ - กันกรณีข้างบนเกิดซ้ำ"""
    const = [n for i, n in enumerate(names) if np.all(X[:, i] == X[0, i])]
    if len(const) > 0.30 * len(names):
        raise RuntimeError(
            "%s: feature ที่เป็นค่าคงที่ %d/%d ตัว (%.0f%%) - encoder น่าจะอ่าน dtype ผิด\n"
            "  ตัวอย่าง: %s" % (where, len(const), len(names),
                                len(const) / len(names) * 100, ", ".join(const[:10])))
    return const


class SysmonEncoder:
    """encode ตามเปเปอร์ หัวข้อ 3.1 แต่จำ mapping ไว้เพื่อใช้กับข้อมูลใหม่

    null -> -1 ทุกที่
    categorical < 21 ค่า  -> label encoding (ค่าที่ไม่เคยเห็นตอน fit -> -1)
    categorical >= 21 ค่า -> ความยาวสตริง
    numeric               -> คงค่าเดิม

    ทำไมไม่ใช้ one-hot/factorize ทั้งชุด: ค่าฝั่ง Linux กับ Windows ไม่ทับกันเลย
    (`/usr/bin/bash` vs `C:\\Windows\\...`) จะได้เลขคนละช่วง -> โมเดลแยก platform
    ได้ทันที 100% แล้วใช้ทางลัดนั้นแทนการเรียนพฤติกรรมมัลแวร์
    """

    def __init__(self, threshold=CARDINALITY_THRESHOLD):
        self.threshold = threshold
        self.kinds_ = {}       # col -> "numeric" | "cat" | "strlen"
        self.maps_ = {}        # col -> {value: code}
        self.features_ = []

    def fit(self, df):
        df = df.replace("-", np.nan)
        cols = [c for c in df.columns if c not in DROP and not str(c).startswith("_")]
        self.features_ = []
        for c in cols:
            s = df[c]
            if s.isna().all():                      # ขั้นที่ 2 ของเปเปอร์: ตัดคอลัมน์ null ล้วน
                continue
            self.features_.append(c)
            if _is_numeric(s):
                self.kinds_[c] = "numeric"
                continue
            s = s.astype("string")
            if s.nunique(dropna=True) < self.threshold:
                self.kinds_[c] = "cat"
                vals = sorted(v for v in s.dropna().unique())
                self.maps_[c] = {v: i for i, v in enumerate(vals)}
            else:
                self.kinds_[c] = "strlen"
        return self

    def transform(self, df):
        df = df.replace("-", np.nan)
        out = {}
        for c in self.features_:
            kind = self.kinds_[c]
            if c not in df.columns:                 # CSV ใหม่ขาดคอลัมน์ -> ถือว่า null
                out[c] = np.full(len(df), -1.0)
                continue
            s = df[c]
            if kind == "numeric":
                out[c] = pd.to_numeric(s, errors="coerce").fillna(-1).astype(float).values
            elif kind == "cat":
                out[c] = s.astype("string").map(self.maps_[c]).fillna(-1).astype(float).values
            else:
                out[c] = s.astype("string").str.len().fillna(-1).astype(float).values
        return pd.DataFrame(out, index=df.index)[self.features_]

    def fit_transform(self, df):
        return self.fit(df).transform(df)


# ==========================================================================
# process-level aggregation
# ==========================================================================
PROC_FEATURES_DOC = """รวม event ของ ProcessGuid เดียวกันเป็น 1 แถว

event เดี่ยวๆ ของมัลแวร์หน้าตาเหมือน benign - powershell เขียนไฟล์ 1 ไฟล์
ไม่มีอะไรบอกได้ว่าอันตราย สิ่งที่แยกได้จริงคือรูปแบบรวมของ process:
เขียน 400 ไฟล์ใน 3 วินาที / ต่อ IP เดิมซ้ำ 30 รอบ / แตะ registry 200 key"""

PROC_EVENT_IDS = [1, 2, 3, 4, 5, 8, 9, 11, 12, 13, 23]   # ตรึงไว้ให้ CSV ใหม่ได้คอลัมน์เท่ากัน


def aggregate_processes(df):
    df = df[df["ProcessGuid"].notna()].copy()
    df["_ts"] = pd.to_datetime(df["UtcTime"], errors="coerce")
    g = df.groupby("ProcessGuid", sort=True)

    f = pd.DataFrame(index=g.size().index)
    f["n_events"] = g.size()
    counts = df.pivot_table(index="ProcessGuid", columns="EventID",
                            values="_ts", aggfunc="size").reindex(f.index).fillna(0)
    for e in PROC_EVENT_IDS:
        f["ev_%d" % e] = counts[e] if e in counts.columns else 0.0
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
    f = f.fillna(0).replace([np.inf, -np.inf], 0).astype(float)

    meta = pd.DataFrame(index=f.index)
    meta["label"] = g["label"].max() if "label" in df.columns else 0
    meta["session"] = g["session"].first() if "session" in df.columns else "?"
    meta["run"] = g["run_id"].first() if "run_id" in df.columns else meta["session"]
    meta["platform"] = g["platform"].first() if "platform" in df.columns else "?"
    meta["proc"] = f.index.to_numpy()
    return f, meta


def family_of(session):
    """ชื่อ session -> ตระกูลมัลแวร์ (benign / miner / ransomware / trojan / botnet / exploit)"""
    s = str(session).lower()
    s = s.replace("_win", "").replace("_real", "")
    for fam in ("benign", "miner", "ransomware", "trojan", "botnet", "exploit"):
        if s.startswith(fam):
            return fam
    return "other"


# ==========================================================================
# โหลด + เตรียมเมทริกซ์
# ==========================================================================
def load(csv, level):
    """คืน (df_raw_features, meta) โดย meta มี label / session / platform / proc"""
    raw = pd.read_csv(csv, low_memory=False)
    if "label" not in raw.columns:
        raw["label"] = 0
    if level == "process":
        feats, meta = aggregate_processes(raw)
    else:
        feats = raw
        meta = pd.DataFrame(index=raw.index)
        meta["label"] = pd.to_numeric(raw["label"], errors="coerce").fillna(0).astype(int)
        meta["session"] = raw.get("session", "?")
        meta["run"] = raw["run_id"] if "run_id" in raw.columns else meta["session"]
        meta["platform"] = raw.get("platform", "?")
        meta["proc"] = raw.get("ProcessGuid", pd.Series(raw.index)).fillna("NA").astype(str)
        # ขั้นที่ 3 ของเปเปอร์: ตัดแถวซ้ำ (ไม่นับคอลัมน์ที่ใช้ trace เท่านั้น)
        trace = [c for c in ("record_id", "recv_timestamp", "UtcTime") if c in feats.columns]
        sub = [c for c in feats.columns if c not in trace]
        keep = ~feats.replace("-", np.nan).duplicated(subset=sub)
        feats, meta = feats[keep].reset_index(drop=True), meta[keep].reset_index(drop=True)
    meta["family"] = meta["session"].map(family_of)
    meta["scen"] = meta["platform"].astype(str) + "|" + meta["session"].astype(str)
    return feats, meta


def make_split(kind, meta, seed=SEED, test_size=0.3):
    y = meta["label"].values
    idx = np.arange(len(y))
    if kind == "random":
        return train_test_split(idx, test_size=test_size, random_state=seed, stratify=y)
    if kind == "paper":
        # Fig.4: เทรนด้วย benign อย่างเดียว, เทสด้วย benign ที่กันไว้ + malware ทั้งหมด
        rs = np.random.RandomState(seed)
        ben = np.where(y == 0)[0].copy()
        rs.shuffle(ben)
        n = int(len(ben) * 0.9)
        return ben[:n], np.concatenate([ben[n:], np.where(y == 1)[0]])
    groups = {"process": meta["proc"], "run": meta["run"],
              "scenario": meta["scen"]}[kind].values
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    return next(gss.split(idx, y, groups=groups))


# ==========================================================================
# เมตริก
# ==========================================================================
def metrics(yte, pred, score=None):
    r = dict(Accuracy=accuracy_score(yte, pred),
             Precision=precision_score(yte, pred, zero_division=0),
             Recall=recall_score(yte, pred, zero_division=0),
             F1=f1_score(yte, pred, zero_division=0),
             Flag_Rate=float(np.mean(pred)))
    r["AUC"] = (roc_auc_score(yte, score)
                if score is not None and len(np.unique(yte)) > 1 else np.nan)
    return r


def show(rows):
    df = pd.DataFrame(rows)
    pd.set_option("display.width", 220)
    print("\n" + df.round(4).to_string(index=False))
    return df


# ==========================================================================
# main
# ==========================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=DEFAULT_CSV)
    ap.add_argument("--level", choices=["event", "process"], default="process")
    ap.add_argument("--split", choices=["process", "run", "scenario", "random", "paper"],
                    default="process")
    ap.add_argument("--pca", type=int, default=0,
                    help="จำนวน component (0 = ไม่ใช้ PCA). ถ้าใส่ --pca-search จะถูกทับ")
    ap.add_argument("--pca-search", action="store_true",
                    help="ไล่หา n ที่ F1 ดีสุดบน validation (ตามเปเปอร์ แต่ไม่ดูจาก test)")
    ap.add_argument("--contamination", type=float, default=None,
                    help="ค่าตั้งต้นของ unsupervised (default: จูนจาก validation ถ้าทำได้)")
    ap.add_argument("--tune-metric", choices=["f1", "accuracy"], default="f1",
                    help="จูน threshold ของ unsupervised ให้ดีที่สุดตามเมตริกไหน")
    ap.add_argument("--drop-derived", action="store_true",
                    help="ตัด feature ที่เป็น artifact ของ pipeline (%s)"
                         % ", ".join(DERIVED_DROP))
    ap.add_argument("--family", action="store_true",
                    help="เทรนโมเดลบอกตระกูลมัลแวร์เพิ่ม (ใช้ตอน deploy)")
    ap.add_argument("--svm-max-train", type=int, default=20000,
                    help="SVM rbf เป็น O(n^2) - สุ่มลดจำนวนแถวเทรนถ้าเกินค่านี้")
    ap.add_argument("--results", default=os.path.join(_ROOT, "reference", "ml_results.csv"))
    ap.add_argument("--model-dir", default=os.path.join(_ROOT, "models"))
    ap.add_argument("--no-save", action="store_true")
    a = ap.parse_args()

    print("=" * 78)
    print("อ่าน %s" % a.csv)
    feats, meta = load(a.csv, a.level)
    y = meta["label"].values
    print("  level=%s  %d แถว  malicious=%.3f  session=%d"
          % (a.level, len(feats), y.mean(), meta["scen"].nunique()))
    nrun = meta["run"].nunique()
    if a.split == "run" and nrun <= meta["scen"].nunique():
        print("  !! run_id มี %d ค่า เท่ากับจำนวน scenario - แต่ละ scenario เก็บรอบเดียว\n"
              "     --split run จะเหมือน --split scenario ต้องเก็บซ้ำหลายรอบก่อน" % nrun)

    tr, te = make_split(a.split, meta)
    ytr, yte = y[tr], y[te]
    print("  split=%s  train %d / test %d  test malicious=%.3f  (ทายคลาสใหญ่ได้ %.3f)"
          % (a.split, len(tr), len(te), yte.mean(), max(yte.mean(), 1 - yte.mean())))
    if a.split == "random":
        print("  !! random split ให้ตัวเลขสูงเกินจริง - event หลายแถวมาจาก process เดียวกัน")

    if a.drop_derived:
        gone = [c for c in feats.columns if c in DERIVED_DROP]
        feats = feats.drop(columns=gone)
        print("  --drop-derived: ตัด %s" % (", ".join(gone) if gone else "(ไม่มีให้ตัด)"))

    # ---------- encode: fit จาก train เท่านั้น ----------
    enc = SysmonEncoder()
    if a.level == "event":
        enc.fit(feats.iloc[tr])
        Xtr = enc.transform(feats.iloc[tr]).values
        Xte = enc.transform(feats.iloc[te]).values
        names = enc.features_
    else:
        enc = None
        Xtr, Xte = feats.iloc[tr].values, feats.iloc[te].values
        names = list(feats.columns)
    const = assert_matrix_sane(Xtr, names, "หลัง encode ชุด train")
    print("  feature = %d ตัว%s" % (len(names),
          ("  (ค่าคงที่ %d ตัว)" % len(const)) if const else ""))
    if a.level == "event":
        from collections import Counter
        k = Counter(enc.kinds_[c] for c in names)
        print("    numeric %d / label-encoded %d / ความยาวสตริง %d"
              % (k["numeric"], k["cat"], k["strlen"]))

    scaler = StandardScaler().fit(Xtr)
    Atr, Ate = scaler.transform(Xtr), scaler.transform(Xte)

    # ---------- validation set ที่แยกจาก test (ใช้เลือก PCA / contamination) ----------
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=SEED)
    sub_tr, sub_val = next(gss.split(np.arange(len(tr)), ytr,
                                     groups=meta["proc"].values[tr]))
    has_val_mal = len(np.unique(ytr[sub_val])) > 1

    # ---------- PCA ----------
    n_pca = a.pca
    if a.pca_search:
        if not has_val_mal:
            print("  ข้าม --pca-search: validation ไม่มีแถว malicious (split=paper)")
        else:
            best = (-1, 0)
            for n in range(1, min(len(names), 30) + 1):
                p = PCA(n_components=n, random_state=SEED).fit(Atr[sub_tr])
                m = RandomForestClassifier(random_state=SEED, n_jobs=-1,
                                           **PAPER_HP["Random Forest"])
                m.fit(p.transform(Atr[sub_tr]), ytr[sub_tr])
                s = f1_score(ytr[sub_val], m.predict(p.transform(Atr[sub_val])),
                             zero_division=0)
                if s > best[0]:
                    best = (s, n)
            n_pca = best[1]
            print("  PCA search: n=%d (val F1=%.4f)" % (n_pca, best[0]))

    pca = None
    if n_pca:
        pca = PCA(n_components=min(n_pca, Atr.shape[1]), random_state=SEED).fit(Atr)
        Atr, Ate = pca.transform(Atr), pca.transform(Ate)
        print("  PCA %d component  explained variance = %.3f"
              % (pca.n_components_, pca.explained_variance_ratio_.sum()))

    tag = dict(Level=a.level, Protocol=a.split, Features=len(names),
               PCA_Components=(pca.n_components_ if pca else 0))
    rows, saved = [], {}

    # ================= SUPERVISED =================
    if len(np.unique(ytr)) > 1:
        print("\n--- SUPERVISED (class_weight=balanced ตามที่เปเปอร์ใช้ class balancing) ---")
        models = [
            ("Naive Bayes", GaussianNB(**PAPER_HP["Naive Bayes"])),
            ("Decision Tree", DecisionTreeClassifier(random_state=SEED,
                                                     class_weight="balanced",
                                                     **PAPER_HP["Decision Tree"])),
            ("Random Forest", RandomForestClassifier(random_state=SEED, n_jobs=-1,
                                                     class_weight="balanced",
                                                     **PAPER_HP["Random Forest"])),
            ("SVM", SVC(random_state=SEED, class_weight="balanced",
                        probability=False, **PAPER_HP["SVM"])),
        ]
        for name, m in models:
            fit_idx = np.arange(len(ytr))
            if name == "SVM" and len(fit_idx) > a.svm_max_train:
                fit_idx = np.random.RandomState(SEED).choice(
                    fit_idx, a.svm_max_train, replace=False)
                print("    (SVM สุ่มลดแถวเทรนเหลือ %d - rbf เป็น O(n^2))" % a.svm_max_train)
            m.fit(Atr[fit_idx], ytr[fit_idx])
            pred = m.predict(Ate)
            sc = (m.predict_proba(Ate)[:, 1] if hasattr(m, "predict_proba")
                  else m.decision_function(Ate))
            rows.append(dict(Learning_Type="Supervised", Algorithm=name, **tag,
                             **metrics(yte, pred, sc)))
            saved[name] = m
            print("    %-14s acc=%.4f  f1=%.4f" % (name, rows[-1]["Accuracy"], rows[-1]["F1"]))
    else:
        print("\n--- ข้าม SUPERVISED: train ไม่มีแถว malicious (split=paper) ---")

    # ================= UNSUPERVISED =================
    # เทรนด้วย benign อย่างเดียวเสมอ - นี่คือจุดที่โค้ดรอบแรกพลาด
    print("\n--- UNSUPERVISED (เทรนด้วย benign อย่างเดียว ตาม Fig.4 ของเปเปอร์) ---")
    Ab = Atr[ytr == 0]
    print("    benign ที่ใช้เทรน %d แถว" % len(Ab))
    rs = np.random.RandomState(SEED)
    sub = Ab[rs.choice(len(Ab), min(6000, len(Ab)), replace=False)]

    cont = a.contamination if a.contamination is not None else 0.1
    unsup = [
        ("Isolation Forest", IsolationForest(n_estimators=200, contamination=cont,
                                             random_state=SEED, n_jobs=-1).fit(Ab)),
        ("Local Outlier Factor", LocalOutlierFactor(n_neighbors=20, novelty=True,
                                                    contamination=cont).fit(Ab)),
        ("One-Class SVM", OneClassSVM(kernel="rbf", gamma="scale", nu=cont).fit(sub)),
    ]
    for name, m in unsup:
        score = -m.score_samples(Ate)
        pred = (m.predict(Ate) == -1).astype(int)
        r = metrics(yte, pred, score)
        # จูน threshold จาก validation ถ้ามี malicious ให้จูน (ไม่แตะ test)
        if a.contamination is None and has_val_mal:
            val_sc = -m.score_samples(Atr[sub_val])
            fn = (f1_score if a.tune_metric == "f1"
                  else lambda t_, p_, **k: accuracy_score(t_, p_))
            best = max(((fn(ytr[sub_val],
                            (val_sc >= np.quantile(val_sc, 1 - c)).astype(int),
                            zero_division=0), c)
                        for c in np.arange(0.05, 0.65, 0.05)))
            thr = np.quantile(-m.score_samples(Atr), 1 - best[1])
            pred = (score >= thr).astype(int)
            r = metrics(yte, pred, score)
            r["Tuned_Contamination"] = round(float(best[1]), 2)
        rows.append(dict(Learning_Type="Unsupervised", Algorithm=name, **tag, **r))
        saved[name] = m
        print("    %-22s acc=%.4f  f1=%.4f  AUC=%.4f"
              % (name, r["Accuracy"], r["F1"], r["AUC"]))

    # baseline ที่ต้องพิมพ์คู่เสมอ - โมเดลไหนไม่ชนะบรรทัดนี้ = ไม่ได้ตรวจจับอะไรเลย
    b = metrics(yte, np.ones_like(yte))
    rows.append(dict(Learning_Type="Unsupervised", Algorithm="[baseline] flag ทุกแถว",
                     **tag, **b))
    print("    %-22s acc=%.4f  f1=%.4f   <-- ไม่คิดอะไรเลย ต้องชนะบรรทัดนี้"
          % ("[baseline]", b["Accuracy"], b["F1"]))

    # ================= ตระกูลมัลแวร์ (ทางเลือก) =================
    fam_model = None
    if a.family and len(np.unique(ytr)) > 1:
        print("\n--- FAMILY (บอกว่าเป็นมัลแวร์ตระกูลไหน ใช้ตอน deploy) ---")
        fam = meta["family"].values
        fam_model = RandomForestClassifier(n_estimators=200, random_state=SEED,
                                           n_jobs=-1, class_weight="balanced")
        fam_model.fit(Atr, fam[tr])
        print(classification_report(fam[te], fam_model.predict(Ate), zero_division=0))

    # ================= เขียนผล =================
    res = show(rows)
    os.makedirs(os.path.dirname(os.path.abspath(a.results)), exist_ok=True)
    cols = ["Learning_Type", "Algorithm", "Level", "Protocol", "Features",
            "PCA_Components", "Accuracy", "Precision", "Recall", "F1", "AUC", "Flag_Rate"]
    cols += [c for c in res.columns if c not in cols]
    mode, header = ("a", False) if os.path.exists(a.results) else ("w", True)
    res[cols].to_csv(a.results, mode=mode, header=header, index=False)
    print("\nเขียนผล -> %s%s" % (a.results, "  (ต่อท้ายของเดิม)" if mode == "a" else ""))

    if not a.no_save:
        os.makedirs(a.model_dir, exist_ok=True)
        path = os.path.join(a.model_dir, "%s_%s.pkl" % (a.level, a.split))
        joblib.dump(dict(level=a.level, split=a.split, encoder=enc, scaler=scaler,
                         pca=pca, feature_names=names, models=saved,
                         family_model=fam_model,
                         train_malicious_rate=float(ytr.mean()),
                         proc_event_ids=PROC_EVENT_IDS), path)
        print("เซฟโมเดล -> %s  (เอาไปใช้ต่อด้วย ml_predict.py)" % path)


if __name__ == "__main__":
    main()
