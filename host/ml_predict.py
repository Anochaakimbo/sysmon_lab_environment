# -*- coding: utf-8 -*-
"""
ml_predict.py - เอาโมเดล .pkl จาก ml_train.py ไปตรวจ CSV ที่ไม่ได้อยู่ในชุด train

    # ตรวจ log ใหม่ (มีคอลัมน์ label -> รายงานความแม่นให้ด้วย)
    python host/ml_predict.py models/process_process.pkl host/dataset/xxx_labeled.csv

    # ไม่มี label ก็ตรวจได้ - รายงานแค่ว่าเจออะไรบ้าง
    python host/ml_predict.py models/process_process.pkl new_log.csv --model "Random Forest"

    # เขียนผลรายแถวออกไฟล์เพื่อไล่ดูเอง
    python host/ml_predict.py models/process_process.pkl new_log.csv --out pred.csv

⚠️ CSV ที่เอามาตรวจต้องผ่าน pipeline เดียวกัน (parse -> enrich -> label)
   ไม่งั้นคอลัมน์ไม่ตรง encoder จะเติม -1 ให้ทั้งคอลัมน์ แล้วผลจะเพี้ยนเงียบๆ
   สคริปต์นี้เตือนให้ถ้าคอลัมน์หายเกิน 20%
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
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)

warnings.filterwarnings("ignore")

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)
# ต้อง import เพื่อให้ joblib unpickle คลาส SysmonEncoder ได้
from ml_train import SysmonEncoder, aggregate_processes, family_of  # noqa: E402,F401


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("model", help="ไฟล์ .pkl จาก ml_train.py")
    ap.add_argument("csv", help="CSV ที่จะตรวจ")
    ap.add_argument("--model-name", "--model", dest="model_name", default=None,
                    help="ใช้โมเดลตัวไหนใน bundle (default: Random Forest ถ้ามี)")
    ap.add_argument("--out", default=None, help="เขียนผลรายแถวลงไฟล์")
    ap.add_argument("--top", type=int, default=15, help="แสดง process ที่น่าสงสัยสุดกี่ตัว")
    a = ap.parse_args()

    b = joblib.load(a.model)
    print("โมเดล: %s  (level=%s, split=%s, feature=%d, PCA=%s)"
          % (os.path.basename(a.model), b["level"], b["split"],
             len(b["feature_names"]), b["pca"].n_components_ if b["pca"] else "off"))
    print("มีให้เลือก: %s" % ", ".join(b["models"].keys()))

    raw = pd.read_csv(a.csv, low_memory=False)
    print("\nอ่าน %s -> %d แถว" % (a.csv, len(raw)))

    # ---------- เตรียมเมทริกซ์ให้เหมือนตอนเทรนเป๊ะ ----------
    if b["level"] == "process":
        feats, meta = aggregate_processes(raw)
        X = feats.reindex(columns=b["feature_names"], fill_value=0.0).values
        missing = [c for c in b["feature_names"] if c not in feats.columns]
        unit = "process"
    else:
        enc = b["encoder"]
        X = enc.transform(raw).values
        missing = [c for c in b["feature_names"] if c not in raw.columns]
        meta = pd.DataFrame(index=raw.index)
        meta["label"] = pd.to_numeric(raw.get("label"), errors="coerce")
        meta["session"] = raw.get("session", "?")
        meta["platform"] = raw.get("platform", "?")
        meta["proc"] = raw.get("ProcessGuid", pd.Series(raw.index)).astype(str)
        unit = "event"

    if missing:
        pct = len(missing) / len(b["feature_names"]) * 100
        flag = "🚨" if pct > 20 else "หมายเหตุ:"
        print("%s คอลัมน์ที่โมเดลต้องการแต่ไม่มีใน CSV %d/%d (%.0f%%): %s"
              % (flag, len(missing), len(b["feature_names"]), pct, ", ".join(missing[:8])))
        if pct > 20:
            print("   ผลที่ได้จะเพี้ยน - CSV น่าจะไม่ได้ผ่าน pipeline เดียวกัน")

    X = b["scaler"].transform(X)
    if b["pca"] is not None:
        X = b["pca"].transform(X)
    print("ตรวจ %d %s" % (len(X), unit))

    # ---------- เลือกโมเดล ----------
    name = a.model_name
    if name is None:
        name = "Random Forest" if "Random Forest" in b["models"] else list(b["models"])[0]
    if name not in b["models"]:
        _sys.exit("ไม่มีโมเดลชื่อ '%s' ใน bundle" % name)
    m = b["models"][name]

    if hasattr(m, "predict_proba"):                       # supervised
        score = m.predict_proba(X)[:, 1]
        pred = m.predict(X)
    elif hasattr(m, "decision_function") and hasattr(m, "fit_predict") is False:
        score = m.decision_function(X)
        pred = m.predict(X)
    else:                                                 # unsupervised (คืน 1/-1)
        score = -m.score_samples(X)
        pred = (m.predict(X) == -1).astype(int)
    pred = np.asarray(pred).astype(int)

    print("\n=== ผลตรวจด้วย %s ===" % name)
    print("  ชี้ว่าเป็นมัลแวร์ %d/%d (%.1f%%)" % (pred.sum(), len(pred), pred.mean() * 100))

    # ---------- ถ้ามี label ก็วัดความแม่นให้ ----------
    ytrue = meta["label"]
    if ytrue.notna().all() and ytrue.nunique() > 1:
        yt = ytrue.astype(int).values
        print("\n  เทียบกับ label จริง:")
        print("    Accuracy  %.4f" % accuracy_score(yt, pred))
        print("    Precision %.4f" % precision_score(yt, pred, zero_division=0))
        print("    Recall    %.4f" % recall_score(yt, pred, zero_division=0))
        print("    F1        %.4f" % f1_score(yt, pred, zero_division=0))
        print("    AUC       %.4f" % roc_auc_score(yt, score))
        tn, fp, fn, tp = confusion_matrix(yt, pred, labels=[0, 1]).ravel()
        print("    confusion  TN=%d FP=%d FN=%d TP=%d" % (tn, fp, fn, tp))
        base = max(yt.mean(), 1 - yt.mean())
        print("    (ทายคลาสใหญ่อย่างเดียวได้ %.4f - ต้องชนะค่านี้)" % base)
    elif ytrue.notna().all() and ytrue.nunique() == 1:
        print("\n  CSV มี label คลาสเดียว (%d) - วัด precision/recall ไม่ได้"
              % int(ytrue.iloc[0]))

    # ---------- บอกว่าเป็นมัลแวร์ตระกูลไหน ----------
    fam_model = b.get("family_model")
    out = pd.DataFrame(dict(unit=meta["proc"].values, session=meta["session"].values,
                            platform=meta["platform"].values,
                            pred=pred, score=score))
    if "label" in meta:
        out["label"] = meta["label"].values
    if fam_model is not None:
        fam = fam_model.predict(X)
        fam_p = fam_model.predict_proba(X).max(axis=1)
        out["family"] = fam
        out["family_conf"] = fam_p
        hit = out[out["pred"] == 1]
        if len(hit):
            print("\n=== มัลแวร์ที่เจอ แยกตามตระกูล (เฉพาะ %d %s ที่ถูกชี้ว่าเป็นมัลแวร์) ==="
                  % (len(hit), unit))
            tab = (hit.groupby("family")["family_conf"]
                      .agg(["size", "mean"])
                      .rename(columns={"size": "จำนวน", "mean": "ความมั่นใจเฉลี่ย"})
                      .sort_values("จำนวน", ascending=False))
            print(tab.round(3).to_string())
        else:
            print("\n  ไม่พบมัลแวร์")
    else:
        print("\n  (bundle นี้ไม่มี family model - เทรนใหม่ด้วย --family ถ้าอยากรู้ตระกูล)")

    # ---------- ตัวที่น่าสงสัยสุด ----------
    top = out.sort_values("score", ascending=False).head(a.top)
    cols = [c for c in ("unit", "session", "platform", "score", "pred", "family", "label")
            if c in top.columns]
    print("\n=== %d %s ที่คะแนนน่าสงสัยสูงสุด ===" % (len(top), unit))
    print(top[cols].round(3).to_string(index=False))

    if a.out:
        d = os.path.dirname(os.path.abspath(a.out))
        if d:
            os.makedirs(d, exist_ok=True)
        out.to_csv(a.out, index=False)
        print("\nเขียนผลรายแถว -> %s" % a.out)


if __name__ == "__main__":
    main()
