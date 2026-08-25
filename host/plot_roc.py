# -*- coding: utf-8 -*-
"""
plot_roc.py - วาด ROC curve ของทุกอัลกอริทึม สำหรับใส่สไลด์

    python host/plot_roc.py                        # ได้ reference/roc_curve.png
    python host/plot_roc.py --demo                 # โชว์วิธีคำนวณทีละขั้นด้วยตัวอย่าง 8 แถว
    python host/plot_roc.py --out docs/roc.png

ROC curve = กราฟที่ได้จากการ "เลื่อนเส้นตัด" ไปทีละค่า แล้วบันทึกว่าที่เส้นตัดนั้น
  แกน Y  TPR (True Positive Rate)  = จับมัลแวร์ได้กี่ % ของมัลแวร์ทั้งหมด   (= recall)
  แกน X  FPR (False Positive Rate) = กล่าวหา benign ผิดกี่ % ของ benign ทั้งหมด
AUC = พื้นที่ใต้เส้นนั้น
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

warnings.filterwarnings("ignore")

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)


def demo():
    """ตัวอย่าง 8 แถว - คำนวณ ROC ด้วยมือให้ดูทีละขั้น"""
    from sklearn.metrics import roc_auc_score, roc_curve
    score = np.array([0.95, 0.90, 0.80, 0.65, 0.55, 0.40, 0.30, 0.10])
    y = np.array([1, 1, 0, 1, 0, 1, 0, 0])          # 4 malicious / 4 benign

    print("ตัวอย่าง 8 แถว เรียงคะแนนจากมากไปน้อย")
    print("  %-8s %-8s %s" % ("score", "จริง", ""))
    for s, t in zip(score, y):
        print("  %-8.2f %-8s %s" % (s, "MAL" if t else "ben", "#" * int(s * 20)))

    P, N = y.sum(), (1 - y).sum()
    print("\nเลื่อนเส้นตัดลงมาทีละแถว แล้วนับ")
    print("  %-10s %-6s %-6s %-8s %-8s" % ("เส้นตัด", "TP", "FP", "TPR", "FPR"))
    print("  %-10s %-6d %-6d %-8.2f %-8.2f" % (">1.00", 0, 0, 0, 0))
    tp = fp = 0
    for s, t in zip(score, y):
        tp += t
        fp += 1 - t
        print("  %-10s %-6d %-6d %-8.2f %-8.2f"
              % (">=%.2f" % s, tp, fp, tp / P, fp / N))

    print("\nเอาจุด (FPR, TPR) ทั้งหมดมาต่อกัน = ROC curve")
    fpr, tpr, thr = roc_curve(y, score)
    print("  จุดที่ได้:", " -> ".join("(%.2f,%.2f)" % (a, b) for a, b in zip(fpr, tpr)))
    print("  AUC = พื้นที่ใต้เส้น = %.4f" % roc_auc_score(y, score))
    print("\n  ตรวจด้วยนิยามอีกแบบ: สุ่มคู่ mal-ben ทุกคู่ (4x4=16 คู่)")
    m, b = score[y == 1], score[y == 0]
    win = sum(1 for x in m for z in b if x > z) + 0.5 * sum(1 for x in m for z in b if x == z)
    print("     mal ได้คะแนนสูงกว่า %d จาก 16 คู่ = %.4f  <- ตรงกับ AUC" % (win, win / 16))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(_HERE, "dataset", "merged_dataset.csv"))
    ap.add_argument("--level", choices=["event", "process"], default="process")
    ap.add_argument("--split", default="process")
    ap.add_argument("--out", default=os.path.join(_ROOT, "reference", "roc_curve.png"))
    ap.add_argument("--demo", action="store_true")
    a = ap.parse_args()

    if a.demo:
        demo()
        return

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib import font_manager as fm

    # ต้องตั้งฟอนต์ที่มีสระ/วรรณยุกต์ไทย ไม่งั้น matplotlib วาดเป็นกล่องสี่เหลี่ยม
    have = {f.name for f in fm.fontManager.ttflist}
    for cand in ("Leelawadee UI", "Tahoma", "Microsoft Sans Serif"):
        if cand in have:
            plt.rcParams["font.family"] = cand
            break
    plt.rcParams["axes.unicode_minus"] = False
    from sklearn.metrics import roc_auc_score, roc_curve
    from sklearn.preprocessing import StandardScaler
    from ml_train import (DERIVED_DROP, SEED, load, make_split,
                          supervised_models, unsupervised_models)

    feats, meta = load(a.csv, a.level)
    feats = feats.drop(columns=[c for c in feats.columns if c in DERIVED_DROP])
    y = meta["label"].values
    tr, te = make_split(a.split, meta)
    sc = StandardScaler().fit(feats.iloc[tr])
    A, B = sc.transform(feats.iloc[tr]), sc.transform(feats.iloc[te])
    ytr, yte = y[tr], y[te]
    print("level=%s split=%s  train %d / test %d (malicious %.1f%%)"
          % (a.level, a.split, len(tr), len(te), yte.mean() * 100))

    curves = []
    for name, m in supervised_models():
        fit = np.arange(len(ytr))
        if name == "SVM" and len(fit) > 20000:
            fit = np.random.RandomState(SEED).choice(fit, 20000, replace=False)
        m.fit(A[fit], ytr[fit])
        s_ = (m.predict_proba(B)[:, 1] if hasattr(m, "predict_proba")
              else m.decision_function(B))
        curves.append(("Supervised", name, s_))
    for name, m in unsupervised_models(A[ytr == 0], 0.3):
        curves.append(("Unsupervised", name, -m.score_samples(B)))

    fig, ax = plt.subplots(figsize=(7.2, 6.4), dpi=160)
    sup_c = ["#1d4ed8", "#0f9d58", "#b45309", "#7c3aed"]
    uns_c = ["#dc2626", "#db2777", "#0891b2"]
    si = ui = 0
    for kind, name, s_ in sorted(curves, key=lambda c: -roc_auc_score(yte, c[2])):
        fpr, tpr, _ = roc_curve(yte, s_)
        auc = roc_auc_score(yte, s_)
        if kind == "Supervised":
            col, ls = sup_c[si % 4], "-"
            si += 1
        else:
            col, ls = uns_c[ui % 3], "--"
            ui += 1
        ax.plot(fpr, tpr, ls, color=col, lw=1.9,
                label="%-22s AUC %.4f" % (name, auc))

    ax.plot([0, 1], [0, 1], ":", color="#94a3b8", lw=1.4, label="%-22s AUC 0.5000" % "random guess")
    ax.set_xlabel("False Positive Rate  (กล่าวหา benign ผิด)")
    ax.set_ylabel("True Positive Rate  (จับมัลแวร์ได้)")
    ax.set_title("ROC — %s-level, %d feature, group split by ProcessGuid"
                 % (a.level, feats.shape[1]), fontsize=11)
    ax.set_xlim(-0.01, 1.01)
    ax.set_ylim(-0.01, 1.01)
    ax.grid(alpha=.25, lw=.6)
    ax.legend(loc="lower right", fontsize=8.5, prop={"family": "monospace"}, framealpha=.95)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    fig.tight_layout()

    d = os.path.dirname(os.path.abspath(a.out))
    if d:
        os.makedirs(d, exist_ok=True)
    fig.savefig(a.out)
    print("เขียน %s" % a.out)


if __name__ == "__main__":
    main()
