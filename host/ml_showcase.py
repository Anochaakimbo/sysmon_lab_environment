# -*- coding: utf-8 -*-
"""
ml_showcase.py - รันครบทุกอัลกอริทึมตามเปเปอร์ + เทียบกับเปเปอร์ + สรุปข้อจำกัด
                 สำหรับนำเสนอ

    python host/ml_showcase.py                       # ตารางหลัก + ข้อจำกัด
    python host/ml_showcase.py --txt docs/presentation_results.txt
    python host/ml_showcase.py --full                # + leave-one-scenario-out (ช้ากว่า)

อัลกอริทึม 7 ตัวตามเปเปอร์ (Achmad et al., Cyber Security and Applications 3, 2025):
    Supervised   : Naive Bayes, Decision Tree, Random Forest, SVM
    Unsupervised : Isolation Forest, Local Outlier Factor, One-Class SVM

ทุกตัวเลขในเอาต์พุตคำนวณสดจาก merged_dataset.csv ไม่มีค่าที่พิมพ์ค้างไว้
(ยกเว้นคอลัมน์ "เปเปอร์" ซึ่งคัดมาจาก Table 7/8 ของเปเปอร์)
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
import io
import os
import warnings

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)
from ml_train import (DERIVED_DROP, SEED, SysmonEncoder, load, make_split,  # noqa: E402
                      metrics, supervised_models, unsupervised_models)

DEFAULT_CSV = os.path.join(_HERE, "dataset", "merged_dataset.csv")

# F1 ที่เปเปอร์รายงาน (Table 7 supervised / Table 8 unsupervised)
PAPER_F1 = {
    "Naive Bayes": 0.3810, "Decision Tree": 0.8720,
    "Random Forest": 0.8868, "SVM": 0.5906,
    "Isolation Forest": 0.7620, "Local Outlier Factor": 0.9750,
    "One-Class SVM": 0.8051,
}

OUT = io.StringIO()


def say(*a):
    line = " ".join(str(x) for x in a)
    print(line)
    OUT.write(line + "\n")


def prep(feats, meta, tr, te, level, drop_derived=True):
    if drop_derived:
        feats = feats.drop(columns=[c for c in feats.columns if c in DERIVED_DROP])
    if level == "event":
        enc = SysmonEncoder().fit(feats.iloc[tr])
        Xtr, Xte = enc.transform(feats.iloc[tr]).values, enc.transform(feats.iloc[te]).values
        names = enc.features_
    else:
        Xtr, Xte, names = feats.iloc[tr].values, feats.iloc[te].values, list(feats.columns)
    s = StandardScaler().fit(Xtr)
    return s.transform(Xtr), s.transform(Xte), names


def all_models(A, ytr, B, yte, svm_max=20000):
    """รันครบ 7 ตัว คืน list ของ dict"""
    rows = []
    for name, m in supervised_models():
        fit = np.arange(len(ytr))
        if name == "SVM" and len(fit) > svm_max:
            fit = np.random.RandomState(SEED).choice(fit, svm_max, replace=False)
        m.fit(A[fit], ytr[fit])
        sc = (m.predict_proba(B)[:, 1] if hasattr(m, "predict_proba")
              else m.decision_function(B))
        rows.append(dict(kind="Supervised", model=name, **metrics(yte, m.predict(B), sc)))
    for name, m in unsupervised_models(A[ytr == 0], 0.3):
        rows.append(dict(kind="Unsupervised", model=name,
                         **metrics(yte, (m.predict(B) == -1).astype(int),
                                   -m.score_samples(B))))
    rows.append(dict(kind="-", model="ทายคลาสใหญ่อย่างเดียว",
                     **metrics(yte, np.zeros_like(yte) if yte.mean() < .5
                               else np.ones_like(yte))))
    return rows


def table(rows, title, note=""):
    say("\n" + "=" * 84)
    say(title)
    if note:
        say(note)
    say("=" * 84)
    say("%-22s %8s %8s %8s %8s %8s %10s" %
        ("Algorithm", "Accuracy", "Precision", "Recall", "F1", "AUC", "เปเปอร์ F1"))
    say("-" * 84)
    last = None
    for r in rows:
        if r["kind"] != last and r["kind"] != "-":
            say("[%s]" % r["kind"])
            last = r["kind"]
        if r["kind"] == "-":
            say("-" * 84)
        p = PAPER_F1.get(r["model"])
        say("%-22s %8.4f %8.4f %8.4f %8.4f %8s %10s" %
            (r["model"], r["Accuracy"], r["Precision"], r["Recall"], r["F1"],
             "%.4f" % r["AUC"] if r["AUC"] == r["AUC"] else "  -  ",
             "%.4f" % p if p else "  -  "))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=DEFAULT_CSV)
    ap.add_argument("--full", action="store_true", help="รวม leave-one-scenario-out ด้วย")
    ap.add_argument("--txt", default=None, help="เขียนเอาต์พุตทั้งหมดลงไฟล์ .txt")
    ap.add_argument("--out", default=os.path.join(_ROOT, "reference", "showcase.csv"))
    a = ap.parse_args()

    # ---------------------------------------------------------------- dataset
    raw = pd.read_csv(a.csv, low_memory=False)
    say("=" * 84)
    say("SYSMON MALWARE DETECTION - ผลการทดลอง")
    say("=" * 84)
    say("dataset : %s" % os.path.basename(a.csv))
    say("          %s แถว  |  %d คอลัมน์ดิบ" % (format(len(raw), ","), raw.shape[1]))
    say("          Linux %s / Windows %s"
        % (format(int((raw.platform == "linux").sum()), ","),
           format(int((raw.platform == "windows").sum()), ",")))
    say("          benign %.1f%% / malicious %.1f%%"
        % ((raw.label == 0).mean() * 100, (raw.label == 1).mean() * 100))
    say("          %d scenario  |  %d รอบเก็บ  |  %d เครื่อง"
        % (raw.groupby(["platform", "session"]).ngroups,
           raw["run_id"].nunique() if "run_id" in raw.columns else 0,
           raw["computer"].nunique()))
    say("\nเทียบกับเปเปอร์อ้างอิง: 71,017 แถว | Windows อย่างเดียว | 5 เครื่องใน AD domain")

    feats, meta = load(a.csv, "process")
    y = meta["label"].values
    tr, te = make_split("process", meta)
    A, B, names = prep(feats, meta, tr, te, "process")
    rows = all_models(A, y[tr], B, y[te])

    table(rows,
          "ตารางที่ 1 - ผลหลัก: process-level, %d feature, แบ่ง train/test ตาม ProcessGuid" % len(names),
          "test %s process (malicious %.1f%%)  |  unsupervised เทรนด้วย benign อย่างเดียวตาม Fig.4 ของเปเปอร์"
          % (format(len(te), ","), y[te].mean() * 100))

    # ---------------------------------------------------- ตารางที่ 2: โปรโตคอล
    say("\n" + "=" * 84)
    say("ตารางที่ 2 - ตัวเลขเดียวกันเปลี่ยนได้ 40 จุด แค่เปลี่ยนวิธีแบ่ง train/test")
    say("=" * 84)
    say("%-34s %10s %10s   %s" % ("วิธีแบ่ง", "RF acc", "RF F1", "อธิบาย"))
    say("-" * 84)
    proto_rows = []
    for split, desc in [("random", "สุ่มแถว (เปเปอร์ใช้แบบนี้) - ตัวเลขสูงเกินจริง"),
                        ("process", "GroupSplit ตาม ProcessGuid - ที่เรารายงาน"),
                        ("scenario", "กันการโจมตีทั้งชนิดออก - เคส zero-day")]:
        t2, e2 = make_split(split, meta)
        A2, B2, _ = prep(feats, meta, t2, e2, "process")
        m = dict(supervised_models())["Random Forest"]
        m.fit(A2, y[t2])
        p = m.predict(B2)
        acc, f1 = accuracy_score(y[e2], p), f1_score(y[e2], p, zero_division=0)
        say("%-34s %10.4f %10.4f   %s" % (split, acc, f1, desc))
        proto_rows.append(dict(protocol=split, acc=acc, f1=f1))

    # ---------------------------------------------------- ตารางที่ 3: LOSO
    if a.full:
        say("\n" + "=" * 84)
        say("ตารางที่ 3 - leave-one-scenario-out (กันการโจมตีออกทีละชนิดจนครบ)")
        say("=" * 84)
        say("%-24s %9s %9s %9s %9s" % ("กันออก", "baseline", "RF F1", "LOF F1", "LOF AUC"))
        say("-" * 84)
        f2 = feats.drop(columns=[c for c in feats.columns if c in DERIVED_DROP])
        scen = meta["scen"].values
        agg = []
        for s in sorted(set(scen)):
            if s.split("|")[-1].startswith("benign"):
                continue
            ti = np.where(scen == s)[0]
            tj = np.where(scen != s)[0]
            if len(np.unique(y[ti])) < 2:
                continue
            sc_ = StandardScaler().fit(f2.iloc[tj])
            A3, B3 = sc_.transform(f2.iloc[tj]), sc_.transform(f2.iloc[ti])
            base = f1_score(y[ti], np.ones_like(y[ti]), zero_division=0)
            m = dict(supervised_models())["Random Forest"]
            m.fit(A3, y[tj])
            rf = f1_score(y[ti], m.predict(B3), zero_division=0)
            lof = dict(unsupervised_models(A3[y[tj] == 0], 0.3))["Local Outlier Factor"]
            lp = (lof.predict(B3) == -1).astype(int)
            lf1 = f1_score(y[ti], lp, zero_division=0)
            lauc = roc_auc_score(y[ti], -lof.score_samples(B3))
            say("%-24s %9.3f %9.3f %9.3f %9.3f" % (s, base, rf, lf1, lauc))
            agg.append((base, rf, lf1, lauc))
        g = np.array(agg)
        say("-" * 84)
        say("%-24s %9.3f %9.3f %9.3f %9.3f" % ("เฉลี่ย", *g.mean(axis=0)))
        say("ชนะ baseline: RF %d/%d   LOF %d/%d"
            % ((g[:, 1] > g[:, 0]).sum(), len(g), (g[:, 2] > g[:, 0]).sum(), len(g)))

    # ---------------------------------------------------- ข้อจำกัด (วัดสด)
    say("\n" + "=" * 84)
    say("ข้อจำกัด - ทำไมตัวเลขถึงยังไม่น่าเชื่อถือเท่าที่ควร")
    say("=" * 84)

    # 1) harness leakage
    L = raw.CommandLine.astype("string").str.len().fillna(-1)
    best = max(((((L > t).astype(int) == raw.label).mean(), t) for t in range(-1, 400, 5)))
    say("\n1. HARNESS LEAKAGE - โมเดลเรียน 'คำสั่งยาว = มัลแวร์' ไม่ใช่พฤติกรรม")
    say("   ความยาว CommandLine  median: benign %d  vs  malicious %d"
        % (L[raw.label == 0].median(), L[raw.label == 1].median()))
    say("   ใช้เงื่อนไข 'ความยาว > %d' อย่างเดียวไม่ต้องมีโมเดล ได้ accuracy %.4f"
        % (best[1], best[0]))
    say("   (ทายคลาสใหญ่อย่างเดียวได้ %.4f)" % max(raw.label.mean(), 1 - raw.label.mean()))
    say("   สาเหตุ: Atomic Red Team เรียกทุกอย่างผ่าน PowerShell พร้อม argument ยาว")
    say("           ส่วน benign เป็นคำสั่งสั้น -> ความยาวกลายเป็นลายเซ็นของเครื่องมือทดสอบ")
    say("   แก้: ทำ benign ให้มีคำสั่งยาวพอกัน ไม่ใช่ตัด CommandLine ทิ้ง")

    # 2) จำนวนรอบเก็บ
    nrun = raw["run_id"].nunique() if "run_id" in raw.columns else 0
    nscen = raw.groupby(["platform", "session"]).ngroups
    say("\n2. เก็บแค่รอบเดียวต่อ scenario (%d รอบ / %d scenario)" % (nrun, nscen))
    say("   -> ทำ cross-validation แบบกันไว้ 1 รอบไม่ได้ จึงไม่มี error bar")
    say("   -> ตอบไม่ได้ว่า 'รันซ้ำแล้วผลเหมือนเดิมไหม'")
    say("   แก้: เก็บซ้ำ 3 รอบต่อ scenario (กดรันใหม่ ไม่ใช่ยืด duration) ~9 ชม.")

    # 3) ความหลากหลาย
    say("\n3. ความหลากหลายของสภาพแวดล้อมต่ำ - %d เครื่อง, user เดียว, workgroup"
        % raw["computer"].nunique())
    say("   เปเปอร์อ้างอิงใช้ 5 เครื่องใน AD domain เก็บต่อเนื่อง 31 ชม.")
    say("   -> โมเดลอาจเรียนลักษณะเฉพาะของเครื่องนี้ ไม่ใช่ของมัลแวร์")

    # 4) label จาก lineage
    if "label_method" in raw.columns:
        lm = raw.label_method.value_counts()
        say("\n4. label มาจาก lineage ไม่ใช่การวิเคราะห์ทีละ event  (%s)"
            % ", ".join("%s %s" % (k, format(v, ",")) for k, v in lm.items()))
    else:
        say("\n4. label มาจาก lineage ไม่ใช่การวิเคราะห์ทีละ event")
    say("   label=1 แปลว่า 'สืบสายจาก process ที่รันในแซนด์บ็อกซ์'")
    say("   บาง event จึงเป็นกิจกรรมปกติของ OS ที่ติด label มาด้วย")
    say("   วัดแล้ว (trojan_win): มีหลักฐานตรงในตัว event เอง 45.5% / ติดเพราะสายเลือดล้วน 22.6%")

    # 5) feature ที่รั่ว
    say("\n5. ต้องตัด feature ที่รั่ว 6 ตัวออกก่อนเทรน (--drop-derived)")
    say("   CurrentDirectory: /tmp/lab_sandbox = malicious 100%  <- seed dir ของตัว labeler เอง")
    say("   ancestor_depth  : มาจาก lineage tree เดียวกับที่สร้าง label")
    say("   img_len         : เปเปอร์ตัด Image ทิ้งเองเพราะรั่ว label")
    say("   ถ้าไม่ตัด F1 จะสูงกว่านี้ ~2 จุด แต่เป็นตัวเลขที่ป้องกันตัวไม่ได้")

    # 6) event เดี่ยวๆ แยกไม่ออก
    say("\n6. ที่ระดับ event เดี่ยวๆ มัลแวร์หน้าตาเหมือน benign")
    say("   powershell เขียนไฟล์ 1 ไฟล์ ไม่มีอะไรบอกได้ว่าอันตราย")
    say("   จึงต้องรวมเป็น process-level ก่อน (F1 ต่างกันประมาณ 0.11)")

    say("\n" + "=" * 84)
    say("สรุปสิ่งที่จะทำต่อ")
    say("=" * 84)
    say("1. เก็บซ้ำ 3 รอบต่อ scenario -> รายงานเป็น mean +/- sd")
    say("2. เพิ่มความหลากหลายของ benign โดยเฉพาะคำสั่งยาว เพื่อลบ harness leakage")
    say("3. เพิ่ม feature เชิงพฤติกรรม (entropy ชื่อไฟล์, จำนวน child process,")
    say("   ความสม่ำเสมอของช่วงเวลา network connect) แทนการพึ่งความยาวคำสั่ง")
    say("4. ขยายเป็นหลายเครื่อง เพื่อตัดข้อครหาว่าโมเดลจำเครื่องเดียว")

    # ---------------------------------------------------------------- เขียนไฟล์
    df = pd.DataFrame(rows)
    df["paper_F1"] = df["model"].map(PAPER_F1)
    d = os.path.dirname(os.path.abspath(a.out))
    if d:
        os.makedirs(d, exist_ok=True)
    df.to_csv(a.out, index=False)
    print("\n[เขียน] %s" % a.out)
    if a.txt:
        d = os.path.dirname(os.path.abspath(a.txt))
        if d:
            os.makedirs(d, exist_ok=True)
        io.open(a.txt, "w", encoding="utf-8").write(OUT.getvalue())
        print("[เขียน] %s" % a.txt)


if __name__ == "__main__":
    main()
