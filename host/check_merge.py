"""
check_merge.py - ตรวจว่า dataset Linux + Windows เอาไปเทรนรวมกันได้จริงไหม

ไม่ใช่การเทรนโมเดลจริง แต่เป็นการ "หาโกง" ก่อนเทรน:
ถ้าโมเดลแยก platform ได้ง่าย มันจะใช้ทางลัดนั้นแทนการเรียนพฤติกรรมมัลแวร์
แล้วได้ F1 สูงปลอมๆ (ดู CLAUDE.md หัวข้อกับดักด้านระเบียบวิธี ข้อ 5)

ตรวจ 5 อย่าง:
  1. schema ตรงกันไหม + คอลัมน์ไหน fill rate ต่างกันจนแยก platform ได้
  2. โมเดลทำนาย "platform" ได้แม่นแค่ไหน (ยิ่งใกล้ 100% ยิ่งอันตราย)
     -> แล้วไล่ตัด feature ที่รั่วออกทีละตัว ดูว่าเหลือเท่าไหร่
  3. สัดส่วน label ของแต่ละ platform สมดุลกันไหม
     (ถ้าไม่สมดุล platform จะกลายเป็น proxy ของ label ทันที)
  4. event type ไหนมีอยู่ฝั่งเดียว (โมเดลใช้เป็น fingerprint ได้)
  5. ทดสอบจริง: เทรนทำนาย malicious แล้วดูว่า feature ที่มันใช้
     เป็นตัวเดียวกับที่บอก platform หรือเปล่า

ใช้งาน:
    python host/check_merge.py
    python host/check_merge.py --dataset-dir host/dataset
"""
import argparse
import glob
import os
import sys
import warnings

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# ห้ามใช้เป็น feature (ตรงกับ merge_dataset.py + CLAUDE.md)
DROP_BEFORE_FIT = [
    "recv_timestamp", "record_id", "session", "computer", "host_ip",
    "ProcessGuid", "LogonGuid", "ParentProcessGuid", "UtcTime",
    "CreationUtcTime", "root_image", "is_seed", "label_method", "enrich_method",
    "label", "platform",
]

EVENT_NAMES = {
    "1": "ProcessCreate", "2": "FileCreateTime", "3": "NetworkConnect",
    "5": "ProcessTerminate", "8": "CreateRemoteThread", "9": "RawAccessRead",
    "11": "FileCreate", "12": "RegistryAddDelete", "13": "RegistrySetValue",
    "23": "FileDelete",
}


def encode(df, feats):
    """แปลงเป็นตัวเลขแบบที่ preprocessing ทั่วไปทำ: has-value flag + ค่า"""
    cols = {}
    for c in feats:
        s = df[c]
        cols[c + "__has"] = s.notna().astype(np.int8)
        if s.dtype == object or str(s.dtype) in ("str", "string"):
            cols[c + "__cat"] = pd.factorize(s.astype(str))[0]
        else:
            cols[c + "__num"] = pd.to_numeric(s, errors="coerce").fillna(-1)
    return pd.DataFrame(cols, index=df.index)


def fit_acc(X, y, seed=0):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.3, random_state=seed, stratify=y)
    m = RandomForestClassifier(n_estimators=60, random_state=seed, n_jobs=-1).fit(Xtr, ytr)
    return accuracy_score(yte, m.predict(Xte)), pd.Series(m.feature_importances_, index=X.columns)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-dir", default="host/dataset")
    args = ap.parse_args()

    files = sorted(glob.glob(f"{args.dataset_dir}/*_labeled.csv"))
    if not files:
        print(f"[!] ไม่พบ *_labeled.csv ใน {args.dataset_dir}")
        return 1

    # แยก platform จาก "คอลัมน์ platform" ไม่ใช่ชื่อไฟล์
    # 24 ส.ค. 2026: เดิมใช้ pattern "_win_" ในชื่อไฟล์ ทำให้ benign ฝั่ง Windows
    # (ชื่อ benign_<time>_*) ถูกนับเป็น Linux -> ตัวเลข RegistrySetValue ของ Linux
    # โผล่ 1,374 แถวทั้งที่ Sysmon for Linux ไม่มี registry event เลย
    df = pd.concat([pd.read_csv(p, low_memory=False) for p in files], ignore_index=True)
    if "platform" not in df.columns:
        print("[!] ไม่มีคอลัมน์ platform - CSV เก่าเกินไป ให้ rebuild_dataset.py ใหม่")
        return 1
    is_win = df["platform"].astype(str) == "windows"
    L, W = df[~is_win].reset_index(drop=True), df[is_win].reset_index(drop=True)
    if L.empty or W.empty:
        print(f"[!] ต้องมีทั้งสอง platform - Linux {len(L):,} แถว / Windows {len(W):,} แถว")
        return 1
    y_plat = (df["platform"].astype(str) == "windows").astype(int)
    y_mal = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)

    print("=" * 68)
    print("  ตรวจความพร้อม merge Linux + Windows")
    print("=" * 68)
    print("")
    print(f"  ไฟล์ {len(files)} ไฟล์")
    print(f"  Linux   {len(L):>7,} แถว")
    print(f"  Windows {len(W):>7,} แถว")
    print(f"  รวม     {len(df):>7,} แถว  (Windows = {y_plat.mean()*100:.1f}%)")

    # ---- 1) schema + fill rate ----
    print("\n" + "=" * 68)
    print("  1) schema และ fill rate")
    print("=" * 68)
    only_l = sorted(set(L.columns) - set(W.columns))
    only_w = sorted(set(W.columns) - set(L.columns))
    print(f"  คอลัมน์ Linux {len(L.columns)} / Windows {len(W.columns)}")
    print(f"  เฉพาะ Linux  : {only_l or 'ไม่มี'}")
    print(f"  เฉพาะ Windows: {only_w or 'ไม่มี'}")

    common = sorted(set(L.columns) & set(W.columns))
    gaps = []
    for c in common:
        a, b = L[c].notna().mean() * 100, W[c].notna().mean() * 100
        if abs(a - b) >= 20:
            gaps.append((abs(a - b), c, a, b))
    gaps.sort(reverse=True)
    print(f"\n  คอลัมน์ที่ fill rate ต่างกัน >= 20 จุด ({len(gaps)} ตัว):")
    for d, c, a, b in gaps:
        print(f"    {c:<26} Linux {a:>5.1f}%  Windows {b:>5.1f}%  ต่าง {d:>5.1f}")
    if not gaps:
        print("    (ไม่มี)")

    # ---- 2) ทำนาย platform ได้แม่นแค่ไหน ----
    print("\n" + "=" * 68)
    print("  2) โมเดลแยก platform ออกง่ายแค่ไหน (ยิ่งใกล้ 100% ยิ่งอันตราย)")
    print("=" * 68)
    feats = [c for c in df.columns if c not in DROP_BEFORE_FIT]
    X = encode(df, feats)
    base = max(y_plat.mean(), 1 - y_plat.mean()) * 100

    acc, imp = fit_acc(X, y_plat)
    print(f"\n  ใช้ feature ทั้งหมด ({len(feats)} คอลัมน์): {acc*100:>6.2f}%   (ทายมั่ว = {base:.1f}%)")
    print("  feature ที่บอก platform มากสุด:")
    for k, v in imp.sort_values(ascending=False).head(8).items():
        print(f"    {k:<32} {v:.4f}")

    # ไล่ตัดตัวที่รั่วออกทีละรอบ ดูว่าเหลือเท่าไหร่
    print("\n  ไล่ตัด feature ที่รั่วออกทีละรอบ:")
    Xc, dropped = X.copy(), []
    for i in range(5):
        acc_i, imp_i = fit_acc(Xc, y_plat)
        top = imp_i.sort_values(ascending=False)
        kill = [k for k in top.index[:6]]
        base_cols = sorted({k.rsplit("__", 1)[0] for k in kill})
        print(f"    รอบ {i+1}: acc {acc_i*100:>6.2f}%   ตัด {', '.join(base_cols[:4])}")
        dropped += base_cols
        Xc = Xc[[c for c in Xc.columns if c.rsplit("__", 1)[0] not in set(dropped)]]
        if Xc.shape[1] < 6:
            break
    acc_f, _ = fit_acc(Xc, y_plat)
    print(f"    เหลือ {Xc.shape[1]} feature: acc {acc_f*100:.2f}%")

    # ---- 3) สัดส่วน label ต่อ platform ----
    print("\n" + "=" * 68)
    print("  3) สัดส่วน label ต่อ platform (ต่างกันมาก = platform เป็น proxy ของ label)")
    print("=" * 68)
    lm, wm = y_mal[y_plat == 0].mean() * 100, y_mal[y_plat == 1].mean() * 100
    print(f"\n  Linux   malicious {lm:>5.1f}%")
    print(f"  Windows malicious {wm:>5.1f}%")
    print(f"  ต่างกัน {abs(lm-wm):>5.1f} จุด")
    if abs(lm - wm) >= 15:
        print("  [!] ต่างเกิน 15 จุด - โมเดลเดา label จาก platform ได้กำไรทันที")

    # ---- 4) event type ที่มีฝั่งเดียว ----
    print("\n" + "=" * 68)
    print("  4) event type ที่มีอยู่ฝั่งเดียว (ใช้เป็น fingerprint ของ platform ได้)")
    print("=" * 68)
    le = set(L["EventID"].astype(str).unique())
    we = set(W["EventID"].astype(str).unique())
    print(f"\n  {'EventID':<8} {'event':<20} {'Linux':>9} {'Windows':>9}")
    for e in sorted(le | we, key=lambda x: int(x) if str(x).isdigit() else 999):
        a = (L["EventID"].astype(str) == e).sum()
        b = (W["EventID"].astype(str) == e).sum()
        flag = "  <-- ฝั่งเดียว" if (a == 0) != (b == 0) else ""
        print(f"  {e:<8} {EVENT_NAMES.get(e,'?'):<20} {a:>9,} {b:>9,}{flag}")

    # ---- 5) โมเดลทำนาย malicious ใช้ feature เดียวกับที่บอก platform ไหม ----
    print("\n" + "=" * 68)
    print("  5) โมเดลทำนาย malicious ใช้ feature เดียวกับที่บอก platform หรือเปล่า")
    print("=" * 68)
    acc_m, imp_m = fit_acc(X, y_mal)
    top_plat = set(imp.sort_values(ascending=False).head(15).index)
    top_mal = imp_m.sort_values(ascending=False).head(15)
    overlap = [k for k in top_mal.index if k in top_plat]
    print(f"\n  ทำนาย malicious: acc {acc_m*100:.2f}%")
    print(f"  feature 15 อันดับแรกของสองงานซ้ำกัน {len(overlap)}/15 ตัว")
    for k in overlap:
        print(f"    {k}")
    if len(overlap) >= 5:
        print("\n  [!] ซ้ำกันเยอะ = โมเดลอาจใช้ทางลัด platform แทนพฤติกรรมมัลแวร์")

    print("\n" + "=" * 68)
    print("  สรุป")
    print("=" * 68)
    verdict = []
    if acc > 0.95:
        verdict.append(f"แยก platform ได้ {acc*100:.1f}% -> merge แบบ union ตรงๆ ไม่ปลอดภัย")
    if abs(lm - wm) >= 15:
        verdict.append(f"สัดส่วน label ต่างกัน {abs(lm-wm):.1f} จุด -> ต้อง balance ก่อน")
    if (le ^ we):
        verdict.append(f"event type ฝั่งเดียว {sorted(le ^ we)} -> เป็น fingerprint")
    if not verdict:
        verdict.append("ไม่พบสัญญาณ leakage ชัดเจน")
    for v in verdict:
        print(f"  - {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
