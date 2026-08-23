"""
select_merge_features.py - หาชุด feature ที่ merge Linux + Windows แล้วไม่รั่ว platform

ปัญหา: ถ้าโมเดลแยก platform ออก มันจะใช้ทางลัดนั้นแทนการเรียนพฤติกรรมมัลแวร์
       -> F1 สูงปลอม (ดู CLAUDE.md กับดักข้อ 5)

วิธี: greedy backward elimination
  1. encode ตามเปเปอร์ (host/paper_encoding.py)
  2. เทรนโมเดลทำนาย "platform"
  3. ถ้าแม่นเกินเกณฑ์ -> ตัด feature ที่ importance สูงสุดทิ้ง แล้ววนใหม่
  4. หยุดเมื่อทำนาย platform ไม่ได้ดีกว่าทายมั่วอย่างมีนัย
  5. รายงาน F1 ของการทำนาย malicious ทุกก้าว เพื่อดูว่าจ่ายค่าอะไรไปบ้าง

แล้วเทียบ 3 ทางเลือกที่ CLAUDE.md วางไว้:
  A. union + ตัด feature ที่รั่ว   (ผลจากขั้น 1-4)
  B. union ทั้งหมด ไม่ตัด         (ฐานอ้างอิง - ตัวเลขสวยแต่หลอก)
  C. แยกเทรนแยกทดสอบ             (Linux เอง / Windows เอง)

ใช้งาน:
    python host/select_merge_features.py
    python host/select_merge_features.py --margin 3 --max-drop 25
"""
import os as _os
import sys as _sys

_os.environ.setdefault("PYTHONIOENCODING", "utf-8")
_os.environ.setdefault("PYTHONUTF8", "1")
for _stream in (_sys.stdout, _sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

import argparse
import glob
import os
import warnings

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")

sys_path = os.path.dirname(os.path.abspath(__file__))
if sys_path not in _sys.path:
    _sys.path.insert(0, sys_path)
from paper_encoding import prepare  # noqa: E402


def fit(X, y, seed=0, n=80):
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.3, random_state=seed, stratify=y)
    m = RandomForestClassifier(n_estimators=n, random_state=seed, n_jobs=-1).fit(Xtr, ytr)
    pred = m.predict(Xte)
    return (accuracy_score(yte, pred),
            f1_score(yte, pred, zero_division=0),
            pd.Series(m.feature_importances_, index=X.columns))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-dir", default="host/dataset")
    ap.add_argument("--margin", type=float, default=3.0,
                    help="ยอมให้ทำนาย platform เกินทายมั่วได้กี่จุด (default 3)")
    ap.add_argument("--max-drop", type=int, default=30, help="ตัดได้มากสุดกี่ feature")
    ap.add_argument("--min-features", type=int, default=6)
    args = ap.parse_args()

    files = sorted(glob.glob(f"{args.dataset_dir}/*_labeled.csv"))
    if not files:
        print(f"[!] ไม่พบ *_labeled.csv ใน {args.dataset_dir}")
        return 1

    print("=" * 70)
    print("  หาชุด feature ที่ merge Linux + Windows ได้โดยไม่รั่ว platform")
    print("=" * 70)
    print(f"\n  ไฟล์ {len(files)} ไฟล์")

    X, y_mal, y_plat, df, kinds = prepare(files, verbose=True)
    if y_plat is None or y_plat.nunique() < 2:
        print("[!] ต้องมีข้อมูลทั้งสอง platform")
        return 1

    base_plat = max(y_plat.mean(), 1 - y_plat.mean()) * 100
    print(f"\n  {len(X):,} แถว x {X.shape[1]} feature")
    print(f"  malicious {y_mal.mean()*100:.1f}%   windows {y_plat.mean()*100:.1f}%")
    print(f"  ทายมั่ว platform ได้ {base_plat:.1f}%   เป้าหมาย <= {base_plat + args.margin:.1f}%")

    # ---------- B. ฐานอ้างอิง: ไม่ตัดอะไร ----------
    acc_p0, _, imp_p0 = fit(X, y_plat)
    acc_m0, f1_m0, _ = fit(X, y_mal)
    print("\n" + "=" * 70)
    print("  B) union ทั้งหมด ไม่ตัด feature (ฐานอ้างอิง)")
    print("=" * 70)
    print(f"  ทำนาย platform : {acc_p0*100:>6.2f}%")
    print(f"  ทำนาย malicious: acc {acc_m0*100:>6.2f}%   F1 {f1_m0:.4f}")
    if acc_p0 * 100 > base_plat + args.margin:
        print("  [!] แยก platform ได้ -> F1 ข้างบนเชื่อไม่ได้ อาจมาจากทางลัด")

    # ---------- A. ไล่ตัด feature ที่รั่ว ----------
    print("\n" + "=" * 70)
    print("  A) ไล่ตัด feature ที่บอก platform ทีละตัว")
    print("=" * 70)
    print(f"\n  {'ตัดตัวไหนออก':<26} {'#feat':>6} {'platform':>10} {'mal F1':>9}")
    print("  " + "-" * 56)

    Xc = X.copy()
    history = []
    dropped = []
    for step in range(args.max_drop):
        acc_p, _, imp_p = fit(Xc, y_plat)
        _, f1_m, _ = fit(Xc, y_mal)
        history.append((len(dropped), Xc.shape[1], acc_p * 100, f1_m,
                        dropped[-1] if dropped else "-"))
        print(f"  {(dropped[-1] if dropped else '(ยังไม่ตัด)'):<26} "
              f"{Xc.shape[1]:>6} {acc_p*100:>9.2f}% {f1_m:>9.4f}")

        if acc_p * 100 <= base_plat + args.margin:
            print("\n  -> ทำนาย platform ไม่ได้ดีกว่าทายมั่วแล้ว หยุด")
            break
        if Xc.shape[1] <= args.min_features:
            print("\n  -> feature เหลือน้อยสุดแล้ว หยุด")
            break

        worst = imp_p.sort_values(ascending=False).index[0]
        dropped.append(worst)
        Xc = Xc.drop(columns=[worst])

    acc_pA, _, _ = fit(Xc, y_plat)
    acc_mA, f1_mA, impA = fit(Xc, y_mal)

    print(f"\n  ตัดออกทั้งหมด {len(dropped)} ตัว:")
    for i in range(0, len(dropped), 4):
        print("    " + ", ".join(dropped[i:i + 4]))
    print(f"\n  feature ที่เหลือ ({Xc.shape[1]} ตัว):")
    for i in range(0, Xc.shape[1], 4):
        print("    " + ", ".join(list(Xc.columns)[i:i + 4]))
    print(f"\n  ทำนาย platform : {acc_pA*100:>6.2f}%   (ทายมั่ว {base_plat:.1f}%)")
    print(f"  ทำนาย malicious: acc {acc_mA*100:>6.2f}%   F1 {f1_mA:.4f}")
    print("\n  feature ที่ยังสำคัญต่อการหามัลแวร์:")
    for k, v in impA.sort_values(ascending=False).head(10).items():
        print(f"    {k:<24} {v:.4f}")

    # ---------- C. แยกเทรน ----------
    print("\n" + "=" * 70)
    print("  C) แยกเทรนแยกทดสอบ (ไม่ merge)")
    print("=" * 70)
    for tag, mask in (("Linux", y_plat == 0), ("Windows", y_plat == 1)):
        Xs, ys = X[mask], y_mal[mask]
        if ys.nunique() < 2:
            print(f"  {tag:<8} มี label เดียว ({ys.iloc[0]}) - เทรนไม่ได้")
            continue
        acc_s, f1_s, _ = fit(Xs, ys)
        print(f"  {tag:<8} {len(Xs):>7,} แถว   malicious {ys.mean()*100:>5.1f}%"
              f"   acc {acc_s*100:>6.2f}%   F1 {f1_s:.4f}")

    # ---------- สรุป ----------
    print("\n" + "=" * 70)
    print("  สรุป")
    print("=" * 70)
    print(f"  B) union ไม่ตัด     : platform {acc_p0*100:>6.2f}%   mal F1 {f1_m0:.4f}  <- เชื่อไม่ได้")
    print(f"  A) union ตัดที่รั่ว : platform {acc_pA*100:>6.2f}%   mal F1 {f1_mA:.4f}")
    print(f"     จ่ายไป {Xc.shape[1]}/{X.shape[1]} feature, F1 ต่างจาก B {f1_mA - f1_m0:+.4f}")
    print("\n  ตัวเลข A คือค่าที่รายงานในธีสิสได้ ส่วน B ไว้แสดงว่าถ้าไม่ตัดจะหลอกตัวเองแค่ไหน")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
