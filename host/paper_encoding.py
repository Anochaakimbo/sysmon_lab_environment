"""
paper_encoding.py - preprocessing ตามเปเปอร์อ้างอิงเป๊ะๆ
(Achmad et al., Cyber Security and Applications 3, 2025, 100110 — หัวข้อ 3.1)

ใช้ร่วมกันทั้ง check_merge.py และตอนเทรนจริง เพื่อให้ตัวเลขที่รายงานในธีสิส
มาจาก preprocessing เดียวกันทั้งหมด

สิ่งที่เปเปอร์ทำ (อ้างหน้า 3 ของ PDF):
  1. แทน "-" ด้วย null
  2. ตัดคอลัมน์ที่เป็น null ทั้งหมดทิ้ง
  3. ตัดแถวซ้ำ (duplicate) ทิ้ง
  4. ตัด feature ที่รั่ว label หรือไม่มีความหมายทั่วไป:
       Image, node_id, ProcessGUID, ProcessId, UtcTime, timestamp,
       parent_node_id, host_name
     ⚠️ Image ถูกตัดเพราะ "direct association with the target variable (label)"
        — เป็นข้อความในเปเปอร์เอง ไม่ใช่การตีความ
  5. encode:
       categorical ที่มี unique < 21  -> label encoding (null = -1)
       categorical ที่มี unique >= 21 -> **ความยาวสตริง** (null = -1)
       numeric                        -> คงค่าเดิม (null = -1)

ทำไม "ความยาวสตริง" สำคัญกับงานเรา:
  ถ้าใช้ factorize/one-hot ค่าฝั่ง Linux กับ Windows ไม่มีทางซ้ำกันเลย
  -> เลขคนละช่วง -> โมเดลแยก platform ได้ทันที 100%
  ส่วนความยาวสตริงทับซ้อนกันได้ (/usr/bin/bash = 13, C:\\Windows\\... = 27)
  ตัวเลข leakage ที่วัดด้วย encoder นี้จึงเป็นค่าจริง ไม่ใช่ worst case
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

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# ตัดตามเปเปอร์ (ชื่อคอลัมน์ฝั่งเราต่างจากของเขาเล็กน้อย - map ให้ตรงความหมาย)
#   เปเปอร์ host_name  -> ของเรา computer / host_ip
#   เปเปอร์ node_id / parent_node_id -> ของเรา ProcessGuid / ParentProcessGuid
#   เปเปอร์ timestamp  -> ของเรา recv_timestamp
# ---------------------------------------------------------------------------
PAPER_DROP = [
    "Image",              # เปเปอร์ระบุเองว่าตัดเพราะรั่ว label
    "ProcessId",
    "ProcessGuid",
    "ParentProcessGuid",
    "UtcTime",
    "computer",
    "host_ip",
    "recv_timestamp",
]

# คอลัมน์ของเราที่ไม่มีในเปเปอร์ และเป็น bookkeeping ของ pipeline เราเอง
OURS_DROP = [
    "record_id", "session", "platform", "label", "label_method",
    "is_seed", "enrich_method", "root_image", "LogonGuid", "CreationUtcTime",
]

CARDINALITY_THRESHOLD = 21   # ตามเปเปอร์


def load_and_clean(paths, drop_duplicates=True, verbose=True):
    """อ่าน CSV หลายไฟล์ -> ทำขั้นตอน 1-3 ของเปเปอร์"""
    frames = [pd.read_csv(p, low_memory=False) for p in paths]
    df = pd.concat(frames, ignore_index=True)
    n0 = len(df)

    # 1) "-" -> null
    df = df.replace("-", np.nan)

    # 2) ตัดคอลัมน์ที่ null ทั้งหมด
    all_null = [c for c in df.columns if df[c].isna().all()]
    df = df.drop(columns=all_null)

    # 3) ตัดแถวซ้ำ (ไม่นับคอลัมน์ที่ใช้ trace)
    n_dup = 0
    if drop_duplicates:
        trace = [c for c in ("record_id", "recv_timestamp", "UtcTime") if c in df.columns]
        subset = [c for c in df.columns if c not in trace]
        before = len(df)
        df = df.drop_duplicates(subset=subset).reset_index(drop=True)
        n_dup = before - len(df)

    if verbose:
        print(f"  โหลด {n0:,} แถว -> เหลือ {len(df):,} แถว")
        print(f"    ตัดคอลัมน์ null ล้วน {len(all_null)} ตัว: {all_null if all_null else '(ไม่มี)'}")
        print(f"    ตัดแถวซ้ำ {n_dup:,} แถว")
    return df


def feature_columns(df, extra_drop=()):
    """คอลัมน์ที่เหลือหลังตัดตามเปเปอร์ + ของเรา"""
    drop = set(PAPER_DROP) | set(OURS_DROP) | set(extra_drop)
    return [c for c in df.columns if c not in drop]


def encode(df, feats, verbose=False):
    """ขั้นตอน 5 ของเปเปอร์: label encoding / ความยาวสตริง / numeric"""
    cols = {}
    kinds = {"label_enc": [], "str_len": [], "numeric": []}

    for c in feats:
        s = df[c]
        is_obj = s.dtype == object or str(s.dtype) in ("str", "string", "category")

        if not is_obj:
            cols[c] = pd.to_numeric(s, errors="coerce").fillna(-1).astype(float)
            kinds["numeric"].append(c)
            continue

        s = s.astype("string")
        nuniq = s.nunique(dropna=True)

        if nuniq < CARDINALITY_THRESHOLD:
            codes = pd.factorize(s, use_na_sentinel=True)[0]   # null -> -1 อยู่แล้ว
            cols[c] = pd.Series(codes, index=df.index).astype(float)
            kinds["label_enc"].append(c)
        else:
            # ความยาวสตริง, null -> -1
            cols[c] = s.str.len().fillna(-1).astype(float)
            kinds["str_len"].append(c)

    X = pd.DataFrame(cols, index=df.index)

    if verbose:
        print(f"    label encoding (<{CARDINALITY_THRESHOLD} ค่า) : {len(kinds['label_enc'])} คอลัมน์")
        print(f"    ความยาวสตริง (>={CARDINALITY_THRESHOLD} ค่า)  : {len(kinds['str_len'])} คอลัมน์")
        print(f"    numeric                        : {len(kinds['numeric'])} คอลัมน์")
    return X, kinds


def prepare(paths, extra_drop=(), verbose=True):
    """ทางลัด: load -> clean -> encode  คืน (X, y_label, y_platform, df)"""
    df = load_and_clean(paths, verbose=verbose)
    y_label = pd.to_numeric(df.get("label"), errors="coerce").fillna(0).astype(int)
    y_plat = (df.get("platform").astype(str) == "windows").astype(int) \
        if "platform" in df.columns else None
    feats = feature_columns(df, extra_drop)
    X, kinds = encode(df, feats, verbose=verbose)
    return X, y_label, y_plat, df, kinds
