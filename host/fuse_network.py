"""
fuse_network.py - รวม Zeek flow (network-based) เข้ากับ Sysmon (host-based)

หัวใจของงานนี้: Sysmon EventID 3 รู้ว่า "process ไหน" เปิด socket
                Zeek รู้ว่า flow นั้น "ส่งกี่ไบต์ นานแค่ไหน คุยโปรโตคอลอะไร"
                join ด้วย 4-tuple + เวลา -> ได้ทั้งสองอย่างในแถวเดียว

    Sysmon ev3 : Image, ProcessGuid, User, SourceIp:Port -> DestinationIp:Port, UtcTime
    Zeek conn  :                           id.orig_h:p   -> id.resp_h:p,        ts
                                           └───────── join key ─────────┘

สิ่งที่ได้ที่ Sysmon ให้ไม่ได้: orig_bytes, resp_bytes, duration, service, conn_state,
                               dns query, http host/user-agent, ssl server_name
สิ่งที่ได้ที่ Zeek ให้ไม่ได้:   process ที่เป็นเจ้าของ flow + label จาก lineage

⚠️ clock skew: Sysmon UtcTime มาจากนาฬิกาใน VM, pcap ts มาจากนาฬิกา host
   สคริปต์นี้ "วัด offset เอง" จาก flow ที่ 4-tuple ตรงกันแบบไม่กำกวม
   แล้วรายงานให้เห็น ไม่ได้สมมติว่านาฬิกาตรงกัน

ใช้งาน:
    python host/fuse_network.py --session botnet_win_001
    python host/fuse_network.py --all
    python host/fuse_network.py --session x --window 5     # ขยายหน้าต่างเวลา (วินาที)

ผลลัพธ์:
    host/dataset/<session>_fused_events.csv   Sysmon ev3 + คอลัมน์ Zeek
    host/dataset/<session>_netproc.csv        สรุประดับ process (feature สำหรับ ML)
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
import csv
import math
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

HOST_DIR = Path(__file__).resolve().parent
DATASET_DIR = HOST_DIR / "dataset"

csv.field_size_limit(10 * 1024 * 1024)

# คอลัมน์จาก Zeek ที่ติดไปกับแถว Sysmon
ZEEK_ATTACH = [
    "uid", "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "orig_pkts", "resp_pkts",
    "dns_query", "dns_qtype_name", "dns_answers",
    "http_method", "http_host", "http_uri", "http_user_agent", "http_status_code",
    "ssl_server_name", "ssl_version",
    "files_mime_type", "files_filename",
]


# ------------------------------------------------------------------ helpers
def parse_utc(s):
    """Sysmon UtcTime -> epoch seconds (float). คืน None ถ้าแปลงไม่ได้"""
    if not s:
        return None
    s = s.strip().replace("Z", "")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def fnum(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def shannon(s):
    """entropy ของสตริง - ใช้กับ label ของ DNS เพื่อจับ tunneling"""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n)
                for c in {ch: s.count(ch) for ch in set(s)}.values())


def key4(sip, sport, dip, dport, proto):
    return (sip or "", str(sport or ""), dip or "", str(dport or ""),
            (proto or "").lower())


def read_csv(path):
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


# ------------------------------------------------------------------ matching
def build_flow_index(flows):
    """4-tuple -> [(ts, flow)] เรียงตามเวลา"""
    idx = defaultdict(list)
    for fl in flows:
        k = key4(fl.get("id.orig_h"), fl.get("id.orig_p"),
                 fl.get("id.resp_h"), fl.get("id.resp_p"), fl.get("proto"))
        idx[k].append((fnum(fl.get("ts"), 0.0), fl))
    for k in idx:
        idx[k].sort(key=lambda t: t[0])
    return idx


def estimate_offset(ev3, idx):
    """ประเมิน clock offset (zeek_ts - sysmon_ts) จาก 4-tuple ที่ไม่กำกวม

    ใช้เฉพาะ key ที่มี flow เดียวและ event เดียว -> จับคู่ได้แน่นอนโดยไม่ต้องใช้เวลา
    คืน (offset, จำนวนคู่ที่ใช้ประเมิน)
    """
    ev_by_key = defaultdict(list)
    for e in ev3:
        ts = parse_utc(e.get("UtcTime"))
        if ts is not None:
            ev_by_key[key4(e.get("SourceIp"), e.get("SourcePort"),
                           e.get("DestinationIp"), e.get("DestinationPort"),
                           e.get("Protocol"))].append(ts)

    deltas = []
    for k, ev_ts in ev_by_key.items():
        flows = idx.get(k)
        if flows and len(flows) == 1 and len(ev_ts) == 1:
            deltas.append(flows[0][0] - ev_ts[0])
    if not deltas:
        return 0.0, 0
    return statistics.median(deltas), len(deltas)


def match(ev3, idx, offset, window):
    """จับคู่ Sysmon ev3 -> Zeek flow; คืน (matched_pairs, unmatched_events)"""
    used = set()
    pairs, unmatched = [], []
    for e in ev3:
        ts = parse_utc(e.get("UtcTime"))
        k = key4(e.get("SourceIp"), e.get("SourcePort"),
                 e.get("DestinationIp"), e.get("DestinationPort"),
                 e.get("Protocol"))
        cands = idx.get(k, [])
        best, best_d = None, None
        for fts, fl in cands:
            uid = fl.get("uid", "")
            if uid and uid in used:
                continue
            if ts is None:
                best = fl
                break
            d = abs(fts - (ts + offset))
            if d <= window and (best_d is None or d < best_d):
                best, best_d = fl, d
        if best is not None:
            uid = best.get("uid", "")
            if uid:
                used.add(uid)
            pairs.append((e, best, best_d))
        else:
            unmatched.append(e)
    return pairs, unmatched


# ------------------------------------------------------------ process rollup
def _cv(times):
    """(n, mean, sd, cv) ของช่วงห่างระหว่างการเชื่อมต่อ - คืน None ถ้าน้อยเกินวัด"""
    if len(times) < 3:
        return None
    ts = sorted(times)
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a >= 0]
    if len(gaps) < 2:
        return None
    mean = statistics.fmean(gaps)
    if mean <= 0:
        return None
    sd = statistics.pstdev(gaps)
    return len(ts), mean, sd, sd / mean


def beacon_stats(times_by_dst):
    """ความสม่ำเสมอของช่วงเวลา - CV ต่ำ = beacon เป็นจังหวะ = สัญญาณ C2

    ⚠️ ต้องวัด "แยกตามปลายทาง" ไม่ใช่รวมทุก destination ของ process
    process เดียวที่คุยหลายปลายทางพร้อมกันจะได้ gap สลับไปมาจนดูไม่สม่ำเสมอ
    ทั้งที่แต่ละช่องทางเป็นจังหวะเป๊ะ (เคสของ botnet beacon ตรงๆ)

    รายงานช่องทางที่สม่ำเสมอที่สุด (CV ต่ำสุด) ที่มีอย่างน้อย MIN_HITS ครั้ง
    """
    MIN_HITS = 4
    best = None          # (cv, n, mean, sd, dst)
    for dst, ts in times_by_dst.items():
        r = _cv(ts)
        if not r:
            continue
        n, mean, sd, cv = r
        if n < MIN_HITS:
            continue
        if best is None or cv < best[0]:
            best = (cv, n, mean, sd, dst)

    if best is None:
        # ไม่มีช่องทางไหนยาวพอ - วัดรวมไว้เป็นข้อมูลคร่าวๆ
        allts = [t for ts in times_by_dst.values() for t in ts]
        r = _cv(allts)
        if not r:
            return {"beacon_n": len(allts), "beacon_mean_s": "",
                    "beacon_sd_s": "", "beacon_cv": "", "beacon_dst": ""}
        n, mean, sd, cv = r
        return {"beacon_n": n, "beacon_mean_s": round(mean, 3),
                "beacon_sd_s": round(sd, 3), "beacon_cv": round(cv, 4),
                "beacon_dst": ""}

    cv, n, mean, sd, dst = best
    return {"beacon_n": n, "beacon_mean_s": round(mean, 3),
            "beacon_sd_s": round(sd, 3), "beacon_cv": round(cv, 4),
            "beacon_dst": dst}


NETPROC_COLS = [
    "session", "ProcessGuid", "Image", "User", "label",
    "flow_n", "flow_matched", "dst_ip_n", "dst_port_n",
    "bytes_sent", "bytes_recv", "dur_total_s", "dur_max_s",
    "svc_set", "conn_state_set", "ext_dst_n",
    "dns_n", "dns_qlen_max", "dns_ent_max",
    "http_n", "http_ua_set", "ssl_n", "ssl_sni_set",
    "beacon_n", "beacon_mean_s", "beacon_sd_s", "beacon_cv", "beacon_dst",
]


def rollup(session, pairs, unmatched):
    """สรุปต่อ process - นี่คือตารางที่เอาไปเป็น feature จริง
    (process-level ดีกว่า event-level อยู่แล้ว: F1 0.959 vs 0.811)"""
    g = defaultdict(lambda: {
        "rows": [], "flows": [], "matched": 0,
        "dst_ip": set(), "dst_port": set(), "svc": set(), "cs": set(),
        "ua": set(), "sni": set(), "times": defaultdict(list),
        "sent": 0.0, "recv": 0.0, "dur": 0.0, "dur_max": 0.0,
        "dns": 0, "qlen": 0, "ent": 0.0, "http": 0, "ssl": 0, "ext": set(),
    })

    def touch(e, fl):
        guid = e.get("ProcessGuid") or ""
        b = g[guid]
        b["rows"].append(e)
        dip = e.get("DestinationIp") or ""
        b["dst_ip"].add(dip)
        b["dst_port"].add(str(e.get("DestinationPort") or ""))
        # นอกวง lab (ไม่ใช่ 192.168.*) = ออกอินเทอร์เน็ตจริง
        if dip and not dip.startswith("192.168.") and not dip.startswith("127."):
            b["ext"].add(dip)
        ts = parse_utc(e.get("UtcTime"))
        if ts is not None:
            b["times"][dip + ":" + str(e.get("DestinationPort") or "")].append(ts)
        if fl is None:
            return
        b["matched"] += 1
        b["flows"].append(fl)
        b["sent"] += fnum(fl.get("orig_bytes"))
        b["recv"] += fnum(fl.get("resp_bytes"))
        d = fnum(fl.get("duration"))
        b["dur"] += d
        b["dur_max"] = max(b["dur_max"], d)
        if fl.get("service"):
            b["svc"].add(fl["service"])
        if fl.get("conn_state"):
            b["cs"].add(fl["conn_state"])
        if fl.get("dns_query"):
            b["dns"] += 1
            q = fl["dns_query"]
            label = q.split(".")[0]
            b["qlen"] = max(b["qlen"], len(q))
            b["ent"] = max(b["ent"], shannon(label))
        if fl.get("http_host") or fl.get("http_uri"):
            b["http"] += 1
            if fl.get("http_user_agent"):
                b["ua"].add(fl["http_user_agent"][:60])
        if fl.get("ssl_server_name"):
            b["ssl"] += 1
            b["sni"].add(fl["ssl_server_name"])

    for e, fl, _d in pairs:
        touch(e, fl)
    for e in unmatched:
        touch(e, None)

    out = []
    for guid, b in g.items():
        first = b["rows"][0]
        row = {
            "session": session,
            "ProcessGuid": guid,
            "Image": first.get("Image", ""),
            "User": first.get("User", ""),
            "label": first.get("label", ""),
            "flow_n": len(b["rows"]),
            "flow_matched": b["matched"],
            "dst_ip_n": len(b["dst_ip"]),
            "dst_port_n": len(b["dst_port"]),
            "bytes_sent": int(b["sent"]),
            "bytes_recv": int(b["recv"]),
            "dur_total_s": round(b["dur"], 3),
            "dur_max_s": round(b["dur_max"], 3),
            "svc_set": "|".join(sorted(b["svc"])),
            "conn_state_set": "|".join(sorted(b["cs"])),
            "ext_dst_n": len(b["ext"]),
            "dns_n": b["dns"],
            "dns_qlen_max": b["qlen"],
            "dns_ent_max": round(b["ent"], 3),
            "http_n": b["http"],
            "http_ua_set": "|".join(sorted(b["ua"]))[:200],
            "ssl_n": b["ssl"],
            "ssl_sni_set": "|".join(sorted(b["sni"]))[:200],
        }
        row.update(beacon_stats(b["times"]))
        out.append(row)
    out.sort(key=lambda r: -r["flow_n"])
    return out


# ------------------------------------------------------------------ driver
def fuse(session, window=3.0, offset=None, force=False, quiet=False):
    sys_csv = DATASET_DIR / (session + "_labeled.csv")
    if not sys_csv.exists():
        raise RuntimeError(
            "ไม่พบ {}\n".format(sys_csv.name) +
            "  ต้องมี Sysmon CSV ที่ label แล้วก่อน (orchestrator ทำให้อัตโนมัติ\n"
            "  หรือ python host/rebuild_dataset.py)"
        )
    zeek_csv = DATASET_DIR / (session + "_zeek.csv")
    if not zeek_csv.exists():
        raise RuntimeError(
            "ไม่พบ {}\n".format(zeek_csv.name) +
            "  รัน python host/run_zeek.py --session {} ก่อน".format(session)
        )

    ev_out = DATASET_DIR / (session + "_fused_events.csv")
    pr_out = DATASET_DIR / (session + "_netproc.csv")
    if ev_out.exists() and not force:
        print("  [ข้าม] {} มีแล้ว (--force เพื่อทับ)".format(ev_out.name))
        return None

    sysrows = read_csv(sys_csv)
    flows = read_csv(zeek_csv)
    ev3 = [r for r in sysrows if str(r.get("EventID", "")).strip() == "3"]

    idx = build_flow_index(flows)
    if offset is None:
        offset, noff = estimate_offset(ev3, idx)
    else:
        noff = -1

    pairs, unmatched = match(ev3, idx, offset, window)
    matched_uids = {fl.get("uid") for _e, fl, _d in pairs if fl.get("uid")}
    orphan_flows = [f for f in flows if f.get("uid") not in matched_uids]

    # ---- เขียน event-level ----
    base_cols = list(sysrows[0].keys()) if sysrows else []
    cols = base_cols + ["zeek_" + c for c in ZEEK_ATTACH] + ["zeek_dt_s"]
    with open(ev_out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for e, fl, d in pairs:
            row = dict(e)
            for c in ZEEK_ATTACH:
                row["zeek_" + c] = fl.get(c, "")
            row["zeek_dt_s"] = round(d, 3) if d is not None else ""
            w.writerow(row)
        for e in unmatched:
            row = dict(e)
            for c in ZEEK_ATTACH:
                row["zeek_" + c] = ""
            row["zeek_dt_s"] = ""
            w.writerow(row)

    # ---- เขียน process-level ----
    procs = rollup(session, pairs, unmatched)
    with open(pr_out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=NETPROC_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(procs)

    rate = (len(pairs) / len(ev3) * 100) if ev3 else 0.0
    stats = {
        "session": session, "sysmon_ev3": len(ev3), "zeek_flows": len(flows),
        "matched": len(pairs), "match_rate": rate,
        "unmatched_ev": len(unmatched), "orphan_flows": len(orphan_flows),
        "offset": offset, "offset_n": noff, "procs": len(procs),
    }
    if not quiet:
        report(stats, procs)
    return stats


def report(s, procs):
    print("  Sysmon EventID 3   : {:,} แถว".format(s["sysmon_ev3"]))
    print("  Zeek conn flows    : {:,} flow".format(s["zeek_flows"]))
    off = "วัดจาก {} คู่".format(s["offset_n"]) if s["offset_n"] >= 0 else "ระบุเอง"
    print("  clock offset       : {:+.3f} s  ({})".format(s["offset"], off))
    print("  จับคู่ได้          : {:,} ({:.1f}% ของ ev3)".format(
        s["matched"], s["match_rate"]))
    print("  ev3 ที่ไม่มี flow   : {:,}".format(s["unmatched_ev"]))
    print("  flow ที่ไม่มี ev3   : {:,}  <- traffic ที่ Sysmon มองไม่เห็น".format(
        s["orphan_flows"]))
    print("  process ที่มี net   : {:,}".format(s["procs"]))

    if s["sysmon_ev3"] == 0:
        print("  [!] ไม่มี EventID 3 ใน Sysmon เลย - scenario นี้ไม่ได้ต่อเน็ต?")
    elif s["match_rate"] < 30:
        print("  [!] match rate ต่ำมาก - ตรวจ:")
        print("      - เก็บ pcap ถูก adapter ไหม (ทั้ง VMnet1 และ VMnet8)")
        print("      - pcap เริ่มเก็บก่อน scenario รันจริงหรือเปล่า")
        print("      - clock offset เกินหน้าต่างไหม (ลอง --window 10)")

    top = [p for p in procs if p["flow_n"] > 0][:8]
    if top:
        print("\n  process ที่มี network มากสุด:")
        print("    {:<38} {:>5} {:>5} {:>9} {:>8} {:>7}".format(
            "Image", "flow", "dst", "sent", "cv", "label"))
        for p in top:
            img = (p["Image"] or "?").split("\\")[-1].split("/")[-1]
            print("    {:<38} {:>5} {:>5} {:>9,} {:>8} {:>7}".format(
                img[:38], p["flow_n"], p["dst_ip_n"], p["bytes_sent"],
                p["beacon_cv"] if p["beacon_cv"] != "" else "-", p["label"]))


def main():
    ap = argparse.ArgumentParser(description="รวม Zeek flow เข้ากับ Sysmon")
    ap.add_argument("--session")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--window", type=float, default=3.0,
                    help="หน้าต่างเวลาจับคู่ (วินาที) default 3")
    ap.add_argument("--offset", type=float, default=None,
                    help="บังคับ clock offset (ปกติวัดเอง)")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    if args.all:
        sessions = sorted(p.name[:-len("_zeek.csv")]
                          for p in DATASET_DIR.glob("*_zeek.csv"))
    elif args.session:
        sessions = [args.session]
    else:
        ap.error("ต้องระบุ --session หรือ --all")

    if not sessions:
        print("ไม่มี *_zeek.csv - รัน host/run_zeek.py ก่อน")
        return 1

    ok = fail = 0
    for s in sessions:
        print("\n== {} ==".format(s))
        try:
            fuse(s, window=args.window, offset=args.offset, force=args.force)
            ok += 1
        except RuntimeError as e:
            print("  [!] {}".format(e))
            fail += 1
    print("\nสรุป: สำเร็จ {} / ล้มเหลว {}".format(ok, fail))
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
