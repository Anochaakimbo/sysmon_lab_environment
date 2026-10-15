# -*- coding: utf-8 -*-
"""eval_web.py - หน้าเว็บประเมินโมเดล: อัปโหลด .pkl (จาก export_model.py) + CSV ของ Sysmon แล้วดูผล

    python host/eval_web.py            # เปิด http://127.0.0.1:8090

ทำ 3 อย่าง: (1) ระบุ OS ของ CSV เอง จากรูปแบบ path / User / EventID ที่มีเฉพาะ Windows
(2) ตรวจโปรเซสที่น่าจะเป็นการโจมตีด้วย detector ของ OS นั้น (3) ทายประเภทการโจมตีของโปรเซสที่ถูก flag
ด้วย type model (5 ประเภทตามสถานการณ์ในแล็บ: ransomware, trojan, botnet, miner, exploit)

CSV ต้องเป็นระดับ event (หนึ่งแถวต่อหนึ่ง Sysmon event) อย่างน้อยมี ProcessGuid, EventID
label (0/1) ถ้ามีจะคำนวณ metric ให้; session (ชื่อสถานการณ์แบบ dataset ของเรา) ถ้ามีจะวัดความถูกของประเภทให้
คอลัมน์อื่นที่ขาด (เช่น CommandLine ใน NLME) เติมเป็นค่าว่าง แล้วหน้าเว็บบอกว่าฟีเจอร์ไหนกลายเป็นค่าคงที่

⚠️ .pkl คือ pickle: โหลดแล้วรันโค้ดในไฟล์ได้ เปิดเฉพาะไฟล์ที่ตัวเองสร้าง เว็บนี้ฟังเฉพาะ 127.0.0.1
"""
import html, io, os, sys
import joblib
import numpy as np
import pandas as pd
from flask import Flask, request
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import revised_experiments as R

# คอลัมน์ดิบที่ aggregate() ใช้ -> ฟีเจอร์ที่ได้จากคอลัมน์นั้น
RAW_TO_FEATURES = {
    "CommandLine": ["cmd_len"], "ParentCommandLine": ["pcmd_len"], "Device": ["n_device"],
    "TargetFilename": ["n_files"], "DestinationIp": ["n_dst_ip"], "DestinationPort": ["n_dst_port"],
    "TargetObject": ["n_regobj"], "UtcTime": ["dur_s", "rate"], "ParentProcessGuid": [],
}
REQUIRED = ["ProcessGuid", "EventID"]
WIN_ONLY_EVENTS = {2, 6, 7, 8, 10, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 24, 25, 26}
TYPE_MIN_SHARE = 0.25   # ประเภทรองต้องมีโปรเซสถูก flag ตั้งแต่ 25% ไม่งั้นเป็นแค่สัญญาณรบกวนจาก type model

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 ** 3

PAGE = """<!doctype html><html lang="th"><head><meta charset="utf-8"><title>ประเมินโมเดล Sysmon</title>
<style>body{font-family:sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#222}
table{border-collapse:collapse;margin:8px 0}td,th{border:1px solid #ccc;padding:4px 10px;text-align:right}
th{background:#f3f3f3}td:first-child,th:first-child{text-align:left}.warn{background:#fff4e5;border-left:4px solid #f0a020;padding:8px 12px;margin:8px 0}
.err{background:#fde8e8;border-left:4px solid #d33;padding:8px 12px}.ok{background:#e8f4fd;border-left:4px solid #2a7ab8;padding:8px 12px;margin:8px 0}
form{background:#f7f7f7;padding:12px;border-radius:6px}</style></head>
<body><h2>ประเมินโมเดลกับ Sysmon CSV</h2>
<form method="post" action="/evaluate" enctype="multipart/form-data">
<p>โมเดล (.pkl จาก <code>host/export_model.py</code>): <input type="file" name="model" accept=".pkl" required></p>
<p>CSV ระดับ event: <input type="file" name="csv" accept=".csv,.gz" required></p>
<p>threshold: <input name="thr" value="0.5" size="4"></p>
<p><button>ประเมิน</button></p></form>%s</body></html>"""


def table(rows, head):
    h = "".join("<th>%s</th>" % html.escape(str(c)) for c in head)
    b = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % html.escape(str(c)) for c in r) for r in rows)
    return "<table><tr>%s</tr>%s</table>" % (h, b)


def detect_os(df):
    """นับหลักฐานต่อ OS: path แบบ C:\\ หรือ /, User แบบ DOMAIN\\name, EventID ที่ Sysmon for Linux ไม่มี"""
    win = lin = 0
    for c in ("Image", "TargetFilename", "CurrentDirectory"):
        if c in df.columns:
            s = df[c].dropna().astype(str)
            win += s.str.match(r"^[A-Za-z]:\\").sum()
            lin += s.str.startswith("/").sum()
    if "User" in df.columns:
        win += df.User.dropna().astype(str).str.contains("\\", regex=False).sum()
    win += df.EventID.isin(WIN_ONLY_EVENTS).sum()
    return ("windows" if win >= lin else "linux"), int(win), int(lin)


def evaluate(bundle, df, thr):
    out, warn = [], []
    miss = [c for c in REQUIRED if c not in df.columns]
    if miss:
        return '<p class="err">CSV ไม่มีคอลัมน์ %s ประเมินไม่ได้</p>' % ", ".join(miss)
    has_label = "label" in df.columns
    has_type = "session" in df.columns
    df = df.copy()
    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int) if has_label else 0
    df["EventID"] = pd.to_numeric(df.EventID, errors="coerce")
    platform, win, lin = detect_os(df)
    out.append('<div class="ok">ระบบปฏิบัติการที่ตรวจได้: <b>%s</b> (หลักฐาน Windows %d จุด, Linux %d จุด)</div>'
               % (platform, win, lin))
    if min(win, lin) > 0.05 * max(win, lin):
        warn.append("CSV มีหลักฐานของทั้งสอง OS ปนกัน ควรแยกไฟล์ตาม OS ก่อนประเมิน")
    df["platform"] = platform
    if "run_id" not in df.columns:   # แยกโปรเซสต่างเครื่องที่ ProcessGuid ชนกัน
        df["run_id"] = df.host_name if "host_name" in df.columns else "upload"
    df["run_id"] = df.run_id.astype(str)
    df["session"] = df.session.astype(str) if has_type else "upload"
    lost = [c for c in RAW_TO_FEATURES if c not in df.columns or df[c].isna().all()]
    for c in lost:
        df[c] = np.nan
    feats = bundle["features"]
    f, m, dropped = R.aggregate(df)
    f = f.reindex(columns=feats, fill_value=0.0)
    model, typer = bundle["detectors"][platform], bundle["typers"][platform]
    imp = dict(zip(feats, model.feature_importances_))
    dead = [x for c in lost for x in RAW_TO_FEATURES[c]]
    if dead:
        warn.append("คอลัมน์ %s ไม่มีหรือว่างทั้งคอลัมน์ ฟีเจอร์ %s จึงเป็นค่าคงที่ "
                    "ซึ่งรวมกันคิดเป็น %.0f%% ของ importance ของโมเดล"
                    % (", ".join(lost), ", ".join(dead), 100 * sum(imp.get(x, 0) for x in dead)))
    other = sorted(set(df.EventID.dropna().astype(int)) - set(R.EVENT_IDS))
    if other:
        warn.append("EventID %s ไม่มีตอนเทรน นับรวมแค่ใน n_events" % other)
    if not has_label:
        warn.append("CSV ไม่มีคอลัมน์ label จึงคำนวณ metric ไม่ได้")
    p = model.predict_proba(f.values)[:, 1]
    yh = (p >= thr).astype(int)
    out.append("<h3>ข้อมูล</h3>" + table([[len(df), dropped, len(f), "%.1f%%" % (100 * m.label.mean()) if has_label else "-",
                                            "%.1f%%" % (100 * yh.mean())]],
                                          ["event", "event ที่ตัดทิ้ง (ไม่มี ProcessGuid)", "โปรเซส", "label=1 จริง", "ทายเป็น label=1"]))
    out += ['<div class="warn">%s</div>' % html.escape(w) for w in warn]
    if has_label:
        y = m.label.values
        auc = "%.3f" % roc_auc_score(y, p) if len(np.unique(y)) > 1 else "-"
        row = lambda name, yy, a: [name, "%.3f" % accuracy_score(y, yy), "%.3f" % precision_score(y, yy, zero_division=0),
                                   "%.3f" % recall_score(y, yy, zero_division=0), "%.3f" % f1_score(y, yy, zero_division=0), a]
        out.append("<h3>ตรวจจับ: ผลระดับโปรเซส (threshold %.2f)</h3>" % thr + table(
            [row("โมเดล", yh, auc), row("baseline: ทายว่า benign ทุกตัว", np.zeros_like(y), "0.500"),
             row("baseline: ทายว่า malicious ทุกตัว", np.ones_like(y), "0.500")],
            ["", "Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]))
        tn, fp, fn, tp = confusion_matrix(y, yh, labels=[0, 1]).ravel()
        out.append(table([["จริง 0", tn, fp], ["จริง 1", fn, tp]], ["", "ทาย 0", "ทาย 1"]))
        out.append("<p>อ่านคู่กับ baseline เสมอ: Accuracy สูงไม่มีความหมายถ้าไม่ชนะการทายคลาสที่มากกว่าทุกตัว "
                   "ROC-AUC ไม่ขึ้นกับ threshold และสัดส่วนคลาส จึงใช้เทียบข้ามชุดข้อมูลได้ดีกว่า</p>")
    img = df.assign(_k=df.platform + "|" + df.run_id + "|" + df.ProcessGuid.astype(str)).groupby("_k").Image.first() \
        if "Image" in df.columns else pd.Series(dtype=str)

    # ---- ประเภทการโจมตีของโปรเซสที่ถูก flag
    flag = yh == 1
    out.append("<h3>ประเภทการโจมตีที่พบ</h3>")
    if not flag.any():
        out.append("<p>ไม่มีโปรเซสถูก flag ที่ threshold นี้</p>")
    else:
        tp_ = typer.predict_proba(f.values[flag])
        t = typer.classes_[tp_.argmax(1)]
        share = pd.Series(t).value_counts(normalize=True)
        found = [k for k, v in share.items() if v >= TYPE_MIN_SHARE]
        out.append('<div class="ok">ประเภทหลัก: <b>%s</b> (%.0f%% ของโปรเซสที่ถูก flag)%s<br>'
                   'โปรเซสที่ถูก flag %d จาก %d ตัว (%.1f%%) ซึ่งอาจรวมการแจ้งเตือนผิดด้วย</div>'
                   % (share.index[0], 100 * share.iloc[0],
                      " ประเภทรอง: %s" % ", ".join(found[1:]) if len(found) > 1 else "",
                      flag.sum(), len(flag), 100 * flag.mean()))
        rows = []
        for k in typer.classes_:
            on = t == k
            ex = pd.Series([img.get(i, "") for i in f.index[flag][on]]).value_counts().index[:3]
            rows.append([k, int(on.sum()), "%.1f%%" % (100 * on.mean()),
                         "%.2f" % tp_[on].max(1).mean() if on.any() else "-", " ; ".join(map(str, ex))])
        out.append(table(rows, ["ประเภท", "โปรเซสที่ถูก flag", "สัดส่วน", "ความมั่นใจเฉลี่ย", "Image ที่พบบ่อย"]))
        truth = m.scenario.values[flag]
        known = np.isin(truth, typer.classes_)
        if has_type and known.any():
            out.append("<p>เทียบกับชื่อสถานการณ์ใน CSV (เฉพาะโปรเซสที่ถูก flag และ label=1): ทายประเภทถูก %.1f%% จาก %d โปรเซส</p>"
                       % (100 * (t[known] == truth[known]).mean(), known.sum()))
        out.append("<p>ประเภทมาจากสถานการณ์จำลองในแล็บ 5 แบบเท่านั้น ถ้ามัลแวร์จริงเป็นแบบอื่น โมเดลก็ยังตอบเป็น 1 ใน 5 แบบนี้</p>")

    top = np.argsort(-p)[:15]
    tt = typer.predict(f.values[top])
    out.append("<h3>โปรเซสที่คะแนนสูงสุด 15 ตัว</h3>" + table(
        [[img.get(f.index[i], ""), "%.3f" % p[i], tt[j], m.label.iloc[i] if has_label else "-"] for j, i in enumerate(top)],
        ["Image", "คะแนน", "ประเภทที่ทาย", "label จริง"]))
    return "".join(out)


@app.get("/")
def index():
    return PAGE % ""


@app.post("/evaluate")
def run():
    try:
        bundle = joblib.load(io.BytesIO(request.files["model"].read()))
        if not (isinstance(bundle, dict) and {"features", "detectors", "typers"} <= set(bundle)):
            return PAGE % '<p class="err">.pkl ต้องมาจาก host/export_model.py (dict ที่มี features, detectors, typers)</p>'
        up = request.files["csv"]
        df = pd.read_csv(up.stream, low_memory=False, compression="gzip" if up.filename.endswith(".gz") else None)
        body = evaluate(bundle, df, float(request.form.get("thr", 0.5)))
    except Exception as e:   # แสดง error บนหน้าแทน 500 เปล่าๆ
        body = '<p class="err">%s: %s</p>' % (type(e).__name__, html.escape(str(e)))
    return PAGE % body


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8090)
