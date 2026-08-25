"""
dashboard.py - เว็บ dashboard ควบคุม lab แบบกดปุ่ม (ไม่ต้องพิมพ์คำสั่ง)

รันบน host แล้วเปิด http://localhost:8000
- กดรัน scenario (revert -> boot -> รัน -> เก็บ log -> pipeline อัตโนมัติ)
- จัดการ collectors (log_receiver + c2_server) ให้เอง
- ดู log สด + สถานะ VM + สถิติ dataset + กด merge

zero-dependency: ใช้ http.server ของ stdlib เรียก orchestrator.py โดยตรง
รันทีละ scenario (sequential) ตามข้อจำกัด RAM

ใช้งาน:
    python host/dashboard.py
    # เปิด browser ไปที่ http://localhost:8000
"""
import csv
import glob
import io
import json
import os
import subprocess
import sys
import threading
import time
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Windows console default = cp1252 -> print ภาษาไทย crash
# ต้อง set os.environ ก่อน spawn ใดๆ เพื่อให้ทุก child process (collectors +
# parse/enrich/label ที่ orchestrator เรียก) inherit utf-8 ไม่ crash
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

import orchestrator as orch
import orchestrator_win as orch_win

HOST_DIR = Path(__file__).resolve().parent
LAB_DIR = HOST_DIR.parent
LOG_DIR = HOST_DIR / "logs"
DATASET_DIR = HOST_DIR / "dataset"

# ---------------------------------------------------------------------------
# ทะเบียน scenario รวมสองแพลตฟอร์ม
#
# 24 ส.ค. 2026: เดิม dashboard import แต่ orchestrator (Linux) และฮาร์ดโค้ด vm="target1"
# -> กดเก็บผ่านหน้าเว็บได้เฉพาะ Linux ฝั่ง Windows ไม่มีปุ่มให้กดด้วยซ้ำ
#
# ชื่อ scenario ฝั่ง Windows ลงท้าย _win อยู่แล้วทุกตัว ยกเว้น benign ที่ชนกับ Linux
# จึงตั้ง key เป็น benign_win ในทะเบียนนี้ (ตัว SCENARIOS ของ orchestrator_win ยังใช้ benign)
# ---------------------------------------------------------------------------
WIN_KEY_MAP = {"benign": "benign_win"}          # key ที่ dashboard ใช้ -> key จริงใน orch_win


def _registry():
    # คืน {key: {platform, spec, real_name}} ของทั้งสองแพลตฟอร์ม
    reg = {}
    for k, v in orch.SCENARIOS.items():
        reg[k] = {"platform": "linux", "spec": v, "real_name": k}
    for k, v in orch_win.SCENARIOS.items():
        key = WIN_KEY_MAP.get(k, k)
        reg[key] = {"platform": "windows", "spec": v, "real_name": k}
    return reg


REGISTRY = _registry()

# preset ชุด scenario สะอาดของแต่ละแพลตฟอร์ม
CLEAN_SET_LINUX = ["benign", "ransomware", "botnet", "miner", "exploit", "trojan"]
CLEAN_SET_WIN = ["benign_win", "ransomware_win", "botnet_win", "miner_win",
                 "exploit_win", "trojan_win"]
CLEAN_SET = CLEAN_SET_LINUX + CLEAN_SET_WIN

# ---- สถานะรวม (job เดียวต่อครั้ง เพราะ sequential) ----
STATE = {
    "job": None,          # ชื่อ scenario ที่กำลังรัน
    "phase": "idle",      # idle / running / done / error
    "started": None,
    "queue": [],          # scenario ที่รอในคิว
    "done": [],           # scenario ที่เก็บเสร็จรอบนี้
    "log": [],            # บรรทัด log สด (เก็บ 400 บรรทัดล่าสุด)
}
COLLECTORS = {"receiver": None, "pool": None, "c2": None}
LOCK = threading.Lock()


def logline(msg):
    with LOCK:
        STATE["log"].append(f"{datetime.now():%H:%M:%S}  {msg}")
        del STATE["log"][:-400]


# ---------------------------------------------------------- collectors
def _spawn(script, *args):
    # บังคับ utf-8: collectors print ภาษาไทย ถ้า subprocess inherit cp1252 (Windows)
    # จะ crash ทันทีตอน print -> ไม่ listen -> log ไม่เข้า (เคยทำ dataset หายทั้งรอบ)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    return subprocess.Popen([sys.executable, str(HOST_DIR / script), *args],
                            cwd=str(HOST_DIR), env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)


def start_collectors(session, platform="linux"):
    """เปิด collector ที่จำเป็นตามแพลตฟอร์ม

    log_receiver = ท่อ syslog ของ Linux เท่านั้น
      ฝั่ง Windows ไม่ได้ส่ง syslog แต่ export EVTX ผ่าน shared folder ตอนจบ scenario
      -> เปิดไปก็ไม่มีอะไรเข้า และไปยึดพอร์ต 5514 เปล่าๆ

    mining_pool (:3333) + c2_server (:8080/:4444) ใช้ทั้งสองแพลตฟอร์ม
      botnet_win beacon ไป :8080/:4444 และ miner_win ต่อ pool :3333
      mining_pool ต้อง start ก่อนเพื่อยึด 3333"""
    stop_collectors()
    if platform == "linux":
        COLLECTORS["receiver"] = _spawn("log_receiver.py", "--session", session)
    COLLECTORS["pool"] = _spawn("mining_pool.py")      # :3333 stratum
    time.sleep(0.5)
    COLLECTORS["c2"] = _spawn("c2_server.py")          # :8080 + :4444
    recv = f"log_receiver(session={session}) + " if platform == "linux" else ""
    logline(f"[collectors] {recv}mining_pool + c2_server  [{platform}]")


def stop_collectors():
    for k in ("receiver", "pool", "c2"):
        p = COLLECTORS.get(k)
        if p and p.poll() is None:
            p.terminate()
        COLLECTORS[k] = None


# ---------------------------------------------------------- run scenario
class _LogStream(io.TextIOBase):
    def write(self, s):
        for ln in s.splitlines():
            if ln.strip():
                logline(ln)
        return len(s)


def _run_one(name, duration, atomic_timeout):
    """รัน scenario 1 ตัว (revert->boot->run->pipeline) - เก็บ stdout ไป log สด"""
    entry = REGISTRY.get(name)
    if not entry:
        logline(f"[dashboard] ไม่รู้จัก scenario '{name}'")
        return False

    platform = entry["platform"]
    STATE.update(job=name, phase="running", started=datetime.now().isoformat())
    session = f"{name}_dash_{datetime.now():%H%M%S}"
    start_collectors(session, platform)
    ls = _LogStream()
    ok = False
    try:
        with redirect_stdout(ls), redirect_stderr(ls):
            if platform == "windows":
                # orchestrator_win ตั้งชื่อ session เองจาก scenario + เวลา
                # และไม่มี arg vm/atomic_timeout (ใช้ env ATOMIC_TIMEOUT ใน _lib.ps1 แทน)
                orch_win.run_scenario(entry["real_name"], float(duration), repeat=True)
            else:
                orch.run_scenario(name, "target1", float(duration),
                                  repeat=True, atomic_timeout=int(atomic_timeout))
        logline(f"[dashboard] เสร็จ scenario '{name}' [{platform}]")
        ok = True
    except Exception as e:  # noqa
        logline(f"[dashboard] '{name}' ล้ม: {e}")
    finally:
        stop_collectors()
    return ok


def run_worker(scenarios, duration, atomic_timeout):
    """รัน scenario ในคิวเรียงกัน (1 ตัวต่อครั้ง) - หัวใจของ automation หลายตัว"""
    with LOCK:
        STATE["queue"] = list(scenarios)
        STATE["done"] = []
    logline(f"[dashboard] เริ่มคิว {len(scenarios)} scenario: {', '.join(scenarios)}")
    for name in scenarios:
        with LOCK:
            STATE["queue"] = [s for s in STATE["queue"] if s != name]
        ok = _run_one(name, duration, atomic_timeout)
        with LOCK:
            STATE["done"].append({"name": name, "ok": ok})
    STATE.update(job=None, phase="done")
    logline(f"[dashboard] จบคิวทั้งหมด ({len(scenarios)} scenario)")


def run_merge():
    STATE.update(job="merge", phase="running")
    try:
        r = subprocess.run([sys.executable, str(HOST_DIR / "merge_dataset.py"),
                            "--exclude", "trojan_r04", "exploit_r01", "miner_real"],
                           cwd=str(HOST_DIR), capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=120)
        for ln in (r.stdout + r.stderr).splitlines():
            if ln.strip():
                logline(ln)
        STATE["phase"] = "done"
    except Exception as e:  # noqa
        STATE["phase"] = "error"
        logline(f"[merge] ล้ม: {e}")


def save_snapshot_bg(platform="linux"):
    # snapshot ต้องยิงเข้า VM ที่ตรงกับแท็บที่ผู้ใช้เปิดอยู่
    # ไม่งั้นกดจากหน้า Windows แล้วไป snapshot target1 ของ Linux แทน
    STATE.update(job="snapshot", phase="running")
    try:
        if platform == "windows":
            orch_win.snapshot_save()
            logline(f"[snapshot] บันทึก clean snapshot ของ {orch_win.VM} แล้ว")
        else:
            orch.snapshot_save("target1")
            logline("[snapshot] บันทึก clean snapshot ของ target1 แล้ว")
        STATE["phase"] = "done"
    except Exception as e:  # noqa
        STATE["phase"] = "error"
        logline(f"[snapshot] ล้ม: {e}")


# ---------------------------------------------------------- dataset stats
def dataset_stats():
    out = {"sessions": [], "total": 0, "malicious": 0}
    for f in sorted(glob.glob(str(DATASET_DIR / "*_labeled.csv"))):
        try:
            rows = list(csv.DictReader(open(f, encoding="utf-8")))
        except OSError:
            continue
        if not rows:
            continue
        mal = sum(1 for r in rows if r.get("label") == "1")
        out["sessions"].append({
            "name": Path(f).stem.split("_2026")[0],
            "events": len(rows),
            "malicious_pct": round(mal / len(rows) * 100, 1),
        })
    merged = DATASET_DIR / "merged_dataset.csv"
    if merged.exists():
        rows = list(csv.DictReader(open(merged, encoding="utf-8")))
        out["total"] = len(rows)
        out["malicious"] = sum(1 for r in rows if r.get("label") == "1")
    return out


def busy():
    return STATE["phase"] == "running"


# ---------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            return self._send(200, HTML, "text/html; charset=utf-8")
        if self.path == "/api/state":
            with LOCK:
                st = {"job": STATE["job"], "phase": STATE["phase"],
                      "busy": busy(), "queue": STATE["queue"],
                      "done": STATE["done"], "log": STATE["log"][-120:]}
            return self._send(200, json.dumps(st))
        if self.path == "/api/scenarios":
            sc = [{"name": k, "platform": e["platform"],
                   "attack": e["spec"].get("attack", ""),
                   "label": e["spec"].get("label", "")}
                  for k, e in REGISTRY.items()]
            return self._send(200, json.dumps(sc))
        if self.path == "/api/dataset":
            return self._send(200, json.dumps(dataset_stats()))
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path in ("/api/run", "/api/run_batch"):
            if busy():
                return self._send(409, json.dumps({"error": "มี job รันอยู่"}))
            if self.path == "/api/run":
                names = [body.get("scenario")]
            else:
                names = body.get("scenarios") or CLEAN_SET
            names = [n for n in names if n in REGISTRY]
            if not names:
                return self._send(400, json.dumps({"error": "ไม่มี scenario ที่ใช้ได้"}))
            dur = body.get("duration", 5)
            at = body.get("atomic_timeout", 240)
            threading.Thread(target=run_worker, args=(names, dur, at),
                             daemon=True).start()
            return self._send(200, json.dumps({"ok": True, "started": names}))
        if self.path == "/api/merge":
            if busy():
                return self._send(409, json.dumps({"error": "มี job รันอยู่"}))
            threading.Thread(target=run_merge, daemon=True).start()
            return self._send(200, json.dumps({"ok": True}))
        if self.path == "/api/snapshot":
            if busy():
                return self._send(409, json.dumps({"error": "มี job รันอยู่"}))
            plat = body.get("platform", "linux")
            threading.Thread(target=save_snapshot_bg, args=(plat,),
                             daemon=True).start()
            return self._send(200, json.dumps({"ok": True}))
        return self._send(404, json.dumps({"error": "not found"}))


HTML = r"""<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sysmon Lab Dashboard</title>
<style>
:root{
  --bg:#f4f7fb; --panel:#ffffff; --border:#dce4ef; --border-soft:#eaf0f8;
  --fg:#152238; --mut:#64748b; --acc:#2563eb; --acc-dark:#1d4ed8;
  --acc-soft:#eaf1ff; --ok:#0f9d58; --bad:#dc2626; --warn:#b45309;
  --shadow:0 1px 2px rgba(21,34,56,.06), 0 4px 12px rgba(21,34,56,.05);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font-family:"Inter","Segoe UI",system-ui,-apple-system,sans-serif;font-size:14px;
  -webkit-font-smoothing:antialiased}

/* ---------- header ---------- */
header{background:var(--panel);border-bottom:1px solid var(--border);
  padding:0 24px;display:flex;align-items:center;gap:14px;height:60px;
  position:sticky;top:0;z-index:10;box-shadow:0 1px 3px rgba(21,34,56,.04)}
header h1{font-size:16px;margin:0;font-weight:650;letter-spacing:-.01em}
.badge{padding:4px 11px;border-radius:999px;font-size:12px;font-weight:500;
  background:var(--bg);border:1px solid var(--border);color:var(--mut);
  display:inline-flex;align-items:center;white-space:nowrap}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:7px}

/* ---------- segmented tabs ---------- */
.tabs{display:flex;gap:2px;margin-left:auto;background:var(--bg);
  border:1px solid var(--border);border-radius:10px;padding:3px}
.tab{padding:6px 16px;border-radius:7px;background:transparent;color:var(--mut);
  cursor:pointer;font-size:13px;font-weight:500;transition:.15s;user-select:none;
  border:none;white-space:nowrap}
.tab:hover{color:var(--fg)}
.tab.on{background:var(--acc);color:#fff;font-weight:600;
  box-shadow:0 1px 3px rgba(37,99,235,.3)}

/* ---------- layout ---------- */
.wrap{display:grid;grid-template-columns:1fr 1fr;gap:18px;padding:22px;
  max-width:1280px;margin:0 auto}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;
  padding:20px;box-shadow:var(--shadow)}
.panel h2{font-size:12px;margin:0 0 16px;color:var(--mut);text-transform:uppercase;
  letter-spacing:.06em;font-weight:650}
.full{grid-column:1/3}

/* ---------- buttons ---------- */
button{background:var(--panel);color:var(--fg);border:1px solid var(--border);
  border-radius:9px;padding:9px 14px;cursor:pointer;font-size:13px;font-weight:500;
  font-family:inherit;transition:.15s}
button:hover:not(:disabled){border-color:var(--acc);color:var(--acc-dark);
  background:var(--acc-soft)}
button:active:not(:disabled){transform:translateY(1px)}
button:disabled{opacity:.45;cursor:not-allowed}
button.run{background:var(--acc);color:#fff;border-color:var(--acc);font-weight:600;
  box-shadow:0 1px 3px rgba(37,99,235,.25)}
button.run:hover:not(:disabled){background:var(--acc-dark);border-color:var(--acc-dark);
  color:#fff}

/* ---------- scenario list ---------- */
#scbtns{display:flex;flex-direction:column;gap:6px;margin:4px 0 2px}
#scbtns > div{display:flex;align-items:center;gap:10px;padding:0}
#scbtns button.run{background:var(--panel);color:var(--fg);border:1px solid var(--border);
  box-shadow:none;font-weight:500;padding:10px 13px}
#scbtns button.run:hover:not(:disabled){background:var(--acc-soft);
  border-color:var(--acc);color:var(--acc-dark)}
input[type=checkbox]{width:16px;height:16px;accent-color:var(--acc);cursor:pointer;
  flex:none;margin:0}
.scrow{flex:1;display:flex;align-items:center;justify-content:space-between;gap:10px;
  text-align:left;min-width:0}
.scname{display:flex;align-items:center;font-weight:550;white-space:nowrap}
.sctags{display:flex;gap:4px;flex-wrap:nowrap;overflow:hidden}
.tag{background:var(--bg);border:1px solid var(--border-soft);color:var(--mut);
  border-radius:5px;padding:2px 6px;font-size:10.5px;font-weight:500;
  font-family:"Cascadia Code",Consolas,monospace;white-space:nowrap}
.tag.more{background:transparent;border-color:transparent}
#scbtns button.run.picked{background:var(--acc-soft);border-color:var(--acc);
  color:var(--acc-dark);box-shadow:inset 0 0 0 1px var(--acc)}
.confirm{display:flex;align-items:center;justify-content:space-between;gap:12px;
  flex-wrap:wrap;margin-top:12px;padding:13px 15px;border-radius:11px;
  background:var(--acc-soft);border:1px solid var(--acc)}
.ctext{font-size:13px;line-height:1.7;min-width:0}
.cmeta{display:block;color:var(--mut);font-size:11.5px}
.cbtns{display:flex;gap:8px;flex:none}
#offline{display:none}
#offline.on{display:block;background:var(--bad);color:#fff;padding:10px 20px;
  font-size:13px;font-weight:500;position:sticky;top:0;z-index:20}

/* ---------- controls ---------- */
.ctl{display:flex;gap:9px;align-items:center;margin:14px 0}
.ctl label{color:var(--mut);font-size:12px;font-weight:500}
input[type=number]{background:var(--panel);color:var(--fg);border:1px solid var(--border);
  border-radius:8px;padding:8px 10px;width:74px;font-family:inherit;font-size:13px}
input[type=number]:focus{outline:none;border-color:var(--acc);
  box-shadow:0 0 0 3px var(--acc-soft)}
input[type=number]:disabled{background:var(--bg);color:var(--mut);cursor:not-allowed}

/* ---------- stats ---------- */
.stat{font-size:30px;font-weight:700;letter-spacing:-.02em;line-height:1.1}
.stat small{font-size:13px;color:var(--mut);font-weight:400}
.statbox{flex:1;background:var(--bg);border:1px solid var(--border-soft);
  border-radius:11px;padding:14px 16px}
.statbox small{color:var(--mut);font-size:12px;display:block;margin-top:3px}

/* ---------- table ---------- */
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:9px 10px;text-align:left;border-bottom:1px solid var(--border-soft)}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;
  letter-spacing:.04em}
tbody tr:hover{background:var(--bg)}
tbody tr:last-child td{border-bottom:none}
.bar{height:5px;background:var(--border-soft);border-radius:99px;overflow:hidden;
  margin-top:5px}
.bar>span{display:block;height:100%;background:var(--bad);border-radius:99px}

/* ---------- log ---------- */
#log{background:#0f172a;border:1px solid #1e293b;border-radius:11px;padding:14px;
  height:340px;overflow-y:auto;font-family:"Cascadia Code",Consolas,monospace;
  font-size:12px;line-height:1.65;white-space:pre-wrap;color:#cbd5e1}
#log::-webkit-scrollbar{width:9px}
#log::-webkit-scrollbar-thumb{background:#334155;border-radius:99px}

@media(max-width:920px){.wrap{grid-template-columns:1fr}.full{grid-column:1}}
</style></head><body>
<header>
  <h1 id="title">Sysmon Lab</h1>
  <span class="badge" id="vmstate"><span class="dot" style="background:#94a3b8"></span>...</span>
  <span class="badge" id="jobstate">idle</span>
  <div class="tabs">
    <div class="tab" id="tab-linux" onclick="setPlat('linux')">Linux</div>
    <div class="tab" id="tab-windows" onclick="setPlat('windows')">Windows</div>
  </div>
</header>
<div class="wrap">
  <div class="panel">
    <h2>รัน Scenario</h2>
    <div class="ctl">
      <label>duration (นาที)</label><input id="dur" type="number" value="5" min="1">
      <label>atomic timeout</label><input id="at" type="number" value="240">
    </div>
    <div id="vmline" style="color:var(--mut);font-size:12px;margin:0 0 10px"></div>
    <div id="scbtns"></div>
    <div id="confirmbar"></div>
    <div class="ctl" style="margin-top:14px;flex-wrap:wrap">
      <button onclick="selectSet(cleanSet())" id="cleanbtn">✓ เลือกชุดสะอาด</button>
      <button onclick="selectSet([])">✗ ล้าง</button>
      <button onclick="runBatch()" id="batchbtn" class="run">▶ เก็บทั้งชุดที่เลือก</button>
    </div>
    <div id="queue" style="color:var(--mut);font-size:12px;margin-top:6px"></div>
    <div class="ctl" style="margin-top:10px">
      <button onclick="snap()" id="snapbtn">💾 Save clean snapshot</button>
    </div>
  </div>
  <div class="panel">
    <h2>Dataset</h2>
    <div style="display:flex;gap:12px;margin-bottom:16px">
      <div class="statbox"><div class="stat" id="total">–</div><small>events รวม</small></div>
      <div class="statbox"><div class="stat" id="malpct">–</div><small>malicious</small></div>
    </div>
    <table id="sesstbl"><thead><tr><th>session</th><th>events</th><th>mal%</th></tr></thead><tbody></tbody></table>
    <div class="ctl" style="margin-top:12px">
      <button onclick="merge()" id="mergebtn" class="full">🔀 Merge dataset (สะอาด)</button>
    </div>
  </div>
  <div class="panel full">
    <h2>Log สด</h2>
    <div id="log"></div>
  </div>
</div>
<script>
const $=s=>document.querySelector(s);
const CLEAN_LINUX=["benign","ransomware","botnet","miner","exploit","trojan"];
const CLEAN_WIN=["benign_win","ransomware_win","botnet_win","miner_win","exploit_win","trojan_win"];
const CLEAN=CLEAN_LINUX.concat(CLEAN_WIN);
let scenarios=[];
async function j(u,m,b){
  try{
    const r=await fetch(u,{method:m||'GET',
      headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):null});
    offline(false);
    return await r.json();
  }catch(e){
    // dashboard ตายแล้วแต่หน้าเว็บยังค้างอยู่ - เคยเจอแล้วกดปุ่มเงียบสนิทหาสาเหตุไม่เจอ
    offline(true);
    throw e;
  }}
function offline(on){
  let b=$('#offline');
  if(!b){b=document.createElement('div');b.id='offline';document.body.prepend(b)}
  b.className=on?'on':'';
  b.textContent=on?'⚠ ติดต่อ dashboard ไม่ได้ — เซิร์ฟเวอร์อาจปิดไปแล้ว  (รัน  python host/dashboard.py  ใหม่ แล้วกด Ctrl+Shift+R)':'';
}
// แท็บ platform - RAM 32GB รันได้ทีละ VM อยู่แล้ว การแยกหน้าจึงตรงกับวิธีทำงานจริง
// และกันกดข้ามฝั่งโดยไม่ตั้งใจ (เสียเวลา revert+boot ผิดเครื่องราว 10 นาที)
let PLAT = localStorage.getItem('plat') || 'linux';
let PICKED = null;      // scenario ที่เลือกไว้รอยืนยัน (เก็บทีละตัว ไม่ใช่คิวรวม)
const VM_OF = {linux:'target1', windows:'wintarget'};
function cleanSet(){return PLAT==='windows'?CLEAN_WIN:CLEAN_LINUX}

function setPlat(p){
  PLAT=p; localStorage.setItem('plat',p); PICKED=null;
  $('#tab-linux').className='tab'+(p==='linux'?' on':'');
  $('#tab-windows').className='tab'+(p==='windows'?' on':'');
  $('#title').textContent=(p==='windows'?'🪟 Windows':'🐧 Linux')+' — Sysmon Lab Dashboard';
  $('#cleanbtn').textContent=`✓ เลือกชุดสะอาด (${cleanSet().length})`;
  $('#at').disabled = (p==='windows');   // ฝั่ง Windows ใช้ env ATOMIC_TIMEOUT ใน _lib.ps1
  renderSc();
}

function renderSc(){
  const rows=scenarios.filter(s=>s.platform===PLAT);
  if(!rows.length){$('#scbtns').innerHTML='<div style="color:var(--mut)">ไม่มี scenario</div>';return}
  const clean=cleanSet();
  const n=rows.length, mal=rows.filter(s=>!s.name.startsWith('benign')).length;
  $('#vmline').innerHTML=`VM <b style="color:var(--fg)">${VM_OF[PLAT]}</b>
     &nbsp;·&nbsp; ${n} scenario &nbsp;·&nbsp; ${mal} malicious / ${n-mal} benign`;
  $('#scbtns').innerHTML = rows.map(s=>{
      const benign=s.name.startsWith('benign');
      // จุดสีแทน emoji - เข้ากับธีมมากกว่าและอ่านง่ายบนพื้นขาว
      const dot=`<span class="dot" style="background:${benign?'var(--ok)':'var(--bad)'}"></span>`;
      const tags=(s.attack||'').split(',').filter(Boolean).slice(0,3)
        .map(x=>`<span class="tag">${x.trim()}</span>`).join('');
      const more=(s.attack||'').split(',').filter(Boolean).length-3;
      return `<div>
        <input type="checkbox" class="scchk" value="${s.name}" ${clean.includes(s.name)?'checked':''}>
        <button class="run scrow${PICKED===s.name?' picked':''}" data-sc="${s.name}"
                onclick="pick('${s.name}')" title="${s.attack||'(no attack listed)'}">
          <span class="scname">${dot}${s.name}</span>
          <span class="sctags">${tags}${more>0?`<span class="tag more">+${more}</span>`:''}</span>
        </button></div>`}).join('');
  renderConfirm()}

// กดแถว = เลือกไว้ก่อน ต้องกดยืนยันอีกทีถึงจะเริ่มเก็บ
// (เดิมกดแล้วรันทันที เผลอโดนแล้วเสียเวลา revert+boot ~10 นาที)
//
// ⚠️ ห้ามเรียก renderSc() ที่นี่ - มันสร้าง innerHTML ใหม่ทั้งก้อน
//    แล้ว checkbox จะถูกตั้งกลับไปตาม cleanSet() = ติ๊กหมดทุกอัน (เคยพลาดมาแล้ว)
//    แค่สลับ class ของปุ่มพอ ของที่ผู้ใช้ติ๊กไว้จะไม่หาย
function pick(name){
  PICKED = (PICKED===name ? null : name);
  document.querySelectorAll('#scbtns button.scrow').forEach(b=>
    b.classList.toggle('picked', b.dataset.sc===PICKED));
  renderConfirm()}

function renderConfirm(){
  const bar=$('#confirmbar');
  if(!PICKED){bar.innerHTML='';return}
  const s=scenarios.find(x=>x.name===PICKED)||{};
  bar.innerHTML=`
    <div class="confirm">
      <div class="ctext">
        จะเริ่มเก็บ <b>${PICKED}</b> บน VM <b>${VM_OF[PLAT]}</b>
        <span class="cmeta">duration ${$('#dur').value} นาที · revert snapshot ก่อนเริ่ม</span>
        ${s.attack?`<span class="cmeta">${s.attack}</span>`:''}
      </div>
      <div class="cbtns">
        <button class="run" onclick="confirmRun()">▶ ยืนยันเริ่มเก็บ</button>
        <button onclick="pick(null)">ยกเลิก</button>
      </div>
    </div>`}

async function confirmRun(){
  const name=PICKED;
  pick(null);                      // ล้างการเลือกโดยไม่แตะ checkbox
  await run(name)}

async function loadSc(){scenarios=await j('/api/scenarios');setPlat(PLAT)}
function selected(){return[...document.querySelectorAll('.scchk:checked')].map(c=>c.value)}
function selectSet(set){document.querySelectorAll('.scchk').forEach(c=>c.checked=set.includes(c.value))}
async function run(name){await j('/api/run','POST',
  {scenario:name,duration:+$('#dur').value,atomic_timeout:+$('#at').value})}
async function runBatch(){const s=selected();if(!s.length)return alert('เลือก scenario ก่อน');
  if(!confirm(`เก็บ ${s.length} scenario เรียงกัน?\n${s.join(', ')}\n\nใช้เวลา ~${s.length*13} นาที`))return;
  await j('/api/run_batch','POST',{scenarios:s,duration:+$('#dur').value,atomic_timeout:+$('#at').value})}
async function merge(){await j('/api/merge','POST',{})}
async function snap(){if(!confirm(`บันทึก clean snapshot ของ VM ${VM_OF[PLAT]} ?`))return;
  await j('/api/snapshot','POST',{platform:PLAT})}
async function tick(){
  const st=await j('/api/state');
  const busy=st.busy;
  $('#jobstate').textContent=busy?`▶ ${st.job||'...'} (${st.phase})`:st.phase;
  $('#jobstate').style.borderColor=busy?'var(--warn)':(st.phase=='error'?'var(--bad)':'var(--border)');
  document.querySelectorAll('#scbtns button,#mergebtn,#snapbtn,#batchbtn').forEach(b=>b.disabled=busy);
  const q=$('#queue');
  if((st.done&&st.done.length)||(st.queue&&st.queue.length)){
    const done=(st.done||[]).map(d=>`${d.ok?'✅':'❌'} ${d.name}`).join('  ');
    const pend=(st.queue||[]).map(n=>`⏳ ${n}`).join('  ');
    q.innerHTML=`คิว: ${done} ${busy&&st.job?'▶ '+st.job:''}  ${pend}`;
  }else q.innerHTML='';
  const lg=$('#log');const atBottom=lg.scrollTop+lg.clientHeight>=lg.scrollHeight-40;
  lg.textContent=st.log.join('\n');if(atBottom)lg.scrollTop=lg.scrollHeight;
  const ds=await j('/api/dataset');
  $('#total').textContent=ds.total?ds.total.toLocaleString():'–';
  $('#malpct').textContent=ds.total?((ds.malicious/ds.total*100).toFixed(1)+'%'):'–';
  $('#sesstbl tbody').innerHTML=ds.sessions.map(s=>`<tr><td>${s.name}</td>
    <td>${s.events.toLocaleString()}</td><td>${s.malicious_pct}%
    <div class="bar"><span style="width:${s.malicious_pct}%"></span></div></td></tr>`).join('');
}
loadSc();tick();setInterval(tick,2000);
</script></body></html>"""


def main():
    port = 8000
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[*] Dashboard: http://localhost:{port}  (Ctrl+C เพื่อหยุด)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        stop_collectors()
        print("\n[*] หยุดแล้ว")


if __name__ == "__main__":
    main()
