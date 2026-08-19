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
import subprocess
import sys
import threading
import time
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Windows console default = cp1252 -> print ภาษาไทย crash; บังคับ utf-8
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

import orchestrator as orch

HOST_DIR = Path(__file__).resolve().parent
LAB_DIR = HOST_DIR.parent
LOG_DIR = HOST_DIR / "logs"
DATASET_DIR = HOST_DIR / "dataset"

# preset ชุด scenario สะอาด (6 ตัว) สำหรับเก็บ dataset ครบชุด
# ใช้ real malware ให้ครบ 3 ตัว (miner_real/exploit_real/trojan_real) เพื่อความสม่ำเสมอ
CLEAN_SET = ["benign", "ransomware", "botnet", "miner_real", "exploit_real", "trojan_real"]

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
    return subprocess.Popen([sys.executable, str(HOST_DIR / script), *args],
                            cwd=str(HOST_DIR), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)


def start_collectors(session):
    """เปิด log_receiver + mining_pool (stratum :3333) + c2_server (:8080/:4444)
    mining_pool ต้อง start ก่อนเพื่อยึด 3333 (miner_real ใช้ stratum จริง)"""
    stop_collectors()
    COLLECTORS["receiver"] = _spawn("log_receiver.py", "--session", session)
    COLLECTORS["pool"] = _spawn("mining_pool.py")      # :3333 stratum
    time.sleep(0.5)
    COLLECTORS["c2"] = _spawn("c2_server.py")          # :8080 + :4444
    logline(f"[collectors] log_receiver(session={session}) + mining_pool + c2_server")


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
    STATE.update(job=name, phase="running", started=datetime.now().isoformat())
    session = f"{name}_dash_{datetime.now():%H%M%S}"
    start_collectors(session)
    ls = _LogStream()
    ok = False
    try:
        with redirect_stdout(ls), redirect_stderr(ls):
            orch.run_scenario(name, "target1", float(duration),
                              repeat=True, atomic_timeout=int(atomic_timeout))
        logline(f"[dashboard] เสร็จ scenario '{name}'")
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


def save_snapshot_bg():
    STATE.update(job="snapshot", phase="running")
    try:
        orch.snapshot_save("target1")
        logline("[snapshot] บันทึก clean snapshot แล้ว")
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
            sc = [{"name": k, "attack": v.get("attack", ""),
                   "label": v.get("label", "")}
                  for k, v in orch.SCENARIOS.items()]
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
            names = [n for n in names if n in orch.SCENARIOS]
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
            threading.Thread(target=save_snapshot_bg, daemon=True).start()
            return self._send(200, json.dumps({"ok": True}))
        return self._send(404, json.dumps({"error": "not found"}))


HTML = r"""<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sysmon Lab Dashboard</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--mut:#8b949e;
--acc:#2f81f7;--ok:#3fb950;--bad:#f85149;--warn:#d29922}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font-family:"Segoe UI",system-ui,sans-serif;font-size:14px}
header{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;
align-items:center;gap:14px}
header h1{font-size:16px;margin:0;font-weight:600}
.badge{padding:2px 10px;border-radius:12px;font-size:12px;border:1px solid var(--border)}
.wrap{display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:16px;max-width:1200px;margin:0 auto}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px}
.panel h2{font-size:13px;margin:0 0 12px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
button{background:var(--panel);color:var(--fg);border:1px solid var(--border);
border-radius:8px;padding:10px;cursor:pointer;font-size:13px;transition:.15s}
button:hover:not(:disabled){border-color:var(--acc);background:#1c2333}
button:disabled{opacity:.4;cursor:not-allowed}
button.run{border-color:#2a4}
.ctl{display:flex;gap:8px;align-items:center;margin:12px 0}
.ctl label{color:var(--mut);font-size:12px}
input{background:var(--bg);color:var(--fg);border:1px solid var(--border);
border-radius:6px;padding:6px 8px;width:64px}
#log{background:#010409;border:1px solid var(--border);border-radius:8px;padding:10px;
height:340px;overflow-y:auto;font-family:"Cascadia Code",Consolas,monospace;font-size:12px;
line-height:1.5;white-space:pre-wrap;color:#c9d1d9}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{padding:6px 8px;text-align:left;border-bottom:1px solid var(--border)}
th{color:var(--mut);font-weight:500}
.bar{height:6px;background:var(--bg);border-radius:3px;overflow:hidden;margin-top:4px}
.bar>span{display:block;height:100%;background:var(--bad)}
.stat{font-size:26px;font-weight:700}.stat small{font-size:13px;color:var(--mut);font-weight:400}
.full{grid-column:1/3}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
</style></head><body>
<header>
  <h1>🛡️ Sysmon for Linux — Lab Dashboard</h1>
  <span class="badge" id="vmstate"><span class="dot" style="background:#666"></span>...</span>
  <span class="badge" id="jobstate">idle</span>
</header>
<div class="wrap">
  <div class="panel">
    <h2>รัน Scenario</h2>
    <div class="ctl">
      <label>duration (นาที)</label><input id="dur" type="number" value="5" min="1">
      <label>atomic timeout</label><input id="at" type="number" value="240">
    </div>
    <div id="scbtns"></div>
    <div class="ctl" style="margin-top:14px;flex-wrap:wrap">
      <button onclick="selectClean()">✓ เลือก 6 ตัวสะอาด</button>
      <button onclick="runBatch()" id="batchbtn" class="run">▶ เก็บทั้งชุดที่เลือก</button>
    </div>
    <div id="queue" style="color:var(--mut);font-size:12px;margin-top:6px"></div>
    <div class="ctl" style="margin-top:10px">
      <button onclick="snap()" id="snapbtn">💾 Save clean snapshot</button>
    </div>
  </div>
  <div class="panel">
    <h2>Dataset</h2>
    <div style="display:flex;gap:24px;margin-bottom:12px">
      <div><div class="stat" id="total">–</div><small>events รวม</small></div>
      <div><div class="stat" id="malpct">–</div><small>malicious</small></div>
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
const CLEAN=["benign","ransomware","botnet","miner_real","exploit_real","trojan_real"];
let scenarios=[];
async function j(u,m,b){const r=await fetch(u,{method:m||'GET',
  headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):null});return r.json()}
async function loadSc(){scenarios=await j('/api/scenarios');
  $('#scbtns').innerHTML=scenarios.map(s=>{
    const real=s.name.includes('real');
    return `<div style="display:flex;align-items:center;gap:8px;margin:4px 0">
      <input type="checkbox" class="scchk" value="${s.name}" ${CLEAN.includes(s.name)?'checked':''}>
      <button class="run" style="flex:1;text-align:left" onclick="run('${s.name}')" title="${s.attack}">
        ${real?'🔴':'🟢'} ${s.name}</button></div>`}).join('')}
function selected(){return[...document.querySelectorAll('.scchk:checked')].map(c=>c.value)}
function selectClean(){document.querySelectorAll('.scchk').forEach(c=>c.checked=CLEAN.includes(c.value))}
async function run(name){await j('/api/run','POST',
  {scenario:name,duration:+$('#dur').value,atomic_timeout:+$('#at').value})}
async function runBatch(){const s=selected();if(!s.length)return alert('เลือก scenario ก่อน');
  if(!confirm(`เก็บ ${s.length} scenario เรียงกัน?\n${s.join(', ')}\n\nใช้เวลา ~${s.length*13} นาที`))return;
  await j('/api/run_batch','POST',{scenarios:s,duration:+$('#dur').value,atomic_timeout:+$('#at').value})}
async function merge(){await j('/api/merge','POST',{})}
async function snap(){await j('/api/snapshot','POST',{})}
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
