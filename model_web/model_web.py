"""Local tester for trusted user-uploaded sklearn pickle/joblib models and CSV."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import secrets
from pathlib import Path
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import uuid

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

import feature_processing as rx
from uploaded_model import load_trusted_model, run_uploaded

ROOT = Path(__file__).resolve().parent
ASSETS = Path(__file__).with_name('assets')
MODEL_DIR = ROOT / 'models' / 'web_tester'
MODEL_FILE = MODEL_DIR / 'random_forest.joblib'
MAX_BYTES = 100 * 1024 * 1024
MAX_ROWS = 200_000
REQUIRED = ['EventID', 'UtcTime', 'ProcessGuid', 'ParentProcessGuid',
            'CommandLine', 'ParentCommandLine', 'TargetFilename',
            'DestinationIp', 'DestinationPort', 'TargetObject', 'Device']
RESULTS: OrderedDict = OrderedDict()
RESULT_LOCK = threading.Lock()
PREDICT_LOCK = threading.Lock()
UPLOADED_MODELS: OrderedDict = OrderedDict()


def source_hash():
    return hashlib.sha256(Path(rx.__file__).read_bytes()).hexdigest()


def read_events(data: bytes, platform='', run_id=''):
    """Validate the raw-event schema, keeping absent truth separate from model input."""
    if len(data) > MAX_BYTES:
        raise ValueError('ไฟล์ใหญ่เกิน 100 MB')
    try:
        text = data.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise ValueError('กรุณาบันทึก CSV เป็น UTF-8 ก่อนอัปโหลด') from exc
    try:
        headers = next(csv.reader(io.StringIO(text)))
    except (StopIteration, csv.Error) as exc:
        raise ValueError('ไฟล์ CSV ว่างหรืออ่านหัวคอลัมน์ไม่ได้') from exc
    if len(headers) != len(set(headers)):
        raise ValueError('พบชื่อคอลัมน์ซ้ำ กรุณาแก้หัวตารางก่อนอัปโหลด')
    missing = sorted(set(REQUIRED) - set(headers))
    if missing:
        raise ValueError('ขาดคอลัมน์: ' + ', '.join(missing))
    try:
        d = pd.read_csv(io.StringIO(text), dtype=str, nrows=MAX_ROWS + 1)
    except Exception as exc:
        raise ValueError('อ่าน CSV ไม่สำเร็จ กรุณาตรวจตัวคั่นและจำนวนคอลัมน์') from exc
    if d.empty:
        raise ValueError('ไฟล์ไม่มีแถวข้อมูล')
    if len(d) > MAX_ROWS:
        raise ValueError('รองรับไม่เกิน 200,000 Event ต่อไฟล์')
    notes = []
    if 'platform' not in d:
        if platform not in ('linux', 'windows'):
            raise ValueError('ไฟล์ไม่มี platform: เลือกระบบปฏิบัติการในช่องข้อมูลที่ขาด')
        d['platform'] = platform
        notes.append('ใช้ platform ที่ระบุให้ทุก Event ในไฟล์')
    d['platform'] = d.platform.str.strip().str.lower()
    if not d.platform.isin(['windows', 'linux']).all():
        raise ValueError('platform ต้องเป็น windows หรือ linux ทุกแถว')
    if 'run_id' not in d:
        if not run_id.strip():
            raise ValueError('ไฟล์ไม่มี run_id: ถ้าเป็นข้อมูลหนึ่งรอบ ให้ระบุรหัสรอบทดลองก่อนทดสอบ')
        d['run_id'] = run_id.strip()
        notes.append('กำหนด run_id เดียวทั้งไฟล์ตามที่ระบุ ต้องเป็นข้อมูลจากหนึ่งรอบทดลองเท่านั้น')
    if d.run_id.isna().any() or d.run_id.str.strip().eq('').any():
        raise ValueError('run_id ต้องไม่ว่าง')
    if d.run_id.str.contains('|', regex=False).any():
        raise ValueError('run_id ต้องไม่มีเครื่องหมาย |')
    if 'session' not in d:
        d['session'] = d.run_id
    d['EventID'] = pd.to_numeric(d.EventID, errors='coerce')
    if d.EventID.isna().any() or (d.EventID % 1 != 0).any():
        raise ValueError('EventID ต้องเป็นเลขจำนวนเต็มทุกแถว')
    unknown = sorted(set(d.EventID) - set(rx.EVENT_IDS))
    if unknown:
        raise ValueError('EventID นอก schema ของโมเดลนี้: ' + ', '.join(str(int(x)) for x in unknown))
    times = pd.to_datetime(d.UtcTime, errors='coerce', format='mixed', utc=True)
    if times.isna().any():
        raise ValueError(f'UtcTime ว่างหรืออ่านไม่ได้ {int(times.isna().sum()):,} แถว')
    d['UtcTime'] = times.dt.strftime('%Y-%m-%d %H:%M:%S.%f')
    truth = pd.to_numeric(d['label'], errors='coerce') if 'label' in d else pd.Series(np.nan, index=d.index)
    if 'label' in d and (d.label.notna() & ~truth.isin([0, 1])).any():
        raise ValueError('label ต้องเป็น 0, 1 หรือเว้นว่าง')
    d['_truth_known'] = truth.isin([0, 1])
    # Placeholder only for rx.aggregate's metadata. Never counted as ground truth.
    d['label'] = truth.fillna(0).astype(int)
    for col in ['ProcessGuid', 'ParentProcessGuid']:
        d[col] = d[col].str.strip().str.lower().replace('', np.nan)
    invalid = d.ProcessGuid.isna() | d.ProcessGuid.eq(rx.NULL_GUID)
    dropped = int(invalid.sum())
    d = d.loc[~invalid].copy()
    if d.empty:
        raise ValueError('ไม่พบ ProcessGuid ที่ใช้ได้หลังตัดรหัสว่างและรหัสศูนย์')
    d['_process_key'] = d.platform + '|' + d.run_id + '|' + d.ProcessGuid
    f, m, _ = rx.aggregate(d)
    groups = d.groupby('_process_key')
    m['truth_known'] = groups._truth_known.all().reindex(m.index)
    m['ProcessGuid'] = groups.ProcessGuid.first().reindex(m.index)
    m['Image'] = groups.Image.first().reindex(m.index).fillna('') if 'Image' in d else ''
    conflict = int((groups.label.nunique() > 1).sum())
    if dropped:
        notes.append(f'ตัด {dropped:,} Event ที่ ProcessGuid ว่างหรือเป็นรหัสศูนย์')
    if conflict:
        notes.append(f'{conflict:,} โปรเซสมี label หลายค่า: ใช้ค่าสูงสุดตามโค้ดวิจัย')
    return d, f, m, dict(input_events=len(truth), dropped_events=dropped, notes=notes)


def train(csv_path: Path):
    data = csv_path.read_bytes()
    d, f, m, audit = read_events(data)
    if not m.truth_known.all() or set(m.label) != {0, 1}:
        raise ValueError('ชุดฝึกต้องมี label ครบ และมีทั้ง 0 กับ 1')
    # One fixed fold for the web demonstration; explicitly not the paper's 25-fold result.
    split = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=0)
    tr, te = next(split.split(f, m.label, groups=m.lineage))
    assert not set(m.lineage.iloc[tr]) & set(m.lineage.iloc[te])
    model = make_pipeline(StandardScaler(), dict(rx.supervised())['Random Forest'])
    model.fit(f.iloc[tr].values, m.label.iloc[tr].values)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    train_ids = set(m.platform.iloc[tr] + '|' + m.ProcessGuid.iloc[tr])
    metadata = dict(name='Random Forest', version='web-rf-32-v1', feature_count=len(f.columns),
                    created_utc=datetime.now(timezone.utc).isoformat(),
                    source=csv_path.name, source_sha256=hashlib.sha256(data).hexdigest(),
                    feature_source_sha256=source_hash(), sklearn_version=sklearn.__version__,
                    input_events=audit['input_events'], dropped_events=audit['dropped_events'],
                    train_processes=len(tr), test_processes=len(te),
                    train_lineages=int(m.lineage.iloc[tr].nunique()),
                    test_lineages=int(m.lineage.iloc[te].nunique()),
                    split='StratifiedGroupKFold, 5 folds, seed 0, first fold only',
                    platforms=sorted(m.platform.unique()), columns=list(f.columns),
                    parameters=model[-1].get_params(), threshold=0.5)
    artifact = dict(model=model, metadata=metadata, train_ids=train_ids)
    joblib.dump(artifact, MODEL_FILE)
    (MODEL_DIR / 'manifest.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding='utf-8')
    holdout = d[d._process_key.isin(m.index[te])].drop(columns=['_truth_known', '_process_key'])
    holdout.to_csv(MODEL_DIR / 'heldout_events.csv', index=False, encoding='utf-8-sig')
    m.assign(split=np.where(m.index.isin(m.index[tr]), 'train', 'test')).to_csv(MODEL_DIR / 'split_manifest.csv')
    report, _ = predict(artifact, holdout.to_csv(index=False).encode(), 'heldout_events.csv', 0.5)
    (MODEL_DIR / 'holdout_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(dict(model=str(MODEL_FILE), train=len(tr), test=len(te), metrics=report['metrics']), ensure_ascii=False))


def metric_block(rows):
    known = rows[rows.true_label.notna()]
    if known.empty:
        return None
    y, p = known.true_label.to_numpy(dtype=int), known.prediction.to_numpy(dtype=int)
    score_values = known.score.to_numpy() if known.score.notna().all() else None
    scores = rx.scores(y, p, score_values)
    scores = {k: float(v) if np.isfinite(v) else None for k, v in scores.items()}
    scores.update(n_labeled=len(y), confusion=confusion_matrix(y, p, labels=[0, 1]).tolist())
    return scores


def predict(artifact, data, filename, threshold, platform='', run_id=''):
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError('threshold ต้องอยู่ระหว่าง 0 และ 1')
    d, f, m, audit = read_events(data, platform, run_id)
    cols = artifact['metadata']['columns']
    if list(f.columns) != cols:
        raise ValueError('schema ฟีเจอร์ไม่ตรงกับโมเดล ต้องเตรียมโมเดลใหม่')
    prob = artifact['model'].predict_proba(f.values)
    positive_idx = list(artifact['model'].classes_).index(1)
    rows = m[['platform', 'run', 'ProcessGuid', 'Image']].copy()
    rows['score'] = prob[:, positive_idx]
    rows['prediction'] = (rows.score >= threshold).astype(int)
    rows['true_label'] = m.label.where(m.truth_known, np.nan)
    rows['seen_in_training'] = (m.platform + '|' + m.ProcessGuid).isin(artifact['train_ids'])
    rows['n_events'] = f.n_events.astype(int)
    rows.index.name = 'process_key'
    rows = rows.reset_index().sort_values('score', ascending=False)
    overlap = int(rows.seen_in_training.sum())
    notes = audit['notes'] + ['ผลนี้เป็นการทำนายเมื่อมี Event ครบในไฟล์ ไม่ใช่การตรวจจับแบบสดหรือผล 5 fold ซ้ำ 5 ครั้งในบทความ']
    if overlap:
        notes.insert(0, f'พบ {overlap:,} โปรเซสที่รหัสตรงกับชุดฝึก คะแนนจึงไม่ใช่ผลทดสอบอิสระ')
    else:
        notes.append('ไม่พบรหัสโปรเซสซ้ำกับชุดฝึก แต่ยังต้องตรวจแหล่งข้อมูลและรอบทดลองเพื่อยืนยันความเป็นอิสระ')
    if not rows.true_label.notna().all():
        notes.append('คำนวณคะแนนเฉพาะโปรเซสที่ทุก Event มี label; โปรเซสที่ไม่มี label ยังคงทำนายได้')
    report = dict(filename=filename, model=artifact['metadata']['version'], threshold=threshold,
                  events=audit['input_events'], dropped_events=audit['dropped_events'],
                  processes=len(rows), flagged=int(rows.prediction.sum()),
                  labeled=int(rows.true_label.notna().sum()), overlap=overlap, notes=notes,
                  metrics=metric_block(rows),
                  by_os={p: dict(processes=len(r), flagged=int(r.prediction.sum()), metrics=metric_block(r))
                         for p, r in rows.groupby('platform')})
    return report, rows


def csv_bytes(rows):
    safe = rows.copy()
    for col in safe.select_dtypes(include=['object', 'string']).columns:
        safe[col] = safe[col].map(lambda x: "'" + x if isinstance(x, str) and x.lstrip().startswith(('=', '+', '-', '@')) else x)
    return safe.to_csv(index=False).encode('utf-8-sig')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def send(self, status, body, content_type='application/json; charset=utf-8', attachment=None):
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False, allow_nan=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        if attachment:
            self.send_header('Content-Disposition', f'attachment; filename="{attachment}"')
        self.end_headers()
        self.wfile.write(body)

    def allowed(self):
        hosts = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        origin = self.headers.get('Origin')
        if self.headers.get('Host') not in hosts or (origin and origin not in {'http://' + h for h in hosts}):
            self.send(403, dict(error='ใช้เว็บจาก localhost เท่านั้น'))
            return False
        return True

    def do_GET(self):
        if not self.allowed():
            return
        url = urlsplit(self.path)
        if url.path == '/api/model':
            self.send(200, dict(ready=False, token=self.server.upload_token, required=REQUIRED,
                                max_bytes=MAX_BYTES, max_rows=MAX_ROWS))
        elif url.path == '/api/sample':
            self.send(404, dict(error='ใช้ CSV ที่ตรงกับโมเดลของคุณ'))
        elif url.path == '/api/download':
            key = parse_qs(url.query).get('id', [''])[0]
            with RESULT_LOCK:
                result = RESULTS.get(key)
            if result is None:
                self.send(404, dict(error='ผลหมดอายุ กรุณาทดสอบใหม่'))
            else:
                self.send(200, result, 'text/csv; charset=utf-8', 'process_predictions.csv')
        elif url.path in ('/', '/app.js', '/style.css'):
            file = 'index.html' if url.path == '/' else url.path[1:]
            ctype = {'index.html': 'text/html', 'app.js': 'text/javascript', 'style.css': 'text/css'}[file]
            self.send(200, (ASSETS / file).read_bytes(), ctype + '; charset=utf-8')
        else:
            self.send(404, dict(error='ไม่พบหน้า'))

    def do_POST(self):
        if not self.allowed():
            return
        url = urlsplit(self.path)
        if url.path not in ('/api/predict', '/api/upload-model'):
            self.send(404, dict(error='ไม่พบ API')); return
        if not secrets.compare_digest(self.headers.get('X-Model-Token', ''), self.server.upload_token):
            self.send(403, dict(error='กรุณารีเฟรชหน้าเว็บก่อนอัปโหลด')); return
        if not PREDICT_LOCK.acquire(blocking=False):
            self.send(409, dict(error='กำลังประมวลผลไฟล์ก่อนหน้า กรุณารอสักครู่')); return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= MAX_BYTES:
                raise ValueError('ไฟล์ต้องไม่ว่างและมีขนาดไม่เกิน 100 MB')
            q = parse_qs(url.query)
            self.connection.settimeout(60)
            data = self.rfile.read(size)
            if len(data) != size:
                raise ValueError('อัปโหลดไม่ครบ กรุณาลองอีกครั้ง')
            options = {k:v[0] for k,v in q.items()}
            filename = options.get('filename', 'uploaded.csv')[:200]
            if url.path == '/api/upload-model':
                artifact = load_trusted_model(data, filename, trusted=options.get('trusted') == '1')
                key = uuid.uuid4().hex
                UPLOADED_MODELS[key] = artifact
                while len(UPLOADED_MODELS) > 3:
                    UPLOADED_MODELS.popitem(last=False)
                self.send(200, dict(model_id=key, metadata=artifact['metadata']))
                return
            artifact = UPLOADED_MODELS.get(options.get('model_id', ''))
            if artifact is None:
                raise ValueError('กรุณาอัปโหลดโมเดลก่อน (หรือโมเดลหมดอายุ ให้โหลดใหม่)')
            report, rows = run_uploaded(artifact, data, filename, options, read_events, metric_block, MAX_ROWS)
            key = uuid.uuid4().hex
            with RESULT_LOCK:
                RESULTS[key] = csv_bytes(rows)
                while len(RESULTS) > 5:
                    RESULTS.popitem(last=False)
            report['download_id'] = key
            report['rows'] = json.loads(rows.to_json(orient='records'))
            self.send(200, report)
        except (ValueError, pd.errors.ParserError) as exc:
            self.send(400, dict(error=str(exc)))
        except Exception as exc:
            print(f'Prediction error: {type(exc).__name__}: {exc}', flush=True)
            self.send(500, dict(error='ประมวลผลไม่สำเร็จ โปรดตรวจ log ของเซิร์ฟเวอร์'))
        finally:
            PREDICT_LOCK.release()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--train', action='store_true')
    ap.add_argument('--csv', type=Path, default=ROOT.parent / 'FINAL_DATASET.csv')
    ap.add_argument('--port', type=int, default=8765)
    args = ap.parse_args()
    if args.train:
        train(args.csv); return
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    server.upload_token = secrets.token_urlsafe(32)
    print(f'Sysmon Model Lab: http://127.0.0.1:{args.port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
