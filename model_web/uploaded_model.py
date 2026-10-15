"""Adapters for trusted, user-supplied sklearn classifier/outlier artifacts."""
import csv
import hashlib
import io
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, is_classifier, is_outlier_detector
from sklearn.exceptions import InconsistentVersionWarning
from sklearn.pipeline import Pipeline
from sklearn.utils.validation import check_is_fitted

MAX_MODEL_BYTES = 100 * 1024 * 1024


def load_trusted_model(data, filename, trusted=False):
    # pickle/joblib deserialization can execute code. This gate is consent, NOT a sandbox.
    if not trusted:
        raise ValueError('ยืนยันก่อนว่าเป็นโมเดลของคุณเองหรือมาจากแหล่งที่เชื่อถือได้')
    if not filename.lower().endswith(('.pkl', '.pickle', '.joblib')):
        raise ValueError('รองรับไฟล์ .pkl, .pickle และ .joblib')
    if not 0 < len(data) <= MAX_MODEL_BYTES:
        raise ValueError('โมเดลต้องมีขนาดไม่เกิน 100 MB และไม่ใช่ไฟล์ว่าง')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', InconsistentVersionWarning)
            loaded = joblib.load(io.BytesIO(data))
    except InconsistentVersionWarning as exc:
        raise ValueError(f'เวอร์ชัน scikit-learn ไม่ตรง: โมเดลใช้ {exc.original_sklearn_version} แต่เว็บใช้ {exc.current_sklearn_version} กรุณาเปิดเว็บใน environment ที่ตรงกับตอนฝึก') from exc
    except ModuleNotFoundError as exc:
        raise ValueError(f'โมเดลต้องใช้โมดูล {exc.name} ซึ่งยังไม่มีใน environment นี้') from exc
    except Exception as exc:
        raise ValueError(f'อ่านโมเดลไม่ได้ ({type(exc).__name__}) ต้องเป็นไฟล์ที่บันทึกด้วย pickle/joblib และใช้ไลบรารีรุ่นที่ตรงกัน') from exc
    bundle = loaded if isinstance(loaded, dict) else {}
    model = loaded
    if bundle:
        for key in ('model', 'pipeline', 'classifier', 'rf', 'estimator'):
            if key in bundle:
                model = bundle[key]; break
    if not isinstance(model, BaseEstimator) or not callable(getattr(model, 'predict', None)):
        raise ValueError('ไม่พบโมเดล scikit-learn ที่มี predict(); รองรับ estimator, Pipeline หรือ dict ที่มี model/pipeline/classifier/rf/estimator')
    if not is_classifier(model) and not is_outlier_detector(model):
        raise ValueError('เว็บนี้รองรับโมเดลจำแนกสองคลาสและโมเดลตรวจค่าผิดปกติ ไม่รองรับ regression/clustering')
    try:
        check_is_fitted(model)
    except Exception as exc:
        raise ValueError('โมเดลยังไม่ได้ฝึก หรือไม่มีสถานะ fitted ที่อ่านได้') from exc
    scaler = bundle.get('scaler')
    if scaler is not None and isinstance(model, Pipeline):
        raise ValueError('ไฟล์มีทั้ง Pipeline และ scaler แยก กรุณาบันทึก preprocessing เป็น Pipeline เดียวเพื่อไม่แปลงข้อมูลซ้ำ')
    if scaler is not None and (not isinstance(scaler, BaseEstimator) or not callable(getattr(scaler, 'transform', None))):
        raise ValueError('scaler ในไฟล์ไม่มี transform() ที่ใช้ได้')
    outlier = is_outlier_detector(model)
    if not outlier:
        classes = np.asarray(getattr(model, 'classes_', []))
        if classes.ndim != 1 or len(classes) != 2 or set(classes.tolist()) != {0, 1}:
            raise ValueError('โมเดลจำแนกต้องใช้คลาส 0 = ปกติ และ 1 = การโจมตี (ตัวเลข)')
    front = scaler if scaler is not None else model
    metadata = bundle.get('metadata', {})
    if not isinstance(metadata, dict):
        metadata = {}
    stored = bundle.get('columns', bundle.get('feature_names', bundle.get('features', metadata.get('columns'))))
    names = getattr(front, 'feature_names_in_', None)
    if names is not None:
        names = list(map(str, names))
        if stored is not None and names != list(stored):
            raise ValueError('ชื่อฟีเจอร์ใน metadata ไม่ตรงกับ feature_names_in_ ของโมเดล')
    elif stored is not None:
        if not isinstance(stored, (list, tuple, np.ndarray, pd.Index)):
            raise ValueError('columns/feature_names/features ต้องเป็นรายการชื่อฟีเจอร์ตามลำดับ')
        names = list(stored)
    else:
        names = []
    if any(not isinstance(x, str) or not x.strip() for x in names) or len(names) != len(set(names)):
        raise ValueError('ชื่อฟีเจอร์ต้องเป็นข้อความไม่ว่างและไม่ซ้ำกัน')
    count = getattr(front, 'n_features_in_', None)
    if count is not None and names and len(names) != int(count):
        raise ValueError('จำนวนชื่อฟีเจอร์ไม่ตรงกับจำนวน input ของโมเดล')
    notes = []
    if not isinstance(model, Pipeline) and scaler is None:
        notes.append('ไฟล์ไม่มี Pipeline/scaler: CSV ต้องเตรียมข้อมูลเหมือนตอนฝึก หากเคย scale/PCA ให้บันทึกขั้นตอนนั้นรวมใน Pipeline')
    if not names:
        notes.append('โมเดลไม่มีชื่อฟีเจอร์ ต้องระบุรายชื่อเรียงตามลำดับตอนฝึกก่อนทดสอบ')
    notes.append('ไม่มีหลักฐานชุดฝึกที่ตรวจสอบได้สำหรับโมเดลที่อัปโหลด จึงยังยืนยันไม่ได้ว่าข้อมูลทดสอบเป็นอิสระ')
    score_kind = 'anomaly' if outlier else 'probability' if hasattr(model, 'predict_proba') else 'decision' if hasattr(model, 'decision_function') else 'none'
    name = type(model).__name__
    if isinstance(model, Pipeline):
        name = 'Pipeline · ' + type(model.steps[-1][1]).__name__
    info = dict(name=name, filename=filename, sha256=hashlib.sha256(data).hexdigest(),
                columns=names, feature_count=int(count) if count is not None else len(names) or None,
                preprocessing='Pipeline' if isinstance(model, Pipeline) else type(scaler).__name__ if scaler is not None else 'ไม่มีในไฟล์',
                score_kind=score_kind, outlier=outlier, notes=notes)
    typer = bundle.get('typer')
    if typer is not None:
        if not is_classifier(typer) or not callable(getattr(typer, 'predict_proba', None)):
            raise ValueError('typer ในไฟล์ต้องเป็นโมเดลจำแนกที่มี predict_proba()')
        if getattr(typer, 'n_features_in_', len(names)) != len(names):
            raise ValueError('typer ต้องรับฟีเจอร์ชุดเดียวกับโมเดลตรวจจับ')
        info['attack_types'] = [str(c) for c in typer.classes_]
    if bundle.get('platform') in ('linux', 'windows'):
        info['platform'] = bundle['platform']
    return dict(model=model, scaler=scaler, metadata=info, typer=typer)


def importances(model):
    est = model.steps[-1][1] if isinstance(model, Pipeline) else model
    return getattr(est, 'feature_importances_', None)


def feature_order(artifact, supplied):
    known = artifact['metadata']['columns']
    entered = [x.strip() for x in supplied.replace('\n', ',').split(',') if x.strip()]
    if known:
        if entered and known != entered:
            raise ValueError('ลำดับฟีเจอร์ที่ระบุไม่ตรงกับข้อมูลในโมเดล')
        return known
    if not entered:
        raise ValueError('โมเดลไม่มีชื่อฟีเจอร์ กรุณาระบุลำดับฟีเจอร์ที่ใช้ตอนฝึกในช่องชื่อฟีเจอร์')
    if len(entered) != len(set(entered)):
        raise ValueError('รายชื่อฟีเจอร์ซ้ำกัน')
    count = artifact['metadata']['feature_count']
    if count is not None and len(entered) != count:
        raise ValueError(f'โมเดลต้องการ {count} ฟีเจอร์ แต่ระบุ {len(entered)} ชื่อ')
    return entered


def read_feature_csv(data, names, label_column, max_rows):
    try:
        text = data.decode('utf-8-sig')
        headers = next(csv.reader(io.StringIO(text)))
        if len(headers) != len(set(headers)):
            raise ValueError('ชื่อคอลัมน์ CSV ซ้ำกัน')
        d = pd.read_csv(io.StringIO(text), nrows=max_rows + 1, low_memory=False)
    except (UnicodeDecodeError, StopIteration, pd.errors.ParserError) as exc:
        raise ValueError('อ่าน CSV ไม่ได้ กรุณาใช้ UTF-8 และหัวคอลัมน์ที่ถูกต้อง') from exc
    if d.empty or len(d) > max_rows:
        raise ValueError(f'CSV ต้องมี 1–{max_rows:,} แถว')
    missing = sorted(set(names) - set(d.columns))
    if missing:
        raise ValueError('CSV ขาดฟีเจอร์: ' + ', '.join(missing))
    if label_column and label_column in names:
        raise ValueError('คอลัมน์ label อยู่ในฟีเจอร์ด้วย กรุณาตรวจโมเดลเพื่อป้องกัน label leakage')
    truth = pd.Series(np.nan, index=d.index)
    if label_column and label_column in d:
        truth = pd.to_numeric(d[label_column], errors='coerce')
        if (d[label_column].notna() & ~truth.isin([0, 1])).any():
            raise ValueError('label จริงต้องเป็น 0/1 หรือว่าง')
    x = d.loc[:, names].copy()
    return d, x, truth


def run_uploaded(artifact, data, filename, options, read_events, metric_block, max_rows):
    names = feature_order(artifact, options.get('features', ''))
    mode = options.get('mode', 'features')
    notes = list(artifact['metadata']['notes'])
    if mode == 'events':
        if options.get('confirm_event_schema') != '1':
            raise ValueError('ยืนยันก่อนว่าโมเดลใช้ฟีเจอร์จาก aggregate() ของโครงการรุ่นนี้จริง')
        d, x, m, audit = read_events(data, options.get('platform', ''), options.get('run_id', ''))
        if set(names) - set(x.columns):
            raise ValueError('โมเดลต้องการฟีเจอร์นอกชุด Sysmon 32 ตัว กรุณาอัปโหลด CSV ฟีเจอร์ที่เตรียมไว้')
        x = x.loc[:, names]
        rows = m[['platform', 'run', 'ProcessGuid', 'Image']].copy()
        rows['true_label'] = m.label.where(m.truth_known, np.nan)
        rows['n_events'] = d.groupby('_process_key').size().reindex(rows.index)
        rows.index.name = 'process_key'; rows = rows.reset_index()
        events, dropped = audit['input_events'], audit['dropped_events']
        notes.extend(audit['notes'])
        imp = importances(artifact['model'])
        dead = [c for c in audit['dead_features'] if c in names]
        if dead and imp is not None:
            share = float(sum(imp[names.index(c)] for c in dead))
            notes.insert(0, f'ฟีเจอร์ {", ".join(dead)} เป็นค่าคงที่เพราะคอลัมน์ต้นทางหายไป คิดเป็น {share:.0%} ของ importance ของโมเดล ผลจึงต่ำกว่าข้อมูลที่มีคอลัมน์ครบ')
        trained_on = artifact['metadata'].get('platform')
        if trained_on and set(rows.platform) - {trained_on}:
            notes.insert(0, f'โมเดลนี้ฝึกบน {trained_on} แต่ข้อมูลเป็น {", ".join(sorted(set(rows.platform)))} บทความพบว่าข้าม OS ไม่ได้')
        notes.append('ใช้ตัวรวม Event ของโครงการปัจจุบันตามที่ผู้ใช้ยืนยัน ไม่ได้อนุมานจากนามสกุล .pkl')
    elif mode == 'features':
        d, x, truth = read_feature_csv(data, names, options.get('label_column', 'label'), max_rows)
        rows = pd.DataFrame(index=d.index)
        rows['process_key'] = [f'row:{i+1}' for i in range(len(d))]
        rows['platform'] = d['platform'].fillna('unknown').astype(str).str.strip().str.lower() if 'platform' in d else 'unknown'
        rows.loc[~rows.platform.isin(['windows', 'linux']), 'platform'] = 'unknown'
        rows['run'] = d['run_id'].fillna('').astype(str) if 'run_id' in d else ''
        rows['ProcessGuid'] = d['ProcessGuid'].fillna('').astype(str) if 'ProcessGuid' in d else ''
        rows['Image'] = d['Image'].fillna('').astype(str) if 'Image' in d else ''
        rows['true_label'] = truth
        rows['n_events'] = np.nan
        events, dropped = len(d), 0
        notes.append('หนึ่งแถวใน CSV เป็นหนึ่งตัวอย่างทดสอบ ใช้เฉพาะฟีเจอร์ที่โมเดลต้องการตามลำดับ')
    else:
        raise ValueError('รูปแบบข้อมูลไม่ถูกต้อง')
    model, scaler = artifact['model'], artifact['scaler']
    front = scaler if scaler is not None else model
    model_input = x if hasattr(front, 'feature_names_in_') else x.to_numpy()
    try:
        if scaler is not None:
            model_input = scaler.transform(model_input)
            if hasattr(model, 'feature_names_in_'):
                model_input = pd.DataFrame(model_input, columns=model.feature_names_in_)
        p = np.asarray(model.predict(model_input))
        kind = artifact['metadata']['score_kind']
        if artifact['metadata']['outlier']:
            if not set(np.unique(p)).issubset({-1, 1}):
                raise ValueError('ตัวตรวจค่าผิดปกติต้องคืนค่า -1 หรือ 1')
            pred = (p == -1).astype(int)
            s = -np.asarray(model.score_samples(model_input)) if hasattr(model, 'score_samples') else -np.asarray(model.decision_function(model_input)) if hasattr(model, 'decision_function') else None
            notes.append('แปลงผล outlier: -1 เป็น label 1 (ผิดปกติ), +1 เป็น label 0 (ปกติ); คะแนนสูงหมายถึงผิดปกติมาก')
        else:
            pred = p.astype(int)
            if kind == 'probability':
                s = np.asarray(model.predict_proba(model_input))[:, list(model.classes_).index(1)]
            elif kind == 'decision':
                s = np.asarray(model.decision_function(model_input))
                if model.classes_[1] != 1:
                    s = -s
            else:
                s = None
        threshold = None
        if options.get('use_threshold') == '1':
            if kind != 'probability':
                raise ValueError('ปรับ threshold แบบ 0–1 ได้เฉพาะโมเดลที่มี predict_proba')
            threshold = float(options.get('threshold', .5))
            if not np.isfinite(threshold) or not 0 <= threshold <= 1:
                raise ValueError('threshold ต้องอยู่ระหว่าง 0 และ 1')
            pred = (s >= threshold).astype(int)
        if pred.ndim != 1 or len(pred) != len(rows) or not set(np.unique(pred)).issubset({0, 1}):
            raise ValueError('ผลทำนายต้องเป็นเวกเตอร์สองคลาส 0/1')
        if s is not None and (s.ndim != 1 or len(s) != len(rows) or not np.isfinite(s).all()):
            raise ValueError('โมเดลคืนคะแนนที่ไม่ใช่ตัวเลขจำกัดหรือจำนวนไม่ตรงกับข้อมูล')
    except Exception as exc:
        raise ValueError('โมเดลทำนายไม่สำเร็จ ตรวจชนิดข้อมูล/ฟีเจอร์และ preprocessing: ' + str(exc)[:600]) from exc
    rows['prediction'] = pred
    rows['score'] = s if s is not None else np.nan
    rows['seen_in_training'] = None  # Unknown, including in downloaded CSV; never claim no overlap.
    attack_types = None
    if artifact.get('typer') is not None:
        rows['attack_type'] = None
        flag = (pred == 1)
        if flag.any():
            typer = artifact['typer']  # fitted on unscaled features, so it gets x rather than model_input
            tp = typer.predict_proba(x.loc[flag] if hasattr(typer, 'feature_names_in_') else x.to_numpy()[flag])
            rows.loc[flag, 'attack_type'] = typer.classes_[tp.argmax(1)]
            counts = rows.loc[flag, 'attack_type'].value_counts()
            attack_types = [dict(type=str(k), processes=int(v), share=float(v / flag.sum())) for k, v in counts.items()]
        notes.append('ประเภทการโจมตีทายเฉพาะตัวอย่างที่ถูกทำนายเป็นการโจมตี และมีได้แค่ประเภทที่ typer รู้จัก '
                     '(สถานการณ์จำลองในแล็บ) ตัวอย่างที่ทำนายผิดเป็นการโจมตีก็ได้ประเภทด้วย')
    rows = rows.sort_values('score', ascending=False, na_position='last')
    report = dict(filename=filename, model=artifact['metadata']['name'], model_file=artifact['metadata']['filename'],
                  model_sha256=artifact['metadata']['sha256'], input_mode=mode, score_kind=kind,
                  threshold=threshold, events=events, dropped_events=dropped, processes=len(rows),
                  flagged=int(rows.prediction.sum()), labeled=int(rows.true_label.notna().sum()), overlap=None,
                  notes=notes, metrics=metric_block(rows), attack_types=attack_types,
                  by_os={p:dict(processes=len(r),flagged=int(r.prediction.sum()),metrics=metric_block(r)) for p,r in rows.groupby('platform')})
    return report, rows
