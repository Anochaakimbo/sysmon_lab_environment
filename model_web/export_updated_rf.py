"""Export per-OS or pooled Random Forests; reserve machine 2 for evaluation."""
import argparse
import hashlib
import json
import pickle
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import scipy
import sklearn
from sklearn.metrics import confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'host'))
import replay_detect as rd
import revised_experiments as rx


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--combined', action='store_true', help='Fit one RF on both operating systems')
    args = ap.parse_args()
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Use a new empty output directory')
    out.mkdir(parents=True, exist_ok=True)
    parts, sources = [], []
    files = [(ROOT / 'data/FINAL_DATASET_fixed.csv.gz', 1, 'original_fixed')]
    files += [(p, 1, 'repeat') for p in sorted((ROOT / 'data/repeat').glob('*_labeled.csv.gz'))]
    files += [(p, 2, 'external_machine') for p in sorted((ROOT / 'data/machine2').glob('*_labeled.csv.gz'))]
    assert len(files) == 37, 'Expected 1 merged original, 24 repeat and 12 machine-2 files'
    for path, machine, kind in files:
        frame = pd.read_csv(path, low_memory=False)
        if kind != 'original_fixed':
            frame['run_id'] = path.name.removesuffix('_labeled.csv.gz')
        frame['machine'] = machine
        frame['collection'] = kind
        sources.append(dict(path=str(path.relative_to(ROOT)), sha256=sha(path), events=len(frame),
                            machine=machine, collection=kind))
        parts.append(frame)
    raw = pd.concat(parts, ignore_index=True)
    assert raw.label.isin([0, 1]).all()
    assert raw.groupby('run_id').machine.nunique().max() == 1
    assert raw.groupby('run_id').platform.nunique().max() == 1
    run_info = raw.groupby('run_id').agg(machine=('machine', 'first'), platform=('platform', 'first'),
                                       events=('label', 'size'), attack_fraction=('label', 'mean'))
    assert len(run_info) == 48
    valid_guid = raw.ProcessGuid.notna() & (raw.ProcessGuid != rx.NULL_GUID)
    invalid_ts = pd.to_datetime(raw.loc[valid_guid, 'UtcTime'], errors='coerce').isna().sum()
    if invalid_ts:
        raise ValueError(f'{invalid_ts} valid-GUID events have invalid timestamps')
    print('Input audit:', raw.groupby(['machine', 'platform']).size().to_dict(), flush=True)
    write_json(out / 'input_audit.json', dict(sources=sources, events=len(raw), runs=len(run_info),
               excluded_missing_or_zero_guid_events=int((~valid_guid).sum()), invalid_timestamps=int(invalid_ts)))
    print('Preparing full-process behavior features using current repository code...', flush=True)
    feats, meta = rd.prefix_features(raw, behavior=True, ages=[np.inf])
    harness_count = int(meta.harness.sum())
    keep = ~meta.harness
    x, meta = feats[np.inf].loc[keep], meta.loc[keep].copy()
    meta['machine'] = meta.run.map(run_info.machine)
    assert not meta.machine.isna().any()
    assert x.index.equals(meta.index) and x.index.is_unique
    assert np.isfinite(x.to_numpy()).all()
    assert len(x.columns) == 53
    assert not set(x.columns) & {'label', 'platform', 'run_id', 'machine', 'session', 'scenario'}
    meta['split'] = np.where(meta.machine.eq(1), 'train', 'test')
    assert not set(meta.loc[meta.split.eq('train'), 'run']) & set(meta.loc[meta.split.eq('test'), 'run'])
    assert not set(meta.loc[meta.split.eq('train'), 'lineage']) & set(meta.loc[meta.split.eq('test'), 'lineage'])
    meta.to_csv(out / 'split_manifest.csv', index_label='process_key', encoding='utf-8-sig')
    run_info.to_csv(out / 'run_manifest.csv', encoding='utf-8-sig')
    versions = dict(python=platform.python_version(), sklearn=sklearn.__version__, numpy=np.__version__,
                    pandas=pd.__version__, scipy=scipy.__version__, joblib=joblib.__version__)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    results = {}
    for os_name in (('combined',) if args.combined else ('linux', 'windows')):
        selected_os = meta.platform.isin(['linux', 'windows']) if args.combined else meta.platform.eq(os_name)
        train = selected_os & meta.machine.eq(1)
        test = selected_os & meta.machine.eq(2)
        assert meta.loc[train, 'label'].nunique() == meta.loc[test, 'label'].nunique() == 2
        print(f'Training {os_name}: {train.sum()} processes; held-out test: {test.sum()}', flush=True)
        model = dict(rx.supervised())['Random Forest']
        model.fit(x.loc[train], meta.loc[train, 'label'])
        prediction = model.predict(x.loc[test])
        score = model.predict_proba(x.loc[test])[:, list(model.classes_).index(1)]
        metrics = rx.scores(meta.loc[test, 'label'], prediction, score)
        metrics['confusion_matrix_labels_0_1'] = confusion_matrix(meta.loc[test, 'label'], prediction, labels=[0, 1]).tolist()
        by_os = {}
        for platform_name in sorted(meta.loc[test, 'platform'].unique()):
            mask = meta.loc[test, 'platform'].eq(platform_name).to_numpy()
            y_os = meta.loc[test, 'label'].to_numpy()[mask]
            by_os[platform_name] = dict(processes=int(mask.sum()), **rx.scores(y_os, prediction[mask], score[mask]))
            by_os[platform_name]['confusion_matrix_labels_0_1'] = confusion_matrix(y_os, prediction[mask], labels=[0, 1]).tolist()
        info = dict(platform=os_name, train_processes=int(train.sum()), test_processes=int(test.sum()),
                    train_runs=int(meta.loc[train, 'run'].nunique()), test_runs=int(meta.loc[test, 'run'].nunique()),
                    features=list(x.columns), versions=versions, repo_commit=commit,
                    protocol='Train corrected machine-1 original + repeat runs; test machine-2 runs. One pooled estimator for both OSes.' if args.combined else 'Train corrected machine-1 original + repeat runs; test all machine-2 runs of the same OS.',
                    feature_protocol='replay_detect full-process behavior=True, ages=[inf]; exclude harness processes after aggregation.',
                    threshold='estimator.predict default (0.5); no test-set tuning', metrics=metrics, by_os=by_os,
                    limitation='Offline simulated attack classification; same scenario families on a different machine. Not unseen attack or real malware validation. Machine-2 outcomes were previously reported in repository research.',
                    selection='RF and clean behavior feature recipe selected from repository reports before this new run; not an exhaustive new comparison of algorithms.')
        model.sysmon_metadata_ = info
        model_path = out / f'sysmon_rf_{os_name}.pkl'
        with model_path.open('wb') as f:
            pickle.dump(model, f, protocol=5)
        test_frame = x.loc[test].copy()
        test_frame['label'] = meta.loc[test, 'label']
        test_frame['platform'] = meta.loc[test, 'platform']
        test_frame['run_id'] = meta.loc[test, 'run']
        test_frame.to_csv(out / f'test_{os_name}_features.csv', index=False, encoding='utf-8-sig')
        # Test real serialized model and CSV, including numerical round-trip.
        restored = joblib.load(model_path)
        csv = pd.read_csv(out / f'test_{os_name}_features.csv')
        np.testing.assert_array_equal(restored.predict(csv[list(x.columns)]), prediction)
        np.testing.assert_allclose(restored.predict_proba(csv[list(x.columns)])[:, 1], score, atol=1e-12)
        pd.DataFrame(dict(process_key=x.loc[test].index, label=csv.label, prediction=prediction, score=score)).to_csv(
            out / f'expected_{os_name}_predictions.csv', index=False, encoding='utf-8-sig')
        info['model_sha256'] = sha(model_path)
        info['test_csv_sha256'] = sha(out / f'test_{os_name}_features.csv')
        write_json(out / f'{os_name}_metrics.json', info)
        results[os_name] = info
        print(os_name, json.dumps(metrics), flush=True)
    source = out / 'preprocessing_source'
    source.mkdir()
    for filename in ('replay_detect.py', 'revised_experiments.py'):
        shutil.copy2(ROOT / 'host' / filename, source / filename)
    shutil.copy2(__file__, out / Path(__file__).name)
    shutil.copy2(Path(__file__).with_name('prepare_behavior_csv.py'), out / 'prepare_behavior_csv.py')
    write_json(out / 'manifest.json', dict(repo_commit=commit, events=len(raw), input_runs=len(run_info),
               features=list(x.columns), dropped_harness_processes=harness_count, retained_processes=len(x),
               source_sha256={p.name: sha(p) for p in source.glob('*.py')}, models=results))
    (out / 'requirements.txt').write_text('\n'.join(f'{k}=={v}' for k, v in {
        'scikit-learn': sklearn.__version__, 'numpy': np.__version__, 'pandas': pd.__version__,
        'scipy': scipy.__version__, 'joblib': joblib.__version__}.items()) + '\n', encoding='utf-8')
    print('DONE:', out, flush=True)


if __name__ == '__main__':
    main()
