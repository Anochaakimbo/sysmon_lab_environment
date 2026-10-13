"""Check a pooled export against the original holdout and the running web API."""
import io
import json
import urllib.parse
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
OUT = HERE / 'exports/sysmon_rf_combined_20261014'
OLD = HERE / 'exports/sysmon_rf_updated_20261014'


def main():
    expected = pd.read_csv(OUT / 'expected_combined_predictions.csv')
    combined = pd.read_csv(OUT / 'test_combined_features.csv')
    original = pd.concat([pd.read_csv(OLD / f'test_{os}_features.csv') for os in ('linux', 'windows')], ignore_index=True)
    pd.testing.assert_frame_equal(combined, original, check_exact=False, atol=1e-12, rtol=1e-12)
    old_split = pd.read_csv(OLD / 'split_manifest.csv').sort_values('process_key').reset_index(drop=True)
    new_split = pd.read_csv(OUT / 'split_manifest.csv').sort_values('process_key').reset_index(drop=True)
    pd.testing.assert_frame_equal(old_split, new_split)
    old_sources = json.loads((OLD / 'input_audit.json').read_text())['sources']
    new_sources = json.loads((OUT / 'input_audit.json').read_text())['sources']
    assert old_sources == new_sources
    base = 'http://127.0.0.1:8765'
    with urllib.request.urlopen(base + '/api/model', timeout=15) as r:
        token = json.load(r)['token']

    def post(endpoint, options, body):
        url = base + endpoint + '?' + urllib.parse.urlencode(options)
        request = urllib.request.Request(url, data=body, headers={
            'X-Model-Token': token, 'Content-Type': 'application/octet-stream'})
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)

    loaded = post('/api/upload-model', {'filename': 'sysmon_rf_combined.pkl', 'trusted': '1'},
                  (OUT / 'sysmon_rf_combined.pkl').read_bytes())
    assert loaded['metadata']['feature_count'] == 53
    report = post('/api/predict', {'filename': 'test_combined_features.csv', 'model_id': loaded['model_id'],
                                  'mode': 'features', 'label_column': 'label'},
                  (OUT / 'test_combined_features.csv').read_bytes())
    rows = pd.DataFrame(report.pop('rows')).set_index('process_key')
    ordered = rows.loc[[f'row:{i+1}' for i in range(len(expected))]]
    np.testing.assert_array_equal(ordered.prediction, expected.prediction)
    # JSON response uses pandas default 10-digit serialization.
    np.testing.assert_allclose(ordered.score, expected.score, atol=1e-9)
    trained = json.loads((OUT / 'combined_metrics.json').read_text())
    for metric in ('Accuracy', 'Precision', 'Recall', 'F1', 'FPR', 'AUC'):
        np.testing.assert_allclose(report['metrics'][metric], trained['metrics'][metric], atol=1e-12)
        for os in ('linux', 'windows'):
            np.testing.assert_allclose(report['by_os'][os]['metrics'][metric], trained['by_os'][os][metric], atol=1e-12)
    records = []
    for name in ('ALL', 'linux', 'windows'):
        metrics = report['metrics'] if name == 'ALL' else report['by_os'][name]['metrics']
        records.append(dict(platform=name, **{k: metrics[k] for k in ('n_labeled', 'Accuracy', 'Precision', 'Recall', 'F1', 'FPR', 'AUC')}))
    pd.DataFrame(records).to_csv(OUT / 'evaluation_summary.csv', index=False, encoding='utf-8-sig')
    report['verification'] = dict(original_test_csvs_match=True, original_split_matches=True,
        input_file_hashes_match=True, web_http_predictions_match=True, overall_and_os_metrics_match=True)
    (OUT / 'web_validation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(pd.DataFrame(records).to_string(index=False))
    print('PASS: same held-out data and split; live web API returned matching predictions and per-OS metrics')


if __name__ == '__main__':
    main()
