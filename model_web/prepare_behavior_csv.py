"""Convert project-schema Sysmon event CSV to the exported RF's 53 features."""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'preprocessing_source' if (HERE / 'preprocessing_source').exists() else HERE.parent / 'host'))
import replay_detect as rd


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--csv', type=Path, required=True)
    ap.add_argument('--os', choices=['linux', 'windows', 'both'], required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    raw = pd.read_csv(a.csv, low_memory=False)
    if 'platform' not in raw or 'run_id' not in raw:
        raise ValueError('Input must have platform and unique run_id columns from the project preprocessing pipeline')
    if not raw.platform.isin(['linux', 'windows']).all():
        raise ValueError('platform must be linux or windows')
    raw = raw.loc[raw.platform.isin(['linux', 'windows']) if a.os == 'both' else raw.platform.eq(a.os)].copy()
    if raw.empty:
        raise ValueError('No events for the requested OS')
    has_truth = 'label' in raw
    if not has_truth:
        raw['label'] = 0  # Needed only by upstream metadata; never used as a feature or returned as truth.
    if 'session' not in raw:
        raw['session'] = 'unknown'
    feats, meta = rd.prefix_features(raw, behavior=True, ages=[np.inf])
    keep = ~meta.harness
    result = feats[np.inf].loc[keep].copy()
    if has_truth:
        result['label'] = meta.loc[keep, 'label']
    result['platform'] = meta.loc[keep, 'platform']
    result['run_id'] = meta.loc[keep, 'run']
    result.to_csv(a.out, index=False, encoding='utf-8-sig')
    print(f'Wrote {len(result)} processes to {a.out}')


if __name__ == '__main__':
    main()
