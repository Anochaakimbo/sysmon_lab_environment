import unittest
import io
import joblib
import numpy as np
import pandas as pd
import model_web as app


class ModelWebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = joblib.load(app.MODEL_FILE)
        cls.sample = pd.read_csv(app.MODEL_DIR / 'heldout_events.csv', nrows=120, dtype=str)

    def encode(self, df):
        return df.to_csv(index=False).encode('utf-8')

    def test_lineages_are_disjoint(self):
        split = pd.read_csv(app.MODEL_DIR / 'split_manifest.csv')
        self.assertFalse(set(split.loc[split.split == 'train', 'lineage']) & set(split.loc[split.split == 'test', 'lineage']))

    def test_missing_label_never_becomes_truth(self):
        report, rows = app.predict(self.artifact, self.encode(self.sample.drop(columns='label')), 'x.csv', .5)
        self.assertIsNone(report['metrics'])
        self.assertEqual(report['labeled'], 0)
        self.assertTrue(rows.true_label.isna().all())

    def test_partial_truth_excludes_whole_process(self):
        d = self.sample.copy()
        d.loc[d.index[0], 'label'] = np.nan
        _, _, meta, _ = app.read_events(self.encode(d))
        guid = d.iloc[0].ProcessGuid.lower()
        self.assertFalse(meta.loc[meta.ProcessGuid == guid, 'truth_known'].any())

    def test_required_column_and_invalid_timestamp(self):
        with self.assertRaisesRegex(ValueError, 'CommandLine'):
            app.read_events(self.encode(self.sample.drop(columns='CommandLine')))
        d = self.sample.copy(); d.loc[0, 'UtcTime'] = 'invalid'
        with self.assertRaisesRegex(ValueError, 'UtcTime'):
            app.read_events(self.encode(d))

    def test_composite_keys_separate_runs(self):
        one = self.sample.iloc[[0]].copy(); two = one.copy(); two['run_id'] = 'different_run'
        _, f, _, _ = app.read_events(self.encode(pd.concat([one, two])))
        self.assertEqual(len(f), 2)

    def test_unknown_events_rejected(self):
        d = self.sample.copy(); d.loc[0, 'EventID'] = '22'
        with self.assertRaisesRegex(ValueError, 'EventID'):
            app.read_events(self.encode(d))

    def test_missing_platform_run_requires_explicit_input(self):
        d = self.sample.drop(columns=['platform', 'run_id'])
        with self.assertRaisesRegex(ValueError, 'platform'):
            app.read_events(self.encode(d))
        with self.assertRaisesRegex(ValueError, 'run_id'):
            app.read_events(self.encode(d), platform='windows')
        _, _, m, _ = app.read_events(self.encode(d), platform='windows', run_id='one_run')
        self.assertEqual(set(m.run), {'one_run'})

    def test_threshold_changes_predictions_not_scores(self):
        _, low = app.predict(self.artifact, self.encode(self.sample), 'x.csv', 0)
        _, high = app.predict(self.artifact, self.encode(self.sample), 'x.csv', 1)
        self.assertTrue((low.prediction == 1).all())
        np.testing.assert_allclose(low.score, high.score)
        for value in [float('nan'), -1, 2]:
            with self.assertRaises(ValueError):
                app.predict(self.artifact, self.encode(self.sample), 'x.csv', value)

    def test_holdout_not_seen_and_training_identity_seen(self):
        report, _ = app.predict(self.artifact, self.encode(self.sample), 'x.csv', .5)
        self.assertEqual(report['overlap'], 0)
        platform, guid = next(iter(self.artifact['train_ids'])).split('|', 1)
        d = self.sample.iloc[[0]].copy(); d['ProcessGuid'] = guid; d['platform'] = platform; d['run_id'] = 'renamed'
        report, _ = app.predict(self.artifact, self.encode(d), 'x.csv', .5)
        self.assertEqual(report['overlap'], 1)

    def test_csv_formula_protection(self):
        data = app.csv_bytes(pd.DataFrame({'Image': ['=1+1', ' +1', '@cmd', 'normal.exe']}))
        result = pd.read_csv(io.BytesIO(data))
        self.assertEqual(result.Image.tolist(), ["'=1+1", "' +1", "'@cmd", 'normal.exe'])


if __name__ == '__main__':
    unittest.main()
