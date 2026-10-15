import io
import pickle
import unittest
from unittest.mock import patch
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.linear_model import RidgeClassifier
import uploaded_model as upload
import model_web as app

class UploadedModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.x = pd.DataFrame({'file_count':[0,1,2,3,8,9,10,12], 'connection_count':[0,2,1,3,7,8,10,9]})
        cls.y = np.array([0,0,0,0,1,1,1,1])
        cls.model = make_pipeline(StandardScaler(), RandomForestClassifier(n_estimators=10, random_state=7)).fit(cls.x, cls.y)
        cls.csv = cls.x.assign(label=cls.y).to_csv(index=False).encode()

    def artifact(self, model=None):
        return upload.load_trusted_model(pickle.dumps(self.model if model is None else model), 'test.pkl', True)

    def predict(self, artifact=None, data=None, **options):
        return upload.run_uploaded(self.artifact() if artifact is None else artifact, self.csv if data is None else data, 'test.csv', options, app.read_events, app.metric_block, 200000)

    def assert_predictions(self, rows, expected):
        observed = rows.set_index('process_key').prediction.reindex(['row:'+str(i+1) for i in range(len(expected))])
        np.testing.assert_array_equal(observed, expected)

    def test_trust_checked_before_deserialization(self):
        with patch.object(upload.joblib, 'load') as loader:
            with self.assertRaises(ValueError): upload.load_trusted_model(b'data', 'x.pkl', False)
            loader.assert_not_called()

    def test_pickle_pipeline_and_reordered_csv(self):
        a = self.artifact()
        self.assertEqual(a['metadata']['columns'], list(self.x))
        data = self.x.assign(label=self.y)[['label','connection_count','file_count']].to_csv(index=False).encode()
        report, rows = self.predict(a, data)
        self.assert_predictions(rows, self.model.predict(self.x))
        self.assertIsNone(report['threshold'])
        self.assertIsNone(report['overlap'])
        self.assertEqual(report['metrics']['F1'], 1)

    def test_compressed_joblib_scaler_bundle(self):
        scaler = StandardScaler().fit(self.x)
        model = RandomForestClassifier(n_estimators=5, random_state=1).fit(scaler.transform(self.x), self.y)
        stream = io.BytesIO()
        joblib.dump({'model':model, 'scaler':scaler, 'columns':list(self.x)}, stream, compress=3)
        a = upload.load_trusted_model(stream.getvalue(), 'test.joblib', True)
        _, rows = self.predict(a)
        self.assert_predictions(rows, model.predict(scaler.transform(self.x)))

    def test_missing_names_requires_explicit_order(self):
        model = RandomForestClassifier(n_estimators=5, random_state=1).fit(self.x.to_numpy(), self.y)
        a = self.artifact(model)
        with self.assertRaises(ValueError): self.predict(a)
        with self.assertRaises(ValueError): self.predict(a, features='file_count')
        _, rows = self.predict(a, features='file_count, connection_count')
        self.assert_predictions(rows, model.predict(self.x.to_numpy()))

    def test_missing_duplicate_features_invalid_labels(self):
        for data in [b'file_count,label\n1,0\n', b'file_count,file_count,connection_count\n1,2,3\n', b'file_count,connection_count,label\n1,2,malware\n']:
            with self.assertRaises(ValueError): self.predict(data=data)
        with self.assertRaises(ValueError): self.predict(label_column='file_count')

    def test_no_truth_and_partial_truth(self):
        report, _ = self.predict(data=self.x.to_csv(index=False).encode())
        self.assertIsNone(report['metrics'])
        d = self.x.assign(label=self.y.astype(float)); d.loc[0,'label']=np.nan
        report, _ = self.predict(data=d.to_csv(index=False).encode())
        self.assertEqual(report['metrics']['n_labeled'], 7)

    def test_decision_function_and_model_predict(self):
        model = SVC().fit(self.x, self.y)
        report, rows = self.predict(self.artifact(model))
        self.assert_predictions(rows, model.predict(self.x))
        self.assertEqual(report['score_kind'], 'decision')
        self.assertIsNotNone(report['metrics']['AUC'])
        with self.assertRaises(ValueError): self.predict(self.artifact(model), use_threshold='1')

    def test_anomaly_direction(self):
        model = IsolationForest(n_estimators=10, contamination=.25, random_state=4).fit(self.x)
        report, rows = self.predict(self.artifact(model))
        self.assert_predictions(rows, (model.predict(self.x)==-1).astype(int))
        expected = dict(zip(['row:'+str(i+1) for i in range(len(self.x))], -model.score_samples(self.x)))
        np.testing.assert_allclose(rows.score, [expected[k] for k in rows.process_key])
        self.assertEqual(report['score_kind'], 'anomaly')

    def test_threshold_explicit_and_validation(self):
        _, rows = self.predict(use_threshold='1', threshold='0')
        self.assertTrue((rows.prediction==1).all())
        for value in ['nan','-1','2']:
            with self.assertRaises(ValueError): self.predict(use_threshold='1', threshold=value)

    def test_event_mode_requires_confirmation(self):
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            self.predict(mode='events')

    def test_no_score_auc_not_fabricated(self):
        rows = pd.DataFrame({'true_label':[0,1], 'prediction':[0,1], 'score':[np.nan,np.nan]})
        self.assertIsNone(app.metric_block(rows)['AUC'])

    def test_reject_invalid_and_multiclass(self):
        with self.assertRaises(ValueError): upload.load_trusted_model(b'not pickle', 'x.pkl', True)
        model = RandomForestClassifier(n_estimators=2).fit(self.x, [0,0,0,1,1,1,2,2])
        with self.assertRaises(ValueError): self.artifact(model)

class EventModeTests(unittest.TestCase):
    """Event mode with the paper's 32 features: OS detection, missing optional columns, attack type."""
    @classmethod
    def setUpClass(cls):
        rows = []
        for run, os_, label, img in [('r1', 'windows', 1, 'C:\lab\a.exe'), ('r1', 'windows', 0, 'C:\Windows\b.exe')]:
            for i in range(30):
                g = '{%08d-0000-0000-0000-%012d}' % (label + 1, i)  # never the null GUID
                rows += [dict(EventID=e, ProcessGuid=g, UtcTime='2026-10-12 10:00:%02d.000' % (j + 1), Image=img,
                              User='DESKTOP\vagrant', TargetFilename=img + str(j) if e == 11 else None, label=label)
                         for j, e in enumerate([1, 11, 11, 13][: 2 + label * 2])]
        cls.events = pd.DataFrame(rows)
        f, m, _ = app.rx.aggregate(cls.events.assign(platform='windows', run_id='r1', session='s', ParentProcessGuid=np.nan,
                                                     CommandLine=np.nan, ParentCommandLine=np.nan, DestinationIp=np.nan,
                                                     DestinationPort=np.nan, TargetObject=np.nan, Device=np.nan))
        y = m.label.to_numpy()
        model = RandomForestClassifier(n_estimators=10, random_state=0).fit(f.to_numpy(), y)
        typer = RandomForestClassifier(n_estimators=5, random_state=0).fit(f.to_numpy()[y == 1], ['ransomware'] * int(y.sum()))
        stream = io.BytesIO()
        joblib.dump(dict(model=model, columns=list(f.columns), typer=typer, platform='linux'), stream)
        cls.artifact = upload.load_trusted_model(stream.getvalue(), 'paper.pkl', True)

    def run_events(self, df):
        return upload.run_uploaded(self.artifact, df.to_csv(index=False).encode(), 'e.csv',
                                   dict(mode='events', confirm_event_schema='1', run_id='r1'),
                                   app.read_events, app.metric_block, 200000)

    def test_detect_os(self):
        self.assertEqual(app.detect_os(self.events)[0], 'windows')
        self.assertEqual(app.detect_os(pd.DataFrame(dict(EventID=[1, 5], Image=['/usr/bin/x', '/bin/sh'])))[0], 'linux')

    def test_missing_columns_baseline_and_types(self):
        report, rows = self.run_events(self.events)
        self.assertEqual(set(rows.platform), {'windows'})
        self.assertTrue(any('CommandLine' in n for n in report['notes']))
        self.assertTrue(any('ฝึกบน linux' in n for n in report['notes']))
        m = report['metrics']
        self.assertAlmostEqual(m['baseline_all_benign_accuracy'], 0.5)
        self.assertAlmostEqual(m['baseline_all_attack_f1'], 2 / 3)
        self.assertEqual(report['attack_types'][0]['type'], 'ransomware')
        self.assertTrue(rows.loc[rows.prediction == 0, 'attack_type'].isna().all())

    def test_mixed_os_rejected(self):
        mixed = pd.concat([self.events, self.events.assign(Image='/usr/bin/x', User='root')])
        with self.assertRaisesRegex(ValueError, 'ปนกัน'):
            self.run_events(mixed)

    def test_typer_feature_count_checked(self):
        stream = io.BytesIO()
        bad = RandomForestClassifier(n_estimators=2).fit(np.zeros((4, 3)), ['a', 'b', 'a', 'b'])
        joblib.dump(dict(model=self.artifact['model'], columns=self.artifact['metadata']['columns'], typer=bad), stream)
        with self.assertRaisesRegex(ValueError, 'typer'):
            upload.load_trusted_model(stream.getvalue(), 'x.pkl', True)

if __name__=='__main__':
    unittest.main()
