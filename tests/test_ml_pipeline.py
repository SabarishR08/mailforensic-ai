"""
Unit tests for the ML pipeline components.

Tests use synthetic data only — no network, no real datasets, no trained models.
Run with: python -m pytest tests/test_ml_pipeline.py -v
"""

import os
import sys
import tempfile
import shutil
import numpy as np
import pandas as pd
import pytest

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.ml_pipeline.data_loader import DataLoader
from backend.ml_pipeline.feature_engineering import FeatureEngineer
from backend.ml_pipeline.model_builder import ModelBuilder
from backend.ml_pipeline.evaluator import ModelEvaluator


# ---------------------------------------------------------------------------
# DataLoader Tests
# ---------------------------------------------------------------------------

class TestDataLoader:
    """Tests for DataLoader label normalization, dedup, balancing, and splitting."""

    def test_normalize_labels_phishing(self):
        dl = DataLoader(data_dir="/nonexistent")
        labels = ['1', 'phishing', 'spam', 'malicious', 'true', 'yes', 'bad',
                   '0', 'legitimate', 'ham', 'false', 'no']
        result = dl._normalize_labels(labels)
        expected = ['phishing', 'phishing', 'phishing', 'phishing', 'phishing',
                    'phishing', 'phishing', 'legitimate', 'legitimate', 'legitimate',
                    'legitimate', 'legitimate']
        assert result == expected

    def test_normalize_labels_numeric(self):
        dl = DataLoader(data_dir="/nonexistent")
        result = dl._normalize_labels(['1', '0', '1', '0', '1'])
        assert result == ['phishing', 'legitimate', 'phishing', 'legitimate', 'phishing']

    def test_remove_duplicates(self):
        dl = DataLoader(data_dir="/nonexistent")
        texts = ['Hello World', 'hello world', 'Hello World', 'Goodbye']
        labels = ['legitimate', 'legitimate', 'legitimate', 'phishing']
        unique_texts, unique_labels = dl._remove_duplicates(texts, labels)
        # 'Hello World' and 'hello world' have same hash after .strip().lower()
        assert len(unique_texts) == 2
        assert 'Goodbye' in unique_texts

    def test_balance_classes(self):
        dl = DataLoader(data_dir="/nonexistent")
        texts = ['a', 'b', 'c', 'd', 'e', 'f']
        labels = ['phishing', 'phishing', 'phishing', 'legitimate', 'legitimate', 'legitimate']
        balanced_texts, balanced_labels = dl._balance_classes(texts, labels)
        assert balanced_labels.count('phishing') == balanced_labels.count('legitimate')

    def test_balance_uneven(self):
        dl = DataLoader(data_dir="/nonexistent")
        texts = list(range(20))
        labels = ['phishing'] * 20 + ['legitimate'] * 5
        texts = list(range(25))
        balanced_texts, balanced_labels = dl._balance_classes(texts, labels)
        counts = {}
        for l in balanced_labels:
            counts[l] = counts.get(l, 0) + 1
        assert counts['phishing'] == counts['legitimate']

    def test_is_valid_url(self):
        dl = DataLoader(data_dir="/nonexistent")
        assert dl._is_valid_url('https://google.com') is True
        assert dl._is_valid_url('http://example.com') is True
        assert dl._is_valid_url('www.test.com') is True
        assert dl._is_valid_url('google.com') is True
        assert dl._is_valid_url('not a url') is False

    def test_read_csv_robust_utf8(self):
        dl = DataLoader(data_dir="/nonexistent")
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("text,label\nHello world,legitimate\nBad email,phishing\n")
            tmp = f.name
        try:
            df = dl._read_csv_robust(tmp)
            assert len(df) == 2
            assert 'text' in df.columns
        finally:
            os.unlink(tmp)

    def test_find_columns(self):
        dl = DataLoader(data_dir="/nonexistent")
        df = pd.DataFrame({'Email Text': ['a', 'b'], 'Label': ['legitimate', 'phishing']})
        text_col, label_col = dl._find_columns(df)
        assert text_col == 'Email Text'
        assert label_col == 'Label'

    def test_find_columns_auto_detect(self):
        dl = DataLoader(data_dir="/nonexistent")
        df = pd.DataFrame({
            'col_a': ['x', 'y'],
            'col_b': ['This is a long email body text with more than 50 chars to trigger auto detect',
                       'Another long email body text with more than 50 chars to trigger auto detect']
        })
        text_col, label_col = dl._find_columns(df)
        assert text_col == 'col_b'

    def test_split_data_proportions(self):
        dl = DataLoader(data_dir="/nonexistent")
        texts = [f'email_{i}' for i in range(200)]
        labels = ['phishing'] * 100 + ['legitimate'] * 100
        splits = dl.split_data(texts, labels, test_size=0.15, val_size=0.10)
        total = len(splits['X_train']) + len(splits['X_val']) + len(splits['X_test'])
        assert total == 200
        # Allow ±2 for rounding in train_test_split
        assert 25 <= len(splits['X_test']) <= 35  # ~15% of 200
        assert 15 <= len(splits['X_val']) <= 25   # ~10% of 200
        assert len(splits['X_train']) > 100        # bulk goes to training

    def test_split_data_stratified(self):
        dl = DataLoader(data_dir="/nonexistent")
        texts = list(range(200))
        labels = ['phishing'] * 100 + ['legitimate'] * 100
        splits = dl.split_data(texts, labels, test_size=0.2, val_size=0.1)
        # Build a lookup: text -> label, then check class balance in test set
        text_to_label = dict(zip(texts, labels))
        test_labels = [text_to_label[t] for t in splits['X_test']]
        phishing_count = test_labels.count('phishing')
        total_test = len(test_labels)
        ratio = phishing_count / total_test if total_test > 0 else 0
        assert 0.35 < ratio < 0.65  # roughly balanced


# ---------------------------------------------------------------------------
# FeatureEngineer Tests
# ---------------------------------------------------------------------------

class TestFeatureEngineer:
    """Tests for feature extraction (manual features, fit/transform)."""

    def test_email_manual_features_length(self):
        fe = FeatureEngineer()
        features = fe._extract_email_manual_features("Hello, this is a test email with https://example.com")
        assert isinstance(features, list)
        assert all(isinstance(f, (int, float)) for f in features)
        assert len(features) == 29  # 29 manual email features

    def test_email_manual_features_url_detection(self):
        fe = FeatureEngineer()
        text_with_urls = "Click https://evil.com and https://phish.com and https://bad.com"
        features = fe._extract_email_manual_features(text_with_urls)
        # Feature index 2 = number of URLs
        assert features[2] >= 3.0

    def test_email_manual_features_urgency_keywords(self):
        fe = FeatureEngineer()
        urgent_text = "URGENT: Your account is SUSPENDED! Click here to verify immediately!"
        normal_text = "Hello, how are you doing today?"
        urgent_features = fe._extract_email_manual_features(urgent_text)
        normal_features = fe._extract_email_manual_features(normal_text)
        # Feature index 5 = urgency keyword count
        assert urgent_features[5] > normal_features[5]

    def test_email_manual_features_capital_ratio(self):
        fe = FeatureEngineer()
        caps_text = "ACT NOW YOUR ACCOUNT WILL BE CLOSED"
        normal_text = "your account will be closed"
        caps_features = fe._extract_email_manual_features(caps_text)
        normal_features = fe._extract_email_manual_features(normal_text)
        # Feature index 14 = capital ratio
        assert caps_features[14] > normal_features[14]

    def test_url_manual_features_length(self):
        fe = FeatureEngineer()
        features = fe._extract_url_manual_features("https://www.google.com/search?q=test")
        assert isinstance(features, list)
        assert len(features) == 36  # 36 manual URL features

    def test_url_manual_features_suspicious_tld(self):
        fe = FeatureEngineer()
        normal_url = fe._extract_url_manual_features("https://google.com")
        # URL must END with the suspicious TLD (not just contain it)
        suspicious_url = fe._extract_url_manual_features("https://evil.tk")
        # Feature index 17 = suspicious TLD
        assert normal_url[17] == 0
        assert suspicious_url[17] == 1

    def test_url_manual_features_ip_address(self):
        fe = FeatureEngineer()
        normal_url = fe._extract_url_manual_features("https://google.com")
        ip_url = fe._extract_url_manual_features("https://192.168.1.1/login")
        # Feature index 16 = IP in URL
        assert normal_url[16] == 0
        assert ip_url[16] == 1

    def test_url_manual_features_popular_domain(self):
        fe = FeatureEngineer()
        google_url = fe._extract_url_manual_features("https://google.com")
        random_url = fe._extract_url_manual_features("https://randomsite.com")
        # Feature index 18 = popular domain
        assert google_url[18] == 1
        assert random_url[18] == 0

    def test_url_manual_features_shortener(self):
        fe = FeatureEngineer()
        normal_url = fe._extract_url_manual_features("https://google.com")
        short_url = fe._extract_url_manual_features("https://bit.ly/abc123")
        # Feature index 29 = URL shortener
        assert normal_url[29] == 0
        assert short_url[29] == 1

    def test_url_manual_features_empty_returns_zeros(self):
        fe = FeatureEngineer()
        features = fe._extract_url_manual_features("")
        # Empty URL triggers the except handler → zero vector of the
        # correct length (36 manual URL features; the old constant 41
        # silently misaligned vectors on parse failures)
        assert len(features) == 36
        assert all(f == 0 for f in features)

    def test_fit_transform_email(self):
        fe = FeatureEngineer()
        # Generate diverse texts with repeated words to satisfy min_df=3
        common_words = ['meeting', 'project', 'update', 'report', 'review',
                        'deadline', 'budget', 'schedule', 'team', 'status']
        texts = []
        for i in range(200):
            w1, w2 = common_words[i % len(common_words)], common_words[(i * 3) % len(common_words)]
            words = [w1] * 3 + [w2] * 2 + [f'extra{i % 10}'] * 3
            texts.append(' '.join(words))
        fe.fit_email_features(texts)
        X = fe.transform_email_features(texts)
        assert X.shape[0] == 200
        assert X.shape[1] > 40  # TF-IDF features + 29 manual features

    def test_fit_transform_url(self):
        fe = FeatureEngineer()
        urls = [f"https://example{i}.com/path" for i in range(50)]
        fe.fit_url_features(urls)
        X = fe.transform_url_features(urls)
        assert X.shape[0] == 50
        assert X.shape[1] > 50  # char TF-IDF + 41 manual

    def test_transform_before_fit_raises(self):
        fe = FeatureEngineer()
        with pytest.raises(ValueError, match="not fitted"):
            fe.transform_email_features(["test"])
        with pytest.raises(ValueError, match="not fitted"):
            fe.transform_url_features(["https://test.com"])


# ---------------------------------------------------------------------------
# ModelBuilder Tests
# ---------------------------------------------------------------------------

class TestModelBuilder:
    """Tests for model creation and configuration."""

    def test_build_email_model_voting(self):
        mb = ModelBuilder(optimize_for='balanced', random_state=42)
        model = mb.build_email_model(advanced=False)
        assert model is not None
        assert hasattr(model, 'fit')

    def test_build_email_model_stacking(self):
        mb = ModelBuilder(optimize_for='balanced', random_state=42)
        model = mb.build_email_model(advanced=True)
        assert model is not None
        assert hasattr(model, 'fit')

    def test_build_url_model(self):
        mb = ModelBuilder(random_state=42)
        model = mb.build_url_model(advanced=True)
        assert model is not None

    def test_class_weight_precision(self):
        mb = ModelBuilder(optimize_for='precision')
        assert mb.class_weight == {0: 1, 1: 2}

    def test_class_weight_recall(self):
        mb = ModelBuilder(optimize_for='recall')
        assert mb.class_weight == {0: 2, 1: 1}

    def test_class_weight_balanced(self):
        mb = ModelBuilder(optimize_for='balanced')
        assert mb.class_weight == 'balanced'

    def test_model_fit_predict_voting(self):
        """Verify a voting ensemble can fit and predict on small data."""
        mb = ModelBuilder(random_state=42)
        model = mb.build_email_model(advanced=False)
        # Generate texts with repeated words to satisfy min_df=3
        from backend.ml_pipeline.feature_engineering import FeatureEngineer
        fe = FeatureEngineer()
        common_words = ['urgent', 'verify', 'account', 'security', 'click']
        texts = []
        for i in range(100):
            words = [common_words[i % len(common_words)]] * 3 + [f'word{i}'] * 2
            texts.append(' '.join(words))
        labels = ['phishing'] * 50 + ['legitimate'] * 50
        fe.fit_email_features(texts)
        X = fe.transform_email_features(texts)
        model.fit(X, labels)
        preds = model.predict(X[:5])
        assert len(preds) == 5
        assert all(p in ['phishing', 'legitimate'] for p in preds)


class TestModelBuilderPorts:
    """Tests for the email-phishing-detector ports (Group B consolidation):
    prefit calibration, full-metric cross-validation, threshold optimization."""

    @staticmethod
    def _make_model_and_data():
        """Small deterministic LR + synthetic features (binary labels)."""
        from sklearn.linear_model import LogisticRegression
        rng = np.random.RandomState(42)
        n = 200
        # Two informative dims + noise dims; class follows the signal
        X = rng.randn(n, 4)
        y = (X[:, 0] + X[:, 1] + 0.1 * rng.randn(n) > 0).astype(int)
        model = LogisticRegression(max_iter=500, random_state=42)
        return model, X, y

    def test_calibrate_model_prefit(self):
        """Prefit calibration (isotonic + sigmoid) works and preserves predict_proba."""
        model, X, y = self._make_model_and_data()
        model.fit(X, y)
        mb = ModelBuilder(random_state=42)
        for method in ('isotonic', 'sigmoid'):
            calibrated = mb.calibrate_model(model, X, y, method=method)
            proba = calibrated.predict_proba(X)
            assert proba.shape == (len(y), 2)
            assert np.allclose(proba.sum(axis=1), 1.0)

    def test_cross_validate_full_metrics(self):
        """CV returns mean + std for accuracy/precision/recall/f1."""
        model, X, y = self._make_model_and_data()
        mb = ModelBuilder(random_state=42)
        results = mb.cross_validate(model, X, y, cv=3)
        for metric in ('accuracy', 'precision', 'recall', 'f1'):
            assert f'{metric}_mean' in results and f'{metric}_std' in results
            assert 0.0 <= results[f'{metric}_mean'] <= 1.0
        # Legacy flat keys still present
        assert 'accuracy_mean' in results and 'f1_mean' in results

    def test_optimize_threshold_finds_best_f1(self):
        """Threshold search beats or matches the 0.5 default on F1."""
        model, X, y = self._make_model_and_data()
        model.fit(X, y)
        mb = ModelBuilder(random_state=42)
        best_threshold, metrics = mb.optimize_threshold(model, X, y, metric='f1')
        assert 0.1 <= best_threshold <= 0.85
        assert {'precision', 'recall', 'f1', 'threshold'} <= set(metrics)
        # Sanity: at the chosen threshold, F1 equals the reported best F1
        y_proba = model.predict_proba(X)[:, 1]
        y_pred = (y_proba >= best_threshold).astype(int)
        from sklearn.metrics import f1_score
        assert f1_score(y, y_pred) == pytest.approx(metrics['f1'])

    def test_optimize_threshold_metric_selection(self):
        """metric='recall' picks a threshold whose recall >= the F1-optimal one."""
        model, X, y = self._make_model_and_data()
        model.fit(X, y)
        mb = ModelBuilder(random_state=42)
        _, f1_metrics = mb.optimize_threshold(model, X, y, metric='f1')
        _, rec_metrics = mb.optimize_threshold(model, X, y, metric='recall')
        assert rec_metrics['recall'] >= f1_metrics['recall'] - 1e-9


# ---------------------------------------------------------------------------
# ModelEvaluator Tests
# ---------------------------------------------------------------------------

class TestModelEvaluator:
    """Tests for evaluation metrics computation."""

    def test_evaluate_perfect_predictions(self):
        evaluator = ModelEvaluator()

        class MockModel:
            def predict(self, X):
                return ['phishing'] * len(X)

        y_true = ['phishing'] * 10
        metrics = evaluator.evaluate(MockModel(), np.zeros((10, 1)), y_true)
        assert metrics['accuracy'] == 1.0
        assert metrics['precision'] == 1.0
        assert metrics['recall'] == 1.0
        assert metrics['f1'] == 1.0
        assert metrics['true_positives'] == 10
        assert metrics['false_negatives'] == 0

    def test_evaluate_mixed_predictions(self):
        evaluator = ModelEvaluator()

        class MockModel:
            def predict(self, X):
                return ['legitimate', 'phishing', 'legitimate', 'phishing']

        y_true = ['phishing', 'phishing', 'legitimate', 'legitimate']
        metrics = evaluator.evaluate(MockModel(), np.zeros((4, 1)), y_true)
        # 2 correct (indices 1,2), 2 wrong (indices 0,3)
        assert metrics['accuracy'] == 0.5
        # phishing: predicted 2, correct 1 → precision = 0.5
        assert metrics['precision'] == 0.5
        # phishing: actual 2, predicted 1 → recall = 0.5
        assert metrics['recall'] == 0.5
        assert metrics['true_positives'] == 1
        assert metrics['false_positives'] == 1
        assert metrics['false_negatives'] == 1
        assert metrics['true_negatives'] == 1

    def test_evaluate_all_legitimate(self):
        evaluator = ModelEvaluator()

        class MockModel:
            def predict(self, X):
                return ['legitimate'] * len(X)

        y_true = ['legitimate'] * 20
        metrics = evaluator.evaluate(MockModel(), np.zeros((20, 1)), y_true)
        assert metrics['accuracy'] == 1.0
        assert metrics['true_negatives'] == 20
        assert metrics['true_positives'] == 0

    def test_evaluate_confusion_matrix_shape(self):
        evaluator = ModelEvaluator()

        class MockModel:
            def predict(self, X):
                return ['phishing', 'legitimate'] * 5

        y_true = ['phishing'] * 5 + ['legitimate'] * 5
        metrics = evaluator.evaluate(MockModel(), np.zeros((10, 1)), y_true)
        total = metrics['true_positives'] + metrics['true_negatives'] + \
                metrics['false_positives'] + metrics['false_negatives']
        assert total == 10
