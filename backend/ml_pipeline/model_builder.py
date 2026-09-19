"""
Advanced Model Builder Module
Creates optimized ensemble models with proper calibration
"""

import numpy as np
from typing import Any, Dict, Tuple
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import cross_val_score, StratifiedKFold
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
import logging

logger = logging.getLogger(__name__)


class ModelBuilder:
    """Advanced model builder with optimal configuration"""

    def __init__(self, optimize_for: str = 'balanced', random_state: int = 42):
        self.optimize_for = optimize_for
        self.random_state = random_state
        self.class_weight = self._get_class_weight()

    def _get_class_weight(self):
        if self.optimize_for == 'precision':
            return {0: 1, 1: 2}
        elif self.optimize_for == 'recall':
            return {0: 2, 1: 1}
        return 'balanced'

    def build_email_model(self, advanced: bool = True) -> Any:
        logger.info(f"Building email model (advanced={advanced})...")
        model = self._build_stacking_ensemble() if advanced else self._build_voting_ensemble()
        logger.info(f"Email model built: {type(model).__name__}")
        return model

    def build_url_model(self, advanced: bool = True) -> Any:
        logger.info(f"Building URL model (advanced={advanced})...")
        model = self._build_stacking_ensemble() if advanced else self._build_voting_ensemble()
        logger.info(f"URL model built: {type(model).__name__}")
        return model

    def _build_voting_ensemble(self):
        from sklearn.ensemble import VotingClassifier, GradientBoostingClassifier
        estimators = [
            ('lr', LogisticRegression(max_iter=1000, C=1.0, solver='saga',
                                     class_weight=self.class_weight, random_state=self.random_state, n_jobs=-1)),
            ('rf', RandomForestClassifier(n_estimators=300, max_depth=35, min_samples_split=4,
                                         min_samples_leaf=2, max_features='sqrt',
                                         class_weight=self.class_weight, random_state=self.random_state, n_jobs=-1)),
            ('xgb', XGBClassifier(n_estimators=300, learning_rate=0.08, max_depth=8,
                                  min_child_weight=2, subsample=0.8, colsample_bytree=0.8,
                                  gamma=0.1, random_state=self.random_state, n_jobs=-1, eval_metric='logloss')),
            ('lgbm', LGBMClassifier(n_estimators=300, learning_rate=0.08, max_depth=8,
                                    num_leaves=64, min_child_samples=20, subsample=0.8,
                                    colsample_bytree=0.8, random_state=self.random_state, n_jobs=-1, verbose=-1)),
        ]
        return VotingClassifier(estimators=estimators, voting='soft', n_jobs=-1)

    def _build_stacking_ensemble(self):
        base_models = [
            ('lr', LogisticRegression(max_iter=1000, C=1.0, solver='saga',
                                     class_weight=self.class_weight, random_state=self.random_state, n_jobs=-1)),
            ('rf', RandomForestClassifier(n_estimators=200, max_depth=30, min_samples_split=4,
                                         min_samples_leaf=2, max_features='sqrt',
                                         class_weight=self.class_weight, random_state=self.random_state, n_jobs=-1)),
            ('xgb', XGBClassifier(n_estimators=250, learning_rate=0.08, max_depth=7,
                                  min_child_weight=2, subsample=0.8, colsample_bytree=0.8,
                                  gamma=0.1, random_state=self.random_state, n_jobs=-1, eval_metric='logloss')),
            ('lgbm', LGBMClassifier(n_estimators=250, learning_rate=0.08, max_depth=7,
                                    num_leaves=50, min_child_samples=20, subsample=0.8,
                                    colsample_bytree=0.8, random_state=self.random_state, n_jobs=-1, verbose=-1)),
        ]
        meta_learner = LogisticRegression(max_iter=1000, C=0.5, class_weight=self.class_weight,
                                         random_state=self.random_state)
        return StackingClassifier(estimators=base_models, final_estimator=meta_learner,
                                  cv=5, stack_method='predict_proba', n_jobs=-1)

    def calibrate_model(self, model, X_val, y_val, method: str = 'isotonic'):
        """Calibrate a prefit model's probabilities on held-out validation data.

        Ported from email-phishing-detector (Group B consolidation), kept
        version-agnostic: sklearn >= 1.6 recommends FrozenEstimator (the
        ``cv='prefit'`` value is deprecated there), older sklearn uses it.
        """
        logger.info(f"Calibrating model using {method} method...")
        try:
            from sklearn.frozen import FrozenEstimator
            calibrated = CalibratedClassifierCV(FrozenEstimator(model), method=method)
        except ImportError:
            calibrated = CalibratedClassifierCV(model, method=method, cv='prefit')
        calibrated.fit(X_val, y_val)
        logger.info("Model calibration complete")
        return calibrated

    def cross_validate(self, model, X, y, cv: int = 5) -> Dict[str, float]:
        """Stratified CV across accuracy/precision/recall/F1, with std devs.

        Full metric set restored from email-phishing-detector (Group B
        consolidation); flat ``*_mean``/``*_std`` keys and the legacy
        ``accuracy_mean``/``f1_mean`` aliases are all emitted.
        """
        from sklearn.model_selection import cross_validate as sk_cross_validate

        logger.info(f"Performing {cv}-fold cross-validation...")
        cv_splitter = StratifiedKFold(n_splits=cv, shuffle=True, random_state=self.random_state)
        cv_results = sk_cross_validate(
            model, X, y, cv=cv_splitter, n_jobs=-1,
            scoring=('accuracy', 'precision', 'recall', 'f1'),
        )
        results: Dict[str, float] = {}
        for metric in ('accuracy', 'precision', 'recall', 'f1'):
            scores = cv_results[f'test_{metric}']
            results[f'{metric}_mean'] = float(scores.mean())
            results[f'{metric}_std'] = float(scores.std())
        # (accuracy_mean / f1_mean double as the legacy flat keys)

        logger.info("Cross-validation results:")
        logger.info(f"  Accuracy: {results['accuracy_mean']:.4f} (+/- {results['accuracy_std']:.4f})")
        logger.info(f"  Precision: {results['precision_mean']:.4f} (+/- {results['precision_std']:.4f})")
        logger.info(f"  Recall: {results['recall_mean']:.4f} (+/- {results['recall_std']:.4f})")
        logger.info(f"  F1-Score: {results['f1_mean']:.4f} (+/- {results['f1_std']:.4f})")
        return results

    def optimize_threshold(self, model, X_val, y_val,
                           metric: str = 'f1') -> Tuple[float, Dict]:
        """Grid-search the decision threshold for the best target metric.

        Ported from email-phishing-detector (Group B consolidation): the
        evaluator applies thresholds, but nothing could *find* the best one.
        Sweeps 0.10–0.85 in 0.05 steps on validation data.

        Returns:
            Tuple of (best_threshold, metrics_at_best_threshold)
        """
        from sklearn.metrics import precision_score, recall_score, f1_score

        logger.info(f"Optimizing threshold for {metric}...")

        y_proba = model.predict_proba(X_val)[:, 1]
        thresholds = np.arange(0.1, 0.9, 0.05)
        best_score = 0.0
        best_threshold = 0.5
        best_metrics: Dict = {}

        for threshold in thresholds:
            y_pred = (y_proba >= threshold).astype(int)

            precision = precision_score(y_val, y_pred, zero_division=0)
            recall = recall_score(y_val, y_pred, zero_division=0)
            f1 = f1_score(y_val, y_pred, zero_division=0)

            score = {'precision': precision, 'recall': recall}.get(metric, f1)

            if score > best_score:
                best_score = score
                best_threshold = float(threshold)
                best_metrics = {
                    'precision': precision,
                    'recall': recall,
                    'f1': f1,
                    'threshold': float(threshold),
                }

        logger.info(f"Optimal threshold: {best_threshold:.3f}")
        logger.info(f"  Precision: {best_metrics.get('precision', 0.0):.4f}")
        logger.info(f"  Recall: {best_metrics.get('recall', 0.0):.4f}")
        logger.info(f"  F1-Score: {best_metrics.get('f1', 0.0):.4f}")

        return best_threshold, best_metrics
