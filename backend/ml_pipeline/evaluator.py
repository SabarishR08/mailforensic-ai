"""
Model Evaluation Module
Comprehensive evaluation with metrics, confusion matrix, and FP/FN analysis.

Upgraded with the full evaluator ported from email-phishing-detector
(Group B consolidation): threshold tuning, ROC-AUC / average-precision,
error-rate analysis, model comparison, text report generation, and
feature-importance extraction.

Backward compatibility: in addition to the nested ``confusion_matrix``
dict and ``f1_score`` key, flat aliases (``f1``, ``true_positives``, ...)
are emitted so existing callers of the old evaluator keep working.
"""

import numpy as np
from typing import Dict, Any, List
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score,
    average_precision_score
)
import logging

logger = logging.getLogger(__name__)

LABELS = ['legitimate', 'phishing']


class ModelEvaluator:
    """
    Comprehensive model evaluation with production-focused metrics
    (ported from email-phishing-detector, extended for this project).
    """

    def __init__(self):
        self.results: Dict[str, Dict[str, Any]] = {}

    def evaluate(self, model: Any, X: Any, y: Any,
                 dataset_name: str = "Test", threshold: float = 0.5) -> Dict[str, Any]:
        """
        Comprehensive model evaluation.

        Args:
            model: Trained model
            X: Test features
            y: Test labels ('legitimate' / 'phishing')
            dataset_name: Name for this evaluation
            threshold: Custom classification threshold on phishing probability

        Returns:
            Dictionary of evaluation metrics (flat keys + nested details)
        """
        logger.info(f"Evaluating model on {dataset_name} set...")

        y_pred = model.predict(X)
        y_proba = None
        if hasattr(model, 'predict_proba'):
            try:
                proba = model.predict_proba(X)
                # classes_ is ['legitimate', 'phishing'] -> phishing column index
                if hasattr(model, 'classes_') and 'phishing' in list(model.classes_):
                    phishing_idx = list(model.classes_).index('phishing')
                    y_proba = proba[:, phishing_idx]
                elif proba.shape[1] == 2:
                    y_proba = proba[:, 1]
            except Exception as e:
                logger.warning(f"predict_proba unavailable: {e}")

        # Apply custom threshold on phishing probability if requested
        if y_proba is not None and threshold != 0.5:
            y_pred = ['phishing' if p >= threshold else 'legitimate' for p in y_proba]

        # Core metrics
        metrics: Dict[str, Any] = {
            'accuracy': accuracy_score(y, y_pred),
            'precision': precision_score(y, y_pred, pos_label='phishing', zero_division=0),
            'recall': recall_score(y, y_pred, pos_label='phishing', zero_division=0),
            'f1': f1_score(y, y_pred, pos_label='phishing', zero_division=0),
        }
        metrics['f1_score'] = metrics['f1']  # epd-style alias

        # Confusion matrix
        cm = confusion_matrix(y, y_pred, labels=LABELS)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        metrics['confusion_matrix'] = {
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'true_positives': int(tp),
        }
        # Flat aliases (old evaluator shape) for backward compatibility
        metrics['true_positives'] = int(tp)
        metrics['true_negatives'] = int(tn)
        metrics['false_positives'] = int(fp)
        metrics['false_negatives'] = int(fn)

        # Error / success rates
        metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        metrics['false_negative_rate'] = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        metrics['true_positive_rate'] = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        metrics['true_negative_rate'] = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        # Ranking metrics
        if y_proba is not None:
            y_binary = np.array([1 if label == 'phishing' else 0 for label in y])
            try:
                metrics['roc_auc'] = float(roc_auc_score(y_binary, y_proba))
                metrics['average_precision'] = float(average_precision_score(y_binary, y_proba))
            except Exception:
                metrics['roc_auc'] = 0.0
                metrics['average_precision'] = 0.0

        # Per-class report
        try:
            metrics['classification_report'] = classification_report(
                y, y_pred, output_dict=True, zero_division=0
            )
        except Exception:
            metrics['classification_report'] = {}

        # Store results (for compare_models / generate_report)
        self.results[dataset_name] = metrics

        self._log_evaluation_results(dataset_name, metrics)
        return metrics

    def _log_evaluation_results(self, dataset_name: str, metrics: Dict[str, Any]):
        """Log evaluation results in a readable format."""
        logger.info(f"\n{'='*70}")
        logger.info(f"Evaluation Results - {dataset_name.upper()}")
        logger.info(f"{'='*70}")

        logger.info(f"  Accuracy:  {metrics['accuracy']*100:.2f}%")
        logger.info(f"  Precision: {metrics['precision']*100:.2f}%")
        logger.info(f"  Recall:    {metrics['recall']*100:.2f}%")
        logger.info(f"  F1-Score:  {metrics['f1']*100:.2f}%")
        if 'roc_auc' in metrics:
            logger.info(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
            logger.info(f"  Avg Precision: {metrics['average_precision']:.4f}")

        cm = metrics['confusion_matrix']
        logger.info(f"  TP: {cm['true_positives']} | TN: {cm['true_negatives']} | "
                    f"FP: {cm['false_positives']} | FN: {cm['false_negatives']}")

        logger.info(f"  Error Analysis:")
        logger.info(f"    False Positive Rate: {metrics['false_positive_rate']*100:.2f}% "
                    f"(legitimate emails incorrectly flagged)")
        logger.info(f"    False Negative Rate: {metrics['false_negative_rate']*100:.2f}% "
                    f"(phishing emails missed)")
        logger.info(f"  Success Rates:")
        logger.info(f"    Sensitivity (TPR): {metrics['true_positive_rate']:.4f}")
        logger.info(f"    Specificity (TNR): {metrics['true_negative_rate']:.4f}")

        # Production readiness assessment
        if metrics['accuracy'] >= 0.95 and metrics['f1'] >= 0.95:
            logger.info(f"  Production Readiness: EXCELLENT - production ready")
        elif metrics['accuracy'] >= 0.90 and metrics['f1'] >= 0.90:
            logger.info(f"  Production Readiness: GOOD - suitable for production")
        elif metrics['accuracy'] >= 0.85:
            logger.info(f"  Production Readiness: FAIR - consider improvements")
        else:
            logger.info(f"  Production Readiness: NEEDS IMPROVEMENT")

        logger.info(f"{'='*70}\n")

    def compare_models(self, results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Compare multiple models.

        Args:
            results: Dictionary of model_name -> evaluation_metrics

        Returns:
            Comparison dictionary with the best model per metric
        """
        logger.info("MODEL COMPARISON")

        comparison: Dict[str, Any] = {}
        metrics_to_compare = [
            'accuracy', 'precision', 'recall', 'f1',
            'false_positive_rate', 'false_negative_rate', 'roc_auc',
        ]

        for metric in metrics_to_compare:
            scores = {name: res.get(metric, 0) for name, res in results.items()}
            if not scores:
                continue
            # For error rates, lower is better
            if 'rate' in metric and 'true' not in metric:
                best_model = min(scores, key=scores.get)
            else:
                best_model = max(scores, key=scores.get)
            comparison[metric] = {
                'best_model': best_model,
                'best_score': scores[best_model],
                'all_scores': scores,
            }
            logger.info(f"  {metric}: {best_model} ({scores[best_model]:.4f})")

        return comparison

    def generate_report(self, model_name: str) -> str:
        """
        Generate a text report of evaluation results.

        Args:
            model_name: Name of the model

        Returns:
            Report string
        """
        if not self.results:
            return "No evaluation results available"

        lines: List[str] = []
        lines.append(f"{'='*80}")
        lines.append(f"EVALUATION REPORT: {model_name.upper()}")
        lines.append(f"{'='*80}")

        for dataset_name, m in self.results.items():
            lines.append(f"\n{dataset_name.upper()} SET:")
            lines.append("-" * 80)
            lines.append(f"Accuracy:  {m['accuracy']:.4f}")
            lines.append(f"Precision: {m['precision']:.4f}")
            lines.append(f"Recall:    {m['recall']:.4f}")
            lines.append(f"F1-Score:  {m['f1']:.4f}")
            if 'roc_auc' in m:
                lines.append(f"ROC-AUC:   {m['roc_auc']:.4f}")

            cm = m['confusion_matrix']
            lines.append(f"\nConfusion Matrix:")
            lines.append(f"  TN: {cm['true_negatives']:,}  FP: {cm['false_positives']:,}")
            lines.append(f"  FN: {cm['false_negatives']:,}  TP: {cm['true_positives']:,}")

            lines.append(f"\nError Rates:")
            lines.append(f"  False Positive Rate: {m['false_positive_rate']:.4f}")
            lines.append(f"  False Negative Rate: {m['false_negative_rate']:.4f}")

        lines.append("\n" + "=" * 80)
        return "\n".join(lines)

    def get_feature_importance(self, model: Any, feature_names: List[str],
                               top_n: int = 20) -> Dict[str, float]:
        """
        Extract feature importance from a trained model.

        Args:
            model: Trained model (tree-based or linear)
            feature_names: Feature names aligned with the model's input columns
            top_n: Number of top features to return

        Returns:
            Dictionary of feature -> importance (top N, sorted descending)
        """
        try:
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
            elif hasattr(model, 'coef_'):
                importances = np.abs(model.coef_[0])
            else:
                logger.warning("Model does not support feature importance extraction")
                return {}

            if len(feature_names) != len(importances):
                logger.warning(
                    f"Feature name count ({len(feature_names)}) != "
                    f"importance count ({len(importances)}); skipping"
                )
                return {}

            feature_importance = dict(zip(feature_names, importances))
            sorted_features = sorted(feature_importance.items(),
                                     key=lambda x: x[1], reverse=True)
            top_features = dict(sorted_features[:top_n])

            logger.info(f"\nTop {top_n} Most Important Features:")
            for i, (feature, importance) in enumerate(sorted_features[:top_n], 1):
                logger.info(f"  {i:2d}. {str(feature)[:50]:50s} {importance:.6f}")

            return top_features

        except Exception as e:
            logger.error(f"Failed to extract feature importance: {e}")
            return {}
