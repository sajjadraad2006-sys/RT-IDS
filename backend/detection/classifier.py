"""Stage 3 — Supervised classifier (XGBoost).

Known-attack classification with confidence scoring. Handles class imbalance
with per-class weights (CICIDS2017 is heavily imbalanced: ~83% Benign).
Exposes feature importances for the dashboard's explainability panel.

No accuracy is assumed. Metrics must come from the artifact manifest produced
from an independently held-out, validated dataset.

Thesis fix #2: The thesis evaluated on only 100 samples with BERTScore.
We enforce minimum 10,000 test samples and report precision/recall/F1.
"""
from __future__ import annotations
import logging
import numpy as np
from pathlib import Path
import joblib
from ..config import CLASSES, CLASSIFIER_CONFIDENCE
from .features import FEATURE_NAMES

log = logging.getLogger("cyberguard.classifier")


class AttackClassifier:
    """XGBoost multi-class classifier for known attack types."""

    def __init__(self, confidence_threshold: float | None = None) -> None:
        self.model = None  # xgboost.XGBClassifier once trained
        self.fitted = False
        self.classes_: list[str] = []
        self.confidence_threshold = float(
            CLASSIFIER_CONFIDENCE if confidence_threshold is None else confidence_threshold
        )

    def fit(self, X: np.ndarray, y: np.ndarray,
            n_estimators: int = 300, max_depth: int = 8) -> "AttackClassifier":
        """Train the classifier on labeled data.

        Handles class imbalance via sample weights: each class contributes
        equally to the loss regardless of frequency.

        Args:
            X: Normalized feature matrix (N × features).
            y: Label array (N,) — string labels like "Benign", "DDoS", etc.
            n_estimators: Number of boosting rounds.
            max_depth: Max tree depth.
        """
        from xgboost import XGBClassifier
        from sklearn.preprocessing import LabelEncoder

        # Encode string labels to integers for XGBoost
        self._le = LabelEncoder()
        y_enc = self._le.fit_transform(y)
        self.classes_ = list(self._le.classes_)

        # Compute class weights for imbalance handling
        classes_unique, counts = np.unique(y_enc, return_counts=True)
        weights = {c: len(y_enc) / (len(classes_unique) * n) for c, n in zip(classes_unique, counts)}
        sample_weight = np.array([weights[v] for v in y_enc])

        xgb_device = "cpu"
        try:
            import xgboost as _xgb_probe
            _test_clf = _xgb_probe.XGBClassifier(device="cuda", n_estimators=1, max_depth=1)
            _test_clf.fit(np.zeros((2, 2)), np.array([0, 1]))
            xgb_device = "cuda"
        except Exception:
            pass
        self.model = XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            tree_method="hist",
            device=xgb_device,
            n_jobs=-1,
            eval_metric="mlogloss",
            verbosity=0,
        )
        self.model.fit(X, y_enc, sample_weight=sample_weight)
        self.fitted = True
        log.info("Classifier trained on %d samples, %d classes: %s",
                 len(y), len(self.classes_), self.classes_)
        return self

    def predict(self, x: np.ndarray) -> tuple[str, float]:
        """Classify a single normalized flow.

        Args:
            x: 1D normalized feature vector.

        Returns:
            (label, confidence) — e.g. ("DDoS", 0.97)
        """
        if not self.fitted or self.model is None:
            raise RuntimeError("Classifier not trained — run trainer.py first")
        proba = self.model.predict_proba(x.reshape(1, -1))[0]
        idx = int(np.argmax(proba))
        label = self._le.inverse_transform([idx])[0]
        return str(label), float(proba[idx])

    def predict_batch(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Classify a batch of flows.

        Returns:
            (labels, confidences) — arrays of length N.
        """
        if not self.fitted or self.model is None:
            raise RuntimeError("Classifier not trained")
        proba = self.model.predict_proba(X)
        idxs = np.argmax(proba, axis=1)
        labels = self._le.inverse_transform(idxs)
        confs = proba[np.arange(len(idxs)), idxs]
        return labels, confs

    def is_confident_attack(self, label: str, confidence: float) -> bool:
        """Check if the prediction is a confident known attack."""
        return label.lower() != "benign" and confidence >= self.confidence_threshold

    def feature_importance(self, top: int = 10) -> list[tuple[str, float]]:
        """Return top-N most important features by XGBoost gain.

        Used by the dashboard's explainability panel.
        """
        if self.model is None:
            return []
        imp = self.model.feature_importances_
        n_features = min(len(FEATURE_NAMES), len(imp))
        order = np.argsort(imp)[::-1][:top]
        return [(FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f"feature_{i}",
                 float(imp[i])) for i in order if i < n_features]

    def save(self, path: str | Path) -> None:
        """Persist the trained model and label encoder."""
        joblib.dump({"model": self.model, "le": self._le,
                     "classes": self.classes_,
                     "confidence_threshold": self.confidence_threshold}, path)
        log.info("Classifier saved to %s", path)

    def load(self, path: str | Path) -> "AttackClassifier":
        """Load a trained model from disk."""
        data = joblib.load(path)
        if isinstance(data, dict):
            self.model = data["model"]
            self._le = data["le"]
            self.classes_ = data.get("classes", [])
            self.confidence_threshold = float(
                data.get("confidence_threshold", self.confidence_threshold)
            )
        else:
            # backward compat
            self.model = data
            from sklearn.preprocessing import LabelEncoder
            self._le = LabelEncoder()
            self._le.classes_ = np.array(CLASSES)
            self.classes_ = CLASSES
        if hasattr(self.model, "set_params"):
            try:
                self.model.set_params(device="cpu")
            except Exception:
                pass
        self.fitted = True
        log.info("Classifier loaded from %s (classes: %s)", path, self.classes_)
        return self
