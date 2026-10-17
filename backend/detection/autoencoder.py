"""Stage 4 — Deep autoencoder for unknown-behavior detection.

Trained ONLY on benign traffic. Attack = high reconstruction error.
Architecture: N → 64 → 32 → 16 (bottleneck) → 32 → 64 → N
Threshold: mean + k*std of validation reconstruction errors (k=2 or 3).

This is what the thesis was missing entirely: catching patterns the
classifier has NEVER seen, without any LLM involvement.

The autoencoder learns to compress-and-reconstruct benign traffic through
a 16-neuron bottleneck. When it sees something that doesn't "look normal",
the reconstruction error spikes — signaling an unknown anomaly for review.
"""
from __future__ import annotations
import logging
import numpy as np
from pathlib import Path
try:
    import torch
    from torch import nn
    _AE_BASE = nn.Module
except ImportError:
    torch = None
    nn = None
    _AE_BASE = object

log = logging.getLogger("cyberguard.autoencoder")


class _AE(_AE_BASE):
    """Symmetric autoencoder: N → 64 → 32 → 16 → 32 → 64 → N.

    The 16-neuron bottleneck forces the network to learn a compact
    representation of "normal" — anything that can't be compressed
    well into 16 dimensions is suspicious.
    """
    def __init__(self, n_features: int) -> None:
        if torch is None or nn is None:
            return
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(n_features, 64), nn.BatchNorm1d(64), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(64, 32), nn.BatchNorm1d(32), nn.ReLU(), nn.Dropout(0.05),
            nn.Linear(32, 16),  # bottleneck
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32), nn.BatchNorm1d(32), nn.ReLU(),
            nn.Linear(32, 64), nn.BatchNorm1d(64), nn.ReLU(),
            nn.Linear(64, n_features),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if torch is None:
            raise RuntimeError("PyTorch is required for Autoencoder forward pass")
        return self.decoder(self.encoder(x))


def _no_grad(fn):
    if torch is not None and hasattr(torch, "no_grad"):
        return torch.no_grad()(fn)
    return fn


class AutoencoderDetector:
    """Unknown-anomaly evidence: high error means distributional deviation.

    Args:
        n_features: Number of input features.
        k: Threshold multiplier — threshold = mean + k * std of benign errors.
           k=3 is balanced; k=2 catches more but raises false positives.
        device: 'cuda', 'cpu', or None for auto-detect.
    """

    def __init__(self, n_features: int, k: float = 3.0,
                 quantile: float | None = 99.5,
                 device: str | None = None) -> None:
        self.n_features = n_features
        self.k = k
        self.quantile = quantile
        self.threshold: float | None = None
        self._mean_err: float = 0.0
        self._std_err: float = 0.0
        if torch is None:
            self.device = "cpu"
            self.net = None
        else:
            self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
            self.net = _AE(n_features).to(self.device)

    def fit(self, X_benign: np.ndarray, X_val: np.ndarray,
            epochs: int = 50, lr: float = 1e-3, batch: int = 512,
            callback=None) -> "AutoencoderDetector":
        """Train on benign-only data. Calibrate threshold on validation set.

        Args:
            X_benign: Normalized benign training features.
            X_val: Normalized benign validation features (for threshold calibration).
            epochs: Number of training epochs.
            lr: Learning rate.
            batch: Mini-batch size.
            callback: Optional function(epoch, loss) called each epoch.
        """
        opt = torch.optim.Adam(self.net.parameters(), lr=lr, weight_decay=1e-5)
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, patience=5, factor=0.5)
        loss_fn = nn.MSELoss(reduction="none")
        Xb = torch.tensor(X_benign, dtype=torch.float32, device=self.device)

        self.net.train()
        for epoch in range(epochs):
            perm = torch.randperm(len(Xb), device=self.device)
            epoch_loss = 0.0
            n_batches = 0
            for i in range(0, len(Xb), batch):
                idx = perm[i:i + batch]
                out = self.net(Xb[idx])
                loss = loss_fn(out, Xb[idx]).mean()
                opt.zero_grad()
                loss.backward()
                opt.step()
                epoch_loss += loss.item()
                n_batches += 1
            avg_loss = epoch_loss / max(n_batches, 1)
            scheduler.step(avg_loss)
            if callback:
                callback(epoch, avg_loss)

        # Calibrate threshold on held-out BENIGN validation data
        errs = self.errors(X_val)
        self._mean_err = float(errs.mean())
        self._std_err = float(errs.std())
        if self.quantile is not None:
            q = float(self.quantile if self.quantile > 1.0 else self.quantile * 100.0)
            self.threshold = float(np.percentile(errs, q))
            log.info("Autoencoder threshold calibrated via %.2fth empirical percentile: %.4f (mean=%.4f, std=%.4f)",
                     q, self.threshold, self._mean_err, self._std_err)
        else:
            self.threshold = self._mean_err + self.k * self._std_err
            log.info("Autoencoder trained (%d epochs). Threshold=%.4f (mean=%.4f + %.1f*std=%.4f)",
                     epochs, self.threshold, self._mean_err, self.k, self._std_err)
        return self

    @_no_grad
    def errors(self, X: np.ndarray) -> np.ndarray:
        """Compute per-sample reconstruction MSE.

        Returns:
            1D array of reconstruction errors (length = number of samples).
        """
        self.net.eval()
        Xt = torch.tensor(X, dtype=torch.float32, device=self.device)
        out = self.net(Xt)
        errors = ((out - Xt) ** 2).mean(dim=1).cpu().numpy()
        return np.clip(
            np.nan_to_num(errors, nan=1e30, posinf=1e30, neginf=1e30),
            0.0, 1e30,
        )

    def score(self, x: np.ndarray) -> float:
        """Reconstruction error for one normalized flow."""
        return float(self.errors(x.reshape(1, -1))[0])

    def score_batch(self, X: np.ndarray) -> np.ndarray:
        """Reconstruction errors for a batch of flows."""
        return self.errors(X)

    def is_unknown_anomaly(self, x: np.ndarray) -> tuple[bool, float]:
        """Check if a flow exceeds the calibrated unknown-anomaly threshold.

        Returns:
            (is_anomaly, reconstruction_error)
        """
        err = self.score(x)
        if self.threshold is None:
            raise RuntimeError("autoencoder is not fitted")
        return err > self.threshold, err

    def anomaly_ratio(self, err: float) -> float:
        """How many standard deviations above the mean this error is.
        Useful for severity scoring: ratio > k means anomalous."""
        if self._std_err <= 0:
            return 0.0
        return (err - self._mean_err) / max(self._std_err, 1e-9)

    def save(self, path: str | Path) -> None:
        """Persist model weights, threshold, and calibration stats."""
        if torch is None:
            raise RuntimeError("PyTorch is required to save neural autoencoder artifacts")
        torch.save({
            "state": self.net.state_dict(),
            "threshold": self.threshold,
            "k": self.k,
            "quantile": self.quantile,
            "mean_err": self._mean_err,
            "std_err": self._std_err,
            "n_features": self.n_features,
        }, path)
        log.info("Autoencoder saved to %s", path)

    def load(self, path: str | Path, n_features: int | None = None) -> "AutoencoderDetector":
        """Load model from disk."""
        if torch is None:
            raise RuntimeError("PyTorch is required to load neural autoencoder artifacts")
        ckpt = torch.load(path, map_location=self.device, weights_only=True)
        nf = n_features or ckpt.get("n_features", self.n_features)
        self.net = _AE(nf).to(self.device)
        self.net.load_state_dict(ckpt["state"])
        self.threshold = ckpt["threshold"]
        self.k = ckpt.get("k", self.k)
        self.quantile = ckpt.get("quantile", self.quantile)
        self._mean_err = ckpt.get("mean_err", 0.0)
        self._std_err = ckpt.get("std_err", 0.0)
        self.n_features = nf
        log.info("Autoencoder loaded from %s (threshold=%.4f)", path, self.threshold)
        return self
