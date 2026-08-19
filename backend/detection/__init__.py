"""CyberGuard detection core: 4-stage pipeline (the 90%).

Stage 1: Feature extraction — 32 numeric flow features
Stage 2: Z-Score statistical filter — CPU-only and vectorized; benchmark locally
Stage 3: XGBoost supervised classifier — measured per artifact, never assumed
Stage 4: Deep autoencoder — unknown-anomaly signal via reconstruction error
"""
