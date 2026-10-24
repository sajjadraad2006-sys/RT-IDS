"""Resolve the active model bundle through a constrained atomic pointer."""
from __future__ import annotations

import json
from pathlib import Path

from ..config import BASE_DIR, MODELS_DIR, TRAINED_DIR
from .integrity import IntegrityError


ACTIVE_POINTER = MODELS_DIR / "active_bundle.json"


def resolve_active_bundle_dir() -> Path:
    if not ACTIVE_POINTER.exists():
        return TRAINED_DIR.resolve()
    try:
        payload = json.loads(ACTIVE_POINTER.read_text(encoding="utf-8"))
        relative = payload["bundle_path"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise IntegrityError("active bundle pointer is invalid") from exc
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise IntegrityError("active bundle pointer path must be repository-relative")
    target = (BASE_DIR / relative).resolve()
    allowed_roots = [
        TRAINED_DIR.resolve(),
        (MODELS_DIR / "candidate_cicids2017").resolve(),
        (MODELS_DIR / "candidates").resolve(),
        (MODELS_DIR / "releases").resolve(),
    ]
    if not any(target == root or root in target.parents for root in allowed_roots):
        raise IntegrityError("active bundle pointer escapes allowed model directories")
    if not target.is_dir() or target.is_symlink():
        raise IntegrityError("active bundle pointer target is unavailable or unsafe")
    return target
