"""Label-independent feature hashing and duplicate-label diagnostics.

Labels are deliberately kept outside the feature fingerprint.  Including a
label in the fingerprint hides the most important data-quality failure this
module is intended to find: identical telemetry carrying conflicting labels.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Iterable

import numpy as np
import pandas as pd

from .features import FEATURE_NAMES


FEATURE_HASH_SCHEMA_VERSION = "cyberguard-feature-row-hash-v2"
EXACT_HASH_ALGORITHM = "pandas-uint64-feature-only-fixed-key-v2"
NEAR_HASH_ALGORITHM = "pandas-uint64-log1p-round3-feature-only-fixed-key-v2"


def canonical_feature_hashes(X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Return exact and coarse hashes for a finite canonical feature matrix.

    The hashes intentionally exclude labels, capture identifiers, timestamps,
    and row indices.  The near hash rounds ``log1p(max(value, 0))`` to three
    decimals; it is evidence of similarity, not proof that two flows are the
    same observation.
    """
    matrix = np.asarray(X)
    if matrix.ndim != 2 or matrix.shape[1] != len(FEATURE_NAMES):
        raise ValueError(
            f"expected an N x {len(FEATURE_NAMES)} canonical feature matrix"
        )
    if not np.isfinite(matrix).all():
        raise ValueError("feature hashes require a finite matrix")

    exact_frame = pd.DataFrame(matrix, columns=FEATURE_NAMES)
    exact = pd.util.hash_pandas_object(
        exact_frame, index=False, hash_key="cyberguard-audit"
    ).to_numpy(dtype=np.uint64)
    near_frame = pd.DataFrame(
        np.round(np.log1p(np.maximum(matrix, 0.0)), 3), columns=FEATURE_NAMES
    )
    near = pd.util.hash_pandas_object(
        near_frame, index=False, hash_key="cyberguard-near1"
    ).to_numpy(dtype=np.uint64)
    return exact, near


def duplicate_label_report(
    hashes: Iterable[int] | np.ndarray,
    labels: Iterable[str] | np.ndarray,
) -> dict[str, int]:
    """Summarize same-label duplicates and label-conflicting hash groups.

    ``same_label_duplicate_rows`` counts repeated rows beyond the first row for
    each hash/label pair.  ``conflicting_label_rows`` counts every row belonging
    to a hash associated with two or more distinct labels.  These measures can
    overlap and therefore remain separately named rather than being presented
    as a partition of all duplicates.
    """
    counts: dict[int, Counter[str]] = defaultdict(Counter)
    total = 0
    for raw_hash, raw_label in zip(hashes, labels):
        counts[int(raw_hash)][str(raw_label)] += 1
        total += 1

    same_label_rows = sum(
        max(count - 1, 0)
        for label_counts in counts.values()
        for count in label_counts.values()
    )
    conflicting = [
        label_counts for label_counts in counts.values() if len(label_counts) > 1
    ]
    return {
        "rows": int(total),
        "unique_feature_hashes": int(len(counts)),
        "same_label_duplicate_rows": int(same_label_rows),
        "conflicting_label_feature_groups": int(len(conflicting)),
        "conflicting_label_rows": int(
            sum(sum(label_counts.values()) for label_counts in conflicting)
        ),
    }


def label_independent_duplicate_analysis(
    exact_hashes: np.ndarray,
    near_hashes: np.ndarray,
    labels: np.ndarray,
) -> dict:
    """Build the versioned exact/near duplicate report used by audits."""
    if not (len(exact_hashes) == len(near_hashes) == len(labels)):
        raise ValueError("feature hashes and labels must have equal lengths")
    return {
        "schema_version": "cyberguard-duplicate-label-report-v1",
        "feature_hash_schema_version": FEATURE_HASH_SCHEMA_VERSION,
        "label_included_in_feature_hash": False,
        "exact": duplicate_label_report(exact_hashes, labels),
        "near": duplicate_label_report(near_hashes, labels),
    }
