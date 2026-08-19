"""Export reviewed, non-conflicting Smart Logs for offline shadow training.

Usage:
    python -m backend.decision.export_reviewed reviewed-cases.jsonl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from ..db.models import DecisionCase, SessionLocal
from .models import SmartLog


def feedback_conflicts(smart: SmartLog, verdict: str) -> bool:
    known_malicious = (
        not smart.review_required
        and smart.detection.stage == "classifier"
        and smart.detection.severity in {"high", "critical"}
    )
    known_benign = not smart.review_required and smart.detection.type.lower() == "benign"
    return (known_malicious and verdict == "benign") or (
        known_benign and verdict == "malicious"
    )


def export_reviewed(path: Path, *, include_conflicts: bool = False) -> dict:
    exported = 0
    excluded_conflicts = 0
    invalid = 0
    with path.open("x", encoding="utf-8") as output, SessionLocal() as session:
        rows = (
            session.query(DecisionCase)
            .filter(DecisionCase.reviewed_at.is_not(None))
            .order_by(DecisionCase.reviewed_at.asc())
            .all()
        )
        for case in rows:
            try:
                smart = SmartLog.model_validate_json(case.smart_log_json)
            except ValidationError:
                invalid += 1
                continue
            conflict = feedback_conflicts(smart, case.analyst_verdict)
            if conflict and not include_conflicts:
                excluded_conflicts += 1
                continue
            output.write(json.dumps({
                "schema_version": "reviewed-case-v1",
                "smart_log": smart.model_dump(mode="json"),
                "analyst_verdict": case.analyst_verdict,
                "reviewed_by": case.reviewed_by,
                "reviewed_at": case.reviewed_at,
                "conflict": conflict,
                "training_effect": "shadow_candidate_only",
            }, sort_keys=True) + "\n")
            exported += 1
    return {
        "exported": exported,
        "excluded_conflicts": excluded_conflicts,
        "invalid": invalid,
        "path": str(path),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--include-conflicts", action="store_true")
    args = parser.parse_args()
    result = export_reviewed(args.output, include_conflicts=args.include_conflicts)
    print(json.dumps(result, sort_keys=True))
