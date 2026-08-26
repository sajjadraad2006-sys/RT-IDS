"""Regression tests for clean-checkout fixtures and launcher reproducibility."""
from __future__ import annotations

import json
from pathlib import Path

from backend.config import BASE_DIR
from backend.detection.integrity import sha256_file, validate_dataset_manifest
from cyberguard.datasets.generate_sample import generate_sample_dataset


def test_committed_fixture_matches_generator_and_default_manifest(tmp_path):
    manifest_path = BASE_DIR / "cyberguard/datasets/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(manifest["datasets"]) == 1
    declaration = manifest["datasets"][0]
    assert declaration["id"] == "synthetic-cicids-shape-fixture-small-v1"
    assert declaration["training_approved"] is False

    validated = validate_dataset_manifest(manifest_path, BASE_DIR)
    assert [item["id"] for item in validated] == [declaration["id"]]

    generated = generate_sample_dataset(tmp_path / "sample_traffic.csv", 2000)
    committed = BASE_DIR / declaration["path"]
    assert generated.read_bytes() == committed.read_bytes()
    assert sha256_file(generated) == declaration["sha256"]


def test_requirement_files_are_exact_pinned():
    for filename in ("requirements.txt", "requirements-dev.txt", "requirements.lock"):
        lines = (BASE_DIR / filename).read_text(encoding="utf-8").splitlines()
        requirements = [
            line.strip()
            for line in lines
            if line.strip() and not line.lstrip().startswith(("#", "-"))
        ]
        assert requirements
        assert all("==" in requirement for requirement in requirements)
        # Environment markers may legitimately contain comparisons such as
        # ``sys_platform != 'linux'``; only inspect the requirement specifier.
        specs = [requirement.split(";", 1)[0].strip() for requirement in requirements]
        assert all(
            not any(operator in spec for operator in (">=", "<=", "~=", "!="))
            for spec in specs
        )


def test_launcher_never_kills_foreign_port_owner_and_gates_success():
    launcher = (BASE_DIR / "run.sh").read_text(encoding="utf-8")
    assert "fuser" not in launcher
    assert "kill -9" not in launcher
    assert "Dependency pins are not satisfied" in launcher
    assert "Required verification failed; CyberGuard was not started." in launcher
    assert launcher.index('mkdir -p "$SCRIPT_DIR/logs"') < launcher.index(
        '>"$SCRIPT_DIR/logs/llama.log"'
    )
