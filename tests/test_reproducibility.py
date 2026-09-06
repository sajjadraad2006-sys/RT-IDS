"""Regression tests for clean-checkout fixtures and launcher reproducibility."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import csv

from backend.config import BASE_DIR, DB_PATH
from backend.detection.integrity import sha256_file, validate_dataset_manifest
from backend.detection.input_schema import FlowSchemaValidator
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

    with committed.open("r", encoding="utf-8", newline="") as handle:
        fieldnames = csv.DictReader(handle).fieldnames
    validator = FlowSchemaValidator(fieldnames or [], input_format="csv")
    assert validator.report.supported is True
    assert validator.report.feature_coverage_percentage == 100.0


def test_pytest_database_is_isolated_from_repository_state():
    assert DB_PATH.name == "cyberguard-test.sqlite"
    assert BASE_DIR not in DB_PATH.parents


def test_requirement_files_are_exact_pinned():
    for filename in (
        "requirements.txt", "requirements-dev.txt", "requirements-constraints.txt"
    ):
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


def test_dependency_constraints_are_not_misrepresented_as_hash_lock():
    constraints = (BASE_DIR / "requirements-constraints.txt").read_text(
        encoding="utf-8"
    ).lower()
    assert "no package hashes" in constraints
    assert "--hash=" not in constraints
    assert not (BASE_DIR / "requirements.lock").exists()
    runtime = (BASE_DIR / "requirements.txt").read_text(encoding="utf-8")
    assert "-c requirements-constraints.txt" in runtime
    assert "supported resolver is pip" in runtime


def test_verify_gate_fails_when_active_bundled_snapshot_is_missing():
    environment = os.environ.copy()
    environment["CG_ATTACK_VERSION"] = "v-missing-verification-fixture"
    result = subprocess.run(
        [sys.executable, "verify.py"],
        cwd=BASE_DIR,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 1
    assert "MITRE snapshot validation: FAIL:" in result.stdout
    assert "techniques=0): PASS" not in result.stdout


def test_launcher_never_kills_foreign_port_owner_and_gates_success():
    launcher = (BASE_DIR / "run.sh").read_text(encoding="utf-8")
    assert "fuser" not in launcher
    assert "kill -9" not in launcher
    assert "Dependency pins are not satisfied" in launcher
    assert "Required verification failed; CyberGuard was not started." in launcher
    assert launcher.index('mkdir -p "$SCRIPT_DIR/logs"') < launcher.index(
        '>"$SCRIPT_DIR/logs/llama.log"'
    )


def test_run_bash_launcher_exists_executable_and_delegates():
    run_bash = BASE_DIR / "run.bash"
    assert run_bash.exists()
    assert os.access(run_bash, os.X_OK)
    content = run_bash.read_text(encoding="utf-8")
    assert "run.sh" in content
    assert "exec" in content

    syntax_result = subprocess.run(
        ["bash", "-n", str(run_bash), str(BASE_DIR / "run.sh")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert syntax_result.returncode == 0

    help_result = subprocess.run(
        ["bash", str(run_bash), "--help"],
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    assert help_result.returncode == 0
    assert "Usage: bash run.bash" in help_result.stdout
    assert "--skip-llm" in help_result.stdout
    assert "--skip-mitre-sync" in help_result.stdout

