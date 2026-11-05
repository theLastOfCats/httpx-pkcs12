"""Safety boundaries for automatic dependency merges."""

from copy import deepcopy
from pathlib import Path
import runpy

import pytest
import yaml

policy = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / ".github/scripts/dependabot_automerge.py")
)


def message(*updates: tuple[str, str]) -> str:
    metadata = {"updated-dependencies": [
        {"dependency-name": name, "update-type": update_type}
        for name, update_type in updates
    ]}
    return "Dependency update\n\n---\n" + yaml.safe_dump(metadata) + "...\n"


@pytest.mark.parametrize("name", ["ruff", "mypy", "pytest", "pytest-cov", "httpx", "pyyaml"])
def test_development_patch_update_is_eligible(name: str) -> None:
    assert policy["eligible_metadata"](
        message((name, "version-update:semver-patch")), "uv"
    )


@pytest.mark.parametrize("unsafe", [
    ("cryptography", "version-update:semver-patch"),
    ("cffi", "version-update:semver-patch"),
    ("ruff", "version-update:semver-major"),
    ("ruff", "unknown"),
])
def test_unsafe_member_rejects_entire_mixed_group(unsafe: tuple[str, str]) -> None:
    safe = ("mypy", "version-update:semver-minor")
    assert not policy["eligible_metadata"](message(safe, unsafe), "uv")
    assert not policy["eligible_metadata"](message(unsafe, safe), "uv")


@pytest.mark.parametrize("document", [
    "No update metadata", "---\nupdated-dependencies: []", 
    "Update\n---\nupdated-dependencies: []\n...\n",
    "Update\n---\nupdated-dependencies: [null]\n...\n",
    "Update\n---\nupdated-dependencies: [\n...\n",
])
def test_missing_or_malformed_metadata_is_ineligible(document: str) -> None:
    assert not policy["eligible_metadata"](document, "uv")


def test_action_major_and_unknown_ecosystem_require_manual_merge() -> None:
    minor = message(("actions/checkout", "version-update:semver-minor"))
    assert policy["eligible_metadata"](minor, "github_actions")
    assert not policy["eligible_metadata"](minor, "unknown")
    major = message(("actions/checkout", "version-update:semver-major"))
    assert not policy["eligible_metadata"](major, "github_actions")


def test_runtime_closure_detects_transitive_and_variant_changes() -> None:
    lock = {"package": [
        {"name": "httpx-pkcs12", "dependencies": [{"name": "cryptography"}],
         "optional-dependencies": {"dev": [{"name": "ruff"}]}},
        {"name": "cryptography", "version": "50.0.1", "dependencies": [{"name": "cffi"}]},
        {"name": "cffi", "version": "2.0.0"},
        {"name": "cffi", "version": "2.1.0"},
        {"name": "ruff", "version": "0.16.9"},
    ]}
    original = policy["runtime_packages"](lock)
    development = deepcopy(lock)
    development["package"][-1]["version"] = "0.17.0"
    assert policy["runtime_packages"](development) == original
    for index in (1, 2, 3):
        changed = deepcopy(lock)
        changed["package"][index]["version"] = "99.0.0"
        assert policy["runtime_packages"](changed) != original
