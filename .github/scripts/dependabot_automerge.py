"""Merge verified, low-risk Dependabot updates only after required CI passes."""

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
from typing import Any

import yaml

DEV_DEPENDENCIES = {"pytest", "pytest-cov", "ruff", "mypy", "httpx", "pyyaml"}
SAFE_UPDATES = {"version-update:semver-patch", "version-update:semver-minor"}
REQUIRED_CHECKS = {"lint", "test (3.13)", "test (3.14)", "test (3.15)"}


def api(path: str, *, method: str = "GET", data: dict | None = None) -> Any:
    command = ["gh", "api", path, "--method", method]
    if data is not None:
        command.extend(["--input", "-"])
    result = subprocess.run(
        command, input=json.dumps(data) if data is not None else None,
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout) if result.stdout else None


def eligible_metadata(message: str, ecosystem: str) -> bool:
    """Unknown or mixed-major metadata must never inherit a safe classification."""
    if "\n---\n" not in message:
        return False
    document = message.split("\n---\n", 1)[1].split("\n...", 1)[0]
    try:
        metadata = yaml.safe_load(document)
    except yaml.YAMLError:
        return False
    if not isinstance(metadata, dict):
        return False
    dependencies = metadata.get("updated-dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        return False
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            return False
        name = dependency.get("dependency-name")
        if not isinstance(name, str) or not name:
            return False
        if dependency.get("update-type") not in SAFE_UPDATES:
            return False
        if ecosystem == "uv":
            if name not in DEV_DEPENDENCIES:
                return False
        elif ecosystem != "github_actions":
            return False
    return True


def runtime_packages(lock: dict) -> dict:
    """Include every variant of every transitive runtime dependency in uv.lock."""
    packages = {}
    for package in lock["package"]:
        packages.setdefault(package["name"], []).append(package)
    root = packages["httpx-pkcs12"]
    pending = [item["name"] for package in root for item in package.get("dependencies", [])]
    runtime = {}
    while pending:
        name = pending.pop()
        if name in runtime:
            continue
        runtime[name] = packages[name]
        for package in packages[name]:
            pending.extend(item["name"] for item in package.get("dependencies", []))
    return runtime


def main() -> None:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    run = event["workflow_run"]
    repository = os.environ["GITHUB_REPOSITORY"]
    if (run["event"] != "pull_request" or run["conclusion"] != "success"
            or run["head_repository"]["full_name"] != repository):
        return
    prefix = f"repos/{repository}"
    candidates = api(f"{prefix}/commits/{run['head_sha']}/pulls")
    candidates = [pr for pr in candidates if pr["state"] == "open"
                  and pr["base"]["ref"] == "main"
                  and pr["base"]["repo"]["full_name"] == repository
                  and pr["head"]["repo"] is not None
                  and pr["head"]["repo"]["full_name"] == repository
                  and pr["head"]["sha"] == run["head_sha"]
                  and pr["user"]["login"] == "dependabot[bot]"]
    if len(candidates) != 1:
        return
    pr = api(f"{prefix}/pulls/{candidates[0]['number']}")
    if pr["head"]["sha"] != run["head_sha"] or pr["draft"]:
        return
    branch = pr["head"]["ref"].split("/")
    if len(branch) < 3 or branch[0] != "dependabot":
        return
    ecosystem = branch[1]
    # Standard Dependabot PRs have one signed commit. Manual edits remain manual.
    commits = api(f"{prefix}/pulls/{pr['number']}/commits?per_page=2")
    if len(commits) != 1:
        return
    commit = commits[0]
    if (commit["sha"] != run["head_sha"] or not commit.get("author")
            or commit["author"]["login"] != "dependabot[bot]"
            or not commit["commit"]["verification"]["verified"]
            or not eligible_metadata(commit["commit"]["message"], ecosystem)):
        return
    # A result capped at 100 is not proof that every changed file was inspected.
    files = api(f"{prefix}/pulls/{pr['number']}/files?per_page=100")
    if not files or len(files) != pr["changed_files"]:
        return
    if any(item["status"] != "modified" for item in files):
        return
    if ecosystem == "uv":
        if {item["filename"] for item in files} != {"uv.lock"}:
            return
        locks = []
        for ref in (pr["base"]["sha"], pr["head"]["sha"]):
            blob = api(f"{prefix}/contents/uv.lock?ref={ref}")
            locks.append(tomllib.loads(base64.b64decode(blob["content"]).decode()))
        if runtime_packages(locks[0]) != runtime_packages(locks[1]):
            print(f"PR #{pr['number']}: runtime dependency changes require review")
            return
    elif ecosystem == "github_actions":
        if not all(item["filename"].startswith(".github/workflows/")
                   and item["filename"].endswith((".yml", ".yaml")) for item in files):
            return
    else:
        return
    print(f"PR #{pr['number']}: verified patch/minor {ecosystem} update is eligible")
    checks = api(f"{prefix}/commits/{run['head_sha']}/check-runs?filter=latest&per_page=100")
    successful = {check["name"] for check in checks["check_runs"]
                  if check["app"]["slug"] == "github-actions"
                  and check["conclusion"] == "success"}
    if not REQUIRED_CHECKS <= successful:
        print("Waiting for all required CI checks")
        return
    if "--dry-run" in sys.argv:
        print("Dry run: would squash-merge the exact verified head")
        return
    # No queued auto-merge: a future head can never inherit this decision.
    result = api(f"{prefix}/pulls/{pr['number']}/merge", method="PUT", data={
        "sha": run["head_sha"], "merge_method": "squash",
        "commit_title": f"chore(deps): {pr['title']} (#{pr['number']})",
    })
    if not result.get("merged"):
        raise RuntimeError(result)
    print(f"Merged PR #{pr['number']} at {result['sha']}")


if __name__ == "__main__":
    main()
