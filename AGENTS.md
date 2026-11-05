# Repository Guidelines

## Project Overview

`httpx-pkcs12` is a Python library that converts PKCS#12 (`.p12`/`.pfx`) client certificates into an `ssl.SSLContext` for HTTPX. It also exposes certificate metadata and optional expiration checks. There is no application server or CLI to launch.

## Architecture & Data Flow

- Implementation lives in `httpx_pkcs12/__init__.py`. Public APIs are `create_ssl_context`, `load_pkcs12_from_file`, `get_certificate_info`, and `CertificateError`.
- Context creation: bytes or file path → normalize password → `cryptography.load_key_and_certificates` → optional expiration checks → temporary PEM containing private key, leaf, and additional certificates → `SSLContext.load_cert_chain` → return context.
- `load_pkcs12_from_file` delegates to context creation. `get_certificate_info` parses independently and returns `(not_valid_before, not_valid_after, common_name, alternative_names)` with UTC dates; SAN strings use `DNS:`, `IP:`, and `Email:` prefixes.
- Functions are synchronous and stateless; there is no dependency-injection framework, shared mutable state, or async transport. Pass the returned context as `verify=context` to either `httpx.Client` or `httpx.AsyncClient`; certificate loading itself remains synchronous.
- `validate=True` checks expiration of present leaf/additional certificates, not not-before dates or full chain validity. The context requires peer verification and hostname checking, but does not explicitly load server trust roots. Additional bundle certificates form the client chain, not a configured CA trust store.

## Key Directories

- `httpx_pkcs12/`: library implementation and package version.
- `tests/`: generated-certificate tests; no checked-in certificate fixtures.
- `.github/workflows/`: tests, lint/type checks, and package publishing.
- `.github/scripts/`: trusted default-branch Dependabot merge policy; never execute PR code in its privileged workflow.

## Development Commands

Run from the repository root:

```sh
uv sync --frozen --extra dev --python 3.14
uv run pytest --cov=httpx_pkcs12 --cov-report=xml
uv run pytest tests/test_httpx_pkcs12.py -k expired
uv run ruff check
uv run mypy httpx_pkcs12
uv build
```

`uv build` produces wheel and source archives in `dist/`; publishing CI uses the same command at the release tag. CI installs locked development dependencies before lint/type checks so dependency PRs exercise the tools they actually change. For library usage examples rather than a run command, see `README.md`.

## Code Conventions & Common Patterns

- Use Python 3.13-compatible syntax, annotated functions, `snake_case` functions/variables, and `PascalCase` exceptions. Existing APIs use `bytes | str | Path` and explicit `None` unions; mypy requires typed definitions.
- Ruff targets Python 3.13 and an 88-character line length. Its explicit lint `select` list is empty; a passing lint command is not evidence of broad style checking. No formatter command is configured.
- A `str` certificate input means a file path, not encoded bundle contents. String passwords are UTF-8 encoded; bytes and `None` pass through.
- Preserve the temporary-file lifecycle: private keys are written as unencrypted PEM, flushed before SSL loading, and unlinked in `finally`. Cleanup suppresses `OSError`; never log key material or passwords.
- `_validate_certificate` raises `CertificateError`; parsing, file I/O, and SSL-loading errors otherwise propagate. Metadata extraction returns `(None, None, None, [])` without a leaf and currently suppresses SAN parsing exceptions. Do not assume a uniform exception wrapper.

## Important Files

- `pyproject.toml`: dependencies, optional `dev` extra, Hatchling build backend, Ruff/mypy settings, and dynamic version source.
- `httpx_pkcs12/__init__.py`: public entry points, TLS behavior, and `__version__` used by packaging.
- `uv.lock` and `.python-version`: dependency lock and local Python selection.
- `tests/test_httpx_pkcs12.py`: generated-certificate tests; `tests/test_dependabot_automerge.py`: fail-closed metadata and transitive runtime-dependency safety boundaries.
- `README.md`: installation, HTTPX integration, API reference, and error handling.
- `.github/workflows/{test,lint,publish}.yml`: CI and release commands.
- `.github/dependabot.yml`: monthly grouped version updates for Python dependencies and GitHub Actions, with one open version-update PR per ecosystem. Do not reintroduce an outdated-action PR gate.
- `release-please-config.json` and `.release-please-manifest.json`: Python release strategy and last released version. Release Please updates `__version__` and `CHANGELOG.md` in a manually merged release PR; do not bump the version independently.

## Runtime/Tooling Preferences

Python >=3.13 is required; `.python-version` selects 3.14. Use `uv` with the committed lockfile; `dev` is an optional extra, not a dependency group. `cryptography` is the runtime dependency; HTTPX is in the development extra and must also be available in consuming applications. Test CI selects Python 3.13–3.15; lint and packaging use 3.14. Keep changes compatible with the minimum supported version.

## Testing & QA

Tests use pytest, plain `test_*` functions, `pytest.raises`, and a `temp_cert_file` fixture. `generate_test_certificate(days_valid=30)` creates encrypted self-signed RSA certificates in memory; negative validity creates expired certificates. Tests need a writable temporary directory, not network services.

Current coverage includes byte/path inputs, the file helper, expiration validation on/off, metadata, password forms, and an unlink-call assertion. It does not prove a real HTTP/TLS handshake, malformed/wrong-password handling, additional chains, or cleanup on failure. For relevant changes, assert observable behavior and failure paths rather than only context existence. CI generates `coverage.xml` for Codecov; no minimum coverage threshold is configured.

Routine Dependabot patch/minor version updates are grouped monthly; security updates are not governed by that schedule. Development tools and GitHub Actions can merge after the `lint` and `test (3.13)`/`test (3.14)`/`test (3.15)` checks pass; runtime, transitive-runtime, major, unknown, and manually edited updates remain manual. Main branch protection must enforce those checks, including for administrators. The merge script deliberately does not queue GitHub auto-merge: every decision is bound to one signed, checked head SHA.

Use Conventional Commits: `fix:` for patch, `feat:` for minor, `!`/`BREAKING CHANGE:` for major, `chore(deps):` for non-release tool updates. Keep PyPI publishing in `publish.yml` for its trusted-publisher identity; release creation and publication run in that same workflow, without relying on token-created tag events. Token-created release PRs need maintainer approval of their Test/Lint runs, then a manual merge. Find approval-blocked runs via `gh api 'repos/OWNER/REPO/actions/runs?event=pull_request&head_sha=SHA'` and approve each `action_required` run through `POST /repos/OWNER/REPO/actions/runs/RUN_ID/approve`; separately dispatched checks do not satisfy this PR gate. Rerun failed publishing jobs rather than expecting a new main push to republish an existing tag.
