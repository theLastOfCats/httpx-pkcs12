# httpx-pkcs12

Enhanced PKCS12 (PFX/P12) certificate support for the HTTPX Python client. This package allows you to easily use PKCS12 certificates with HTTPX for client certificate authentication.

## Features

- Simple API for loading PKCS12 certificates
- Support for certificate validation
- Extract certificate information
- Works with both file paths and certificate data
- Accepts passwords as strings or bytes
- Proper cleanup of temporary certificate files
- Comprehensive type hints

## Installation

Requires **Python 3.13 or newer**. CI tests Python 3.13, 3.14, and 3.15;
local development uses Python 3.14.

```bash
pip install httpx-pkcs12
```

Or with uv:

```bash
uv add httpx-pkcs12
```

## Usage

### Basic Usage

```python
import httpx
from httpx_pkcs12 import create_ssl_context

# Load certificate from file
context = create_ssl_context(
    'path/to/your/cert.p12',
    password='your-secret-password'
)

# With async client
async with httpx.AsyncClient(verify=context) as client:
    response = await client.get('https://api.example.com')

# With sync client
with httpx.Client(verify=context) as client:
    response = client.get('https://api.example.com')

# Or for a one-off request
response = httpx.get('https://api.example.com', verify=context)
```

### Advanced Usage

```python
from httpx_pkcs12 import create_ssl_context, get_certificate_info

# Load certificate directly from bytes
with open('path/to/cert.p12', 'rb') as f:
    cert_data = f.read()

# Create context without validation (for expired certs)
context = create_ssl_context(
    cert_data,
    password='your-password',
    validate=False
)

# Get certificate information
not_before, not_after, common_name, alt_names = get_certificate_info(
    'path/to/cert.p12',
    password='your-password'
)

print(f"Certificate: {common_name}")
print(f"Valid from: {not_before}")
print(f"Valid until: {not_after}")
print(f"Alternative names: {', '.join(alt_names)}")
```

## API Reference

### `create_ssl_context(pkcs12_data, password=None, validate=True)`

Creates an SSL context from PKCS12 data.

- **pkcs12_data**: The PKCS12 certificate data as bytes or a path to the file
- **password**: Password to decrypt the PKCS12 data (string or bytes)
- **validate**: Whether to validate certificate expiration
- **Returns**: An SSLContext object configured with the certificate

### `load_pkcs12_from_file(certificate_path, password=None, validate=True)`

Convenience function to create an SSL context from a PKCS12 certificate file.

- **certificate_path**: Path to the PKCS12 certificate file
- **password**: Password to decrypt the PKCS12 data
- **validate**: Whether to validate certificate expiration
- **Returns**: An SSLContext object configured with the certificate

### `get_certificate_info(pkcs12_data, password=None)`

Extracts and returns information about the certificate.

- **pkcs12_data**: The PKCS12 certificate data or file path
- **password**: Password to decrypt the PKCS12 data
- **Returns**: Tuple with (not_valid_before, not_valid_after, common_name, alt_names)

## Error Handling

The package raises the following exceptions:

- `CertificateError`: For certificate validation issues
- `ValueError`: For invalid input data
- `IOError`: For file operation failures

## Development and Releases

```bash
uv sync --frozen --extra dev
uv run pytest
uv run ruff check
uv run mypy httpx_pkcs12
uv build
```

Use Conventional Commits: `fix:` releases a patch, `feat:` a minor, and
`feat!:` or a `BREAKING CHANGE:` footer a major version. Routine development-tool
and GitHub Actions updates use `chore(deps):` and do not cause releases.

Release Please maintains a release PR with `CHANGELOG.md`, the version in
`httpx_pkcs12/__init__.py`, and `.release-please-manifest.json`. GitHub requires
approval before running CI on PRs created with `GITHUB_TOKEN`: use **Approve
workflows to run** on the PR (or `gh api repos/OWNER/REPO/actions/runs/RUN_ID/approve --method POST`).
Wait for required CI, then manually merge the release PR. The same
`publish.yml` run creates the tag, builds that
exact tag, publishes through PyPI trusted publishing, and attaches signed
distributions to the GitHub release. If publishing fails after tag creation,
rerun the failed jobs in that run; pushing another commit is not a retry.

Dependabot groups routine patch/minor updates monthly. Development dependencies
and GitHub Actions may merge automatically only after all required CI passes.
Runtime dependencies (including transitive lock changes), major updates, and
unrecognized metadata require manual handling. The privileged merge workflow
uses only default-branch code, verifies the bot's signed commit, and merges
the exact checked head without leaving a pending auto-merge request.

## License

MIT