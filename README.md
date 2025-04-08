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

## License

MIT