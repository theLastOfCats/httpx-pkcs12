## httpx-pkcs12

Addon which activates PKCS12 certificates usage with HTTPX client.

## Usage
```python
with open('path/to/your/cert', 'rb') as f:
    cert_contents = f.read()
password = 'your-secret-password'

context = create_ssl_context(cert_contents, password)

# async version
async with httpx.AsyncClient(verify=context) as client:
    response = ...

# or sync version
response = httpx.get(..., verify=context)
```