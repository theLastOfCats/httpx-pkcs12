"""
httpx_pkcs12: Addon which activates PKCS12 certificates usage with HTTPX client.

This package provides utilities to load PKCS12 (.p12/.pfx) certificates and use them
with HTTPX HTTP client.
"""

import contextlib
from datetime import datetime, timezone
import os
import ssl
import tempfile
from pathlib import Path
from ssl import PROTOCOL_TLS_CLIENT, SSLContext
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)

__version__ = "2.0.0"


class CertificateError(Exception):
    """Exception raised for certificate-related issues."""
    pass


def _validate_certificate(cert: x509.Certificate | None) -> None:
    """
    Validate that a certificate exists and is not expired.
    
    Args:
        cert: The certificate to validate
        
    Raises:
        CertificateError: If certificate is None or expired
    """
    if not cert:
        raise CertificateError("Invalid or missing certificate")

    if cert.not_valid_after_utc < datetime.now(timezone.utc):
        raise CertificateError(
            f"Certificate expired on {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )


def create_ssl_context(
    pkcs12_data: bytes | str | Path,
    password: str | bytes | None = None,
    validate: bool = True,
) -> SSLContext:
    """
    Create an SSL context from PKCS12 data.
    
    Args:
        pkcs12_data: The PKCS12 certificate data or path to the certificate file
        password: The password to decrypt the PKCS12 data
        validate: Whether to validate certificate expiration
        
    Returns:
        SSLContext: The SSLContext object configured with the certificate
        
    Raises:
        CertificateError: If certificate validation fails
        ValueError: If input data is invalid
        IOError: If file operations fail
    """
    # Handle file paths and convert password to bytes
    if isinstance(pkcs12_data, str | Path):
        with open(pkcs12_data, 'rb') as f:
            pkcs12_data = f.read()
    
    password_bytes = None
    if password is not None:
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
    
    # Load certificates from PKCS12 data
    private_key, cert, ca_certs = load_key_and_certificates(
        pkcs12_data, password_bytes
    )
    
    if validate and cert:
        _validate_certificate(cert)
    
    # Create and configure SSL context
    ssl_context = SSLContext(PROTOCOL_TLS_CLIENT)
    
    # Create temporary certificate file
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        try:
            # Write private key
            if private_key:
                private_bytes = private_key.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
                temp_file.write(private_bytes)
            
            # Write certificate
            if cert:
                public_bytes = cert.public_bytes(Encoding.PEM)
                temp_file.write(public_bytes)
            
            # Write CA certificates if available
            if ca_certs:
                for ca_cert in ca_certs:
                    if validate and ca_cert:
                        _validate_certificate(ca_cert)
                    if ca_cert:
                        ca_public_bytes = ca_cert.public_bytes(Encoding.PEM)
                        temp_file.write(ca_public_bytes)
            
            temp_file.flush()
            temp_file_path = temp_file.name
            
            # Load the certificate chain into the SSL context
            ssl_context.load_cert_chain(temp_file_path, password=password_bytes)
            
        finally:
            # Clean up temporary file
            with contextlib.suppress(OSError):
                os.unlink(temp_file.name)
    
    # Set SSL context options for better security
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED  # Use ssl.CERT_REQUIRED instead of VERIFY_PEER
    
    return ssl_context


def load_pkcs12_from_file(
    certificate_path: str | Path, 
    password: str | bytes | None = None,
    validate: bool = True
) -> SSLContext:
    """
    Create an SSL context from a PKCS12 certificate file.
    
    Args:
        certificate_path: Path to the PKCS12 certificate file
        password: Password to decrypt the PKCS12 data
        validate: Whether to validate certificate expiration
        
    Returns:
        SSLContext: The configured SSL context
    """
    return create_ssl_context(certificate_path, password, validate)


def get_certificate_info(
    pkcs12_data: bytes | str | Path,
    password: str | bytes | None = None
) -> tuple[datetime | None, datetime | None, str | None, list[str]]:
    """
    Extract and return information about the certificate in PKCS12 data.
    
    Args:
        pkcs12_data: The PKCS12 certificate data or path
        password: Password to decrypt the PKCS12 data
        
    Returns:
        Tuple containing:
        - Not valid before date
        - Not valid after date
        - Subject common name
        - List of subject alternative names
    """
    # Handle file paths and convert password to bytes
    if isinstance(pkcs12_data, str | Path):
        with open(pkcs12_data, 'rb') as f:
            pkcs12_data = f.read()
    
    password_bytes = None
    if password is not None:
        if isinstance(password, str):
            password_bytes = password.encode('utf-8')
        else:
            password_bytes = password
    
    # Load certificates from PKCS12 data
    _, cert, _ = load_key_and_certificates(pkcs12_data, password_bytes)
    
    if not cert:
        return None, None, None, []
    
    # Extract certificate information
    not_valid_before = cert.not_valid_before_utc
    not_valid_after = cert.not_valid_after_utc
    
    # Get common name from subject
    common_name: str | None = None
    for attribute in cert.subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            value = attribute.value
            if isinstance(value, str):
                common_name = value
            break
    
    # Get subject alternative names if extension exists
    san_list: list[str] = []
    try:
        # Fix the ExtensionOID issue
        for ext in cert.extensions:
            if ext.oid.dotted_string == "2.5.29.17":  # SubjectAltName OID
                san_value = cast("x509.SubjectAlternativeName", ext.value)
                for name in san_value:
                    if isinstance(name, x509.DNSName):
                        san_list.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        san_list.append(f"IP:{name.value}")
                    elif isinstance(name, x509.RFC822Name):
                        san_list.append(f"Email:{name.value}")
    except Exception:
        # Catch any extension parsing errors
        pass
    
    return not_valid_before, not_valid_after, common_name, san_list