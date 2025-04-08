import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
)
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from httpx_pkcs12 import (
    CertificateError,
    create_ssl_context,
    get_certificate_info,
    load_pkcs12_from_file,
)


def generate_test_certificate(days_valid: int = 30):
    """Generate a test certificate and private key for testing."""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Generate self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])
    
    now = datetime.now(timezone.utc)
    
    # For expired certificates (negative days_valid), set both dates in the past
    if days_valid < 0:
        not_valid_before = now + timedelta(days=days_valid*2)  # Even earlier in the past
        not_valid_after = now + timedelta(days=days_valid)     # In the past
    else:
        not_valid_before = now
        not_valid_after = now + timedelta(days=days_valid)
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("test.example.com"),
            x509.DNSName("www.test.example.com"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Create a PKCS12 certificate
    p12_bytes = serialize_key_and_certificates(
        name=b"test-cert",
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password"),
    )
    
    return p12_bytes, private_key, cert


def test_create_ssl_context_from_bytes():
    """Test creating SSL context from certificate bytes."""
    p12_bytes, _, _ = generate_test_certificate()
    
    # Test with bytes and string password
    context = create_ssl_context(p12_bytes, password="password")
    assert context is not None
    
    # Test with bytes and bytes password
    context = create_ssl_context(p12_bytes, password=b"password")
    assert context is not None


@pytest.fixture
def temp_cert_file():
    """Create a temporary certificate file for testing."""
    p12_bytes, _, _ = generate_test_certificate()
    
    with tempfile.NamedTemporaryFile(suffix='.p12', delete=False) as tmp:
        tmp.write(p12_bytes)
        tmp_path = tmp.name
    
    yield tmp_path
    
    # Clean up
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)


def test_create_ssl_context_from_file(temp_cert_file: str):
    """Test creating SSL context from certificate file."""
    # Test with file path as string
    context = create_ssl_context(temp_cert_file, password="password")
    assert context is not None
    
    # Test with file path as Path object
    context = create_ssl_context(Path(temp_cert_file), password="password")
    assert context is not None
    
    # Test with load_pkcs12_from_file helper
    context = load_pkcs12_from_file(temp_cert_file, password="password")
    assert context is not None


def test_expired_certificate():
    """Test validation of expired certificates."""
    # Create an expired certificate
    p12_bytes, _, _ = generate_test_certificate(days_valid=-1)
    
    # Should raise CertificateError when validate=True
    with pytest.raises(CertificateError):
        create_ssl_context(p12_bytes, password="password", validate=True)
    
    # Should not raise when validate=False
    context = create_ssl_context(p12_bytes, password="password", validate=False)
    assert context is not None


def test_get_certificate_info():
    """Test extracting certificate information."""
    p12_bytes, _, cert = generate_test_certificate()
    
    # Get certificate info
    not_before, not_after, common_name, alt_names = get_certificate_info(
        p12_bytes, password="password"
    )
    
    # Check values
    assert not_before == cert.not_valid_before_utc
    assert not_after == cert.not_valid_after_utc
    assert common_name == "test.example.com"
    assert len(alt_names) == 2
    assert "DNS:test.example.com" in alt_names
    assert "DNS:www.test.example.com" in alt_names


def test_password_handling():
    """Test different password formats."""
    p12_bytes, _, _ = generate_test_certificate()
    
    # Test with string password
    create_ssl_context(p12_bytes, password="password")
    
    # Test with bytes password
    create_ssl_context(p12_bytes, password=b"password")
    
    # Test with None password (should fail for our test cert)
    with pytest.raises(ValueError):
        create_ssl_context(p12_bytes, password=None)


def test_cleanup_temp_files():
    """Test that temporary files are cleaned up."""
    p12_bytes, _, _ = generate_test_certificate()
    
    # Mock the unlink function to check if it's called
    with mock.patch('os.unlink') as mock_unlink:
        create_ssl_context(p12_bytes, password="password")
        assert mock_unlink.called