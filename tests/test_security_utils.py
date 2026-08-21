"""Tests for security utilities and SSRF validation."""
import pytest
from src.security_utils import validate_upstream_url

def test_valid_public_urls():
    assert validate_upstream_url("https://api.github.com") == "https://api.github.com"
    assert validate_upstream_url("http://example.com/mcp") == "http://example.com/mcp"

def test_ssrf_forbidden_hostnames():
    with pytest.raises(ValueError, match="SSRF Risk Blocked"):
        validate_upstream_url("http://localhost:8080")

    with pytest.raises(ValueError, match="SSRF Risk Blocked"):
        validate_upstream_url("http://127.0.0.1/admin")

    with pytest.raises(ValueError, match="SSRF Risk Blocked"):
        validate_upstream_url("http://169.254.169.254/latest/meta-data")

    with pytest.raises(ValueError, match="SSRF Risk Blocked"):
        validate_upstream_url("http://0.0.0.0:3000")

def test_invalid_schemes():
    with pytest.raises(ValueError, match="only HTTP and HTTPS are allowed"):
        validate_upstream_url("file:///etc/passwd")

    with pytest.raises(ValueError, match="only HTTP and HTTPS are allowed"):
        validate_upstream_url("gopher://127.0.0.1")
