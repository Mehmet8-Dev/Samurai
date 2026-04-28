import pytest
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from ddos_samurai.licensing.client import validate_license
from ddos_samurai.licensing.features import Tier, LicenseResult

@patch('ddos_samurai.licensing.client.urlopen')
def test_validate_license_success(mock_urlopen):
    # Mock HTTP response
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"valid": true, "tier": "pro", "features": ["gpu_engine"], "limits": {"max_workers": 16}, "expires": "2027-01-01", "session_id": "sess-123"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    result = validate_license(key="SAM-1234-5678-ABCD-EFGH")
    
    assert result.valid is True
    assert result.tier == Tier.PRO
    assert "gpu_engine" in result.features
    assert result.limits.max_workers == 16
    assert result.session_id == "sess-123"

@patch('ddos_samurai.licensing.client.urlopen')
@patch('ddos_samurai.licensing.client.load_cache')
def test_validate_license_network_error_uses_cache(mock_load_cache, mock_urlopen):
    # Simulate network failure
    mock_urlopen.side_effect = URLError("Network unreachable")
    
    # Provide a valid cache
    mock_load_cache.return_value = LicenseResult(
        valid=True,
        tier=Tier.ENTERPRISE,
        features=["ninja_mode"],
        limits=None,
        expires="2027-01-01T00:00:00Z",
        customer_email="test@example.com",
        reason="offline",
        session_id="offline-sess-123",
        offline=True
    )
    
    result = validate_license(key="SAM-1234-5678-ABCD-EFGH")

    
    assert result.valid is True
    assert result.offline is True
    assert result.tier == Tier.ENTERPRISE
    assert "ninja_mode" in result.features

@patch('ddos_samurai.licensing.client.urlopen')
@patch('ddos_samurai.licensing.client.load_cache')
def test_validate_license_network_error_no_cache_fails(mock_load_cache, mock_urlopen):
    mock_urlopen.side_effect = URLError("Network unreachable")
    mock_load_cache.return_value = None
    
    result = validate_license(key="SAM-1234-5678-ABCD-EFGH")
    
    assert result.valid is False
    assert "Lisans sunucusuna ulaşılamadı" in result.reason

