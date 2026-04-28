import os
import tempfile
import pytest
import time
from unittest.mock import patch
from ddos_samurai.licensing.cache import save_cache, load_cache
from ddos_samurai.licensing.features import LicenseResult, Tier

def test_cache_save_and_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        from ddos_samurai.licensing import cache
        
        # Override the default CACHE_DIR and CACHE_FILE path for testing
        cache.CACHE_DIR = tmpdir
        cache.CACHE_FILE = os.path.join(tmpdir, "test_cache.json")
        
        # Test Data
        result = LicenseResult(
            valid=True,
            tier=Tier.PRO,
            features=["gpu_engine", "af_xdp"],
            expires="2027-01-01T00:00:00Z",
            customer_email="test@example.com",
            reason="test",
            session_id="sess_123",
            offline=False
        )
        
        save_cache(result, "test_hwid")
        
        # Load the cache
        loaded = load_cache("test_hwid")
        
        assert loaded is not None
        assert loaded.valid == True
        assert loaded.tier == Tier.PRO
        assert "gpu_engine" in loaded.features

def test_cache_expiration():
    with tempfile.TemporaryDirectory() as tmpdir:
        from ddos_samurai.licensing import cache
        cache.CACHE_DIR = tmpdir
        cache.CACHE_FILE = os.path.join(tmpdir, "test_cache_exp.json")
        
        result = LicenseResult(
            valid=True,
            tier=Tier.PRO,
            features=[],
            expires="2027-01-01T00:00:00Z",
            customer_email="test@example.com",
            reason="test",
            session_id="sess_123",
            offline=False
        )
        
        save_cache(result, "test_hwid")
        
        # Override mtime to simulate an old cache (older than 24 hours)
        # We also need to modify the payload's timestamp for Fernet, 
        # but wait, load_cache decrypts and reads payload.get("cached_at")
        # Since we use Fernet, it's easier to mock time.time in load_cache
        with patch('time.time', return_value=time.time() + (75 * 3600)):
            loaded = load_cache("test_hwid")
            assert loaded is None  # Cache should be invalidated

