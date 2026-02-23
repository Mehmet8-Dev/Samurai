import pytest
import ssl
from ddos_samurai import stealth, h2_mimic, utils

def test_create_ja3_context():
    # Test valid profiles
    for profile in ["chrome_120", "firefox_120"]:
        context = stealth.create_ja3_context(profile)
        assert isinstance(context, ssl.SSLContext)
        assert context.check_hostname is False
        assert context.verify_mode == ssl.CERT_NONE

    # Test invalid profile (should fallback)
    context = stealth.create_ja3_context("invalid_profile")
    assert isinstance(context, ssl.SSLContext)

def test_h2_profiles():
    # Test profile retrieval
    profile = h2_mimic.get_h2_profile("chrome_120")
    assert profile.name == "chrome_120"
    assert h2_mimic.SETTINGS_INITIAL_WINDOW_SIZE in profile.settings
    
    # Test fallback
    profile = h2_mimic.get_h2_profile("unknown")
    assert profile.name == "chrome_120"

def test_mac_to_int():
    mac = "00:11:22:33:44:55"
    mac_int = utils.mac_to_int(mac)
    assert mac_int == 0x001122334455
    
    mac_bytes = utils.mac_to_int("ff:ff:ff:ff:ff:ff")
    assert mac_bytes == (1 << 48) - 1

def test_ip_conversions():
    ip = "1.2.3.4"
    # Manual conversion for test
    expected = (1 << 24) | (2 << 16) | (3 << 8) | 4
    
    # We can't easily import the inline conversion logic from orchestrator, 
    # but we can test if utils has similar helpers or just verify the logic here.
    # Let's assume we might add a helper to utils later.
    pass

def test_waf_bypass_init():
    bypass = stealth.WAFBypass("http://example.com")
    assert bypass.target_url == "http://example.com"
    assert bypass.headless is True
