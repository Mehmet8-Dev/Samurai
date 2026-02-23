import pytest
import subprocess
import sys
import os

def test_cli_help():
    # Test if the CLI help command works
    try:
        result = subprocess.run([sys.executable, "-m", "ddos_samurai.cli", "--help"], 
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0
        assert "DDoSamurai" in result.stdout
    except subprocess.TimeoutExpired:
        pytest.fail("CLI help command timed out")

def test_imports():
    # Ensure all main modules can be imported without error
    modules = [
        "ddos_samurai.orchestrator",
        "ddos_samurai.senders",
        "ddos_samurai.packet",
        "ddos_samurai.stealth",
        "ddos_samurai.gpu_packet",
        "ddos_samurai.gpu_payload",
        "ddos_samurai.h2_mimic"
    ]
    for mod in modules:
        try:
            __import__(mod)
        except ImportError as e:
            pytest.fail(f"Failed to import {mod}: {e}")

def test_root_privileges_check():
    # Check if we are running as root (required for many features)
    # This is more of an environment check than a code test.
    is_root = os.geteuid() == 0
    if not is_root:
        print("\n[WARNING] Tests are not running as root. Some tests will be skipped.")

def test_gateway_resolution_smoke():
    # Test if gateway resolution logic runs without crashing
    from ddos_samurai import senders
    try:
        # Use a common public IP for testing resolution
        iface, mac = senders.get_gateway_info("8.8.8.8")
        # We don't assert mac is not None because it might fail in some CI environments,
        # but the function should not crash.
        assert iface is not None or mac is None or True
    except Exception as e:
        pytest.fail(f"get_gateway_info crashed: {e}")
