import pytest
import os
import json
import subprocess

def test_l2l3_astf_native_verification():
    """Verify native test_l2l3_astf executable containing L2/L3 stack and QUIC loss recovery tests."""
    bin_path = os.path.join("build", "l7_emu_native", "test_l2l3_astf")
    assert os.path.exists(bin_path), f"Binary {bin_path} missing"
    res = subprocess.run([bin_path], capture_output=True, text=True)
    assert res.returncode == 0, f"Native test failed: {res.stderr}\n{res.stdout}"
    assert "ALL VERIFICATION TESTS PASSED SUCCESSFULLY!" in res.stdout

def test_control_selftest():
    """Verify native control selftest."""
    ctrl_bin = os.path.join("build", "control", "samurai_control_selftest")

    assert os.path.exists(ctrl_bin), f"Binary {ctrl_bin} missing"

    res_ctrl = subprocess.run([ctrl_bin], capture_output=True, text=True)
    assert res_ctrl.returncode == 0, f"Control selftest failed: {res_ctrl.stderr}\n{res_ctrl.stdout}"
    assert "control selftest: all checks passed" in res_ctrl.stdout

def test_samurai_cli_build_and_help():
    """Verify samurai CLI native frontend binary."""
    cli_bin = os.path.join("build", "cli", "samurai")
    assert os.path.exists(cli_bin), f"Binary {cli_bin} missing"
    res = subprocess.run([cli_bin, "--help"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "samurai" in res.stdout.lower() or "usage" in res.stdout.lower()
