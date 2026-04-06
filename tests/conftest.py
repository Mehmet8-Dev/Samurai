import os

import pytest

os.environ.setdefault("SAMURAI_GPU_PACKET_CUDA_CPP_NATIVE", "1")


def _test_profile() -> str:
    raw = str(os.environ.get("SAMURAI_TEST_PROFILE", "ci_safe") or "ci_safe").strip().lower()
    if raw not in {"ci_safe", "full"}:
        return "ci_safe"
    return raw


def pytest_collection_modifyitems(config, items):
    profile = _test_profile()
    if profile == "full":
        return

    # Default CI-safe profile: skip privileged/gpu suites.
    skip_priv = pytest.mark.skip(reason="SAMURAI_TEST_PROFILE=ci_safe: skipping privileged test")
    skip_gpu = pytest.mark.skip(reason="SAMURAI_TEST_PROFILE=ci_safe: skipping gpu test")

    for item in items:
        if "privileged" in item.keywords:
            item.add_marker(skip_priv)
            continue
        if "gpu" in item.keywords:
            item.add_marker(skip_gpu)
