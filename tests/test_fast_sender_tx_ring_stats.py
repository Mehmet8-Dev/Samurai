import importlib

import pytest


pytestmark = [pytest.mark.privileged]


def test_tx_ring_python_bridge_removed():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("ddos_samurai.fast_sender")
