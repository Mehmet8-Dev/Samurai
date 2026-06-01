import importlib

import pytest


def test_fast_sender_python_extension_removed():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("ddos_samurai.fast_sender")
