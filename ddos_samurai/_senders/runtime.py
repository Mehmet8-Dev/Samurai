import os


_SENDER_BACKEND_CHOICES = {"xdp", "dpdk"}
_SENDER_FALLBACK_POLICY_CHOICES = {"fail"}


def resolve_sender_backend(value) -> str:
    raw = str(value if value is not None else os.environ.get("SAMURAI_SENDER_BACKEND", "xdp") or "xdp")
    backend = raw.strip().lower()
    if backend not in _SENDER_BACKEND_CHOICES:
        backend = "xdp"
    return backend


def resolve_sender_fallback_policy(value) -> str:
    raw = str(
        value if value is not None else os.environ.get("SAMURAI_SENDER_FALLBACK_POLICY", "fail") or "fail"
    )
    policy = raw.strip().lower()
    if policy not in _SENDER_FALLBACK_POLICY_CHOICES:
        policy = "fail"
    return policy


def load_httpx():
    try:
        import httpx
        return True, httpx
    except ImportError:
        return False, None


def load_websockets():
    try:
        import websockets
        return True, websockets
    except ImportError:
        return False, None


def has_l7_native_quic(*, package: str = "ddos_samurai") -> bool:
    try:
        import importlib

        mod = importlib.import_module("._l7_emu_native", package=package)
        if mod is None or not hasattr(mod, "run_profile"):
            return False
        caps_fn = getattr(mod, "runtime_capabilities", None)
        if not callable(caps_fn):
            return False
        caps = dict(caps_fn() or {})
        return bool(caps.get("quic_native", False))
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return False


def load_h2_transport(*, package: str = "ddos_samurai"):
    _ = package
    return False, None


def load_fast_sender(*, package: str = "ddos_samurai"):
    try:
        import importlib

        mod = importlib.import_module(".fast_sender", package=package)
        return True, mod
    except ImportError:
        return False, None


def load_pacing_engine(*, package: str = "ddos_samurai"):
    try:
        import importlib

        mod = importlib.import_module(".pacing", package=package)
        return {
            "PACING_ENGINE_AVAILABLE": bool(getattr(mod, "PACING_ENGINE_AVAILABLE", False)),
            "PacingConfig": getattr(mod, "PacingConfig", None),
            "PacingMode": getattr(mod, "PacingMode", None),
            "JitterModel": getattr(mod, "JitterModel", None),
            "paced_send": getattr(mod, "paced_send", None),
            "paced_send_l2": getattr(mod, "paced_send_l2", None),
            "paced_send_xdp": getattr(mod, "paced_send_xdp", None),
            "get_stats": getattr(mod, "get_stats", None),
            "reset_stats": getattr(mod, "reset_stats", None),
            "format_stats": getattr(mod, "format_stats", None),
            "cleanup_l2": getattr(mod, "cleanup_l2", None),
        }
    except ImportError:
        return {
            "PACING_ENGINE_AVAILABLE": False,
            "PacingConfig": None,
            "PacingMode": None,
            "JitterModel": None,
            "paced_send": None,
            "paced_send_l2": None,
            "paced_send_xdp": None,
            "get_stats": None,
            "reset_stats": None,
            "format_stats": None,
            "cleanup_l2": None,
        }


def load_xdp_sender(*, package: str = "ddos_samurai"):
    try:
        import importlib

        mod = importlib.import_module(".af_xdp_sender", package=package)
        return {
            "XDP_AVAILABLE": True,
            "XDPSender": getattr(mod, "XDPSender", None),
            "XDPIntegration": getattr(mod, "XDPIntegration", None),
            "check_xdp_available": getattr(mod, "check_xdp_available", None),
        }
    except ImportError:
        return {
            "XDP_AVAILABLE": False,
            "XDPSender": None,
            "XDPIntegration": None,
            "check_xdp_available": lambda: (False, "AF_XDP module not available"),
        }
