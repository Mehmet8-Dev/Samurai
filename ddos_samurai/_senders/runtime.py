import os


_SENDER_BACKEND_CHOICES = {"auto", "txring", "c_ext_l3", "python", "xdp"}
_SENDER_FALLBACK_POLICY_CHOICES = {"allow", "fail"}


def resolve_sender_backend(value) -> str:
    raw = str(value if value is not None else os.environ.get("SAMURAI_SENDER_BACKEND", "auto") or "auto")
    backend = raw.strip().lower()
    if backend not in _SENDER_BACKEND_CHOICES:
        backend = "auto"
    return backend


def resolve_sender_fallback_policy(value) -> str:
    raw = str(
        value if value is not None else os.environ.get("SAMURAI_SENDER_FALLBACK_POLICY", "allow") or "allow"
    )
    policy = raw.strip().lower()
    if policy not in _SENDER_FALLBACK_POLICY_CHOICES:
        policy = "allow"
    return policy


def scapy_getter(*, require_scapy_fn):
    return require_scapy_fn()


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


def load_aioquic():
    try:
        from aioquic.asyncio.client import connect
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.quic.events import StreamDataReceived
        return {
            "AIOQUIC_AVAILABLE": True,
            "connect": connect,
            "QuicConfiguration": QuicConfiguration,
            "H3_ALPN": H3_ALPN,
            "H3Connection": H3Connection,
            "StreamDataReceived": StreamDataReceived,
        }
    except ImportError:
        return {
            "AIOQUIC_AVAILABLE": False,
            "connect": None,
            "QuicConfiguration": None,
            "H3_ALPN": None,
            "H3Connection": None,
            "StreamDataReceived": None,
        }


def load_h2_transport(*, package: str = "ddos_samurai"):
    try:
        import importlib

        h2_transport = importlib.import_module(".h2_transport", package=package)
        return bool(getattr(h2_transport, "HYPER_H2_AVAILABLE", False)), h2_transport
    except Exception:
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
