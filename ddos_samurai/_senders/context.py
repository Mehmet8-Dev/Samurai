from typing import Any, Dict


def close_sender_context(sender_context: Dict[str, Any] | None) -> None:
    """Best-effort cleanup for reusable sender resources."""
    if not isinstance(sender_context, dict):
        return
    dp_session = sender_context.pop("dataplane_session", None)
    if dp_session is not None and hasattr(dp_session, "close"):
        try:
            dp_session.close()
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            pass
    raw_sock = sender_context.pop("raw_socket", None)
    if raw_sock is not None:
        try:
            raw_sock.close()
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            pass
    xdp_sender = sender_context.pop("xdp_sender_instance", None)
    sender_context.pop("xdp_sender_cfg", None)
    if xdp_sender is not None and hasattr(xdp_sender, "stop"):
        try:
            xdp_sender.stop()
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
            pass
