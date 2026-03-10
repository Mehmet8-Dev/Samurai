from typing import Any, Dict


def close_sender_context(sender_context: Dict[str, Any] | None) -> None:
    """Best-effort cleanup for reusable sender resources."""
    if not isinstance(sender_context, dict):
        return
    dp_session = sender_context.pop("dataplane_session", None)
    if dp_session is not None and hasattr(dp_session, "close"):
        try:
            dp_session.close()
        except Exception:
            pass
    raw_sock = sender_context.pop("raw_socket", None)
    if raw_sock is not None:
        try:
            raw_sock.close()
        except Exception:
            pass

