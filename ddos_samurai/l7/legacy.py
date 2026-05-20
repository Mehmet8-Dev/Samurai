from __future__ import annotations


def should_return_c_result(c_result, *, allow_python_fallback: bool) -> bool:
    _ = allow_python_fallback
    if c_result is None:
        return False
    if int(getattr(c_result, "sent", 0) or 0) > 0:
        return True
    if not bool(getattr(c_result, "allow_legacy_fallback", False)):
        return True
    return True
