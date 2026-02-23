"""Backward-compatible alias for workload profiles.

Use `ddos_samurai.workload_profiles` for new imports.
"""

import warnings

from .workload_profiles import TEST_PROFILES, print_profiles

warnings.warn(
    "ddos_samurai.profiles is deprecated; use ddos_samurai.workload_profiles instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["TEST_PROFILES", "print_profiles"]
