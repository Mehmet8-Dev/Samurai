"""Shared profile-name registry to keep TLS/H2 choices aligned."""

PROFILE_NONE = "none"
DEFAULT_BROWSER_PROFILE = "chrome_120"

BROWSER_PROFILE_NAMES = (
    "chrome_120",
    "firefox_120",
    "safari_17",
)

TLS_PROFILE_CHOICES = (PROFILE_NONE, *BROWSER_PROFILE_NAMES)
H2_PROFILE_CHOICES = (PROFILE_NONE, *BROWSER_PROFILE_NAMES)
