"""License system constants and configuration."""

from __future__ import annotations

import os

# ── License Server ──────────────────────────────────────────────────────────
LICENSE_SERVER_URL: str = os.getenv(
    "SAMURAI_LICENSE_SERVER_URL",
    "https://license.ddosamurai.com",
)

API_VERSION: str = "v1"
VALIDATE_ENDPOINT: str = f"/api/{API_VERSION}/license/validate"
HEARTBEAT_ENDPOINT: str = f"/api/{API_VERSION}/license/heartbeat"
DEACTIVATE_ENDPOINT: str = f"/api/{API_VERSION}/license/deactivate"
EXEC_GRANT_ENDPOINT: str = f"/api/{API_VERSION}/license/exec-grant"

# ── Timeouts ────────────────────────────────────────────────────────────────
REQUEST_TIMEOUT_S: int = int(os.getenv("SAMURAI_LICENSE_TIMEOUT_S", "10"))
HEARTBEAT_INTERVAL_S: int = int(os.getenv("SAMURAI_LICENSE_HEARTBEAT_S", "3600"))

# ── Offline Grace Period ────────────────────────────────────────────────────
# Lisans doğrulandıktan sonra, sunucuya ulaşılamasa bile bu süre boyunca
# çalışmaya devam edebilir.
OFFLINE_GRACE_PERIOD_S: int = int(
    os.getenv("SAMURAI_LICENSE_GRACE_HOURS", "72")
) * 3600  # Varsayılan: 72 saat

# ── Cache ───────────────────────────────────────────────────────────────────
CACHE_DIR: str = os.path.join(os.path.expanduser("~"), ".samurai")
CACHE_FILE: str = os.path.join(CACHE_DIR, "license.cache")
LICENSE_KEY_FILE: str = os.path.join(CACHE_DIR, "license.key")

# ── License Key Format ──────────────────────────────────────────────────────
LICENSE_KEY_PREFIX: str = "SAM"
LICENSE_KEY_PATTERN: str = r"^SAM-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$"

# ── Dev Mode ────────────────────────────────────────────────────────────────
# Geliştirme sırasında lisans doğrulamasını atlamak için:
#   SAMURAI_LICENSE_DEV_MODE=1
def is_dev_mode() -> bool:
    """Resolve license dev mode at call-time (not import-time)."""
    return os.getenv("SAMURAI_LICENSE_DEV_MODE", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
