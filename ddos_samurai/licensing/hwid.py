"""Hardware fingerprint generation for license binding.

Cihaz parmak izi: CPU bilgisi + birincil MAC adresi + hostname
birleşiminden SHA-256 hash üretir.  Aynı fiziksel makine her
çalıştırmada aynı HWID'yi döndürür.
"""

from __future__ import annotations

import hashlib
import platform
import uuid


def _get_cpu_id() -> str:
    """CPU tanımlayıcı bilgisini topla (best-effort)."""
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        pass
    return platform.processor() or platform.machine() or "unknown-cpu"


def _get_primary_mac() -> str:
    """Birincil ağ arayüzünün MAC adresini döndür."""
    try:
        mac_int = uuid.getnode()
        # uuid.getnode() bazen rastgele bir değer döner (bit 0 set);
        # bunu tespit ederek stabil bir fallback sağlıyoruz.
        if (mac_int >> 40) & 1:
            return "fallback-mac"
        return ":".join(
            f"{(mac_int >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6))
        )
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        return "fallback-mac"


def get_hardware_id() -> str:
    """Benzersiz donanım parmak izi üret.

    Returns:
        64 karakter hex string (SHA-256 hash).
    """
    cpu = _get_cpu_id()
    mac = _get_primary_mac()
    hostname = platform.node() or "unknown-host"
    system = platform.system() or "unknown-os"

    fingerprint = f"{cpu}|{mac}|{hostname}|{system}"
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
