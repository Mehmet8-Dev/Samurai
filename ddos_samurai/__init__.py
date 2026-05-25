"""
Samurai: High-Performance Network Stress Testing Tool

Features:
    - GPU-accelerated packet generation (CUDA)
    - AF_XDP high-performance packet transmission (Linux)
    - Multiple attack vectors (TCP, UDP, HTTP/2, Amplification)
    - Stealth and evasion capabilities
    - Real-time metrics and monitoring
"""
__version__ = "2.2.0"
__codename__ = "Shogun"
__author__ = "Mehmet Okur"

# Feature availability flags
GPU_AVAILABLE = False
FAST_SENDER_AVAILABLE = False
XDP_AVAILABLE = False  # computed lazily to avoid import-time side effects/noise

# Check GPU (CuPy) availability
try:
    import cupy
    GPU_AVAILABLE = True
except ImportError:
    pass

# NOTE(M6): avoid importing fast_sender at module import time to keep
# control-plane process free from dataplane C-extension side effects.

def get_capabilities():
    """Get a dictionary of available capabilities."""
    # Probe XDP lazily; do not spam logs if it's not built/available.
    xdp_available = False
    try:
        from .af_xdp_sender import check_xdp_available
        xdp_available, _ = check_xdp_available(quiet=True)
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, ImportError, KeyError, IndexError):
        xdp_available = False
    return {
        "version": __version__,
        "codename": __codename__,
        "gpu_acceleration": GPU_AVAILABLE,
        "af_xdp": xdp_available,
        "fast_sender": FAST_SENDER_AVAILABLE,
    }
