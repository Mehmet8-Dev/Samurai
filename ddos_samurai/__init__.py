"""
DDoSamurai: High-Performance Network Stress Testing Tool

Features:
    - GPU-accelerated packet generation (CUDA)
    - AF_XDP high-performance packet transmission (Linux)
    - Multiple attack vectors (TCP, UDP, HTTP/2, Amplification)
    - Stealth and evasion capabilities
    - Real-time metrics and monitoring
"""
try:
    from scapy.all import conf

    # Use AF_Packet sockets for sending packets. This can be more stable
    # in some environments, especially with multiprocessing, compared to
    # the default libpcap.
    conf.use_pcap = False
    try:
        conf.L3socket = conf.L3socket or conf.L3altsocket
        conf.L2socket = conf.L2socket or conf.L2altsocket
    except Exception:
        pass
except Exception:
    # Scapy may fail to initialize in restricted/sandboxed environments.
    conf = None

__version__ = "2.0.0"
__author__ = "DDoSamurai Team"

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

# Check fast_sender availability
try:
    from . import fast_sender
    FAST_SENDER_AVAILABLE = True
except Exception:
    pass

def get_capabilities():
    """Get a dictionary of available capabilities."""
    # Probe XDP lazily; do not spam logs if it's not built/available.
    xdp_available = False
    try:
        from .af_xdp_sender import check_xdp_available
        xdp_available, _ = check_xdp_available(quiet=True)
    except Exception:
        xdp_available = False
    return {
        "version": __version__,
        "gpu_acceleration": GPU_AVAILABLE,
        "af_xdp": xdp_available,
        "fast_sender": FAST_SENDER_AVAILABLE,
    }
