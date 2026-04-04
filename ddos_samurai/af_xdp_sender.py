"""
AF_XDP High-Performance Sender Module for Samurai (Ronin)
=====================================================

This module provides a high-level Python interface for the AF_XDP C extension,
enabling high-performance packet transmission on Linux systems.

Features:
    - Automatic interface detection and configuration
    - Batch packet transmission
    - Real-time statistics and monitoring
    - Integration with existing packet generation (gpu_packet, packet modules)
    - Fallback to standard senders if XDP is unavailable

Requirements:
    - Linux kernel >= 4.18 (recommended: 5.10+)
    - Root privileges
    - libbpf-dev, libelf-dev (for building)
    - Standard Ethernet NIC

Usage:
    from ddos_samurai.af_xdp_sender import XDPSender
    
    sender = XDPSender(interface="eth0")
    sender.start()
    
    # Send packets
    packets = [packet1_bytes, packet2_bytes, ...]
    sent = sender.send(packets)
    
    # Get stats
    stats = sender.get_stats()
    
    sender.stop()

Author: Samurai Team
"""

import os
import sys
import time
import socket
import struct
import logging
import subprocess
import threading
import queue
import shutil
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Callable, Any
from pathlib import Path

# Local imports
from . import utils

# Lazy import of C extension
_xdp_sender = None

def _load_xdp_extension(*, quiet: bool = False):
    """Lazily load the xdp_sender C extension."""
    global _xdp_sender
    
    if _xdp_sender is not None:
        return _xdp_sender
    
    try:
        from . import xdp_sender
        _xdp_sender = xdp_sender
        return xdp_sender
    except ImportError as e:
        if not quiet:
            utils.log_error(f"[XDP] C extension not loaded: {e}")
            utils.log_error("[XDP] Please build with: python setup.py build_ext --inplace")
        return None


# ============================================================================
# Constants
# ============================================================================

XDP_MODE_SKB = 0      # Copy Mode (Generic/SKB) - Most compatible
XDP_MODE_NATIVE = 1   # Native Mode (Driver) - Requires driver support
XDP_MODE_OFFLOAD = 2  # Offload Mode (Hardware) - Requires NIC support

DEFAULT_BATCH_SIZE = 64
DEFAULT_QUEUE_ID = 0


def _mode_name(mode: int) -> str:
    if int(mode) == XDP_MODE_SKB:
        return "SKB/Copy"
    if int(mode) == XDP_MODE_NATIVE:
        return "Native/Zero-Copy"
    if int(mode) == XDP_MODE_OFFLOAD:
        return "Offload(Requested)"
    return "Unknown"


def _normalize_mode2_policy(value: Optional[str]) -> str:
    policy = str(value or "soft").strip().lower()
    if policy not in {"soft", "hard"}:
        raise ValueError("mode2_policy must be 'soft' or 'hard'")
    return policy


def probe_xdp_mode2_capability(interface: str) -> Tuple[str, str]:
    """
    Probe XDP offload capability for interface.
    Returns: ("supported"|"unsupported"|"unknown", reason)
    """
    iface = str(interface or "").strip()
    if not iface:
        return "unknown", "interface is empty"

    if iface == "lo":
        return "unsupported", "loopback interface does not support XDP HW offload"

    ethtool_bin = shutil.which("ethtool")
    if ethtool_bin:
        try:
            out = subprocess.run(
                [ethtool_bin, "-i", iface],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if out.returncode == 0:
                text = (out.stdout or "").lower()
                driver = ""
                for line in text.splitlines():
                    if line.startswith("driver:"):
                        driver = line.split(":", 1)[1].strip()
                        break
                if driver in {"veth", "tun", "tap", "loopback"}:
                    return "unsupported", f"driver={driver} has no XDP HW offload"
        except Exception:
            pass

    ip_bin = shutil.which("ip")
    if ip_bin:
        try:
            out = subprocess.run(
                [ip_bin, "-details", "link", "show", "dev", iface],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if out.returncode == 0:
                text = ((out.stdout or "") + "\n" + (out.stderr or "")).lower()
                if "xdpoffload" in text:
                    return "supported", "interface reports xdpoffload"
        except Exception:
            pass

    return "unknown", "offload capability could not be proven from local probes"


def _env_truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class XDPStats:
    """Statistics for XDP sender."""
    tx_packets: int = 0
    tx_bytes: int = 0
    tx_errors: int = 0
    tx_wakeups: int = 0
    tx_desc_reserve_failures: int = 0
    tx_frame_alloc_failures: int = 0
    tx_partial_batches: int = 0
    tx_retry_loops: int = 0
    tx_completion_events: int = 0
    tx_completed_desc: int = 0
    tx_invalid_packets: int = 0
    tx_backpressure_events: int = 0
    tx_send_calls: int = 0
    tx_send_ns_total: int = 0
    tx_send_ns_max: int = 0
    tx_send_avg_us: float = 0.0
    tx_send_max_us: float = 0.0
    queue_id: int = 0
    elapsed_seconds: float = 0.0
    packets_per_second: float = 0.0
    mbps: float = 0.0
    mode: int = 0
    mode_name: str = "Unknown"
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'XDPStats':
        """Create XDPStats from dictionary."""
        return cls(
            tx_packets=data.get('tx_packets', 0),
            tx_bytes=data.get('tx_bytes', 0),
            tx_errors=data.get('tx_errors', 0),
            tx_wakeups=data.get('tx_wakeups', 0),
            tx_desc_reserve_failures=data.get('tx_desc_reserve_failures', 0),
            tx_frame_alloc_failures=data.get('tx_frame_alloc_failures', 0),
            tx_partial_batches=data.get('tx_partial_batches', 0),
            tx_retry_loops=data.get('tx_retry_loops', 0),
            tx_completion_events=data.get('tx_completion_events', 0),
            tx_completed_desc=data.get('tx_completed_desc', 0),
            tx_invalid_packets=data.get('tx_invalid_packets', 0),
            tx_backpressure_events=data.get('tx_backpressure_events', 0),
            tx_send_calls=data.get('tx_send_calls', 0),
            tx_send_ns_total=data.get('tx_send_ns_total', 0),
            tx_send_ns_max=data.get('tx_send_ns_max', 0),
            tx_send_avg_us=data.get('tx_send_avg_us', 0.0),
            tx_send_max_us=data.get('tx_send_max_us', 0.0),
            queue_id=data.get('queue_id', 0),
            elapsed_seconds=data.get('elapsed_seconds', 0.0),
            packets_per_second=data.get('packets_per_second', 0.0),
            mbps=data.get('mbps', 0.0),
            mode=data.get('mode', 0),
            mode_name=data.get('mode_name', 'Unknown')
        )
    
    def __str__(self) -> str:
        return (f"XDP Stats: {self.tx_packets:,} packets, "
                f"{self.tx_bytes:,} bytes, "
                f"{self.packets_per_second:,.0f} pps, "
                f"{self.mbps:.2f} Mbps, "
                f"reserve_fail={self.tx_desc_reserve_failures:,}, "
                f"alloc_fail={self.tx_frame_alloc_failures:,}, "
                f"backpressure={self.tx_backpressure_events:,}, "
                f"avg_send={self.tx_send_avg_us:.2f}us "
                f"[{self.mode_name}]")


@dataclass
class XDPSystemInfo:
    """System XDP capabilities."""
    af_xdp_available: bool = False
    is_root: bool = False
    kernel_release: str = ""
    num_frames: int = 0
    frame_size: int = 0
    batch_size: int = 0
    headroom: int = 0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'XDPSystemInfo':
        """Create from dictionary."""
        return cls(
            af_xdp_available=bool(data.get('af_xdp_available', False)),
            is_root=bool(data.get('is_root', False)),
            kernel_release=data.get('kernel_release', ''),
            num_frames=data.get('num_frames', 0),
            frame_size=data.get('frame_size', 0),
            batch_size=data.get('batch_size', 0),
            headroom=data.get('headroom', 0)
        )
    
    def __str__(self) -> str:
        status = "✅" if self.af_xdp_available else "❌"
        root_status = "✅" if self.is_root else "❌"
        return (f"AF_XDP: {status} | Root: {root_status} | "
                f"Kernel: {self.kernel_release} | "
                f"Frames: {self.num_frames} × {self.frame_size} bytes")


# ============================================================================
# Helper Functions
# ============================================================================

def get_default_interface() -> Optional[str]:
    """Get the default network interface for packet transmission."""
    try:
        # Method 1: Use ip route to find default interface
        result = subprocess.run(
            ['ip', 'route', 'get', '8.8.8.8'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Parse: "8.8.8.8 via X.X.X.X dev eth0 src X.X.X.X"
            parts = result.stdout.split()
            for i, part in enumerate(parts):
                if part == 'dev' and i + 1 < len(parts):
                    return parts[i + 1]
    except Exception:
        pass
    
    try:
        # Method 2: Use scapy's get_working_if
        from scapy.all import get_working_if
        iface = get_working_if()
        if iface:
            return iface
    except Exception:
        pass
    
    try:
        # Method 3: Find first non-loopback interface
        import os
        interfaces = os.listdir('/sys/class/net/')
        for iface in interfaces:
            if iface != 'lo' and iface.startswith(('eth', 'en', 'wl')):
                return iface
    except Exception:
        pass
    
    return None


def get_interface_mac(interface: str) -> Optional[bytes]:
    """Get MAC address of interface as bytes."""
    try:
        with open(f'/sys/class/net/{interface}/address', 'r') as f:
            mac_str = f.read().strip()
            return bytes.fromhex(mac_str.replace(':', ''))
    except Exception:
        return None


def get_interface_queue_count(interface: str) -> int:
    """Get the number of TX queues for an interface."""
    try:
        path = Path(f'/sys/class/net/{interface}/queues')
        if path.exists():
            queues = [d for d in path.iterdir() if d.name.startswith('tx-')]
            return len(queues)
    except Exception:
        pass
    return 1


def check_xdp_available(*, quiet: bool = False) -> Tuple[bool, str]:
    """
    Check if AF_XDP is available on the system.
    
    Returns:
        Tuple of (available, message)
    """
    xdp = _load_xdp_extension(quiet=quiet)
    
    if xdp is None:
        return False, "XDP C extension not available (not built)"
    
    try:
        if xdp.xdp_available():
            return True, "AF_XDP is available"
        else:
            return False, "AF_XDP socket creation failed (kernel support missing?)"
    except Exception as e:
        return False, f"Error checking XDP availability: {e}"


def get_xdp_system_info() -> Optional[XDPSystemInfo]:
    """Get system XDP capabilities."""
    xdp = _load_xdp_extension()
    
    if xdp is None:
        return None
    
    try:
        info_dict = xdp.xdp_info()
        return XDPSystemInfo.from_dict(info_dict)
    except Exception as e:
        utils.log_error(f"[XDP] Error getting system info: {e}")
        return None


# ============================================================================
# Main XDP Sender Class
# ============================================================================

class XDPSender:
    """
    High-level AF_XDP packet sender for Samurai.
    
    This class provides an easy-to-use interface for sending packets
    using Linux AF_XDP sockets with Copy Mode (SKB/Generic) for
    maximum compatibility.
    
    Example:
        sender = XDPSender(interface="eth0")
        sender.start()
        
        # Send raw IP packets
        packets = [packet_bytes1, packet_bytes2, ...]
        sent = sender.send(packets)
        
        # Get statistics
        stats = sender.get_stats()
        print(f"Sent {stats.tx_packets} packets at {stats.packets_per_second:.0f} pps")
        
        sender.stop()
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        queue_id: int = DEFAULT_QUEUE_ID,
        mode: int = XDP_MODE_SKB,
        batch_size: int = DEFAULT_BATCH_SIZE,
        auto_fallback: bool = True,
        mode2_policy: str = "soft",
        attach_bpf: Optional[bool] = None,
        bpf_section: Optional[str] = None,
        bpf_obj_path: Optional[str] = None,
        use_multi_ctx: Optional[bool] = None,
    ):
        """
        Initialize XDP sender.
        
        Args:
            interface: Network interface to use (auto-detected if None)
            queue_id: Queue ID to use (default: 0)
            mode: XDP mode (0=SKB/Copy, 1=Native/Zero-Copy, 2=Offload request)
            batch_size: Batch size for packet transmission
            auto_fallback: Fall back to raw sockets if XDP unavailable
            mode2_policy: mode=2 için davranış:
                "soft" => unsupported ise mode=1'e düş
                "hard" => unsupported/unknown ise hata ver
            attach_bpf: Auto attach XDP BPF program on start
            bpf_section: BPF section name to attach
            bpf_obj_path: Path to xdp_prog.o object file
            use_multi_ctx: Force enable/disable multi-context API usage.
                None => controlled by SAMURAI_XDP_MULTI_CTX env.
        """
        self.interface = interface or get_default_interface()
        self.queue_id = queue_id
        self.mode = mode
        self.batch_size = batch_size
        self.auto_fallback = auto_fallback
        self.mode2_policy = _normalize_mode2_policy(mode2_policy)
        self.attach_bpf = _env_truthy("SAMURAI_XDP_ATTACH_BPF", True) if attach_bpf is None else bool(attach_bpf)
        self.bpf_section = str(
            bpf_section or os.environ.get("SAMURAI_XDP_BPF_SECTION", "xdp_sock")
        ).strip() or "xdp_sock"
        self.bpf_obj_path = str(
            bpf_obj_path or os.environ.get("SAMURAI_XDP_BPF_OBJ", str(Path(__file__).with_name("xdp_prog.o")))
        ).strip()
        
        self._xdp = None
        self._is_running = False
        self._use_fallback = False
        self._ctx_handle: Optional[int] = None
        if use_multi_ctx is None:
            self._use_multi_ctx = _env_truthy("SAMURAI_XDP_MULTI_CTX", True)
        else:
            self._use_multi_ctx = bool(use_multi_ctx)
        self._effective_mode = int(mode)
        self._mode2_probe_status = "not_run"
        self._mode2_probe_reason = ""
        self._bpf_attached = False
        self._xskmap_pin_path = ""
        self._bpffs_root = ""
        self._lock = threading.Lock()
        
        # Statistics tracking
        self._start_time = None
        self._total_packets = 0
        self._total_bytes = 0
        
        # Validate interface
        if not self.interface:
            raise ValueError("No network interface found or specified")
        
        if not os.path.exists(f'/sys/class/net/{self.interface}'):
            raise ValueError(f"Interface '{self.interface}' does not exist")

    def _cleanup_stale_bpffs_roots(self) -> None:
        """
        Remove stale bpffs pin directories for the same interface/queue.
        Only directories with dead PID suffix are removed.
        """
        base_dir = Path("/sys/fs/bpf")
        if not base_dir.exists():
            return
        prefix = f"samurai_{self.interface}_q{self.queue_id}_"
        try:
            for entry in base_dir.iterdir():
                name = entry.name
                if not entry.is_dir() or not name.startswith(prefix):
                    continue
                pid_str = name[len(prefix):]
                if not pid_str.isdigit():
                    continue
                pid = int(pid_str)
                if pid <= 0:
                    continue
                if os.path.exists(f"/proc/{pid}"):
                    # Live process owns this pin root; do not touch.
                    continue
                shutil.rmtree(entry, ignore_errors=True)
        except Exception as e:
            utils.log_warning(f"[XDP] stale bpffs cleanup skipped: {e}")

    def _attach_bpf_program(self) -> Tuple[bool, str]:
        if not self.attach_bpf:
            return True, "BPF attach disabled"
        if not self.bpf_obj_path:
            return False, "BPF object path is empty"
        if not os.path.exists(self.bpf_obj_path):
            src_path = str(Path(__file__).with_name("xdp_prog.c"))
            if os.path.exists(src_path):
                try:
                    compile_result = subprocess.run(
                        ["clang", "-O2", "-target", "bpf", "-c", src_path, "-o", self.bpf_obj_path],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=False,
                    )
                    if compile_result.returncode != 0:
                        details = (compile_result.stderr or compile_result.stdout or "").strip()
                        return False, f"BPF object compile failed: {details or f'exit={compile_result.returncode}'}"
                    utils.log_info(f"[XDP] Compiled BPF object: {self.bpf_obj_path}")
                except FileNotFoundError:
                    return False, "BPF object missing and `clang` not found"
                except Exception as e:
                    return False, f"BPF object compile exception: {e}"
            else:
                return False, f"BPF object not found: {self.bpf_obj_path}"
        bpftool_path = shutil.which("bpftool")
        if bpftool_path:
            bpffs_root = None
            try:
                self._cleanup_stale_bpffs_roots()
                bpffs_root = Path(f"/sys/fs/bpf/samurai_{self.interface}_q{self.queue_id}_{os.getpid()}")
                prog_pin = bpffs_root / "progs"
                maps_pin = bpffs_root / "maps"
                prog_pin.mkdir(parents=True, exist_ok=True)
                maps_pin.mkdir(parents=True, exist_ok=True)
                load_result = subprocess.run(
                    [
                        bpftool_path,
                        "prog",
                        "loadall",
                        self.bpf_obj_path,
                        str(prog_pin),
                        "type",
                        "xdp",
                        "pinmaps",
                        str(maps_pin),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if load_result.returncode == 0:
                    prog_path = prog_pin / self.bpf_section
                    if not prog_path.exists():
                        candidates = sorted(p for p in prog_pin.iterdir() if p.is_file())
                        if not candidates:
                            return False, "BPF load succeeded but no pinned program found"
                        prog_path = candidates[0]
                        utils.log_warning(
                            f"[XDP] Requested section '{self.bpf_section}' not pinned; using '{prog_path.name}'."
                        )
                    attach_result = subprocess.run(
                        [
                            bpftool_path,
                            "net",
                            "attach",
                            "xdp",
                            "pinned",
                            str(prog_path),
                            "dev",
                            self.interface,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    if attach_result.returncode == 0:
                        xsks_map_pin = maps_pin / "xsks_map"
                        if xsks_map_pin.exists():
                            self._xskmap_pin_path = str(xsks_map_pin)
                            os.environ["SAMURAI_XDP_XSKMAP_PIN"] = self._xskmap_pin_path
                            utils.log_info(f"[XDP] XSKMAP pinned at: {self._xskmap_pin_path}")
                        self._bpffs_root = str(bpffs_root)
                        self._bpf_attached = True
                        return True, "BPF attached via bpftool"
                    details = (attach_result.stderr or attach_result.stdout or "").strip()
                    return False, f"BPF attach (bpftool) failed: {details or f'exit={attach_result.returncode}'}"
                details = (load_result.stderr or load_result.stdout or "").strip()
                return False, f"BPF load (bpftool) failed: {details or f'exit={load_result.returncode}'}"
            except Exception as e:
                return False, f"BPF attach via bpftool exception: {e}"
            finally:
                if not self._bpf_attached and bpffs_root is not None:
                    try:
                        shutil.rmtree(bpffs_root, ignore_errors=True)
                    except Exception:
                        pass
        try:
            result = subprocess.run(
                [
                    "ip", "link", "set", "dev", self.interface,
                    "xdp", "obj", self.bpf_obj_path, "sec", self.bpf_section,
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except FileNotFoundError:
            return False, "`ip` command not found (iproute2 missing)"
        except Exception as e:
            return False, f"BPF attach command failed: {e}"
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            details = stderr or stdout or f"exit={result.returncode}"
            return False, f"BPF attach failed: {details}"
        self._bpf_attached = True
        return True, "BPF attached"

    def _detach_bpf_program(self) -> None:
        if not self._bpf_attached:
            return
        try:
            bpftool_path = shutil.which("bpftool")
            if bpftool_path:
                result = subprocess.run(
                    [bpftool_path, "net", "detach", "xdp", "dev", self.interface],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            else:
                result = subprocess.run(
                    ["ip", "link", "set", "dev", self.interface, "xdp", "off"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
            if result.returncode != 0:
                details = (result.stderr or result.stdout or "").strip() or f"exit={result.returncode}"
                utils.log_warning(f"[XDP] BPF detach failed on {self.interface}: {details}")
        except Exception as e:
            utils.log_warning(f"[XDP] BPF detach exception on {self.interface}: {e}")
        finally:
            if self._xskmap_pin_path and os.environ.get("SAMURAI_XDP_XSKMAP_PIN", "") == self._xskmap_pin_path:
                os.environ.pop("SAMURAI_XDP_XSKMAP_PIN", None)
            self._xskmap_pin_path = ""
            if self._bpffs_root:
                try:
                    shutil.rmtree(self._bpffs_root, ignore_errors=True)
                except Exception:
                    pass
            self._bpffs_root = ""
            self._bpf_attached = False
    
    def _check_requirements(self) -> Tuple[bool, str]:
        """Check if all requirements are met for XDP."""
        # Check root
        if os.geteuid() != 0:
            return False, "Root privileges required (run with sudo)"
        
        # Check kernel version
        try:
            import platform
            kernel = platform.release()
            major, minor = map(int, kernel.split('.')[:2])
            if major < 4 or (major == 4 and minor < 18):
                return False, f"Kernel {kernel} too old (need >= 4.18)"
        except Exception:
            pass
        
        # Check C extension
        xdp = _load_xdp_extension()
        if xdp is None:
            return False, "XDP C extension not built"
        
        # Check AF_XDP availability
        available, msg = check_xdp_available()
        if not available:
            return False, msg
        
        return True, "All requirements met"

    def _probe_mode2_capability(self) -> Tuple[str, str]:
        """
        Probe offload capability for mode=2.
        Returns: ("supported"|"unsupported"|"unknown", reason)
        """
        if self.mode != XDP_MODE_OFFLOAD:
            return "not_applicable", "mode!=2"
        return probe_xdp_mode2_capability(self.interface)
    
    def start(self) -> bool:
        """
        Start the XDP sender.
        
        Returns:
            True if successfully started with XDP, False if using fallback
        """
        with self._lock:
            if self._is_running:
                utils.log_info("[XDP] Already running")
                return not self._use_fallback
            
            # Check requirements
            ok, msg = self._check_requirements()
            
            if not ok:
                utils.log_error(f"[XDP] Requirements not met: {msg}")
                
                if self.auto_fallback:
                    utils.log_info("[XDP] Falling back to standard sender")
                    self._use_fallback = True
                    self._is_running = True
                    self._start_time = time.time()
                    return False
                else:
                    raise RuntimeError(f"XDP requirements not met: {msg}")
            
            # Load and initialize XDP
            self._xdp = _load_xdp_extension()
            self._effective_mode = int(self.mode)
            
            try:
                if self.mode == XDP_MODE_OFFLOAD:
                    probe_status, probe_reason = self._probe_mode2_capability()
                    self._mode2_probe_status = probe_status
                    self._mode2_probe_reason = probe_reason

                    if self.mode2_policy == "hard" and probe_status != "supported":
                        raise RuntimeError(
                            f"mode=2 hard policy violated: {probe_status} ({probe_reason})"
                        )

                    if self.mode2_policy == "soft" and probe_status in {"unsupported", "unknown"}:
                        self._effective_mode = XDP_MODE_NATIVE
                        utils.log_warning(
                            f"[XDP] mode=2 probe {probe_status} ({probe_reason}); soft fallback -> mode=1"
                        )

                if self.attach_bpf:
                    attached, attach_msg = self._attach_bpf_program()
                    if attached:
                        utils.log_info(
                            f"[XDP] BPF program attached: iface={self.interface}, "
                            f"section={self.bpf_section}, obj={self.bpf_obj_path}"
                        )
                    else:
                        raise RuntimeError(attach_msg)

                use_ctx_api = (
                    self._use_multi_ctx
                    and "xdp_create" in dir(self._xdp)
                    and "xdp_destroy" in dir(self._xdp)
                    and "xdp_send_ctx" in dir(self._xdp)
                )

                if use_ctx_api:
                    handle = int(self._xdp.xdp_create(self.interface, self.queue_id, self._effective_mode) or 0)
                    if handle <= 0:
                        raise RuntimeError("xdp_create returned invalid handle")
                    self._ctx_handle = handle
                    result = True
                    utils.log_info(f"[XDP] Multi-context handle allocated: {self._ctx_handle}")
                else:
                    result = self._xdp.xdp_init(self.interface, self.queue_id, self._effective_mode)
                
                if result:
                    utils.log_info(f"[XDP] Started on {self.interface} "
                                  f"(queue={self.queue_id}, mode={_mode_name(self._effective_mode)})")
                    self._is_running = True
                    self._start_time = time.time()
                    return True
                else:
                    raise RuntimeError("xdp_init returned False")
                    
            except Exception as e:
                utils.log_error(f"[XDP] Failed to initialize: {e}")
                self._detach_bpf_program()
                
                if self.auto_fallback:
                    utils.log_info("[XDP] Falling back to standard sender")
                    self._use_fallback = True
                    self._is_running = True
                    self._start_time = time.time()
                    return False
                else:
                    raise
    
    def stop(self) -> None:
        """Stop the XDP sender and cleanup resources."""
        with self._lock:
            if not self._is_running:
                return
            
            if not self._use_fallback and self._xdp:
                try:
                    stats = None
                    if self._ctx_handle is not None:
                        if "xdp_stats_ctx" in dir(self._xdp):
                            stats = self._xdp.xdp_stats_ctx(int(self._ctx_handle))
                    if stats is None:
                        stats = self._xdp.xdp_stats()
                    if stats:
                        self._total_packets = stats.get('tx_packets', 0)
                        self._total_bytes = stats.get('tx_bytes', 0)

                    if self._ctx_handle is not None:
                        if "xdp_destroy" in dir(self._xdp):
                            self._xdp.xdp_destroy(int(self._ctx_handle))
                        else:
                            self._xdp.xdp_cleanup()
                    else:
                        self._xdp.xdp_cleanup()
                except Exception as e:
                    utils.log_error(f"[XDP] Cleanup error: {e}")
                finally:
                    self._detach_bpf_program()
            else:
                self._detach_bpf_program()
            
            self._is_running = False
            self._use_fallback = False
            self._xdp = None
            self._ctx_handle = None
            self._effective_mode = int(self.mode)
            self._mode2_probe_status = "not_run"
            self._mode2_probe_reason = ""
            
            utils.log_info("[XDP] Stopped")
    
    def send(self, packets: List[bytes]) -> int:
        """
        Send a list of raw IP packets.
        
        Args:
            packets: List of bytes objects, each containing a raw IP packet
        
        Returns:
            Number of packets successfully submitted
        """
        if not self._is_running:
            raise RuntimeError("XDP sender not started")
        
        if not packets:
            return 0
        
        if self._use_fallback:
            return self._send_fallback(packets)
        
        try:
            if self._ctx_handle is not None:
                if "xdp_send_ctx" in dir(self._xdp):
                    sent = self._xdp.xdp_send_ctx(int(self._ctx_handle), packets)
                else:
                    raise RuntimeError("xdp_send_ctx API not available for multi-context mode")
            else:
                sent = self._xdp.xdp_send(packets)
            return sent
        except Exception as e:
            utils.log_error(f"[XDP] Send error: {e}")
            return 0

    def send_buffer(self, packet_buffer, packet_size: int, count: int) -> int:
        """
        Send packets from a contiguous fixed-size packet buffer.

        Args:
            packet_buffer: bytes-like object containing count * packet_size bytes
            packet_size: size of each packet
            count: number of packets
        """
        if not self._is_running:
            raise RuntimeError("XDP sender not started")
        if packet_size <= 0 or count <= 0:
            return 0

        if self._use_fallback:
            return self._send_buffer_fallback(packet_buffer, packet_size, count)

        try:
            if self._ctx_handle is not None:
                if "xdp_send_buffer_ctx" in dir(self._xdp):
                    return int(
                        self._xdp.xdp_send_buffer_ctx(
                            int(self._ctx_handle), packet_buffer, int(packet_size), int(count)
                        ) or 0
                    )
                raise RuntimeError("xdp_send_buffer_ctx API not available for multi-context mode")

            if hasattr(self._xdp, "xdp_send_buffer"):
                return int(self._xdp.xdp_send_buffer(packet_buffer, int(packet_size), int(count)) or 0)

            mv = memoryview(packet_buffer)
            packets = [bytes(mv[i * packet_size:(i + 1) * packet_size]) for i in range(count)]
            return int(self._xdp.xdp_send(packets) or 0)
        except Exception as e:
            utils.log_error(f"[XDP] Send buffer error: {e}")
            return 0

    def acquire_tx_frame(self):
        """
        Acquire a writable UMEM frame for in-place packet build.

        Returns:
            Tuple[frame_id, memoryview] or None when no frame is available.
        """
        if not self._is_running:
            raise RuntimeError("XDP sender not started")
        if self._use_fallback:
            raise RuntimeError("UMEM frame API not available in fallback mode")
        if self._ctx_handle is not None:
            raise RuntimeError("UMEM frame API not available in multi-context mode")
        if not hasattr(self._xdp, "xdp_acquire_tx_frame"):
            raise RuntimeError("xdp_acquire_tx_frame API not available")
        return self._xdp.xdp_acquire_tx_frame()

    def submit_tx_frame(self, frame_id: int, length: int) -> bool:
        """Submit a previously acquired TX frame."""
        if not self._is_running:
            raise RuntimeError("XDP sender not started")
        if self._use_fallback:
            raise RuntimeError("UMEM frame API not available in fallback mode")
        if self._ctx_handle is not None:
            raise RuntimeError("UMEM frame API not available in multi-context mode")
        if not hasattr(self._xdp, "xdp_submit_tx_frame"):
            raise RuntimeError("xdp_submit_tx_frame API not available")
        return bool(self._xdp.xdp_submit_tx_frame(int(frame_id), int(length)))

    def release_tx_frame(self, frame_id: int) -> bool:
        """Release a previously acquired TX frame without transmit."""
        if not self._is_running:
            raise RuntimeError("XDP sender not started")
        if self._use_fallback:
            raise RuntimeError("UMEM frame API not available in fallback mode")
        if self._ctx_handle is not None:
            raise RuntimeError("UMEM frame API not available in multi-context mode")
        if not hasattr(self._xdp, "xdp_release_tx_frame"):
            raise RuntimeError("xdp_release_tx_frame API not available")
        return bool(self._xdp.xdp_release_tx_frame(int(frame_id)))
    
    def send_udp(
        self,
        target_ip: str,
        target_port: int,
        payloads: List[bytes],
        source_ports: Optional[List[int]] = None
    ) -> int:
        """
        Send UDP packets (helper method).
        
        Args:
            target_ip: Destination IP address
            target_port: Destination port
            payloads: List of payload bytes
            source_ports: Optional list of source ports
        
        Returns:
            Number of packets sent
        """
        if not self._is_running:
            raise RuntimeError("XDP sender not started")
        
        if not payloads:
            return 0
        
        if self._use_fallback:
            return self._send_udp_fallback(target_ip, target_port, payloads)
        if self._ctx_handle is not None:
            utils.log_error("[XDP] send_udp is not yet supported in multi-context mode")
            return 0
        
        try:
            send_udp_fn = getattr(
                self._xdp,
                "xdp_send_udp_zc",
                getattr(self._xdp, "xdp_send_udp", None),
            )
            if send_udp_fn is None:
                raise RuntimeError("xdp_send_udp API not available in extension")
            if source_ports:
                sent = send_udp_fn(target_ip, target_port, payloads, source_ports)
            else:
                sent = send_udp_fn(target_ip, target_port, payloads)
            return sent
        except Exception as e:
            utils.log_error(f"[XDP] Send UDP error: {e}")
            return 0
    
    def _send_fallback(self, packets: List[bytes]) -> int:
        """Send packets using standard raw socket (fallback)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setblocking(False)
            
            sent = 0
            for pkt in packets:
                try:
                    # Extract destination from IP header
                    if len(pkt) >= 20:
                        dst_ip = socket.inet_ntoa(pkt[16:20])
                        sock.sendto(pkt, (dst_ip, 0))
                        sent += 1
                        self._total_bytes += len(pkt)
                except Exception:
                    pass
            
            sock.close()
            self._total_packets += sent
            return sent
            
        except Exception as e:
            utils.log_error(f"[XDP Fallback] Error: {e}")
            return 0
    
    def _send_udp_fallback(
        self,
        target_ip: str,
        target_port: int,
        payloads: List[bytes]
    ) -> int:
        """Send UDP packets using standard socket (fallback)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            
            sent = 0
            for payload in payloads:
                try:
                    sock.sendto(payload, (target_ip, target_port))
                    sent += 1
                    self._total_bytes += len(payload)
                except Exception:
                    pass
            
            sock.close()
            self._total_packets += sent
            return sent
            
        except Exception as e:
            utils.log_error(f"[XDP Fallback] UDP error: {e}")
            return 0

    def _send_buffer_fallback(self, packet_buffer, packet_size: int, count: int) -> int:
        """Send contiguous packet buffer using standard raw socket fallback."""
        try:
            mv = memoryview(packet_buffer)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setblocking(False)

            sent = 0
            for i in range(count):
                start = i * packet_size
                end = start + packet_size
                pkt = mv[start:end]
                if len(pkt) < 20:
                    continue
                try:
                    dst_ip = socket.inet_ntoa(pkt[16:20])
                    sock.sendto(pkt, (dst_ip, 0))
                    sent += 1
                    self._total_bytes += len(pkt)
                except Exception:
                    pass

            sock.close()
            self._total_packets += sent
            return sent
        except Exception as e:
            utils.log_error(f"[XDP Fallback] buffer error: {e}")
            return 0
    
    def get_stats(self) -> XDPStats:
        """Get current statistics."""
        if not self._is_running:
            return XDPStats()
        
        if self._use_fallback:
            elapsed = time.time() - self._start_time if self._start_time else 0
            pps = self._total_packets / elapsed if elapsed > 0 else 0
            mbps = (self._total_bytes * 8) / (elapsed * 1e6) if elapsed > 0 else 0
            
            return XDPStats(
                tx_packets=self._total_packets,
                tx_bytes=self._total_bytes,
                elapsed_seconds=elapsed,
                packets_per_second=pps,
                mbps=mbps,
                mode=int(self._effective_mode),
                mode_name="Fallback (Raw Socket)"
            )
        
        try:
            if self._ctx_handle is not None:
                if "xdp_stats_ctx" in dir(self._xdp):
                    stats_dict = self._xdp.xdp_stats_ctx(int(self._ctx_handle))
                else:
                    raise RuntimeError("xdp_stats_ctx API not available for multi-context mode")
            else:
                stats_dict = self._xdp.xdp_stats()
            if stats_dict:
                return XDPStats.from_dict(stats_dict)
        except Exception:
            pass
        
        return XDPStats()
    
    @property
    def is_running(self) -> bool:
        """Check if sender is running."""
        return self._is_running
    
    @property
    def is_using_xdp(self) -> bool:
        """Check if using actual XDP (not fallback)."""
        return self._is_running and not self._use_fallback
    
    def __enter__(self) -> 'XDPSender':
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
    
    def __str__(self) -> str:
        status = "running" if self._is_running else "stopped"
        mode = "XDP" if not self._use_fallback else "Fallback"
        return f"XDPSender(interface={self.interface}, status={status}, mode={mode})"


# ============================================================================
# Bulk Sender (High-Throughput Mode)
# ============================================================================

class XDPBulkSender:
    """
    Bulk packet sender optimized for maximum throughput.
    
    Uses multiple threads and larger batches to maximize
    packets per second on AF_XDP.
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        threads: int = 1,
        batch_size: int = 256,
        queue_id_base: int = DEFAULT_QUEUE_ID,
        queue_count: Optional[int] = None,
        use_multi_ctx: Optional[bool] = True,
    ):
        """
        Initialize bulk sender.
        
        Args:
            interface: Network interface
            threads: Number of sender threads
            batch_size: Packets per batch
            queue_id_base: First queue id for affinity mapping
            queue_count: Number of queues to distribute over (auto-detected if None)
            use_multi_ctx: Force enable/disable context-handle API per sender.
                Default True for queue-affinity context isolation.
        """
        self.interface = interface or get_default_interface()
        self.threads = max(1, int(threads))
        self.batch_size = max(1, int(batch_size))
        self.queue_id_base = int(queue_id_base)
        auto_queue_count = int(queue_count) if queue_count is not None else int(get_interface_queue_count(self.interface))
        self.queue_count = max(1, auto_queue_count)
        self.use_multi_ctx = use_multi_ctx

        self._is_running = False
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._senders: List[XDPSender] = []
        self._sender_queues: List[queue.Queue] = []
        self._workers = []
        self._dropped_batches = 0
        self._dispatch_index = 0
        self._start_time: Optional[float] = None

    def _queue_id_for_worker(self, worker_index: int) -> int:
        return int(self.queue_id_base + (worker_index % self.queue_count))

    def _worker_loop(self, worker_index: int) -> None:
        sender_queue = self._sender_queues[worker_index]
        sender = self._senders[worker_index]
        while not self._stop_event.is_set():
            try:
                batch = sender_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if batch is None:
                sender_queue.task_done()
                break

            try:
                if batch:
                    sender.send(batch)
            finally:
                sender_queue.task_done()

    def _aggregate_stats(self) -> XDPStats:
        if not self._senders:
            return XDPStats()

        sender_stats = [s.get_stats() for s in self._senders]
        aggregate = XDPStats(
            tx_packets=sum(st.tx_packets for st in sender_stats),
            tx_bytes=sum(st.tx_bytes for st in sender_stats),
            tx_errors=sum(st.tx_errors for st in sender_stats),
            tx_wakeups=sum(st.tx_wakeups for st in sender_stats),
            tx_desc_reserve_failures=sum(st.tx_desc_reserve_failures for st in sender_stats),
            tx_frame_alloc_failures=sum(st.tx_frame_alloc_failures for st in sender_stats),
            tx_partial_batches=sum(st.tx_partial_batches for st in sender_stats),
            tx_retry_loops=sum(st.tx_retry_loops for st in sender_stats),
            tx_completion_events=sum(st.tx_completion_events for st in sender_stats),
            tx_completed_desc=sum(st.tx_completed_desc for st in sender_stats),
            tx_invalid_packets=sum(st.tx_invalid_packets for st in sender_stats),
            tx_backpressure_events=sum(st.tx_backpressure_events for st in sender_stats),
            tx_send_calls=sum(st.tx_send_calls for st in sender_stats),
            tx_send_ns_total=sum(st.tx_send_ns_total for st in sender_stats),
            tx_send_ns_max=max((st.tx_send_ns_max for st in sender_stats), default=0),
            mode=sender_stats[0].mode if sender_stats else 0,
            mode_name=sender_stats[0].mode_name if sender_stats else "Unknown",
        )

        elapsed = 0.0
        now = time.time()
        if self._start_time is not None and self._is_running:
            elapsed = max(0.0, now - self._start_time)
        if elapsed <= 0.0:
            elapsed = max((st.elapsed_seconds for st in sender_stats), default=0.0)

        aggregate.elapsed_seconds = elapsed
        if elapsed > 0:
            aggregate.packets_per_second = aggregate.tx_packets / elapsed
            aggregate.mbps = (aggregate.tx_bytes * 8) / (elapsed * 1e6)
        else:
            aggregate.packets_per_second = 0.0
            aggregate.mbps = 0.0
        aggregate.tx_send_avg_us = (
            (float(aggregate.tx_send_ns_total) / float(aggregate.tx_send_calls)) / 1000.0
            if aggregate.tx_send_calls > 0 else 0.0
        )
        aggregate.tx_send_max_us = float(aggregate.tx_send_ns_max) / 1000.0
        return aggregate

    def _enqueue_batch(self, packets: List[bytes], timeout: float = 0.2) -> bool:
        if not packets or not self._sender_queues:
            return False

        start_idx = self._dispatch_index % len(self._sender_queues)
        for attempt in range(len(self._sender_queues)):
            idx = (start_idx + attempt) % len(self._sender_queues)
            try:
                self._sender_queues[idx].put(packets, timeout=timeout)
                self._dispatch_index = (idx + 1) % len(self._sender_queues)
                return True
            except queue.Full:
                continue
        self._dropped_batches += 1
        self._dispatch_index = (start_idx + 1) % len(self._sender_queues)
        return False
    
    def start(self) -> None:
        """Start bulk sender."""
        if self._is_running:
            return

        self._senders = []
        self._sender_queues = []
        self._workers = []
        self._stop_event.clear()
        self._dropped_batches = 0
        self._dispatch_index = 0

        try:
            for worker_index in range(self.threads):
                sender = XDPSender(
                    interface=self.interface,
                    queue_id=self._queue_id_for_worker(worker_index),
                    batch_size=self.batch_size,
                    use_multi_ctx=self.use_multi_ctx,
                )
                sender.start()
                self._senders.append(sender)
                self._sender_queues.append(queue.Queue(maxsize=16))
        except Exception:
            for sender in self._senders:
                try:
                    sender.stop()
                except Exception:
                    pass
            self._senders = []
            self._sender_queues = []
            self._workers = []
            raise

        for worker_index in range(self.threads):
            worker = threading.Thread(
                target=self._worker_loop,
                args=(worker_index,),
                daemon=True,
            )
            worker.start()
            self._workers.append(worker)

        self._is_running = True
        self._start_time = time.time()
    
    def stop(self) -> XDPStats:
        """Stop bulk sender and return final stats."""
        if not self._is_running:
            return self._aggregate_stats()

        self._stop_event.set()
        for sender_queue in self._sender_queues:
            try:
                sender_queue.put_nowait(None)
            except queue.Full:
                sender_queue.put(None)
        
        for worker in self._workers:
            worker.join(timeout=5.0)
        self._workers = []
        
        stats = self._aggregate_stats()
        
        for sender in self._senders:
            sender.stop()
        
        self._is_running = False
        self._senders = []
        self._sender_queues = []
        self._start_time = None
        return stats
    
    def send_continuous(
        self,
        packet_generator: Callable[[], List[bytes]],
        duration: float = 10.0,
        on_stats: Optional[Callable[[XDPStats], None]] = None,
        stats_interval: float = 1.0
    ) -> XDPStats:
        """
        Continuously send packets for a duration.
        
        Args:
            packet_generator: Function that returns a list of packets
            duration: How long to send (seconds)
            on_stats: Callback for periodic stats updates
            stats_interval: How often to call on_stats
        
        Returns:
            Final statistics
        """
        if not self._is_running:
            self.start()
        
        start_time = time.time()
        last_stats_time = start_time
        
        try:
            while time.time() - start_time < duration:
                if self._stop_event.is_set():
                    break
                
                # Generate and send packets
                packets = packet_generator()
                if packets:
                    self._enqueue_batch(packets, timeout=0.2)
                
                # Periodic stats callback
                if on_stats and time.time() - last_stats_time >= stats_interval:
                    stats = self._aggregate_stats()
                    if self._dropped_batches:
                        utils.log_warning(
                            f"[XDP Bulk] Dropped batches due to full queue: {self._dropped_batches}"
                        )
                    on_stats(stats)
                    last_stats_time = time.time()
        
        except KeyboardInterrupt:
            pass
        
        return self._aggregate_stats()

    def get_stats(self) -> XDPStats:
        """Get aggregated statistics across all sender contexts."""
        return self._aggregate_stats()

    def get_queue_stats(self) -> List[Dict[str, Any]]:
        """Get per-queue statistics for each sender context."""
        out: List[Dict[str, Any]] = []
        for idx, sender in enumerate(self._senders):
            st = sender.get_stats()
            out.append(
                {
                    "worker_index": idx,
                    "queue_id": int(st.queue_id),
                    "tx_packets": int(st.tx_packets),
                    "tx_bytes": int(st.tx_bytes),
                    "tx_errors": int(st.tx_errors),
                    "tx_backpressure_events": int(st.tx_backpressure_events),
                    "tx_send_avg_us": float(st.tx_send_avg_us),
                    "tx_send_max_us": float(st.tx_send_max_us),
                    "packets_per_second": float(st.packets_per_second),
                    "mbps": float(st.mbps),
                }
            )
        return out


# ============================================================================
# Integration Helper for Samurai
# ============================================================================

class XDPIntegration:
    """
    Integration helper for using XDP with existing Samurai components.
    """
    
    @staticmethod
    def check_availability() -> Tuple[bool, XDPSystemInfo, str]:
        """
        Full availability check for XDP.
        
        Returns:
            Tuple of (is_available, system_info, message)
        """
        info = get_xdp_system_info()
        
        if info is None:
            return False, XDPSystemInfo(), "XDP extension not loaded"
        
        if not info.is_root:
            return False, info, "Root privileges required (run with sudo)"
        
        if not info.af_xdp_available:
            return False, info, "AF_XDP not available on this system"
        
        return True, info, "XDP is available and ready"
    
    @staticmethod
    def create_sender(
        target_ip: str,
        auto_detect_interface: bool = True
    ) -> Optional[XDPSender]:
        """
        Create an XDP sender configured for a target.
        
        Args:
            target_ip: Target IP address
            auto_detect_interface: Auto-detect outgoing interface
        
        Returns:
            Configured XDPSender or None if unavailable
        """
        interface = None
        
        if auto_detect_interface:
            # Find interface that routes to target
            try:
                result = subprocess.run(
                    ['ip', 'route', 'get', target_ip],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    parts = result.stdout.split()
                    for i, part in enumerate(parts):
                        if part == 'dev' and i + 1 < len(parts):
                            interface = parts[i + 1]
                            break
            except Exception:
                interface = get_default_interface()
        else:
            interface = get_default_interface()
        
        if not interface:
            utils.log_error("[XDP] Could not determine interface")
            return None
        
        try:
            sender = XDPSender(interface=interface, auto_fallback=True)
            return sender
        except Exception as e:
            utils.log_error(f"[XDP] Failed to create sender: {e}")
            return None
    
    @staticmethod
    def print_system_info() -> None:
        """Print XDP system information to console."""
        available, info, msg = XDPIntegration.check_availability()
        
        print("\n┌─────────────────────────────────────────────────────┐")
        print("│              AF_XDP System Information              │")
        print("├─────────────────────────────────────────────────────┤")
        print(f"│ Status: {'✅ Available' if available else '❌ Not Available':<39} │")
        print(f"│ Message: {msg:<38} │")
        print("├─────────────────────────────────────────────────────┤")
        
        if info:
            print(f"│ Kernel: {info.kernel_release:<40} │")
            print(f"│ Root: {'Yes' if info.is_root else 'No':<42} │")
            print(f"│ AF_XDP: {'Supported' if info.af_xdp_available else 'Not Supported':<40} │")
            print("├─────────────────────────────────────────────────────┤")
            print(f"│ Frame Count: {info.num_frames:<38} │")
            print(f"│ Frame Size: {info.frame_size:<39} │")
            print(f"│ Batch Size: {info.batch_size:<39} │")
        
        print("└─────────────────────────────────────────────────────┘\n")


# ============================================================================
# CLI Testing
# ============================================================================

def _test_xdp():
    """Test XDP functionality."""
    print("Testing AF_XDP sender...")
    
    XDPIntegration.print_system_info()
    
    available, info, msg = XDPIntegration.check_availability()
    
    if not available:
        print(f"❌ XDP not available: {msg}")
        return False
    
    print(f"✅ XDP available")
    
    # Try to create and send a test packet
    interface = get_default_interface()
    print(f"Using interface: {interface}")
    
    try:
        sender = XDPSender(interface=interface)
        sender.start()
        
        # Create a simple test UDP packet
        test_payload = b"Samurai XDP Test"
        
        # Send test
        sent = sender.send_udp("127.0.0.1", 12345, [test_payload])
        print(f"Sent {sent} test packet(s)")
        
        stats = sender.get_stats()
        print(f"Stats: {stats}")
        
        sender.stop()
        
        print("✅ XDP test successful!")
        return True
        
    except Exception as e:
        print(f"❌ XDP test failed: {e}")
        return False


if __name__ == "__main__":
    _test_xdp()
