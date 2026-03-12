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
                f"{self.mbps:.2f} Mbps "
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
        auto_fallback: bool = True
    ):
        """
        Initialize XDP sender.
        
        Args:
            interface: Network interface to use (auto-detected if None)
            queue_id: Queue ID to use (default: 0)
            mode: XDP mode (0=SKB/Copy, 1=Native)
            batch_size: Batch size for packet transmission
            auto_fallback: Fall back to raw sockets if XDP unavailable
        """
        self.interface = interface or get_default_interface()
        self.queue_id = queue_id
        self.mode = mode
        self.batch_size = batch_size
        self.auto_fallback = auto_fallback
        
        self._xdp = None
        self._is_running = False
        self._use_fallback = False
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
            
            try:
                result = self._xdp.xdp_init(self.interface, self.queue_id, self.mode)
                
                if result:
                    utils.log_info(f"[XDP] Started on {self.interface} "
                                  f"(queue={self.queue_id}, mode={'Copy' if self.mode == 0 else 'Native'})")
                    self._is_running = True
                    self._start_time = time.time()
                    return True
                else:
                    raise RuntimeError("xdp_init returned False")
                    
            except Exception as e:
                utils.log_error(f"[XDP] Failed to initialize: {e}")
                
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
                    stats = self._xdp.xdp_stats()
                    if stats:
                        self._total_packets = stats.get('tx_packets', 0)
                        self._total_bytes = stats.get('tx_bytes', 0)
                    
                    self._xdp.xdp_cleanup()
                except Exception as e:
                    utils.log_error(f"[XDP] Cleanup error: {e}")
            
            self._is_running = False
            self._use_fallback = False
            self._xdp = None
            
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
            if hasattr(self._xdp, "xdp_send_buffer"):
                return int(self._xdp.xdp_send_buffer(packet_buffer, int(packet_size), int(count)) or 0)

            mv = memoryview(packet_buffer)
            packets = [bytes(mv[i * packet_size:(i + 1) * packet_size]) for i in range(count)]
            return int(self._xdp.xdp_send(packets) or 0)
        except Exception as e:
            utils.log_error(f"[XDP] Send buffer error: {e}")
            return 0
    
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
        
        try:
            if source_ports:
                sent = self._xdp.xdp_send_udp(target_ip, target_port, payloads, source_ports)
            else:
                sent = self._xdp.xdp_send_udp(target_ip, target_port, payloads)
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
                mode_name="Fallback (Raw Socket)"
            )
        
        try:
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
        batch_size: int = 256
    ):
        """
        Initialize bulk sender.
        
        Args:
            interface: Network interface
            threads: Number of sender threads
            batch_size: Packets per batch
        """
        self.interface = interface or get_default_interface()
        self.threads = threads
        self.batch_size = batch_size
        
        self._sender = None
        self._is_running = False
        self._packet_queue = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._workers = []
    
    def start(self) -> None:
        """Start bulk sender."""
        self._sender = XDPSender(
            interface=self.interface,
            batch_size=self.batch_size
        )
        self._sender.start()
        self._is_running = True
        self._stop_event.clear()
    
    def stop(self) -> XDPStats:
        """Stop bulk sender and return final stats."""
        self._stop_event.set()
        
        for worker in self._workers:
            worker.join(timeout=5.0)
        
        stats = self._sender.get_stats() if self._sender else XDPStats()
        
        if self._sender:
            self._sender.stop()
        
        self._is_running = False
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
                    self._sender.send(packets)
                
                # Periodic stats callback
                if on_stats and time.time() - last_stats_time >= stats_interval:
                    stats = self._sender.get_stats()
                    on_stats(stats)
                    last_stats_time = time.time()
        
        except KeyboardInterrupt:
            pass
        
        return self._sender.get_stats()


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
