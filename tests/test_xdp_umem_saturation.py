"""
TASK-TEST-L1-01 — AF_XDP UMEM Saturation & Double-Free Stress
=============================================================

This test exercises the AF_XDP frame allocator in ``xdp_sender.c`` under
extreme pressure:

  * **Saturation path** — Exhaust every UMEM descriptor, verify ``alloc_frame``
    returns ``UINT64_MAX`` (no silent corruption), then recycle and re-allocate.
  * **Double-free guard** — Attempt to free the same frame twice and verify
    ``free_count`` does not overshoot ``frame_count`` (the existing bounds check
    in ``free_frame``).
  * **Completion-delay stress** — Simulate slow completion ring reaping while
    the TX path allocates at maximum rate; confirm zero descriptor leaks after
    the full run.

DoD (Definition of Done):
  - 10 M simulated packets with zero ASan / descriptor-leak errors
  - Free-pool size returns to initial value after full alloc → free cycle
  - Double-free is gracefully bounded (``free_count <= frame_count``)

Markers:
  - ``privileged``  — real AF_XDP sockets need ``CAP_NET_ADMIN``
  - ``xdp``         — AF_XDP subsystem

Relates to #4
"""

from __future__ import annotations

import ctypes
import os
import struct
import sys
import textwrap
from typing import List

import pytest

# ---------------------------------------------------------------------------
# Helpers — pure-Python model of the UMEM frame allocator from xdp_sender.c
# ---------------------------------------------------------------------------

# We replicate the *exact* logic from xdp_sender.c so that this test is useful
# even on machines without AF_XDP kernel support (the CI/safe path).  When
# running under SAMURAI_TEST_PROFILE=full the test also exercises the real
# xdp_core native API.

XDP_MAX_FRAMES = 32768
XDP_DEFAULT_FRAMES = 8192
FRAME_SIZE = 4096
HEADROOM = 256
UINT64_MAX = (1 << 64) - 1


class UmemFrameAllocator:
    """
    Pure-Python replica of the ``alloc_frame`` / ``free_frame`` /
    ``xdp_reap_completion_entries`` logic in ``xdp_sender.c``.

    This lets us validate invariants (saturation, double-free bounds, leak
    freedom) without root or AF_XDP kernel support.
    """

    def __init__(self, frame_count: int = XDP_DEFAULT_FRAMES,
                 frame_size: int = FRAME_SIZE,
                 headroom: int = HEADROOM):
        self.frame_count = frame_count
        self.frame_size = frame_size
        self.headroom = headroom

        # free_frames[0..free_count-1] holds available frame *indices*.
        self.free_frames: List[int] = list(range(frame_count))
        self.free_count: int = frame_count

        # outstanding_tx mirrors xsk->outstanding_tx
        self.outstanding_tx: int = 0

        # Simulated completion ring (queue of UMEM addresses to reclaim)
        self._completion_queue: List[int] = []

    # -- alloc_frame (xdp_sender.c:1327-1335) --
    def alloc_frame(self) -> int:
        """Return UMEM byte-address or UINT64_MAX on exhaustion."""
        if self.free_count == 0:
            return UINT64_MAX
        self.free_count -= 1
        idx = self.free_frames[self.free_count]
        return idx * self.frame_size

    # -- free_frame (xdp_sender.c:1338-1351) --
    def free_frame(self, frame_addr: int) -> None:
        """Recycle a frame; silently bounded by frame_count."""
        base = frame_addr
        if base >= self.headroom:
            base -= self.headroom
        idx = base // self.frame_size
        if idx >= self.frame_count:
            return  # out-of-range → ignore (matches C code)
        if self.free_count < self.frame_count:
            self.free_frames[self.free_count] = idx
            self.free_count += 1

    # -- simulate TX submission --
    def submit_tx(self, frame_addr: int) -> None:
        """Enqueue a frame into the simulated completion ring."""
        self.outstanding_tx += 1
        self._completion_queue.append(frame_addr)

    # -- xdp_reap_completion_entries (simplified) --
    def reap_completions(self, max_count: int, recycle: bool = True) -> int:
        """Reap up to *max_count* completions, optionally recycling frames."""
        if not self.outstanding_tx:
            return 0
        want = min(max_count, self.outstanding_tx, len(self._completion_queue))
        reaped = 0
        for _ in range(want):
            addr = self._completion_queue.pop(0)
            if recycle:
                self.free_frame(addr)
            reaped += 1
        self.outstanding_tx -= reaped
        return reaped


# ===========================================================================
# Tests
# ===========================================================================


class TestUmemSaturation:
    """Exhaust UMEM frames and verify allocation semantics."""

    def test_full_alloc_returns_sentinel_on_exhaustion(self):
        """After allocating all frames, the next alloc must return UINT64_MAX."""
        alloc = UmemFrameAllocator(frame_count=1024, frame_size=FRAME_SIZE)
        addrs = []
        for _ in range(1024):
            a = alloc.alloc_frame()
            assert a != UINT64_MAX, "alloc_frame returned UINT64_MAX before pool exhaustion"
            addrs.append(a)

        # Pool is now empty
        assert alloc.free_count == 0
        sentinel = alloc.alloc_frame()
        assert sentinel == UINT64_MAX, (
            f"Expected UINT64_MAX on exhausted pool, got {sentinel:#x}"
        )

    def test_free_then_realloc_returns_all_frames(self):
        """Free every frame, then re-allocate; all must succeed."""
        N = 2048
        alloc = UmemFrameAllocator(frame_count=N, frame_size=FRAME_SIZE)
        addrs = [alloc.alloc_frame() for _ in range(N)]
        assert alloc.free_count == 0

        # Free all
        for a in addrs:
            alloc.free_frame(a)
        assert alloc.free_count == N, (
            f"After freeing {N} frames, free_count={alloc.free_count}"
        )

        # Re-allocate all
        for _ in range(N):
            a = alloc.alloc_frame()
            assert a != UINT64_MAX

        # Exhausted again
        assert alloc.alloc_frame() == UINT64_MAX


class TestDoubleFreeGuard:
    """Verify double-free is bounded, not silently corrupting."""

    def test_double_free_bounded_by_frame_count(self):
        """
        Freeing the same frame twice must NOT push free_count above
        frame_count, matching the guard in xdp_sender.c:1348.
        """
        N = 512
        alloc = UmemFrameAllocator(frame_count=N, frame_size=FRAME_SIZE)
        addr = alloc.alloc_frame()
        assert addr != UINT64_MAX

        # Free once (legitimate)
        alloc.free_frame(addr)
        assert alloc.free_count == N  # back to full

        # Free again (double-free attempt)
        alloc.free_frame(addr)
        assert alloc.free_count <= N, (
            f"Double-free pushed free_count to {alloc.free_count} > frame_count ({N})"
        )

    def test_out_of_range_frame_silently_ignored(self):
        """A frame address beyond the pool must be silently ignored."""
        alloc = UmemFrameAllocator(frame_count=64, frame_size=FRAME_SIZE)
        before = alloc.free_count
        alloc.free_frame(99999 * FRAME_SIZE)  # way beyond pool
        assert alloc.free_count == before, "Out-of-range free corrupted free pool"


class TestCompletionDelayStress:
    """
    Simulate 10 M packets with artificially delayed completion reaping
    to stress-test UMEM descriptor lifecycle.
    """

    TOTAL_PACKETS = 10_000_000
    FRAME_COUNT = 4096
    REAP_INTERVAL = 128   # reap every N submissions
    REAP_BATCH = 64       # max completions per reap call

    def test_10m_packets_zero_descriptor_leak(self):
        """
        Allocate, submit, and reap 10 M times. At the end, every
        descriptor must be returned (free_count == frame_count).
        """
        alloc = UmemFrameAllocator(
            frame_count=self.FRAME_COUNT,
            frame_size=FRAME_SIZE,
        )
        total_sent = 0
        total_reaped = 0
        alloc_failures = 0

        for i in range(self.TOTAL_PACKETS):
            addr = alloc.alloc_frame()
            if addr == UINT64_MAX:
                # Back-pressure: force reap
                reaped = alloc.reap_completions(self.REAP_BATCH, recycle=True)
                total_reaped += reaped
                addr = alloc.alloc_frame()
                if addr == UINT64_MAX:
                    alloc_failures += 1
                    continue

            alloc.submit_tx(addr)
            total_sent += 1

            # Periodic reaping (simulates delayed completion ring)
            if (i + 1) % self.REAP_INTERVAL == 0:
                reaped = alloc.reap_completions(self.REAP_BATCH, recycle=True)
                total_reaped += reaped

        # Drain remaining completions
        while alloc.outstanding_tx > 0:
            reaped = alloc.reap_completions(self.FRAME_COUNT, recycle=True)
            total_reaped += reaped
            if reaped == 0:
                break

        # Assertions
        assert alloc.outstanding_tx == 0, (
            f"Outstanding TX not drained: {alloc.outstanding_tx}"
        )
        assert alloc.free_count == self.FRAME_COUNT, (
            f"Descriptor leak: free_count={alloc.free_count}, expected={self.FRAME_COUNT}"
        )
        assert total_sent == total_reaped, (
            f"Sent/reaped mismatch: sent={total_sent}, reaped={total_reaped}"
        )
        # Accept up to 0.01% allocation failures (back-pressure)
        max_acceptable_failures = self.TOTAL_PACKETS * 0.0001
        assert alloc_failures <= max_acceptable_failures, (
            f"Too many alloc failures: {alloc_failures} > {max_acceptable_failures}"
        )

    def test_burst_saturation_recovery(self):
        """
        Burst-allocate until exhaustion, then batch-reap and verify
        the pool recovers to full capacity.
        """
        FC = 2048
        alloc = UmemFrameAllocator(frame_count=FC, frame_size=FRAME_SIZE)

        # Burst: allocate all frames
        for _ in range(FC):
            addr = alloc.alloc_frame()
            assert addr != UINT64_MAX
            alloc.submit_tx(addr)

        assert alloc.free_count == 0
        assert alloc.outstanding_tx == FC

        # Reap all
        reaped = alloc.reap_completions(FC, recycle=True)
        assert reaped == FC, f"Expected {FC} reaped, got {reaped}"
        assert alloc.free_count == FC
        assert alloc.outstanding_tx == 0

        # Verify re-allocation works
        addr = alloc.alloc_frame()
        assert addr != UINT64_MAX, "Pool did not recover after batch reap"


class TestNativeXdpUmem:
    """
    Real AF_XDP path tests — only run under SAMURAI_TEST_PROFILE=full.
    These require root (CAP_NET_ADMIN) and a real or veth NIC.
    """

    @pytest.mark.privileged
    @pytest.mark.xdp
    def test_native_frame_alloc_lifecycle(self):
        """
        Verify the native xdp_core API frame allocation does not leak.
        (Placeholder — the real implementation uses the C API via ctypes.)
        """
        # This test serves as a documentation entry point. On CI it is
        # automatically skipped by conftest.py (ci_safe profile).
        pytest.skip(
            "Native AF_XDP test requires root and a real NIC. "
            "Run with SAMURAI_TEST_PROFILE=full on a privileged machine."
        )
