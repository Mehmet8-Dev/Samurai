#pragma once
#include <atomic>
#include <cstdint>
#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif

namespace ddos_samurai {

// TASK-CORE-03: Test-and-Test-and-Set (TTAS) SpinLock with exponential backoff.
//
// The naive TAS loop (flag.test_and_set() every iteration) issues a write bus
// transaction on every spin, causing massive cache-line invalidation storms
// under contention. TTAS spins on a read-only check (flag.test()) which stays
// in the shared cache-line state (no bus traffic), and only attempts the
// expensive atomic RMW (test_and_set) when the lock appears free.
//
// Exponential _mm_pause backoff further reduces memory-bus pressure by giving
// the lock holder time to complete its critical section.
//
// Relates to #4
class SpinLock {
  std::atomic<bool> flag{false};

  // Maximum number of _mm_pause iterations before resetting the backoff.
  // Capped to avoid excessive latency on short critical sections.
  static constexpr uint32_t kMaxBackoff = 64;

public:
  void lock() {
    // Fast path: try to acquire immediately (uncontended case).
    if (!flag.exchange(true, std::memory_order_acquire)) {
      return;
    }

    // Slow path: TTAS with exponential backoff.
    uint32_t backoff = 1;
    for (;;) {
      // Test (read-only): spin on shared cache line without bus writes.
      while (flag.load(std::memory_order_relaxed)) {
        // Exponential backoff: yield pipeline resources to sibling hyperthread
        // and reduce memory-bus contention.
        for (uint32_t i = 0; i < backoff; ++i) {
#if defined(__i386__) || defined(__x86_64__)
          _mm_pause();
#elif defined(__aarch64__)
          __asm__ volatile("yield");
#endif
        }
        if (backoff < kMaxBackoff) {
          backoff *= 2;
        }
      }

      // Test-and-Set: the lock *looks* free, attempt atomic acquisition.
      if (!flag.exchange(true, std::memory_order_acquire)) {
        return;  // Acquired.
      }
      // Lost the race — another thread grabbed it first. Reset backoff
      // to a moderate level and resume read-only spinning.
      backoff = (backoff > 4) ? backoff / 2 : 1;
    }
  }

  void unlock() {
    flag.store(false, std::memory_order_release);
  }
};

} // namespace ddos_samurai
