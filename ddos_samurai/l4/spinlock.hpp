#pragma once
#include <atomic>
#if defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#endif

namespace ddos_samurai {
class SpinLock {
  std::atomic_flag flag = ATOMIC_FLAG_INIT;
public:
  void lock() {
    while (flag.test_and_set(std::memory_order_acquire)) {
#if defined(__i386__) || defined(__x86_64__)
      _mm_pause();
#endif
    }
  }
  void unlock() {
    flag.clear(std::memory_order_release);
  }
};
} // namespace ddos_samurai
