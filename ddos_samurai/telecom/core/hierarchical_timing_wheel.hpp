#pragma once

#include "ddos_samurai/telecom/core/session_context.hpp"

#include <cstdint>
#include <cstddef>
#include <functional>
#include <atomic>

namespace ddos_samurai::telecom {

class HierarchicalTimingWheel {
public:
    static constexpr size_t TIER0_SLOTS = 1024; // 1ms çözünürlük (0 - 1023 ms)
    static constexpr size_t TIER1_SLOTS = 64;   // 100ms çözünürlük (0 - 6.4 s)
    static constexpr size_t TIER2_SLOTS = 3600; // 1s çözünürlük (0 - 3600 s)

    using ExpireCallback = std::function<void(TelcoSessionContext*)>;

    explicit HierarchicalTimingWheel(uint64_t tsc_hz = 0);
    ~HierarchicalTimingWheel();

    // Donanım TSC Kalibrasyonu (CPUID leaf 0x15/0x16 + CLOCK_MONOTONIC fallback)
    static uint64_t CalibrateTscHz() noexcept;
    static bool IsInvariantTscSupported() noexcept;

    HierarchicalTimingWheel(const HierarchicalTimingWheel&) = delete;
    HierarchicalTimingWheel& operator=(const HierarchicalTimingWheel&) = delete;

    // Oturumu belirli bir gecikmeyle (milisaniye) çarka bağla (O(1))
    void Schedule(TelcoSessionContext* session, uint32_t delay_ms) noexcept;

    // Oturumu çarktan çıkar (O(1))
    void Cancel(TelcoSessionContext* session) noexcept;

    // Her çalışma döngüsünde TSC ile çağrılır; süresi dolanları tetikler
    uint32_t Advance(uint64_t current_tsc, ExpireCallback cb);

    uint64_t GetTscHz() const noexcept { return tsc_hz_; }
    uint64_t GetTscPerMs() const noexcept { return tsc_per_ms_; }
    uint32_t GetActiveTimers() const noexcept { return active_timers_; }

private:
    uint64_t tsc_hz_;
    uint64_t tsc_per_ms_;
    uint64_t last_tsc_{0};
    uint64_t total_ticks_ms_{0};

    uint32_t wheel0_idx_{0};
    uint32_t wheel1_idx_{0};
    uint32_t wheel2_idx_{0};

    uint32_t active_timers_{0};

    TelcoSessionContext* tier0_[TIER0_SLOTS]{nullptr};
    TelcoSessionContext* tier1_[TIER1_SLOTS]{nullptr};
    TelcoSessionContext* tier2_[TIER2_SLOTS]{nullptr};

    void InsertIntoList(TelcoSessionContext** head, TelcoSessionContext* session, uint8_t tier, uint16_t slot) noexcept;
    void RemoveFromList(TelcoSessionContext** head, TelcoSessionContext* session) noexcept;
};

} // namespace ddos_samurai::telecom
