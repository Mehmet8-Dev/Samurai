#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <cstring>
#include <algorithm>
#include <time.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <x86intrin.h>
#endif

namespace ddos_samurai::telecom {

bool HierarchicalTimingWheel::IsInvariantTscSupported() noexcept {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    unsigned int max_ext = __get_cpuid_max(0x80000000U, nullptr);
    if (max_ext >= 0x80000007U) {
        if (__get_cpuid(0x80000007U, &eax, &ebx, &ecx, &edx)) {
            return (edx & (1U << 8)) != 0; // Invariant TSC flag (bit 8)
        }
    }
    return false;
#elif defined(__aarch64__)
    return true; // Generic Timer (cntvct_el0) is architecturally invariant on ARMv8
#else
    return false;
#endif
}

uint64_t HierarchicalTimingWheel::CalibrateTscHz() noexcept {
#if defined(__x86_64__) || defined(__i386__)
    // 1. CPUID Leaf 0x15: Time Stamp Counter and Nominal Core Crystal Clock
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    unsigned int max_leaf = __get_cpuid_max(0, nullptr);
    if (max_leaf >= 0x15) {
        __cpuid(0x15, eax, ebx, ecx, edx);
        if (eax != 0 && ebx != 0 && ecx != 0) {
            uint64_t hz = (static_cast<uint64_t>(ecx) * ebx) / eax;
            if (hz >= 500000000ULL && hz <= 10000000000ULL) {
                return hz;
            }
        }
    }
#elif defined(__aarch64__)
    uint64_t arm_frq = 0;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(arm_frq));
    if (arm_frq >= 1000000ULL && arm_frq <= 10000000000ULL) {
        return arm_frq;
    }
#endif

    // 2. CLOCK_MONOTONIC kalibrasyonu (5 ms pencere)
    struct timespec ts_start, ts_end;
    if (clock_gettime(CLOCK_MONOTONIC, &ts_start) == 0) {
#if defined(__x86_64__) || defined(__i386__)
        uint64_t c_start = __builtin_ia32_rdtsc();
#elif defined(__aarch64__)
        uint64_t c_start = 0;
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(c_start));
#else
        uint64_t c_start = 0;
#endif
        struct timespec req{0, 5000000}; // 5 ms
        nanosleep(&req, nullptr);
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
#if defined(__x86_64__) || defined(__i386__)
        uint64_t c_end = __builtin_ia32_rdtsc();
#elif defined(__aarch64__)
        uint64_t c_end = 0;
        __asm__ volatile("mrs %0, cntvct_el0" : "=r"(c_end));
#else
        uint64_t c_end = 0;
#endif

        uint64_t ns_elapsed = static_cast<uint64_t>(ts_end.tv_sec - ts_start.tv_sec) * 1000000000ULL +
                              static_cast<uint64_t>(ts_end.tv_nsec - ts_start.tv_nsec);
        if (ns_elapsed > 0 && c_end > c_start) {
            uint64_t cycles = c_end - c_start;
            uint64_t hz = (static_cast<unsigned __int128>(cycles) * 1000000000ULL) / ns_elapsed;
            if (hz >= 500000000ULL && hz <= 10000000000ULL) {
                return hz;
            }
        }
    }

    return 2400000000ULL; // Güvenli 2.4 GHz varsayılan
}

HierarchicalTimingWheel::HierarchicalTimingWheel(uint64_t tsc_hz)
    : tsc_hz_(tsc_hz > 0 ? tsc_hz : CalibrateTscHz()),
      tsc_per_ms_(tsc_hz_ / 1000ULL) {
    if (tsc_per_ms_ == 0) tsc_per_ms_ = 2400000ULL;

    std::memset(tier0_, 0, sizeof(tier0_));
    std::memset(tier1_, 0, sizeof(tier1_));
    std::memset(tier2_, 0, sizeof(tier2_));
}

HierarchicalTimingWheel::~HierarchicalTimingWheel() {
    // Tüm aktif bağlantıları sıfırla
    for (size_t i = 0; i < TIER0_SLOTS; ++i) {
        TelcoSessionContext* curr = tier0_[i];
        while (curr) {
            TelcoSessionContext* next = curr->wheel_next;
            curr->wheel_prev = nullptr;
            curr->wheel_next = nullptr;
            curr->in_wheel = 0;
            curr = next;
        }
        tier0_[i] = nullptr;
    }
    for (size_t i = 0; i < TIER1_SLOTS; ++i) {
        TelcoSessionContext* curr = tier1_[i];
        while (curr) {
            TelcoSessionContext* next = curr->wheel_next;
            curr->wheel_prev = nullptr;
            curr->wheel_next = nullptr;
            curr->in_wheel = 0;
            curr = next;
        }
        tier1_[i] = nullptr;
    }
    for (size_t i = 0; i < TIER2_SLOTS; ++i) {
        TelcoSessionContext* curr = tier2_[i];
        while (curr) {
            TelcoSessionContext* next = curr->wheel_next;
            curr->wheel_prev = nullptr;
            curr->wheel_next = nullptr;
            curr->in_wheel = 0;
            curr = next;
        }
        tier2_[i] = nullptr;
    }
}

void HierarchicalTimingWheel::InsertIntoList(TelcoSessionContext** head, 
                                             TelcoSessionContext* session, 
                                             uint8_t tier, 
                                             uint16_t slot) noexcept {
    session->wheel_prev = nullptr;
    session->wheel_next = *head;
    if (*head != nullptr) {
        (*head)->wheel_prev = session;
    }
    *head = session;

    session->in_wheel = 1;
    session->wheel_tier = tier;
    session->wheel_slot = slot;
    active_timers_++;
}

void HierarchicalTimingWheel::RemoveFromList(TelcoSessionContext** head, 
                                             TelcoSessionContext* session) noexcept {
    if (session->wheel_prev != nullptr) {
        session->wheel_prev->wheel_next = session->wheel_next;
    } else if (head != nullptr && *head == session) {
        *head = session->wheel_next;
    }

    if (session->wheel_next != nullptr) {
        session->wheel_next->wheel_prev = session->wheel_prev;
    }

    session->wheel_prev = nullptr;
    session->wheel_next = nullptr;
    session->in_wheel = 0;
    session->wheel_tier = 0;
    session->wheel_slot = 0;

    if (active_timers_ > 0) {
        active_timers_--;
    }
}

void HierarchicalTimingWheel::Cancel(TelcoSessionContext* session) noexcept {
    if (!session || !session->in_wheel) return;

    if (session->wheel_tier == 1 && session->wheel_slot < TIER0_SLOTS) {
        RemoveFromList(&tier0_[session->wheel_slot], session);
    } else if (session->wheel_tier == 2 && session->wheel_slot < TIER1_SLOTS) {
        RemoveFromList(&tier1_[session->wheel_slot], session);
    } else if (session->wheel_tier == 3 && session->wheel_slot < TIER2_SLOTS) {
        RemoveFromList(&tier2_[session->wheel_slot], session);
    } else {
        session->in_wheel = 0;
    }
}

void HierarchicalTimingWheel::Schedule(TelcoSessionContext* session, uint32_t delay_ms) noexcept {
    if (!session) return;
    if (session->in_wheel) {
        Cancel(session);
    }

    if (delay_ms == 0) delay_ms = 1;

    uint64_t base_tsc = (last_tsc_ != 0) ? last_tsc_ : __builtin_ia32_rdtsc();
    session->timer_expire_tsc = base_tsc + static_cast<uint64_t>(delay_ms) * tsc_per_ms_;

    if (delay_ms < TIER0_SLOTS) {
        uint16_t slot = static_cast<uint16_t>((wheel0_idx_ + delay_ms) % TIER0_SLOTS);
        InsertIntoList(&tier0_[slot], session, 1, slot);
    } else if (delay_ms < 6400) {
        uint16_t delay_ticks = static_cast<uint16_t>(delay_ms / 100);
        uint16_t slot = static_cast<uint16_t>((wheel1_idx_ + delay_ticks) % TIER1_SLOTS);
        InsertIntoList(&tier1_[slot], session, 2, slot);
    } else {
        uint16_t delay_ticks = static_cast<uint16_t>(std::min<uint32_t>(delay_ms / 1000, TIER2_SLOTS - 1));
        uint16_t slot = static_cast<uint16_t>((wheel2_idx_ + delay_ticks) % TIER2_SLOTS);
        InsertIntoList(&tier2_[slot], session, 3, slot);
    }
}

uint32_t HierarchicalTimingWheel::Advance(uint64_t current_tsc, ExpireCallback cb) {
    if (last_tsc_ == 0) {
        last_tsc_ = current_tsc;
        return 0;
    }

    if (current_tsc <= last_tsc_) {
        return 0;
    }

    uint64_t elapsed_tsc = current_tsc - last_tsc_;
    uint32_t elapsed_ms = static_cast<uint32_t>(elapsed_tsc / tsc_per_ms_);
    if (elapsed_ms == 0) {
        return 0;
    }

    // Aşırı gecikme patlamasını çarkın tam turuyla (3600 saniye = 1 saat) sınırla
    elapsed_ms = std::min(elapsed_ms, static_cast<uint32_t>(TIER2_SLOTS * 1000u));
    uint32_t expired_count = 0;

    for (uint32_t step = 0; step < elapsed_ms; ++step) {
        uint64_t step_tsc = last_tsc_ + static_cast<uint64_t>(step + 1) * tsc_per_ms_;
        wheel0_idx_ = (wheel0_idx_ + 1) % TIER0_SLOTS;
        total_ticks_ms_++;

        // Tier 0'daki süresi dolanları boşalt
        while (tier0_[wheel0_idx_] != nullptr) {
            TelcoSessionContext* s = tier0_[wheel0_idx_];
            RemoveFromList(&tier0_[wheel0_idx_], s);
            cb(s);
            expired_count++;
        }

        // Tier 1 kontrolü: Her 100 ms gerçek zamanda kademe kaydır ve dök
        if (total_ticks_ms_ % 100 == 0) {
            wheel1_idx_ = (wheel1_idx_ + 1) % TIER1_SLOTS;
            TelcoSessionContext* list = tier1_[wheel1_idx_];
            tier1_[wheel1_idx_] = nullptr;

            while (list) {
                TelcoSessionContext* next = list->wheel_next;
                list->wheel_prev = nullptr;
                list->wheel_next = nullptr;
                list->in_wheel = 0;
                if (active_timers_ > 0) active_timers_--;

                if (list->timer_expire_tsc <= step_tsc) {
                    cb(list);
                    expired_count++;
                } else {
                    uint64_t rem_tsc = list->timer_expire_tsc - step_tsc;
                    uint32_t rem_ms = static_cast<uint32_t>(rem_tsc / tsc_per_ms_);
                    if (rem_ms == 0) rem_ms = 1;

                    if (rem_ms < TIER0_SLOTS) {
                        uint16_t slot = static_cast<uint16_t>((wheel0_idx_ + rem_ms) % TIER0_SLOTS);
                        InsertIntoList(&tier0_[slot], list, 1, slot);
                    } else {
                        uint16_t delay_ticks = static_cast<uint16_t>(rem_ms / 100);
                        uint16_t slot = static_cast<uint16_t>((wheel1_idx_ + delay_ticks) % TIER1_SLOTS);
                        InsertIntoList(&tier1_[slot], list, 2, slot);
                    }
                }
                list = next;
            }
        }

        // Tier 2 kontrolü: Her 1000 ms gerçek zamanda kademe kaydır ve dök
        if (total_ticks_ms_ % 1000 == 0) {
            wheel2_idx_ = (wheel2_idx_ + 1) % TIER2_SLOTS;
            TelcoSessionContext* list2 = tier2_[wheel2_idx_];
            tier2_[wheel2_idx_] = nullptr;

            while (list2) {
                TelcoSessionContext* next2 = list2->wheel_next;
                list2->wheel_prev = nullptr;
                list2->wheel_next = nullptr;
                list2->in_wheel = 0;
                if (active_timers_ > 0) active_timers_--;

                if (list2->timer_expire_tsc <= step_tsc) {
                    cb(list2);
                    expired_count++;
                } else {
                    uint64_t rem_tsc = list2->timer_expire_tsc - step_tsc;
                    uint32_t rem_ms = static_cast<uint32_t>(rem_tsc / tsc_per_ms_);
                    if (rem_ms == 0) rem_ms = 1;

                    if (rem_ms < TIER0_SLOTS) {
                        uint16_t slot = static_cast<uint16_t>((wheel0_idx_ + rem_ms) % TIER0_SLOTS);
                        InsertIntoList(&tier0_[slot], list2, 1, slot);
                    } else if (rem_ms < 6400) {
                        uint16_t delay_ticks = static_cast<uint16_t>(rem_ms / 100);
                        uint16_t slot = static_cast<uint16_t>((wheel1_idx_ + delay_ticks) % TIER1_SLOTS);
                        InsertIntoList(&tier1_[slot], list2, 2, slot);
                    } else {
                        uint16_t delay_ticks = static_cast<uint16_t>(std::min<uint32_t>(rem_ms / 1000, TIER2_SLOTS - 1));
                        uint16_t slot = static_cast<uint16_t>((wheel2_idx_ + delay_ticks) % TIER2_SLOTS);
                        InsertIntoList(&tier2_[slot], list2, 3, slot);
                    }
                }
                list2 = next2;
            }
        }
    }

    last_tsc_ += static_cast<uint64_t>(elapsed_ms) * tsc_per_ms_;
    return expired_count;
}

} // namespace ddos_samurai::telecom
