#ifndef SAMURAI_TSC_H
#define SAMURAI_TSC_H

#include <stdint.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>

static inline uint64_t samurai_rdtsc(void)
{
#if defined(__x86_64__)
    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | (uint64_t)lo;
#else
    unsigned long long v = 0ULL;
    __asm__ volatile("rdtsc" : "=A"(v));
    return (uint64_t)v;
#endif
}

static inline int samurai_tsc_invariant_supported(void)
{
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    unsigned int max_ext = __get_cpuid_max(0x80000000U, NULL);
    if (max_ext < 0x80000007U) {
        return 0;
    }
    if (!__get_cpuid(0x80000007U, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }
    return (edx & (1U << 8)) ? 1 : 0;
}

#elif defined(__aarch64__)

static inline uint64_t samurai_rdtsc(void)
{
    uint64_t v = 0;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static inline uint64_t samurai_arm_cntfrq(void)
{
    uint64_t freq = 0;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    return freq;
}

static inline int samurai_tsc_invariant_supported(void)
{
    // Generic Timer (cntvct_el0) on ARMv8 is architecturally invariant.
    return 1;
}

#else

static inline uint64_t samurai_rdtsc(void)
{
    return 0ULL;
}

static inline int samurai_tsc_invariant_supported(void)
{
    return 0;
}

#endif

#endif /* SAMURAI_TSC_H */
