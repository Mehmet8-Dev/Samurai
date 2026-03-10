/**
 * Samurai — Deterministic Pacing Engine (C Extension)
 * ======================================================
 *
 * Nanosecond-precision packet pacing using:
 *   1. clock_gettime(CLOCK_MONOTONIC) for monotonic timestamps
 *   2. Hybrid busy-wait + clock_nanosleep for gap control
 *   3. Token bucket rate limiter with burst support
 *   4. SO_TXTIME/ETF kernel offload (when available)
 *   5. Jitter distribution models (uniform, gaussian, exponential)
 *   6. Per-send IPG histogram and jitter statistics
 *
 * Build:
 *   gcc -O2 -Wall -fPIC -shared $(python3-config --includes) \
 *       -o pacing_engine$(python3-config --extension-suffix) \
 *       pacing_engine.c -lpthread -lm $(python3-config --ldflags)
 *
 * Copyright (c) 2026 Samurai — research / authorised testing only.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <sched.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/uio.h>

/* Linux-specific headers */
#include <linux/if_packet.h>
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>

/* ========================================================================== */
/* Constants                                                                  */
/* ========================================================================== */

#define BATCH_SIZE              1024
#define HISTOGRAM_BINS          128
#define HISTOGRAM_BIN_WIDTH_NS  500          /* 0.5 µs per bin → 64 µs range */
#define PERCENTILE_SLOTS        8192         /* ring buffer for p99 calc      */
#define CALIBRATION_ITERS       1000

/* Jitter models */
#define JITTER_NONE             0
#define JITTER_UNIFORM          1
#define JITTER_GAUSSIAN         2
#define JITTER_EXPONENTIAL      3

/* Pacing modes */
#define PACING_NONE             0  /* fire-and-forget, no delay          */
#define PACING_RPS              1  /* target rate  (packets / second)    */
#define PACING_IPG              2  /* fixed inter-packet gap (ns)        */
#define PACING_BURST            3  /* burst_size pkts, burst_gap wait    */

typedef enum {
    AFPKT_HP_OFF = 0,
    AFPKT_HP_AUTO = 1,
    AFPKT_HP_REQUIRED = 2,
} afpacket_hp_mode_t;

typedef struct {
    afpacket_hp_mode_t mode;
    int hugepage_size_kb;
    int ring_target_mb;
    int mlock_ring;
    int prefault_ring;
    int block_size_kb;
    int frame_size;
    int frames_per_block;
    int poll_timeout_ms;
    int spin_limit;
    int busy_poll_us;
    int qdisc_bypass;
} txring_hugepage_policy_t;

typedef struct {
    int mode;
    int effective;
    int madvise_ok;
    int mlock_ok;
    uint64_t prefault_pages;
    uint64_t smaps_kernel_page_kb;
    uint64_t smaps_anon_hugepages_kb;
    char reason[96];
} txring_hugepage_runtime_t;

static txring_hugepage_policy_t g_txring_hp_policy = {
    .mode = AFPKT_HP_OFF,
    .hugepage_size_kb = 2048,
    .ring_target_mb = 64,
    .mlock_ring = 0,
    .prefault_ring = 1,
    .block_size_kb = 0,
    .frame_size = 0,
    .frames_per_block = 64,
    .poll_timeout_ms = 1,
    .spin_limit = 2000,
    .busy_poll_us = 0,
    .qdisc_bypass = 1,
};

static int env_truthy(const char* value)
{
    if (!value || !value[0]) return 0;
    return (
        strcmp(value, "1") == 0 ||
        strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "on") == 0
    );
}

static afpacket_hp_mode_t parse_afpacket_hp_mode(const char* raw)
{
    if (!raw || !raw[0]) return AFPKT_HP_OFF;
    if (
        strcasecmp(raw, "required") == 0 ||
        strcasecmp(raw, "strict") == 0 ||
        strcasecmp(raw, "must") == 0 ||
        strcasecmp(raw, "hard") == 0
    ) {
        return AFPKT_HP_REQUIRED;
    }
    if (
        strcasecmp(raw, "auto") == 0 ||
        strcasecmp(raw, "on") == 0 ||
        strcasecmp(raw, "enable") == 0 ||
        strcmp(raw, "1") == 0
    ) {
        return AFPKT_HP_AUTO;
    }
    return AFPKT_HP_OFF;
}

static const char* afpacket_hp_mode_name(int mode)
{
    switch (mode) {
        case AFPKT_HP_REQUIRED: return "required";
        case AFPKT_HP_AUTO: return "auto";
        default: return "off";
    }
}

static int env_int_default(const char* name, int fallback)
{
    const char* raw = getenv(name);
    char* endptr = NULL;
    long v;
    if (!raw || !raw[0]) return fallback;
    errno = 0;
    v = strtol(raw, &endptr, 10);
    if (errno != 0 || endptr == raw || (endptr && *endptr != '\0')) return fallback;
    if (v <= 0 || v > (1 << 20)) return fallback;
    return (int)v;
}

static int env_int_range(const char* name, int fallback, int min_v, int max_v)
{
    const char* raw = getenv(name);
    char* endptr = NULL;
    long v;
    if (!raw || !raw[0]) return fallback;
    errno = 0;
    v = strtol(raw, &endptr, 10);
    if (errno != 0 || endptr == raw || (endptr && *endptr != '\0')) return fallback;
    if (v < (long)min_v || v > (long)max_v) return fallback;
    return (int)v;
}

static inline unsigned int align_up_u32(unsigned int value, unsigned int align)
{
    if (align == 0U) return value;
    return ((value + align - 1U) / align) * align;
}

static unsigned int next_pow2_u32(unsigned int value)
{
    if (value <= 1U) return 1U;
    value--;
    value |= value >> 1U;
    value |= value >> 2U;
    value |= value >> 4U;
    value |= value >> 8U;
    value |= value >> 16U;
    return value + 1U;
}

static void load_txring_hugepage_policy_from_env(void)
{
    g_txring_hp_policy.mode = parse_afpacket_hp_mode(getenv("SAMURAI_AF_PACKET_HUGEPAGE_MODE"));
    g_txring_hp_policy.hugepage_size_kb = env_int_default("SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB", 2048);
    g_txring_hp_policy.ring_target_mb = env_int_default("SAMURAI_AF_PACKET_RING_TARGET_MB", 64);
    g_txring_hp_policy.mlock_ring = env_truthy(getenv("SAMURAI_AF_PACKET_MLOCK_RING")) ? 1 : 0;
    g_txring_hp_policy.prefault_ring = env_truthy(getenv("SAMURAI_AF_PACKET_PREFAULT_RING")) ? 1 : 0;
    g_txring_hp_policy.block_size_kb = env_int_range("SAMURAI_AF_PACKET_BLOCK_SIZE_KB", 0, 0, 262144);
    g_txring_hp_policy.frame_size = env_int_range("SAMURAI_AF_PACKET_FRAME_SIZE", 0, 0, 262144);
    g_txring_hp_policy.frames_per_block = env_int_range("SAMURAI_AF_PACKET_FRAMES_PER_BLOCK", 64, 1, 4096);
    g_txring_hp_policy.poll_timeout_ms = env_int_range("SAMURAI_AF_PACKET_POLL_TIMEOUT_MS", 1, 0, 1000);
    g_txring_hp_policy.spin_limit = env_int_range("SAMURAI_AF_PACKET_SPIN_LIMIT", 2000, 0, 1000000);
    g_txring_hp_policy.busy_poll_us = env_int_range("SAMURAI_AF_PACKET_BUSY_POLL_US", 0, 0, 1000000);
    g_txring_hp_policy.qdisc_bypass = env_int_range("SAMURAI_AF_PACKET_QDISC_BYPASS", 1, 0, 1);
}

/* SO_TXTIME (kernel ≥ 4.19) */
#ifndef SO_TXTIME
#define SO_TXTIME               61
#endif
#ifndef SCM_TXTIME
#define SCM_TXTIME              SO_TXTIME
#endif

/* SOF_TXTIME flags */
#ifndef SOF_TXTIME_DEADLINE_MODE
#define SOF_TXTIME_DEADLINE_MODE   (1 << 0)
#endif
#ifndef SOF_TXTIME_REPORT_ERRORS
#define SOF_TXTIME_REPORT_ERRORS   (1 << 1)
#endif

/* ========================================================================== */
/* Statistics                                                                 */
/* ========================================================================== */

typedef struct {
    /* counters */
    uint64_t total_packets;
    uint64_t total_bytes;

    /* wall-clock */
    double   elapsed_ns;

    /* inter-packet gap */
    uint64_t ipg_min_ns;
    uint64_t ipg_max_ns;
    double   ipg_sum_ns;
    double   ipg_sum_sq_ns;          /* Welford's online variance */
    uint64_t ipg_count;

    /* IPG histogram (bins of HISTOGRAM_BIN_WIDTH_NS) */
    uint64_t ipg_histogram[HISTOGRAM_BINS];

    /* jitter = |actual_ipg − intended_ipg| */
    double   jitter_min_ns;
    double   jitter_max_ns;
    double   jitter_sum_ns;
    double   jitter_sum_sq_ns;
    uint64_t jitter_count;

    /* target / actual rate */
    double   target_rps;
    double   actual_rps;
    double   rate_accuracy_pct;

    /* wait strategy counters */
    uint64_t busywait_cycles;
    uint64_t sleep_calls;
    uint64_t total_wait_ns;

    /* SO_TXTIME */
    int      so_txtime_active;
    uint64_t txtime_errors;

    /* L2/TX_RING flush + drop visibility */
    uint64_t txring_flush_call_count;
    uint64_t txring_flush_error_count;
    uint64_t txring_flush_eagain_count;
    uint64_t txring_flush_enobufs_count;
    uint64_t txring_flush_ebusy_count;
    uint64_t txring_flush_other_errno_count;
    int      txring_flush_last_errno;
    uint64_t txring_frame_wait_ns;
    uint64_t txring_poll_count;
    uint64_t txring_tp_packets;
    uint64_t txring_tp_drops;
    uint64_t txring_tp_freeze_q_cnt;
    int      txring_packet_version;
    int      afpacket_hugepage_mode;
    int      afpacket_hugepage_effective;
    int      afpacket_hugepage_size_kb;
    int      afpacket_madvise_hugepage_ok;
    int      afpacket_mlock_ok;
    uint64_t afpacket_prefault_pages;
    uint64_t afpacket_smaps_kernel_page_kb;
    uint64_t afpacket_smaps_anon_hugepages_kb;
    uint64_t afpacket_ring_block_size;
    uint64_t afpacket_ring_block_nr;
    uint64_t afpacket_ring_size_bytes;
    char     afpacket_hugepage_reason[96];

    /* calibration */
    uint64_t syscall_overhead_ns;
    uint64_t sleep_overhead_ns;

    /* percentile ring (most recent jitter values, ns) */
    uint64_t pct_ring[PERCENTILE_SLOTS];
    uint32_t pct_ring_idx;
    uint32_t pct_ring_len;            /* how many slots filled so far */
} pacing_stats_t;

static pacing_stats_t g_stats;
static pthread_mutex_t g_stats_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_calib_syscall_overhead_ns = 0;
static uint64_t g_calib_sleep_overhead_ns = 0;

/* ========================================================================== */
/* High-Precision Timing                                                      */
/* ========================================================================== */

static inline uint64_t time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* TAI clock for SO_TXTIME (requires CLOCK_TAI support) */
static inline uint64_t time_tai_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_TAI, &ts) < 0) {
        /* fallback to MONOTONIC if TAI unavailable */
        clock_gettime(CLOCK_MONOTONIC, &ts);
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * Hybrid precision wait.
 *
 * Strategy:
 *   gap >  100 µs  →  clock_nanosleep until  gap − threshold,  then spin
 *   gap 1–100 µs   →  spin (PAUSE hint)
 *   gap <  1 µs    →  no-op (already past)
 *
 * The threshold is calibrated at module load to account for wakeup latency.
 */
static uint64_t g_spin_threshold_ns = 15000;   /* default 15 µs; recalibrated */

static inline void precision_wait(uint64_t target_ns)
{
    uint64_t now = time_ns();
    if (now >= target_ns) return;

    uint64_t remaining = target_ns - now;

    /* Phase 1: kernel sleep for the "bulk" of the wait */
    if (remaining > g_spin_threshold_ns + 5000) {
        struct timespec ts;
        uint64_t wake_at = target_ns - g_spin_threshold_ns;
        ts.tv_sec  = wake_at / 1000000000ULL;
        ts.tv_nsec = wake_at % 1000000000ULL;
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);
        g_stats.sleep_calls++;
    }

    /* Phase 2: spin-wait with PAUSE hint */
    while (time_ns() < target_ns) {
#if defined(__x86_64__) || defined(__i386__)
        __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
        __asm__ volatile("yield" ::: "memory");
#else
        __asm__ volatile("" ::: "memory");
#endif
        g_stats.busywait_cycles++;
    }
}

/* ========================================================================== */
/* PRNG — Xorshift128+ (fast, sufficient quality for jitter)                  */
/* ========================================================================== */

static __thread uint64_t s_rng[2];
static __thread int       s_rng_seeded = 0;

static inline void rng_seed(void)
{
    if (s_rng_seeded) return;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    s_rng[0] = (uint64_t)ts.tv_nsec ^ (uint64_t)(uintptr_t)&ts;
    s_rng[1] = s_rng[0] * 6364136223846793005ULL + 1442695040888963407ULL;
    if (!s_rng[0]) s_rng[0] = 0xDEADBEEFCAFEBABE;
    if (!s_rng[1]) s_rng[1] = 0xCAFEBABEDEADBEEF;
    s_rng_seeded = 1;
}

static inline uint64_t xorshift128plus(void)
{
    uint64_t a = s_rng[0];
    uint64_t b = s_rng[1];
    s_rng[0] = b;
    a ^= a << 23;
    s_rng[1] = a ^ b ^ (a >> 17) ^ (b >> 26);
    return s_rng[1] + b;
}

/* uniform in [0, 1) */
static inline double rng_uniform(void)
{
    return (double)(xorshift128plus() >> 11) * (1.0 / 9007199254740992.0);
}

/* Box-Muller Gaussian N(mean, σ) */
static inline double rng_gaussian(double mean, double sigma)
{
    double u1 = rng_uniform();
    double u2 = rng_uniform();
    if (u1 < 1e-100) u1 = 1e-100;
    return mean + sigma * sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
}

/* Exponential Exp(λ=1/mean) */
static inline double rng_exponential(double mean)
{
    double u = rng_uniform();
    if (u < 1e-100) u = 1e-100;
    return -mean * log(u);
}

/* ========================================================================== */
/* Jitter Calculation                                                         */
/* ========================================================================== */

static inline int64_t calc_jitter_ns(uint64_t base_ns, int model, double pct)
{
    if (model == JITTER_NONE || pct <= 0.0 || base_ns == 0) return 0;

    double bound = (double)base_ns * pct;
    double j = 0.0;

    switch (model) {
    case JITTER_UNIFORM:
        j = bound * (2.0 * rng_uniform() - 1.0);       /* ±bound */
        break;
    case JITTER_GAUSSIAN:
        j = rng_gaussian(0.0, bound / 3.0);             /* 99.7 % in ±bound */
        if (j >  bound) j =  bound;
        if (j < -bound) j = -bound;
        break;
    case JITTER_EXPONENTIAL:
        j = rng_exponential(bound * 0.5) - bound * 0.5; /* centre around 0 */
        if (j >  bound) j =  bound;
        if (j < -bound) j = -bound;
        break;
    }
    return (int64_t)j;
}

static inline uint64_t abs_i64_to_u64(int64_t v)
{
    if (v >= 0) return (uint64_t)v;
    return (uint64_t)(-(v + 1)) + 1ULL;
}

static inline uint64_t add_saturating_u64(uint64_t a, uint64_t b)
{
    if (a > UINT64_MAX - b) return UINT64_MAX;
    return a + b;
}

static inline uint64_t add_jitter_saturating_u64(uint64_t base, int64_t jitter)
{
    if (jitter >= 0) {
        uint64_t uj = (uint64_t)jitter;
        if (base > UINT64_MAX - uj) return UINT64_MAX;
        return base + uj;
    }
    uint64_t neg = abs_i64_to_u64(jitter);
    if (neg >= base) return 0;
    return base - neg;
}

/* ========================================================================== */
/* Token Bucket Rate Limiter                                                  */
/* ========================================================================== */

typedef struct {
    double   tokens;
    double   max_tokens;
    double   refill_rate;     /* tokens per ns  (= target_rps / 1e9) */
    uint64_t last_refill_ns;
} token_bucket_t;

static inline void tb_init(token_bucket_t *tb, double rps, double burst)
{
    tb->tokens        = burst;
    tb->max_tokens    = burst;
    tb->refill_rate   = rps / 1e9;
    tb->last_refill_ns = time_ns();
}

static inline int tb_try_consume(token_bucket_t *tb, uint64_t now_ns)
{
    double elapsed = (double)(now_ns - tb->last_refill_ns);
    tb->tokens += elapsed * tb->refill_rate;
    if (tb->tokens > tb->max_tokens) tb->tokens = tb->max_tokens;
    tb->last_refill_ns = now_ns;

    if (tb->tokens >= 1.0) {
        tb->tokens -= 1.0;
        return 1;
    }
    return 0;
}

/* ========================================================================== */
/* SO_TXTIME helpers                                                          */
/* ========================================================================== */

/**
 * Attempt to enable SO_TXTIME on a raw socket.
 * Returns 1 on success, 0 if unsupported.
 */
static int enable_so_txtime(int fd)
{
    struct {
        int32_t clockid;
        uint32_t flags;
    } txtime_cfg;

    txtime_cfg.clockid = CLOCK_TAI;
    txtime_cfg.flags   = SOF_TXTIME_REPORT_ERRORS;

    if (setsockopt(fd, SOL_SOCKET, SO_TXTIME,
                   &txtime_cfg, sizeof(txtime_cfg)) < 0) {
        return 0;   /* kernel too old or unsupported */
    }
    return 1;
}

/**
 * Send one packet with SCM_TXTIME ancillary data.
 */
static int send_with_txtime(int fd, const void *pkt, size_t len,
                            const struct sockaddr *addr, socklen_t addrlen,
                            uint64_t txtime_ns)
{
    struct iovec iov = { .iov_base = (void *)pkt, .iov_len = len };

    /* ancillary data: SCM_TXTIME carries a uint64_t */
    char cmsgbuf[CMSG_SPACE(sizeof(uint64_t))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name    = (void *)addr;
    msg.msg_namelen = addrlen;
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    msg.msg_control    = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_TXTIME;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(uint64_t));
    *(uint64_t *)CMSG_DATA(cmsg) = txtime_ns;

    int ret = sendmsg(fd, &msg, 0);
    return ret;
}

/* ========================================================================== */
/* Statistics helpers                                                         */
/* ========================================================================== */

static inline void stats_record_ipg(uint64_t actual_ns, uint64_t intended_ns)
{
    /* IPG min / max / moments */
    if (actual_ns < g_stats.ipg_min_ns) g_stats.ipg_min_ns = actual_ns;
    if (actual_ns > g_stats.ipg_max_ns) g_stats.ipg_max_ns = actual_ns;
    g_stats.ipg_sum_ns    += (double)actual_ns;
    g_stats.ipg_sum_sq_ns += (double)actual_ns * (double)actual_ns;
    g_stats.ipg_count++;

    /* IPG histogram */
    uint64_t bin = actual_ns / HISTOGRAM_BIN_WIDTH_NS;
    if (bin >= HISTOGRAM_BINS) bin = HISTOGRAM_BINS - 1;
    g_stats.ipg_histogram[bin]++;

    /* jitter = |actual − intended| */
    if (intended_ns > 0) {
        double diff = (double)actual_ns - (double)intended_ns;
        double absdiff = diff < 0 ? -diff : diff;
        if (g_stats.jitter_count == 0 || absdiff < g_stats.jitter_min_ns)
            g_stats.jitter_min_ns = absdiff;
        if (absdiff > g_stats.jitter_max_ns)
            g_stats.jitter_max_ns = absdiff;
        g_stats.jitter_sum_ns    += absdiff;
        g_stats.jitter_sum_sq_ns += absdiff * absdiff;
        g_stats.jitter_count++;

        /* percentile ring */
        uint32_t idx = g_stats.pct_ring_idx % PERCENTILE_SLOTS;
        g_stats.pct_ring[idx] = (uint64_t)absdiff;
        g_stats.pct_ring_idx++;
        if (g_stats.pct_ring_len < PERCENTILE_SLOTS)
            g_stats.pct_ring_len++;
    }
}

static void stats_reset(double target_rps)
{
    memset(&g_stats, 0, sizeof(g_stats));
    g_stats.target_rps  = target_rps;
    g_stats.ipg_min_ns  = UINT64_MAX;
    g_stats.jitter_min_ns = 1e18;
    g_stats.afpacket_hugepage_mode = AFPKT_HP_OFF;
    g_stats.afpacket_hugepage_effective = 0;
    g_stats.afpacket_hugepage_size_kb = 0;
    g_stats.afpacket_madvise_hugepage_ok = 0;
    g_stats.afpacket_mlock_ok = 0;
    g_stats.afpacket_prefault_pages = 0ULL;
    g_stats.afpacket_smaps_kernel_page_kb = 0ULL;
    g_stats.afpacket_smaps_anon_hugepages_kb = 0ULL;
    g_stats.afpacket_ring_block_size = 0ULL;
    g_stats.afpacket_ring_block_nr = 0ULL;
    g_stats.afpacket_ring_size_bytes = 0ULL;
    (void)snprintf(g_stats.afpacket_hugepage_reason, sizeof(g_stats.afpacket_hugepage_reason), "%s", "disabled");
    g_stats.syscall_overhead_ns = g_calib_syscall_overhead_ns;
    g_stats.sleep_overhead_ns = g_calib_sleep_overhead_ns;
}

/* qsort comparator for p99 */
static int cmp_u64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static double stats_percentile_from_ring(const uint64_t *ring, uint32_t n, double pct)
{
    if (n == 0 || ring == NULL) return 0.0;

    /* copy ring to tmp for sorting */
    uint64_t *tmp = (uint64_t *)malloc(n * sizeof(uint64_t));
    if (!tmp) return 0.0;
    memcpy(tmp, ring, n * sizeof(uint64_t));
    qsort(tmp, n, sizeof(uint64_t), cmp_u64);

    uint32_t idx = (uint32_t)((pct / 100.0) * (n - 1));
    if (idx >= n) idx = n - 1;
    double val = (double)tmp[idx];
    free(tmp);
    return val;
}

static void stats_finalize(void)
{
    if (g_stats.elapsed_ns > 0) {
        g_stats.actual_rps = g_stats.total_packets / (g_stats.elapsed_ns / 1e9);
        if (g_stats.target_rps > 0)
            g_stats.rate_accuracy_pct =
                (g_stats.actual_rps / g_stats.target_rps) * 100.0;
    }
}

/* ========================================================================== */
/* Calibration — measure timing overhead at module init                       */
/* ========================================================================== */

static void calibrate_timing(void)
{
    /* syscall overhead → clock_gettime latency */
    uint64_t sum = 0;
    for (int i = 0; i < CALIBRATION_ITERS; i++) {
        uint64_t t0 = time_ns();
        uint64_t t1 = time_ns();
        sum += (t1 - t0);
    }
    g_calib_syscall_overhead_ns = sum / CALIBRATION_ITERS;

    /* sleep overhead → clock_nanosleep wakeup latency */
    sum = 0;
    struct timespec req;
    for (int i = 0; i < 100; i++) {
        uint64_t target = time_ns() + 1000;    /* request 1 µs sleep */
        req.tv_sec  = target / 1000000000ULL;
        req.tv_nsec = target % 1000000000ULL;
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL);
        uint64_t actual = time_ns();
        sum += (actual - target);               /* overshoot */
    }
    g_calib_sleep_overhead_ns = sum / 100;

    /* set spin threshold = max(15 µs, 2× sleep overshoot) */
    uint64_t overshoot2x = g_calib_sleep_overhead_ns * 2;
    g_spin_threshold_ns = overshoot2x > 15000 ? overshoot2x : 15000;

    pthread_mutex_lock(&g_stats_lock);
    g_stats.syscall_overhead_ns = g_calib_syscall_overhead_ns;
    g_stats.sleep_overhead_ns = g_calib_sleep_overhead_ns;
    pthread_mutex_unlock(&g_stats_lock);
}

/* ========================================================================== */
/* TX_RING Context (for L2 paced sender)                                      */
/* ========================================================================== */

typedef struct {
    int       sock;
    char     *map;
    size_t    ring_size;
    int       packet_version;
    size_t    frame_header_size;
    struct tpacket_req  req_v2;
    struct tpacket_req3 req_v3;
    char      iface[IFNAMSIZ];
    int       is_setup;
    unsigned  frame_idx;
    txring_hugepage_runtime_t hp_runtime;
} ring_ctx_t;

static ring_ctx_t g_ring = {
    .is_setup = 0,
    .sock = -1,
    .map = MAP_FAILED,
    .packet_version = TPACKET_V2,
    .frame_header_size = 0,
    .hp_runtime = {
        .mode = AFPKT_HP_OFF,
        .effective = 0,
        .madvise_ok = 0,
        .mlock_ok = 0,
        .prefault_pages = 0ULL,
        .smaps_kernel_page_kb = 0ULL,
        .smaps_anon_hugepages_kb = 0ULL,
        .reason = "disabled",
    },
};

static const char *packet_version_name(int version)
{
    switch (version) {
        case TPACKET_V3: return "TPACKET_V3";
        case TPACKET_V2: return "TPACKET_V2";
        default: return "TPACKET_UNKNOWN";
    }
}

static int set_packet_version_or_fallback(int sock)
{
    int version = TPACKET_V3;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) == 0) {
        return version;
    }
    version = TPACKET_V2;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) == 0) {
        return version;
    }
    return -1;
}

static size_t frame_header_size_for_version(int version)
{
    if (version == TPACKET_V3) {
        return TPACKET_ALIGN(sizeof(struct tpacket3_hdr));
    }
    return TPACKET_ALIGN(sizeof(struct tpacket2_hdr));
}

static inline unsigned ring_frame_size(void)
{
    if (g_ring.packet_version == TPACKET_V3) {
        return g_ring.req_v3.tp_frame_size;
    }
    return g_ring.req_v2.tp_frame_size;
}

static inline unsigned ring_frame_nr(void)
{
    if (g_ring.packet_version == TPACKET_V3) {
        return g_ring.req_v3.tp_frame_nr;
    }
    return g_ring.req_v2.tp_frame_nr;
}

static inline uint32_t ring_tx_frame_status(void *frame_base)
{
    if (g_ring.packet_version == TPACKET_V3) {
        return ((struct tpacket3_hdr *)frame_base)->tp_status;
    }
    return ((struct tpacket2_hdr *)frame_base)->tp_status;
}

static inline void ring_tx_frame_prepare(void *frame_base, int packet_size)
{
    if (g_ring.packet_version == TPACKET_V3) {
        struct tpacket3_hdr *hdr = (struct tpacket3_hdr *)frame_base;
        hdr->tp_next_offset = 0;
        hdr->tp_len = (uint32_t)packet_size;
        hdr->tp_snaplen = (uint32_t)packet_size;
        hdr->tp_mac = (uint16_t)g_ring.frame_header_size;
        hdr->tp_net = (uint16_t)(g_ring.frame_header_size + 14);
        __sync_synchronize();
        hdr->tp_status = TP_STATUS_SEND_REQUEST;
        return;
    }

    struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)frame_base;
    hdr->tp_len = (uint32_t)packet_size;
    hdr->tp_snaplen = (uint32_t)packet_size;
    hdr->tp_mac = (uint16_t)g_ring.frame_header_size;
    hdr->tp_net = (uint16_t)(g_ring.frame_header_size + 14);
    __sync_synchronize();
    hdr->tp_status = TP_STATUS_SEND_REQUEST;
}

static int probe_smaps_hugepage_info(
    const void* addr,
    uint64_t* out_kernel_page_kb,
    uint64_t* out_anon_hugepages_kb
)
{
    FILE* fp = NULL;
    char line[256];
    uint64_t a = (uint64_t)(uintptr_t)addr;
    int in_region = 0;
    int found = 0;

    if (out_kernel_page_kb) *out_kernel_page_kb = 0ULL;
    if (out_anon_hugepages_kb) *out_anon_hugepages_kb = 0ULL;

    fp = fopen("/proc/self/smaps", "r");
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long start = 0ULL;
        unsigned long long end = 0ULL;
        if (sscanf(line, "%llx-%llx", &start, &end) == 2) {
            in_region = (a >= start && a < end) ? 1 : 0;
            if (in_region) found = 1;
            continue;
        }
        if (!in_region) continue;
        if (strncmp(line, "KernelPageSize:", 15) == 0) {
            unsigned long long kb = 0ULL;
            if (sscanf(line + 15, "%llu", &kb) == 1 && out_kernel_page_kb) {
                *out_kernel_page_kb = (uint64_t)kb;
            }
        } else if (strncmp(line, "AnonHugePages:", 14) == 0) {
            unsigned long long kb = 0ULL;
            if (sscanf(line + 14, "%llu", &kb) == 1 && out_anon_hugepages_kb) {
                *out_anon_hugepages_kb = (uint64_t)kb;
            }
        }
    }

    fclose(fp);
    return found;
}

static void apply_txring_hugepage_policy(void)
{
    txring_hugepage_runtime_t* rt = &g_ring.hp_runtime;
    uint64_t huge_kb = 0ULL;
    uint64_t anon_huge_kb = 0ULL;
    int madvise_rc = -1;
    int mlock_rc = -1;
    size_t page_size;
    size_t i;
    volatile unsigned char sink = 0;

    rt->mode = g_txring_hp_policy.mode;
    rt->effective = 0;
    rt->madvise_ok = 0;
    rt->mlock_ok = 0;
    rt->prefault_pages = 0ULL;
    rt->smaps_kernel_page_kb = 0ULL;
    rt->smaps_anon_hugepages_kb = 0ULL;
    (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "disabled");

    if (!g_ring.is_setup || g_ring.map == MAP_FAILED || g_ring.ring_size == 0) {
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "ring_unavailable");
        return;
    }
    if (g_txring_hp_policy.mode == AFPKT_HP_OFF) {
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "disabled");
        return;
    }

#ifdef MADV_HUGEPAGE
    madvise_rc = madvise((void*)g_ring.map, g_ring.ring_size, MADV_HUGEPAGE);
    if (madvise_rc == 0) rt->madvise_ok = 1;
#else
    madvise_rc = -1;
#endif

    if (g_txring_hp_policy.prefault_ring) {
        page_size = (size_t)getpagesize();
        if (page_size == 0) page_size = 4096;
        for (i = 0; i < g_ring.ring_size; i += page_size) {
            sink ^= g_ring.map[i];
            rt->prefault_pages++;
        }
        (void)sink;
    }

    if (g_txring_hp_policy.mlock_ring) {
        mlock_rc = mlock((void*)g_ring.map, g_ring.ring_size);
        rt->mlock_ok = (mlock_rc == 0) ? 1 : 0;
    } else {
        mlock_rc = 0;
        rt->mlock_ok = 0;
    }

    (void)probe_smaps_hugepage_info(g_ring.map, &huge_kb, &anon_huge_kb);
    rt->smaps_kernel_page_kb = huge_kb;
    rt->smaps_anon_hugepages_kb = anon_huge_kb;
    if (anon_huge_kb > 0ULL || huge_kb >= (uint64_t)g_txring_hp_policy.hugepage_size_kb) {
        rt->effective = 1;
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "effective");
        return;
    }

    if (madvise_rc == 0) {
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "hinted_not_realized");
    } else {
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "madvise_failed");
    }
    if (g_txring_hp_policy.mlock_ring && mlock_rc != 0) {
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "mlock_failed");
    }
}

static int setup_ring(const char *iface, int pkt_size, const uint8_t *mac)
{
    load_txring_hugepage_policy_from_env();

    if (g_ring.is_setup) {
        size_t hdr = g_ring.frame_header_size;
        if (hdr == 0) {
            hdr = frame_header_size_for_version(g_ring.packet_version);
        }
        if (strcmp(g_ring.iface, iface) == 0 &&
            ring_frame_size() >= (unsigned)(pkt_size + hdr)) {
            apply_txring_hugepage_policy();
            return 0;   /* reuse */
        }
        /* teardown old */
        if (g_ring.map != MAP_FAILED)
            munmap(g_ring.map, g_ring.ring_size);
        if (g_ring.sock >= 0)
            close(g_ring.sock);
        g_ring.is_setup = 0;
        g_ring.map = MAP_FAILED;
        g_ring.sock = -1;
        g_ring.packet_version = TPACKET_V2;
        g_ring.frame_header_size = 0;
        memset(&g_ring.req_v2, 0, sizeof(g_ring.req_v2));
        memset(&g_ring.req_v3, 0, sizeof(g_ring.req_v3));
    }

    g_ring.sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_ring.sock < 0) return -1;

    g_ring.packet_version = set_packet_version_or_fallback(g_ring.sock);
    if (g_ring.packet_version < 0) {
        close(g_ring.sock);
        g_ring.sock = -1;
        return -1;
    }

    memset(&g_ring.req_v2, 0, sizeof(g_ring.req_v2));
    memset(&g_ring.req_v3, 0, sizeof(g_ring.req_v3));

    {
        unsigned int page_size = (unsigned int)getpagesize();
        unsigned int frame_min_size = 0U;
        unsigned int frame_size = 0U;
        unsigned int block_size = 0U;
        unsigned int frames_per_block = 0U;
        unsigned int block_nr = 0U;
        unsigned int frame_nr = 0U;
        unsigned int target_mb = (unsigned int)(
            g_txring_hp_policy.ring_target_mb > 0 ? g_txring_hp_policy.ring_target_mb : 64
        );
        unsigned long long target_bytes = (unsigned long long)target_mb * 1024ULL * 1024ULL;
        size_t hdr_sz = frame_header_size_for_version(g_ring.packet_version);

        if (page_size == 0U) page_size = 4096U;
        frame_min_size = (unsigned int)(pkt_size + hdr_sz);
        if (g_txring_hp_policy.frame_size > 0) {
            frame_size = (unsigned int)g_txring_hp_policy.frame_size;
        } else {
            frame_size = next_pow2_u32(frame_min_size);
        }
        frame_size = align_up_u32(frame_size, 64U);
        frame_size = (unsigned int)TPACKET_ALIGN(frame_size);
        if (frame_size < frame_min_size) {
            frame_size = align_up_u32(frame_min_size, 64U);
            frame_size = (unsigned int)TPACKET_ALIGN(frame_size);
        }

        if (g_txring_hp_policy.block_size_kb > 0) {
            block_size = (unsigned int)g_txring_hp_policy.block_size_kb * 1024U;
        } else {
            unsigned int auto_frames = (unsigned int)(
                g_txring_hp_policy.frames_per_block > 0 ? g_txring_hp_policy.frames_per_block : 64
            );
            block_size = frame_size * auto_frames;
        }
        if (block_size < frame_size) block_size = frame_size;
        block_size = align_up_u32(block_size, page_size);
        while (block_size % frame_size != 0U) {
            block_size += page_size;
        }
        frames_per_block = block_size / frame_size;
        if (frames_per_block == 0U) {
            frames_per_block = 1U;
            block_size = frame_size;
        }
        if (target_bytes < (unsigned long long)block_size) {
            target_bytes = (unsigned long long)block_size;
        }
        block_nr = (unsigned int)(
            (target_bytes + (unsigned long long)block_size - 1ULL) / (unsigned long long)block_size
        );
        if (block_nr < 64U) {
            block_nr = 64U;
        }
        frame_nr = block_nr * frames_per_block;
        if (frame_nr < block_nr) {
            frame_nr = block_nr;
        }
        g_ring.frame_header_size = hdr_sz;

        if (g_ring.packet_version == TPACKET_V3) {
            g_ring.req_v3.tp_block_size = block_size;
            g_ring.req_v3.tp_frame_size = frame_size;
            g_ring.req_v3.tp_block_nr   = block_nr;
            g_ring.req_v3.tp_frame_nr   = frame_nr;
            /* Keep RX-specific V3 fields zero for TX_RING. */
            g_ring.req_v3.tp_retire_blk_tov = 0;
            g_ring.req_v3.tp_sizeof_priv = 0;
            g_ring.req_v3.tp_feature_req_word = 0;
        } else {
            g_ring.req_v2.tp_block_size = block_size;
            g_ring.req_v2.tp_frame_size = frame_size;
            g_ring.req_v2.tp_block_nr   = block_nr;
            g_ring.req_v2.tp_frame_nr   = frame_nr;
        }
    }

    if (g_ring.packet_version == TPACKET_V3) {
        if (setsockopt(g_ring.sock, SOL_PACKET, PACKET_TX_RING,
                       &g_ring.req_v3, sizeof(g_ring.req_v3)) < 0) {
            int saved_errno = errno;
            close(g_ring.sock);
            g_ring.sock = -1;
            errno = saved_errno;
            return -1;
        }
    } else {
        if (setsockopt(g_ring.sock, SOL_PACKET, PACKET_TX_RING,
                       &g_ring.req_v2, sizeof(g_ring.req_v2)) < 0) {
            int saved_errno = errno;
            close(g_ring.sock);
            g_ring.sock = -1;
            errno = saved_errno;
            return -1;
        }
    }

    if (g_ring.packet_version == TPACKET_V3) {
        g_ring.ring_size = (size_t)g_ring.req_v3.tp_block_nr * g_ring.req_v3.tp_block_size;
    } else {
        g_ring.ring_size = (size_t)g_ring.req_v2.tp_block_nr * g_ring.req_v2.tp_block_size;
    }
    g_ring.map = mmap(NULL, g_ring.ring_size,
                      PROT_READ | PROT_WRITE, MAP_SHARED,
                      g_ring.sock, 0);
    if (g_ring.map == MAP_FAILED) {
        close(g_ring.sock);
        g_ring.sock = -1;
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = if_nametoindex(iface);
    sll.sll_halen    = ETH_ALEN;
    memcpy(sll.sll_addr, mac, 6);

    if (bind(g_ring.sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        munmap(g_ring.map, g_ring.ring_size);
        close(g_ring.sock);
        g_ring.map = MAP_FAILED;
        g_ring.sock = -1;
        return -1;
    }

    {
        int qdisc_bypass = g_txring_hp_policy.qdisc_bypass ? 1 : 0;
        (void)setsockopt(g_ring.sock, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass));
    }
#ifdef SO_BUSY_POLL
    if (g_txring_hp_policy.busy_poll_us > 0) {
        int busy_poll_us = g_txring_hp_policy.busy_poll_us;
        (void)setsockopt(g_ring.sock, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_us, sizeof(busy_poll_us));
    }
#endif

    strncpy(g_ring.iface, iface, IFNAMSIZ - 1);
    g_ring.iface[IFNAMSIZ - 1] = '\0';
    g_ring.is_setup  = 1;
    g_ring.frame_idx = 0;
    apply_txring_hugepage_policy();
    return 0;
}

static void cleanup_ring(void)
{
    if (g_ring.is_setup) {
        if (g_ring.map != MAP_FAILED)
            munmap(g_ring.map, g_ring.ring_size);
        if (g_ring.sock >= 0)
            close(g_ring.sock);
        g_ring.is_setup = 0;
        g_ring.map = MAP_FAILED;
        g_ring.sock = -1;
        g_ring.packet_version = TPACKET_V2;
        g_ring.frame_header_size = 0;
        memset(&g_ring.req_v2, 0, sizeof(g_ring.req_v2));
        memset(&g_ring.req_v3, 0, sizeof(g_ring.req_v3));
        g_ring.iface[0] = '\0';
        g_ring.frame_idx = 0;
        g_ring.hp_runtime.mode = AFPKT_HP_OFF;
        g_ring.hp_runtime.effective = 0;
        g_ring.hp_runtime.madvise_ok = 0;
        g_ring.hp_runtime.mlock_ok = 0;
        g_ring.hp_runtime.prefault_pages = 0ULL;
        g_ring.hp_runtime.smaps_kernel_page_kb = 0ULL;
        g_ring.hp_runtime.smaps_anon_hugepages_kb = 0ULL;
        (void)snprintf(g_ring.hp_runtime.reason, sizeof(g_ring.hp_runtime.reason), "%s", "disabled");
    }
}

static void drain_ring_packet_stats(void)
{
    if (!g_ring.is_setup || g_ring.sock < 0) return;

    if (g_ring.packet_version == TPACKET_V3) {
        struct tpacket_stats_v3 stats_v3;
        socklen_t optlen = sizeof(stats_v3);
        (void)getsockopt(g_ring.sock, SOL_PACKET, PACKET_STATISTICS, &stats_v3, &optlen);
        return;
    }

    struct tpacket_stats stats;
    socklen_t optlen = sizeof(stats);
    (void)getsockopt(g_ring.sock, SOL_PACKET, PACKET_STATISTICS, &stats, &optlen);
}

static void capture_ring_packet_stats(void)
{
    if (!g_ring.is_setup || g_ring.sock < 0) return;

    if (g_ring.packet_version == TPACKET_V3) {
        struct tpacket_stats_v3 stats_v3;
        socklen_t optlen = sizeof(stats_v3);
        if (getsockopt(g_ring.sock, SOL_PACKET, PACKET_STATISTICS, &stats_v3, &optlen) == 0) {
            g_stats.txring_tp_packets = (uint64_t)stats_v3.tp_packets;
            g_stats.txring_tp_drops = (uint64_t)stats_v3.tp_drops;
            g_stats.txring_tp_freeze_q_cnt = (uint64_t)stats_v3.tp_freeze_q_cnt;
        }
        return;
    }

    struct tpacket_stats stats;
    socklen_t optlen = sizeof(stats);
    if (getsockopt(g_ring.sock, SOL_PACKET, PACKET_STATISTICS, &stats, &optlen) == 0) {
        g_stats.txring_tp_packets = (uint64_t)stats.tp_packets;
        g_stats.txring_tp_drops = (uint64_t)stats.tp_drops;
        g_stats.txring_tp_freeze_q_cnt = 0ULL;
    }
}

static inline const char *flush_errno_name(int err)
{
    if (err == 0) return "NONE";
    if (err == EAGAIN || err == EWOULDBLOCK) return "EAGAIN";
#ifdef ENOBUFS
    if (err == ENOBUFS) return "ENOBUFS";
#endif
#ifdef EBUSY
    if (err == EBUSY) return "EBUSY";
#endif
    return "OTHER";
}

static inline void record_l2_flush_result(ssize_t ret)
{
    g_stats.txring_flush_call_count++;
    if (ret < 0) {
        int err = errno;
        g_stats.txring_flush_error_count++;
        g_stats.txring_flush_last_errno = err;
        if (err == EAGAIN || err == EWOULDBLOCK) {
            g_stats.txring_flush_eagain_count++;
#ifdef ENOBUFS
        } else if (err == ENOBUFS) {
            g_stats.txring_flush_enobufs_count++;
#endif
#ifdef EBUSY
        } else if (err == EBUSY) {
            g_stats.txring_flush_ebusy_count++;
#endif
        } else {
            g_stats.txring_flush_other_errno_count++;
        }
    }
}

/* ========================================================================== */
/* Python: paced_send_l3                                                      */
/*   Paced L3 sender using IPPROTO_RAW + sendmmsg + precision timing          */
/* ========================================================================== */

PyDoc_STRVAR(doc_paced_send_l3,
"paced_send_l3(buffer, target_ip, target_port, packet_size, count, *,\n"
"              target_rps=0, ipg_ns=0, burst_size=1, burst_gap_ns=0,\n"
"              jitter_model=0, jitter_pct=0.0, pacing_mode=0,\n"
"              pin_cpu=-1, use_so_txtime=False) -> int\n"
"\n"
"Send *count* packets from *buffer* with deterministic pacing.\n"
"\n"
"Pacing modes:\n"
"  0 = NONE   — burst as fast as possible (same as plain sendmmsg)\n"
"  1 = RPS    — token-bucket rate limit  (target_rps)\n"
"  2 = IPG    — fixed inter-packet gap   (ipg_ns nanoseconds)\n"
"  3 = BURST  — burst_size packets, then burst_gap_ns wait\n"
"\n"
"Jitter models (applied on top of the base gap):\n"
"  0 = NONE, 1 = UNIFORM, 2 = GAUSSIAN, 3 = EXPONENTIAL\n"
"  jitter_pct in [0.0, 1.0] = fraction of base gap as max jitter.\n"
"\n"
"Returns the number of packets successfully sent.\n"
"Statistics are stored internally; call get_pacing_stats() to retrieve.\n");

static PyObject *py_paced_send_l3(PyObject *self,
                                  PyObject *args, PyObject *kw)
{
    (void)self;
    Py_buffer  view;
    const char *target_ip;
    int         target_port, packet_size, count;

    /* keyword-only pacing parameters */
    double  target_rps     = 0.0;
    int64_t ipg_ns         = 0;
    int     burst_size     = 1;
    int64_t burst_gap_ns   = 0;
    int     jitter_model   = JITTER_NONE;
    double  jitter_pct     = 0.0;
    int     pacing_mode    = PACING_NONE;
    int     pin_cpu        = -1;
    int     use_so_txtime  = 0;

    static char *kwl[] = {
        "buffer", "target_ip", "target_port", "packet_size", "count",
        "target_rps", "ipg_ns", "burst_size", "burst_gap_ns",
        "jitter_model", "jitter_pct", "pacing_mode",
        "pin_cpu", "use_so_txtime", NULL
    };

    if (!PyArg_ParseTupleAndKeywords(
            args, kw, "y*siii|dLiLidiip", kwl,
            &view, &target_ip, &target_port, &packet_size, &count,
            &target_rps, &ipg_ns, &burst_size, &burst_gap_ns,
            &jitter_model, &jitter_pct, &pacing_mode,
            &pin_cpu, &use_so_txtime))
        return NULL;

    if (packet_size <= 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size must be > 0");
        return NULL;
    }
    if (count < 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "count must be >= 0");
        return NULL;
    }
    if (count > 0) {
        uint64_t u_packet_size = (uint64_t)packet_size;
        uint64_t u_count = (uint64_t)count;
        if (u_packet_size > UINT64_MAX / u_count) {
            PyBuffer_Release(&view);
            PyErr_SetString(PyExc_ValueError, "packet_size * count overflow");
            return NULL;
        }
        uint64_t needed = u_packet_size * u_count;
        if ((uint64_t)view.len < needed) {
            PyBuffer_Release(&view);
            PyErr_Format(
                PyExc_ValueError,
                "buffer too small: got %zu bytes, expected at least %llu",
                (size_t)view.len,
                (unsigned long long)needed
            );
            return NULL;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Setup                                                               */
    /* ------------------------------------------------------------------ */

    /* CPU pinning + real-time priority */
    if (pin_cpu >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(pin_cpu, &cpuset);
        sched_setaffinity(0, sizeof(cpuset), &cpuset);

        struct sched_param sp = { .sched_priority = 50 };
        sched_setscheduler(0, SCHED_FIFO, &sp);  /* best-effort */
    }

    /* raw socket */
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        PyBuffer_Release(&view);
        return PyErr_SetFromErrno(PyExc_OSError);
    }

    int on = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    /* SO_TXTIME */
    int txtime_ok = 0;
    if (use_so_txtime)
        txtime_ok = enable_so_txtime(sockfd);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(target_port);
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) <= 0) {
        close(sockfd);
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "Invalid target IP");
        return NULL;
    }

    /* calculate effective IPG (ns) */
    uint64_t eff_ipg = 0;
    if      (pacing_mode == PACING_IPG   && ipg_ns > 0)
        eff_ipg = (uint64_t)ipg_ns;
    else if (pacing_mode == PACING_RPS   && target_rps > 0)
        eff_ipg = (uint64_t)(1e9 / target_rps);
    else if (pacing_mode == PACING_BURST)
        eff_ipg = 0;  /* no gap inside burst; burst_gap_ns between bursts */

    /* token bucket (RPS mode fallback if precision_wait isn't used) */
    token_bucket_t tb = {0};
    if (pacing_mode == PACING_RPS && target_rps > 0)
        tb_init(&tb, target_rps, (double)(burst_size > 0 ? burst_size : 1));

    /* stats reset */
    pthread_mutex_lock(&g_stats_lock);
    stats_reset(target_rps);
    g_stats.so_txtime_active = txtime_ok;
    pthread_mutex_unlock(&g_stats_lock);

    rng_seed();

    /* ------------------------------------------------------------------ */
    /* Hot loop — GIL released                                             */
    /* ------------------------------------------------------------------ */

    const char *data = (const char *)view.buf;
    int  total_sent = 0;
    int  burst_ctr  = 0;
    int  burst_limit = burst_size > 0 ? burst_size : 1;

    Py_BEGIN_ALLOW_THREADS

    pthread_mutex_lock(&g_stats_lock);

    uint64_t t_start    = time_ns();
    uint64_t t_last     = t_start;
    uint64_t t_deadline = t_start;
    uint64_t t_burst_deadline = t_start;
    uint64_t tai_offset = 0;

    if (txtime_ok) {
        /* SO_TXTIME needs CLOCK_TAI; compute offset once */
        uint64_t mono = time_ns();
        uint64_t tai  = time_tai_ns();
        tai_offset = tai - mono;
    }

    /* sendmmsg iov + msg scratch (for single-pkt sends) */
    struct iovec   iov;
    struct mmsghdr mmsg;
    memset(&mmsg, 0, sizeof(mmsg));
    mmsg.msg_hdr.msg_name    = &addr;
    mmsg.msg_hdr.msg_namelen = sizeof(addr);
    mmsg.msg_hdr.msg_iov     = &iov;
    mmsg.msg_hdr.msg_iovlen  = 1;

    for (int i = 0; i < count; i++) {

        /* === PACING GATE === */
        switch (pacing_mode) {
        case PACING_IPG:
            if (i > 0) {
                int64_t j = calc_jitter_ns(eff_ipg, jitter_model, jitter_pct);
                t_deadline = add_saturating_u64(t_deadline, eff_ipg);
                t_deadline = add_jitter_saturating_u64(t_deadline, j);
                precision_wait(t_deadline);
            }
            break;

        case PACING_RPS:
            if (eff_ipg > 0 && i > 0) {
                int64_t j = calc_jitter_ns(eff_ipg, jitter_model, jitter_pct);
                t_deadline = add_saturating_u64(t_deadline, eff_ipg);
                t_deadline = add_jitter_saturating_u64(t_deadline, j);
                precision_wait(t_deadline);
            } else {
                /* fallback: spin on token bucket */
                uint64_t now;
                while (1) {
                    now = time_ns();
                    if (tb_try_consume(&tb, now)) break;
#if defined(__x86_64__) || defined(__i386__)
                    __asm__ volatile("pause" ::: "memory");
#endif
                }
            }
            break;

        case PACING_BURST:
            burst_ctr++;
            if (burst_ctr >= burst_limit && burst_gap_ns > 0) {
                burst_ctr = 0;
                int64_t j = calc_jitter_ns((uint64_t)burst_gap_ns, jitter_model, jitter_pct);
                t_burst_deadline = add_saturating_u64(t_burst_deadline, (uint64_t)burst_gap_ns);
                t_burst_deadline = add_jitter_saturating_u64(t_burst_deadline, j);
                precision_wait(t_burst_deadline);
            }
            break;

        default: /* PACING_NONE — full blast */
            break;
        }

        /* === SEND === */
        uint64_t t_pre = time_ns();

        iov.iov_base = (void *)(data + (uint64_t)i * packet_size);
        iov.iov_len  = packet_size;

        int ret;
        if (txtime_ok && pacing_mode != PACING_NONE) {
            /* SO_TXTIME: tell the kernel WHEN to put it on wire */
            uint64_t tx_tai = t_pre + tai_offset;
            if (pacing_mode == PACING_IPG || pacing_mode == PACING_RPS)
                tx_tai += eff_ipg;  /* schedule slightly ahead */
            ret = send_with_txtime(sockfd, iov.iov_base, iov.iov_len,
                                   (struct sockaddr *)&addr, sizeof(addr),
                                   tx_tai);
            if (ret < 0) g_stats.txtime_errors++;
        } else {
            ret = sendmmsg(sockfd, &mmsg, 1, 0);
        }

        if (ret > 0) {
            total_sent++;
            g_stats.total_packets++;
            g_stats.total_bytes += packet_size;

            /* IPG / jitter stats */
            if (i > 0) {
                uint64_t actual_ipg = t_pre - t_last;
                stats_record_ipg(actual_ipg, eff_ipg);
            }
            t_last = t_pre;
        }
    }

    g_stats.elapsed_ns = (double)(time_ns() - t_start);
    stats_finalize();

    pthread_mutex_unlock(&g_stats_lock);

    Py_END_ALLOW_THREADS

    close(sockfd);
    PyBuffer_Release(&view);
    return PyLong_FromLong(total_sent);
}

/* ========================================================================== */
/* Python: paced_send_l2                                                      */
/*   Paced L2 sender using AF_PACKET TX_RING + precision timing               */
/* ========================================================================== */

PyDoc_STRVAR(doc_paced_send_l2,
"paced_send_l2(iface, buffer, packet_size, count, gateway_mac, *,\n"
"              target_rps=0, ipg_ns=0, burst_size=1, burst_gap_ns=0,\n"
"              jitter_model=0, jitter_pct=0.0, pacing_mode=0,\n"
"              pin_cpu=-1) -> int\n"
"\n"
"L2 zero-copy paced sender via AF_PACKET TX_RING.\n"
"Same pacing / jitter parameters as paced_send_l3.\n");

static PyObject *py_paced_send_l2(PyObject *self,
                                  PyObject *args, PyObject *kw)
{
    (void)self;
    const char *iface;
    Py_buffer   view, mac_view;
    int         packet_size, count;

    double  target_rps   = 0.0;
    int64_t ipg_ns       = 0;
    int     burst_size   = 1;
    int64_t burst_gap_ns = 0;
    int     jitter_model = JITTER_NONE;
    double  jitter_pct   = 0.0;
    int     pacing_mode  = PACING_NONE;
    int     pin_cpu      = -1;

    static char *kwl[] = {
        "iface", "buffer", "packet_size", "count", "gateway_mac",
        "target_rps", "ipg_ns", "burst_size", "burst_gap_ns",
        "jitter_model", "jitter_pct", "pacing_mode",
        "pin_cpu", NULL
    };

    if (!PyArg_ParseTupleAndKeywords(
            args, kw, "sy*iiy*|dLiLidii", kwl,
            &iface, &view, &packet_size, &count, &mac_view,
            &target_rps, &ipg_ns, &burst_size, &burst_gap_ns,
            &jitter_model, &jitter_pct, &pacing_mode, &pin_cpu))
        return NULL;

    if (packet_size <= 0) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&mac_view);
        PyErr_SetString(PyExc_ValueError, "packet_size must be > 0");
        return NULL;
    }
    if (count < 0) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&mac_view);
        PyErr_SetString(PyExc_ValueError, "count must be >= 0");
        return NULL;
    }
    if (count > 0) {
        uint64_t u_packet_size = (uint64_t)packet_size;
        uint64_t u_count = (uint64_t)count;
        if (u_packet_size > UINT64_MAX / u_count) {
            PyBuffer_Release(&view);
            PyBuffer_Release(&mac_view);
            PyErr_SetString(PyExc_ValueError, "packet_size * count overflow");
            return NULL;
        }
        uint64_t needed = u_packet_size * u_count;
        if ((uint64_t)view.len < needed) {
            PyBuffer_Release(&view);
            PyBuffer_Release(&mac_view);
            PyErr_Format(
                PyExc_ValueError,
                "buffer too small: got %zu bytes, expected at least %llu",
                (size_t)view.len,
                (unsigned long long)needed
            );
            return NULL;
        }
    }

    if (mac_view.len != 6) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&mac_view);
        PyErr_SetString(PyExc_ValueError, "MAC address must be 6 bytes");
        return NULL;
    }

    /* CPU pinning */
    if (pin_cpu >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(pin_cpu, &cpuset);
        sched_setaffinity(0, sizeof(cpuset), &cpuset);

        struct sched_param sp = { .sched_priority = 50 };
        sched_setscheduler(0, SCHED_FIFO, &sp);
    }

    if (setup_ring(iface, packet_size, (uint8_t *)mac_view.buf) < 0) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&mac_view);
        return PyErr_SetFromErrno(PyExc_OSError);
    }

    /* effective IPG */
    uint64_t eff_ipg = 0;
    if      (pacing_mode == PACING_IPG   && ipg_ns > 0)      eff_ipg = (uint64_t)ipg_ns;
    else if (pacing_mode == PACING_RPS   && target_rps > 0)   eff_ipg = (uint64_t)(1e9 / target_rps);

    token_bucket_t tb = {0};
    if (pacing_mode == PACING_RPS && target_rps > 0)
        tb_init(&tb, target_rps, (double)(burst_size > 0 ? burst_size : 1));

    pthread_mutex_lock(&g_stats_lock);
    stats_reset(target_rps);
    g_stats.txring_packet_version = g_ring.packet_version;
    g_stats.afpacket_hugepage_mode = g_ring.hp_runtime.mode;
    g_stats.afpacket_hugepage_effective = g_ring.hp_runtime.effective;
    g_stats.afpacket_hugepage_size_kb = g_txring_hp_policy.hugepage_size_kb;
    g_stats.afpacket_madvise_hugepage_ok = g_ring.hp_runtime.madvise_ok;
    g_stats.afpacket_mlock_ok = g_ring.hp_runtime.mlock_ok;
    g_stats.afpacket_prefault_pages = g_ring.hp_runtime.prefault_pages;
    g_stats.afpacket_smaps_kernel_page_kb = g_ring.hp_runtime.smaps_kernel_page_kb;
    g_stats.afpacket_smaps_anon_hugepages_kb = g_ring.hp_runtime.smaps_anon_hugepages_kb;
    g_stats.afpacket_ring_block_size = (uint64_t)(
        g_ring.packet_version == TPACKET_V3 ? g_ring.req_v3.tp_block_size : g_ring.req_v2.tp_block_size
    );
    g_stats.afpacket_ring_block_nr = (uint64_t)(
        g_ring.packet_version == TPACKET_V3 ? g_ring.req_v3.tp_block_nr : g_ring.req_v2.tp_block_nr
    );
    g_stats.afpacket_ring_size_bytes = (uint64_t)g_ring.ring_size;
    (void)snprintf(
        g_stats.afpacket_hugepage_reason,
        sizeof(g_stats.afpacket_hugepage_reason),
        "%s",
        g_ring.hp_runtime.reason
    );
    pthread_mutex_unlock(&g_stats_lock);

    if (g_ring.hp_runtime.mode == AFPKT_HP_REQUIRED && g_ring.hp_runtime.effective <= 0) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&mac_view);
        return PyLong_FromLong(0);
    }

    drain_ring_packet_stats();

    rng_seed();

    const char *data = (const char *)view.buf;
    int total_sent   = 0;
    int burst_ctr    = 0;
    int burst_limit  = burst_size > 0 ? burst_size : 1;
    size_t frame_hdr = g_ring.frame_header_size;
    unsigned int frame_size = ring_frame_size();
    unsigned int frame_nr = ring_frame_nr();
    int spin_limit = g_txring_hp_policy.spin_limit;
    int poll_timeout_base_ms = g_txring_hp_policy.poll_timeout_ms;
    if (spin_limit < 0) spin_limit = 0;
    if (poll_timeout_base_ms < 0) poll_timeout_base_ms = 0;

    struct pollfd pfd = { .fd = g_ring.sock, .events = POLLOUT };

    Py_BEGIN_ALLOW_THREADS

    pthread_mutex_lock(&g_stats_lock);

    uint64_t t_start = time_ns();
    uint64_t t_last  = t_start;
    uint64_t t_deadline = t_start;
    uint64_t t_burst_deadline = t_start;

    for (int i = 0; i < count; i++) {

        /* === PACING GATE === */
        switch (pacing_mode) {
        case PACING_IPG:
            if (i > 0) {
                int64_t j = calc_jitter_ns(eff_ipg, jitter_model, jitter_pct);
                t_deadline = add_saturating_u64(t_deadline, eff_ipg);
                t_deadline = add_jitter_saturating_u64(t_deadline, j);
                precision_wait(t_deadline);
            }
            break;
        case PACING_RPS:
            if (eff_ipg > 0 && i > 0) {
                int64_t j = calc_jitter_ns(eff_ipg, jitter_model, jitter_pct);
                t_deadline = add_saturating_u64(t_deadline, eff_ipg);
                t_deadline = add_jitter_saturating_u64(t_deadline, j);
                precision_wait(t_deadline);
            } else {
                uint64_t now;
                while (1) {
                    now = time_ns();
                    if (tb_try_consume(&tb, now)) break;
#if defined(__x86_64__) || defined(__i386__)
                    __asm__ volatile("pause" ::: "memory");
#endif
                }
            }
            break;
        case PACING_BURST:
            burst_ctr++;
            if (burst_ctr >= burst_limit && burst_gap_ns > 0) {
                burst_ctr = 0;
                int64_t j = calc_jitter_ns((uint64_t)burst_gap_ns, jitter_model, jitter_pct);
                t_burst_deadline = add_saturating_u64(t_burst_deadline, (uint64_t)burst_gap_ns);
                t_burst_deadline = add_jitter_saturating_u64(t_burst_deadline, j);
                precision_wait(t_burst_deadline);
            }
            break;
        default:
            break;
        }

        /* === TX_RING SEND === */
        char *frame_base = g_ring.map + ((size_t)g_ring.frame_idx * frame_size);

        /* wait for frame to become available */
        uint64_t frame_wait_start = time_ns();
        int poll_timeout_ms = poll_timeout_base_ms;
        int spins = spin_limit;
        while (ring_tx_frame_status(frame_base) != TP_STATUS_AVAILABLE) {
            if (--spins > 0) {
#if defined(__x86_64__) || defined(__i386__)
                __asm__ volatile("pause" ::: "memory");
#endif
                continue;
            }
            poll(&pfd, 1, poll_timeout_ms);
            g_stats.txring_poll_count++;
            if (ring_tx_frame_status(frame_base) != TP_STATUS_AVAILABLE) {
                ssize_t flush_ret = sendto(g_ring.sock, NULL, 0, MSG_DONTWAIT, NULL, 0);
                record_l2_flush_result(flush_ret);
            }
            if (poll_timeout_ms < 16) {
                poll_timeout_ms = (poll_timeout_ms <= 0) ? 1 : (poll_timeout_ms << 1);
            } else {
                sched_yield();
            }
        }
        g_stats.txring_frame_wait_ns += (time_ns() - frame_wait_start);

        uint64_t t_pre = time_ns();

        /* copy packet into ring frame */
        char *frame_data = frame_base + frame_hdr;
        memcpy(frame_data, data + (uint64_t)i * packet_size, packet_size);

        ring_tx_frame_prepare(frame_base, packet_size);

        /* flush every burst_size packets, or at end */
        int dyn_flush = burst_size > 0 ? burst_size : 128;
        if (((i + 1) % dyn_flush == 0) || i == count - 1) {
            ssize_t flush_ret = sendto(g_ring.sock, NULL, 0, MSG_DONTWAIT, NULL, 0);
            record_l2_flush_result(flush_ret);
        }

        total_sent++;
        g_stats.total_packets++;
        g_stats.total_bytes += packet_size;

        if (i > 0) {
            uint64_t actual_ipg = t_pre - t_last;
            stats_record_ipg(actual_ipg, eff_ipg);
        }
        t_last = t_pre;

        g_ring.frame_idx =
            (g_ring.frame_idx + 1) % frame_nr;
    }

    capture_ring_packet_stats();
    g_stats.elapsed_ns = (double)(time_ns() - t_start);
    stats_finalize();

    pthread_mutex_unlock(&g_stats_lock);

    Py_END_ALLOW_THREADS

    PyBuffer_Release(&view);
    PyBuffer_Release(&mac_view);
    return PyLong_FromLong(total_sent);
}

/* ========================================================================== */
/* Python: get_pacing_stats                                                   */
/* ========================================================================== */

PyDoc_STRVAR(doc_get_stats,
"get_pacing_stats() -> dict\n"
"\n"
"Return comprehensive pacing statistics from the last paced_send call.\n"
"Keys include: total_packets, total_bytes, elapsed_ns, target_rps,\n"
"actual_rps, rate_accuracy_pct, ipg_min_ns, ipg_max_ns, ipg_mean_ns,\n"
"ipg_stddev_ns, jitter_min_ns, jitter_max_ns, jitter_mean_ns,\n"
"jitter_stddev_ns, jitter_p50_ns, jitter_p95_ns, jitter_p99_ns,\n"
"busywait_cycles, sleep_calls, so_txtime_active, txtime_errors,\n"
"txring_flush_call_count, txring_flush_error_count,\n"
"txring_flush_eagain_count, txring_flush_enobufs_count,\n"
"txring_flush_ebusy_count, txring_flush_other_errno_count,\n"
"txring_flush_last_errno, txring_flush_last_errno_name,\n"
"txring_frame_wait_ns, txring_poll_count,\n"
"txring_tp_packets, txring_tp_drops,\n"
"txring_tp_freeze_q_cnt, txring_packet_version,\n"
"txring_packet_version_name,\n"
"afpacket_hugepage_mode, afpacket_hugepage_effective,\n"
"afpacket_hugepage_reason, afpacket_hugepage_size_kb,\n"
"afpacket_madvise_hugepage_ok, afpacket_mlock_ok,\n"
"afpacket_prefault_pages, afpacket_smaps_kernel_page_kb,\n"
"afpacket_smaps_anon_hugepages_kb, afpacket_ring_block_size,\n"
"afpacket_ring_block_nr, afpacket_ring_size_bytes,\n"
"syscall_overhead_ns, sleep_overhead_ns, spin_threshold_ns,\n"
"ipg_histogram (list of 128 bin counts, 500 ns/bin).\n");

static PyObject *py_get_pacing_stats(PyObject *self, PyObject *args)
{
    (void)self; (void)args;
    pacing_stats_t snap;
    memset(&snap, 0, sizeof(snap));

    pthread_mutex_lock(&g_stats_lock);
    memcpy(&snap, &g_stats, sizeof(snap));
    pthread_mutex_unlock(&g_stats_lock);

    double ipg_mean = 0.0, ipg_stddev = 0.0;
    if (snap.ipg_count > 0)
        ipg_mean = snap.ipg_sum_ns / snap.ipg_count;
    if (snap.ipg_count > 1) {
        double var = (snap.ipg_sum_sq_ns / snap.ipg_count)
                   - (ipg_mean * ipg_mean);
        ipg_stddev = sqrt(var > 0 ? var : 0);
    }

    double j_mean = 0.0, j_stddev = 0.0;
    if (snap.jitter_count > 0)
        j_mean = snap.jitter_sum_ns / snap.jitter_count;
    if (snap.jitter_count > 1) {
        double var = (snap.jitter_sum_sq_ns / snap.jitter_count)
                   - (j_mean * j_mean);
        j_stddev = sqrt(var > 0 ? var : 0);
    }

    double p50 = stats_percentile_from_ring(snap.pct_ring, snap.pct_ring_len, 50.0);
    double p95 = stats_percentile_from_ring(snap.pct_ring, snap.pct_ring_len, 95.0);
    double p99 = stats_percentile_from_ring(snap.pct_ring, snap.pct_ring_len, 99.0);

    PyObject *hist = PyList_New(HISTOGRAM_BINS);
    if (!hist) return NULL;
    for (int b = 0; b < HISTOGRAM_BINS; b++) {
        PyObject *v = PyLong_FromUnsignedLongLong(snap.ipg_histogram[b]);
        if (!v) {
            Py_DECREF(hist);
            return NULL;
        }
        PyList_SET_ITEM(hist, b, v);
    }

    const char *txring_packet_version_name =
        packet_version_name(snap.txring_packet_version);
    const char *last_errno_name = flush_errno_name(snap.txring_flush_last_errno);

    PyObject *out = PyDict_New();
    PyObject *tmp = NULL;
    if (!out) {
        Py_DECREF(hist);
        return NULL;
    }

#define SET_U64(_k, _v) do { \
    tmp = PyLong_FromUnsignedLongLong((unsigned long long)(_v)); \
    if (!tmp || PyDict_SetItemString(out, (_k), tmp) < 0) { \
        Py_XDECREF(tmp); Py_DECREF(hist); Py_DECREF(out); return NULL; \
    } \
    Py_DECREF(tmp); \
} while (0)

#define SET_I64(_k, _v) do { \
    tmp = PyLong_FromLongLong((long long)(_v)); \
    if (!tmp || PyDict_SetItemString(out, (_k), tmp) < 0) { \
        Py_XDECREF(tmp); Py_DECREF(hist); Py_DECREF(out); return NULL; \
    } \
    Py_DECREF(tmp); \
} while (0)

#define SET_DBL(_k, _v) do { \
    tmp = PyFloat_FromDouble((double)(_v)); \
    if (!tmp || PyDict_SetItemString(out, (_k), tmp) < 0) { \
        Py_XDECREF(tmp); Py_DECREF(hist); Py_DECREF(out); return NULL; \
    } \
    Py_DECREF(tmp); \
} while (0)

#define SET_STR(_k, _v) do { \
    tmp = PyUnicode_FromString((_v)); \
    if (!tmp || PyDict_SetItemString(out, (_k), tmp) < 0) { \
        Py_XDECREF(tmp); Py_DECREF(hist); Py_DECREF(out); return NULL; \
    } \
    Py_DECREF(tmp); \
} while (0)

    SET_U64("total_packets", snap.total_packets);
    SET_U64("total_bytes", snap.total_bytes);
    SET_DBL("elapsed_ns", snap.elapsed_ns);
    SET_DBL("target_rps", snap.target_rps);
    SET_DBL("actual_rps", snap.actual_rps);
    SET_DBL("rate_accuracy_pct", snap.rate_accuracy_pct);

    SET_U64("ipg_min_ns", (snap.ipg_min_ns == UINT64_MAX ? 0ULL : snap.ipg_min_ns));
    SET_U64("ipg_max_ns", snap.ipg_max_ns);
    SET_DBL("ipg_mean_ns", ipg_mean);
    SET_DBL("ipg_stddev_ns", ipg_stddev);

    SET_DBL("jitter_min_ns", (snap.jitter_min_ns > 1e17 ? 0.0 : snap.jitter_min_ns));
    SET_DBL("jitter_max_ns", snap.jitter_max_ns);
    SET_DBL("jitter_mean_ns", j_mean);
    SET_DBL("jitter_stddev_ns", j_stddev);
    SET_DBL("jitter_p50_ns", p50);
    SET_DBL("jitter_p95_ns", p95);
    SET_DBL("jitter_p99_ns", p99);

    SET_U64("busywait_cycles", snap.busywait_cycles);
    SET_U64("sleep_calls", snap.sleep_calls);
    SET_I64("so_txtime_active", snap.so_txtime_active);
    SET_U64("txtime_errors", snap.txtime_errors);

    SET_U64("txring_flush_call_count", snap.txring_flush_call_count);
    SET_U64("txring_flush_error_count", snap.txring_flush_error_count);
    SET_U64("txring_flush_eagain_count", snap.txring_flush_eagain_count);
    SET_U64("txring_flush_enobufs_count", snap.txring_flush_enobufs_count);
    SET_U64("txring_flush_ebusy_count", snap.txring_flush_ebusy_count);
    SET_U64("txring_flush_other_errno_count", snap.txring_flush_other_errno_count);
    SET_I64("txring_flush_last_errno", snap.txring_flush_last_errno);
    SET_STR("txring_flush_last_errno_name", last_errno_name);
    SET_U64("txring_frame_wait_ns", snap.txring_frame_wait_ns);
    SET_U64("txring_poll_count", snap.txring_poll_count);
    SET_U64("txring_tp_packets", snap.txring_tp_packets);
    SET_U64("txring_tp_drops", snap.txring_tp_drops);
    SET_U64("txring_tp_freeze_q_cnt", snap.txring_tp_freeze_q_cnt);
    SET_I64("txring_packet_version", snap.txring_packet_version);
    SET_STR("txring_packet_version_name", txring_packet_version_name);

    SET_STR("afpacket_hugepage_mode", afpacket_hp_mode_name(snap.afpacket_hugepage_mode));
    SET_I64("afpacket_hugepage_effective", snap.afpacket_hugepage_effective);
    SET_STR("afpacket_hugepage_reason", snap.afpacket_hugepage_reason);
    SET_I64("afpacket_hugepage_size_kb", snap.afpacket_hugepage_size_kb);
    SET_I64("afpacket_madvise_hugepage_ok", snap.afpacket_madvise_hugepage_ok);
    SET_I64("afpacket_mlock_ok", snap.afpacket_mlock_ok);
    SET_U64("afpacket_prefault_pages", snap.afpacket_prefault_pages);
    SET_U64("afpacket_smaps_kernel_page_kb", snap.afpacket_smaps_kernel_page_kb);
    SET_U64("afpacket_smaps_anon_hugepages_kb", snap.afpacket_smaps_anon_hugepages_kb);
    SET_U64("afpacket_ring_block_size", snap.afpacket_ring_block_size);
    SET_U64("afpacket_ring_block_nr", snap.afpacket_ring_block_nr);
    SET_U64("afpacket_ring_size_bytes", snap.afpacket_ring_size_bytes);

    SET_U64("syscall_overhead_ns", snap.syscall_overhead_ns);
    SET_U64("sleep_overhead_ns", snap.sleep_overhead_ns);
    SET_U64("spin_threshold_ns", g_spin_threshold_ns);

    if (PyDict_SetItemString(out, "ipg_histogram", hist) < 0) {
        Py_DECREF(hist);
        Py_DECREF(out);
        return NULL;
    }
    Py_DECREF(hist);

#undef SET_STR
#undef SET_DBL
#undef SET_I64
#undef SET_U64

    return out;
}

/* ========================================================================== */
/* Python: reset_pacing_stats                                                 */
/* ========================================================================== */

static PyObject *py_reset_stats(PyObject *self, PyObject *args)
{
    (void)self; (void)args;
    pthread_mutex_lock(&g_stats_lock);
    stats_reset(0.0);
    pthread_mutex_unlock(&g_stats_lock);
    Py_RETURN_NONE;
}

/* ========================================================================== */
/* Python: calibrate                                                          */
/* ========================================================================== */

PyDoc_STRVAR(doc_calibrate,
"calibrate() -> dict\n"
"\n"
"Measure system timing characteristics (clock_gettime latency,\n"
"clock_nanosleep wakeup overshoot) and return calibration data.\n"
"Also updates the internal spin-threshold for precision_wait.\n");

static PyObject *py_calibrate(PyObject *self, PyObject *args)
{
    (void)self; (void)args;

    calibrate_timing();

    uint64_t syscall_overhead_ns = 0;
    uint64_t sleep_overhead_ns = 0;
    pthread_mutex_lock(&g_stats_lock);
    syscall_overhead_ns = g_stats.syscall_overhead_ns;
    sleep_overhead_ns = g_stats.sleep_overhead_ns;
    pthread_mutex_unlock(&g_stats_lock);

    return Py_BuildValue(
        "{s:K, s:K, s:K}",
        "syscall_overhead_ns", syscall_overhead_ns,
        "sleep_overhead_ns",   sleep_overhead_ns,
        "spin_threshold_ns",   g_spin_threshold_ns
    );
}

/* ========================================================================== */
/* Python: check_capabilities                                                 */
/* ========================================================================== */

PyDoc_STRVAR(doc_check_caps,
"check_capabilities() -> dict\n"
"\n"
"Probe kernel / NIC capabilities relevant to pacing:\n"
"  so_txtime, clock_tai, sched_fifo, af_packet, tpacket_v3.\n");

static PyObject *py_check_capabilities(PyObject *self, PyObject *args)
{
    (void)self; (void)args;

    /* SO_TXTIME */
    int has_txtime = 0;
    {
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (fd >= 0) {
            has_txtime = enable_so_txtime(fd);
            close(fd);
        }
    }

    /* CLOCK_TAI */
    int has_tai = 0;
    {
        struct timespec ts;
        if (clock_gettime(CLOCK_TAI, &ts) == 0) has_tai = 1;
    }

    /* SCHED_FIFO (root check) */
    int has_fifo = (geteuid() == 0) ? 1 : 0;

    /* AF_PACKET */
    int has_af_packet = 0;
    int has_tpacket_v3 = 0;
    {
        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd >= 0) {
            has_af_packet = 1;
            int version = TPACKET_V3;
            if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) == 0) {
                has_tpacket_v3 = 1;
            }
            close(fd);
        }
    }

    return Py_BuildValue(
        "{s:i, s:i, s:i, s:i, s:i, s:i}",
        "so_txtime",   has_txtime,
        "clock_tai",   has_tai,
        "sched_fifo",  has_fifo,
        "af_packet",   has_af_packet,
        "tpacket_v3",  has_tpacket_v3,
        "is_root",     geteuid() == 0
    );
}

/* ========================================================================== */
/* Python: cleanup_l2_ring                                                    */
/* ========================================================================== */

static PyObject *py_cleanup_ring(PyObject *self, PyObject *args)
{
    (void)self; (void)args;
    cleanup_ring();
    Py_RETURN_NONE;
}

/* ========================================================================== */
/* Module Definition                                                          */
/* ========================================================================== */

static PyMethodDef PacingMethods[] = {
    {"paced_send_l3", (PyCFunction)(void(*)(void))py_paced_send_l3,
     METH_VARARGS | METH_KEYWORDS, doc_paced_send_l3},

    {"paced_send_l2", (PyCFunction)(void(*)(void))py_paced_send_l2,
     METH_VARARGS | METH_KEYWORDS, doc_paced_send_l2},

    {"get_pacing_stats", py_get_pacing_stats, METH_NOARGS, doc_get_stats},

    {"reset_pacing_stats", py_reset_stats, METH_NOARGS,
     "Reset all pacing statistics to zero."},

    {"calibrate", py_calibrate, METH_NOARGS, doc_calibrate},

    {"check_capabilities", py_check_capabilities, METH_NOARGS, doc_check_caps},

    {"cleanup_l2_ring", py_cleanup_ring, METH_NOARGS,
     "Cleanup persistent TX_RING resources for L2 sender."},

    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef pacing_module = {
    PyModuleDef_HEAD_INIT,
    "pacing_engine",
    "Samurai Deterministic Pacing Engine\n\n"
    "Nanosecond-precision packet pacing with:\n"
    "  - Hybrid busy-wait / clock_nanosleep timing\n"
    "  - Token bucket rate limiter\n"
    "  - SO_TXTIME kernel offload\n"
    "  - Jitter models (uniform, gaussian, exponential)\n"
    "  - Comprehensive IPG / jitter statistics\n\n"
    "Pacing modes: NONE=0, RPS=1, IPG=2, BURST=3\n"
    "Jitter models: NONE=0, UNIFORM=1, GAUSSIAN=2, EXPONENTIAL=3\n",
    -1,
    PacingMethods
};

PyMODINIT_FUNC PyInit_pacing_engine(void)
{
    PyObject *m = PyModule_Create(&pacing_module);
    if (!m) return NULL;

    load_txring_hugepage_policy_from_env();

    /* Export constants */
    PyModule_AddIntConstant(m, "PACING_NONE",         PACING_NONE);
    PyModule_AddIntConstant(m, "PACING_RPS",          PACING_RPS);
    PyModule_AddIntConstant(m, "PACING_IPG",          PACING_IPG);
    PyModule_AddIntConstant(m, "PACING_BURST",        PACING_BURST);
    PyModule_AddIntConstant(m, "JITTER_NONE",         JITTER_NONE);
    PyModule_AddIntConstant(m, "JITTER_UNIFORM",      JITTER_UNIFORM);
    PyModule_AddIntConstant(m, "JITTER_GAUSSIAN",     JITTER_GAUSSIAN);
    PyModule_AddIntConstant(m, "JITTER_EXPONENTIAL",  JITTER_EXPONENTIAL);

    /* Calibrate on import */
    calibrate_timing();

    return m;
}
