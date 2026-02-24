/**
 * DDoSamurai — Deterministic Pacing Engine (C Extension)
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
 * Copyright (c) 2026 DDoSamurai — research / authorised testing only.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
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
    uint64_t txring_tp_packets;
    uint64_t txring_tp_drops;
    uint64_t txring_tp_freeze_q_cnt;

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
}

/* qsort comparator for p99 */
static int cmp_u64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static double stats_percentile(double pct)
{
    if (g_stats.pct_ring_len == 0) return 0.0;

    /* copy ring to tmp for sorting */
    uint32_t n = g_stats.pct_ring_len;
    uint64_t *tmp = (uint64_t *)malloc(n * sizeof(uint64_t));
    if (!tmp) return 0.0;
    memcpy(tmp, g_stats.pct_ring, n * sizeof(uint64_t));
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
    g_stats.syscall_overhead_ns = sum / CALIBRATION_ITERS;

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
    g_stats.sleep_overhead_ns = sum / 100;

    /* set spin threshold = max(15 µs, 2× sleep overshoot) */
    uint64_t overshoot2x = g_stats.sleep_overhead_ns * 2;
    g_spin_threshold_ns = overshoot2x > 15000 ? overshoot2x : 15000;
}

/* ========================================================================== */
/* TX_RING Context (for L2 paced sender)                                      */
/* ========================================================================== */

typedef struct {
    int       sock;
    char     *map;
    size_t    ring_size;
    struct tpacket_req req;
    char      iface[IFNAMSIZ];
    int       is_setup;
    unsigned  frame_idx;
} ring_ctx_t;

static ring_ctx_t g_ring = { .is_setup = 0, .sock = -1, .map = MAP_FAILED };

static int setup_ring(const char *iface, int pkt_size, const uint8_t *mac)
{
    if (g_ring.is_setup) {
        size_t hdr = TPACKET_ALIGN(sizeof(struct tpacket2_hdr));
        if (strcmp(g_ring.iface, iface) == 0 &&
            g_ring.req.tp_frame_size >= (unsigned)(pkt_size + hdr))
            return 0;   /* reuse */
        /* teardown old */
        if (g_ring.map != MAP_FAILED)
            munmap(g_ring.map, g_ring.ring_size);
        if (g_ring.sock >= 0)
            close(g_ring.sock);
        g_ring.is_setup = 0;
    }

    g_ring.sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_ring.sock < 0) return -1;

    memset(&g_ring.req, 0, sizeof(g_ring.req));
    g_ring.req.tp_block_size = getpagesize();
    size_t hdr_sz = TPACKET_ALIGN(sizeof(struct tpacket2_hdr));
    while (g_ring.req.tp_block_size < (unsigned)(pkt_size + hdr_sz))
        g_ring.req.tp_block_size <<= 1;
    g_ring.req.tp_frame_size = g_ring.req.tp_block_size;
    g_ring.req.tp_block_nr   = 4096;
    g_ring.req.tp_frame_nr   = g_ring.req.tp_block_nr;

    if (setsockopt(g_ring.sock, SOL_PACKET, PACKET_TX_RING,
                   &g_ring.req, sizeof(g_ring.req)) < 0) {
        close(g_ring.sock);
        return -1;
    }

    g_ring.ring_size = (size_t)g_ring.req.tp_block_nr * g_ring.req.tp_block_size;
    g_ring.map = mmap(NULL, g_ring.ring_size,
                      PROT_READ | PROT_WRITE, MAP_SHARED,
                      g_ring.sock, 0);
    if (g_ring.map == MAP_FAILED) {
        close(g_ring.sock);
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
        return -1;
    }

    strncpy(g_ring.iface, iface, IFNAMSIZ - 1);
    g_ring.is_setup  = 1;
    g_ring.frame_idx = 0;
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
    }
}

static void drain_ring_packet_stats(void)
{
    if (!g_ring.is_setup || g_ring.sock < 0) return;

    struct tpacket_stats stats;
    socklen_t optlen = sizeof(stats);
    (void)getsockopt(g_ring.sock, SOL_PACKET, PACKET_STATISTICS, &stats, &optlen);
}

static void capture_ring_packet_stats(void)
{
    if (!g_ring.is_setup || g_ring.sock < 0) return;

    struct tpacket_stats stats;
    socklen_t optlen = sizeof(stats);
    if (getsockopt(g_ring.sock, SOL_PACKET, PACKET_STATISTICS, &stats, &optlen) == 0) {
        g_stats.txring_tp_packets = (uint64_t)stats.tp_packets;
        g_stats.txring_tp_drops = (uint64_t)stats.tp_drops;
        g_stats.txring_tp_freeze_q_cnt = 0ULL;
    }
}

static inline void record_l2_flush_result(ssize_t ret)
{
    g_stats.txring_flush_call_count++;
    if (ret < 0) {
        g_stats.txring_flush_error_count++;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            g_stats.txring_flush_eagain_count++;
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

    Py_BEGIN_ALLOW_THREADS

    uint64_t t_start    = time_ns();
    uint64_t t_last     = t_start;
    uint64_t t_next     = t_start;
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
                t_next = t_last + eff_ipg;
                t_next += (uint64_t)calc_jitter_ns(eff_ipg, jitter_model, jitter_pct);
                precision_wait(t_next);
            }
            break;

        case PACING_RPS:
            if (eff_ipg > 0 && i > 0) {
                /* IPG-based pacing is more deterministic than token bucket */
                t_next = t_last + eff_ipg;
                t_next += (uint64_t)calc_jitter_ns(eff_ipg, jitter_model, jitter_pct);
                precision_wait(t_next);
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
            if (burst_ctr >= burst_size && burst_gap_ns > 0) {
                burst_ctr = 0;
                t_next = t_last + (uint64_t)burst_gap_ns;
                t_next += (uint64_t)calc_jitter_ns(
                    (uint64_t)burst_gap_ns, jitter_model, jitter_pct);
                precision_wait(t_next);
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
    pthread_mutex_unlock(&g_stats_lock);

    drain_ring_packet_stats();

    rng_seed();

    const char *data = (const char *)view.buf;
    int total_sent   = 0;
    int burst_ctr    = 0;
    size_t frame_hdr = TPACKET_ALIGN(sizeof(struct tpacket2_hdr));

    struct pollfd pfd = { .fd = g_ring.sock, .events = POLLOUT };

    Py_BEGIN_ALLOW_THREADS

    uint64_t t_start = time_ns();
    uint64_t t_last  = t_start;
    uint64_t t_next  = t_start;

    for (int i = 0; i < count; i++) {

        /* === PACING GATE === */
        switch (pacing_mode) {
        case PACING_IPG:
            if (i > 0) {
                t_next = t_last + eff_ipg
                       + (uint64_t)calc_jitter_ns(eff_ipg, jitter_model, jitter_pct);
                precision_wait(t_next);
            }
            break;
        case PACING_RPS:
            if (eff_ipg > 0 && i > 0) {
                t_next = t_last + eff_ipg
                       + (uint64_t)calc_jitter_ns(eff_ipg, jitter_model, jitter_pct);
                precision_wait(t_next);
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
            if (burst_ctr >= burst_size && burst_gap_ns > 0) {
                burst_ctr = 0;
                t_next = t_last + (uint64_t)burst_gap_ns
                       + (uint64_t)calc_jitter_ns(
                             (uint64_t)burst_gap_ns, jitter_model, jitter_pct);
                precision_wait(t_next);
            }
            break;
        default:
            break;
        }

        /* === TX_RING SEND === */
        struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)
            (g_ring.map + g_ring.frame_idx * g_ring.req.tp_frame_size);

        /* wait for frame to become available */
        int spins = 2000;
        while (hdr->tp_status != TP_STATUS_AVAILABLE) {
            if (--spins > 0) {
#if defined(__x86_64__) || defined(__i386__)
                __asm__ volatile("pause" ::: "memory");
#endif
                continue;
            }
            poll(&pfd, 1, 1);
            if (hdr->tp_status != TP_STATUS_AVAILABLE) {
                ssize_t flush_ret = sendto(g_ring.sock, NULL, 0, MSG_DONTWAIT, NULL, 0);
                record_l2_flush_result(flush_ret);
            }
        }

        uint64_t t_pre = time_ns();

        /* copy packet into ring frame */
        char *frame_data = (char *)hdr + frame_hdr;
        memcpy(frame_data, data + (uint64_t)i * packet_size, packet_size);

        hdr->tp_len     = packet_size;
        hdr->tp_snaplen = packet_size;
        hdr->tp_mac     = frame_hdr;
        hdr->tp_net     = frame_hdr + 14;
        hdr->tp_status  = TP_STATUS_SEND_REQUEST;

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
            (g_ring.frame_idx + 1) % g_ring.req.tp_frame_nr;
    }

    capture_ring_packet_stats();
    g_stats.elapsed_ns = (double)(time_ns() - t_start);
    stats_finalize();

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
"txring_flush_eagain_count, txring_tp_packets, txring_tp_drops,\n"
"txring_tp_freeze_q_cnt,\n"
"syscall_overhead_ns, sleep_overhead_ns, spin_threshold_ns,\n"
"ipg_histogram (list of 128 bin counts, 500 ns/bin).\n");

static PyObject *py_get_pacing_stats(PyObject *self, PyObject *args)
{
    (void)self; (void)args;

    pthread_mutex_lock(&g_stats_lock);

    double ipg_mean = 0.0, ipg_stddev = 0.0;
    if (g_stats.ipg_count > 0)
        ipg_mean = g_stats.ipg_sum_ns / g_stats.ipg_count;
    if (g_stats.ipg_count > 1) {
        double var = (g_stats.ipg_sum_sq_ns / g_stats.ipg_count)
                   - (ipg_mean * ipg_mean);
        ipg_stddev = sqrt(var > 0 ? var : 0);
    }

    double j_mean = 0.0, j_stddev = 0.0;
    if (g_stats.jitter_count > 0)
        j_mean = g_stats.jitter_sum_ns / g_stats.jitter_count;
    if (g_stats.jitter_count > 1) {
        double var = (g_stats.jitter_sum_sq_ns / g_stats.jitter_count)
                   - (j_mean * j_mean);
        j_stddev = sqrt(var > 0 ? var : 0);
    }

    double p50 = stats_percentile(50.0);
    double p95 = stats_percentile(95.0);
    double p99 = stats_percentile(99.0);

    /* build histogram list */
    PyObject *hist = PyList_New(HISTOGRAM_BINS);
    for (int b = 0; b < HISTOGRAM_BINS; b++)
        PyList_SET_ITEM(hist, b, PyLong_FromUnsignedLongLong(
                                     g_stats.ipg_histogram[b]));

    pthread_mutex_unlock(&g_stats_lock);

    return Py_BuildValue(
        "{s:K, s:K, s:d, s:d, s:d, s:d,"
        " s:K, s:K, s:d, s:d,"
        " s:d, s:d, s:d, s:d,"
        " s:d, s:d, s:d,"
        " s:K, s:K,"
        " s:i, s:K,"
        " s:K, s:K, s:K, s:K, s:K, s:K,"
        " s:K, s:K, s:K,"
        " s:O}",
        "total_packets",      g_stats.total_packets,
        "total_bytes",        g_stats.total_bytes,
        "elapsed_ns",         g_stats.elapsed_ns,
        "target_rps",         g_stats.target_rps,
        "actual_rps",         g_stats.actual_rps,
        "rate_accuracy_pct",  g_stats.rate_accuracy_pct,

        "ipg_min_ns",         g_stats.ipg_min_ns == UINT64_MAX ? 0ULL : g_stats.ipg_min_ns,
        "ipg_max_ns",         g_stats.ipg_max_ns,
        "ipg_mean_ns",        ipg_mean,
        "ipg_stddev_ns",      ipg_stddev,

        "jitter_min_ns",      g_stats.jitter_min_ns > 1e17 ? 0.0 : g_stats.jitter_min_ns,
        "jitter_max_ns",      g_stats.jitter_max_ns,
        "jitter_mean_ns",     j_mean,
        "jitter_stddev_ns",   j_stddev,

        "jitter_p50_ns",      p50,
        "jitter_p95_ns",      p95,
        "jitter_p99_ns",      p99,

        "busywait_cycles",    g_stats.busywait_cycles,
        "sleep_calls",        g_stats.sleep_calls,

        "so_txtime_active",   g_stats.so_txtime_active,
        "txtime_errors",      g_stats.txtime_errors,

        "txring_flush_call_count", g_stats.txring_flush_call_count,
        "txring_flush_error_count", g_stats.txring_flush_error_count,
        "txring_flush_eagain_count", g_stats.txring_flush_eagain_count,
        "txring_tp_packets", g_stats.txring_tp_packets,
        "txring_tp_drops", g_stats.txring_tp_drops,
        "txring_tp_freeze_q_cnt", g_stats.txring_tp_freeze_q_cnt,

        "syscall_overhead_ns", g_stats.syscall_overhead_ns,
        "sleep_overhead_ns",   g_stats.sleep_overhead_ns,
        "spin_threshold_ns",   g_spin_threshold_ns,

        "ipg_histogram",       hist
    );
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

    return Py_BuildValue(
        "{s:K, s:K, s:K}",
        "syscall_overhead_ns", g_stats.syscall_overhead_ns,
        "sleep_overhead_ns",   g_stats.sleep_overhead_ns,
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
"  so_txtime, clock_tai, sched_fifo, af_packet.\n");

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
    {
        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd >= 0) { has_af_packet = 1; close(fd); }
    }

    return Py_BuildValue(
        "{s:i, s:i, s:i, s:i, s:i}",
        "so_txtime",   has_txtime,
        "clock_tai",   has_tai,
        "sched_fifo",  has_fifo,
        "af_packet",   has_af_packet,
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
    "DDoSamurai Deterministic Pacing Engine\n\n"
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
