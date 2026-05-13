/**
 * AF_XDP High-Performance Packet Sender for Samurai
 * =====================================================
 * 
 * This module implements AF_XDP (Address Family XDP) socket for
 * high-performance packet transmission. Works in Copy Mode (SKB/Generic)
 * which is compatible with most Linux systems and NICs.
 * 
 * Requirements:
 *   - Linux kernel >= 4.18 (recommended: 5.10+)
 *   - Root privileges
 *   - libbpf-dev, libelf-dev
 * 
 * Copy Mode provides:
 *   ✅ AF_XDP works
 *   ✅ Good performance (better than raw sockets)
 *   ❌ No zero-copy (kernel-userspace copy exists)
 *   ❌ Limited by kernel stack
 * 
 * Build: gcc -shared -fPIC -o xdp_sender.so xdp_sender.c $(python3-config --includes --ldflags)
 *        -I/usr/include/bpf -lbpf -lelf -lpthread
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <linux/bpf.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "xdp_native_api.h"
#include "samurai_tsc.h"

// ============================================================================
// Configuration Constants
// ============================================================================

#define XDP_NUM_FRAMES      4096        // Number of UMEM frames
#define XDP_FRAME_SIZE      4096        // Size of each frame (must be power of 2)
#define XDP_HEADROOM        256         // Headroom for XDP metadata
#define XDP_BATCH_SIZE      64          // Maximum batch size for TX
#define XDP_FILL_RING_SIZE  (XDP_NUM_FRAMES * 2)
#define XDP_COMP_RING_SIZE  XDP_NUM_FRAMES
#define XDP_TX_RING_SIZE    XDP_NUM_FRAMES
#define XDP_RX_RING_SIZE    XDP_NUM_FRAMES

#define MAX_PACKET_SIZE     1500        // Maximum packet payload size
#define POLL_TIMEOUT_MS     100         // Poll timeout in milliseconds

// Pacing modes (aligned with pacing_engine)
#define XDP_PACING_NONE     0
#define XDP_PACING_RPS      1
#define XDP_PACING_IPG      2
#define XDP_PACING_BURST    3

// ============================================================================
// XDP Ring Buffer Structures
// ============================================================================

/** Producer/Consumer ring indices (shared with kernel) */
struct xsk_ring_prod {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    uint32_t *consumer;
    void *ring;
    uint32_t *flags;
};

struct xsk_ring_cons {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    uint32_t *consumer;
    void *ring;
    uint32_t *flags;
};

/** UMEM (User Memory) Info */
struct xsk_umem_info {
    void *buffer;
    uint64_t size;
    uint32_t frame_size;
    uint32_t frame_count;
    uint32_t headroom;
    int external_buffer;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    void *fill_map;
    size_t fill_map_len;
    void *comp_map;
    size_t comp_map_len;
    int fd;
};

/** XDP Socket Info */
struct xsk_socket_info {
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    void *tx_map;
    size_t tx_map_len;
    void *rx_map;
    size_t rx_map_len;
    struct xsk_umem_info *umem;
    int fd;
    int ifindex;
    int queue_id;
    uint32_t outstanding_tx;
    uint32_t free_frames[XDP_NUM_FRAMES];
    uint32_t free_count;
    int need_wakeup;
    char ifname[IFNAMSIZ];
};

// ============================================================================
// XDP Context (Global/Per-Interface State)
// ============================================================================

typedef struct {
    struct xsk_socket_info *xsk;
    struct xsk_umem_info *umem;
    int is_initialized;
    int is_running;
    pthread_mutex_t lock;
    
    // Statistics
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
    uint64_t tx_wakeups;
    uint64_t tx_desc_reserve_failures;
    uint64_t tx_frame_alloc_failures;
    uint64_t tx_partial_batches;
    uint64_t tx_retry_loops;
    uint64_t tx_completion_events;
    uint64_t tx_completed_desc;
    uint64_t tx_invalid_packets;
    uint64_t tx_backpressure_events;
    uint64_t tx_send_calls;
    uint64_t tx_send_ns_total;
    uint64_t tx_send_ns_max;
    
    // Timing
    struct timespec start_time;
    
    // Configuration
    int xdp_mode;  // 0 = SKB/Generic, 1 = Native (DRV)
    int queue_id;
    int xsks_map_fd;
    int xsks_map_key;
    int xsks_map_registered;
    int external_umem_mode;

    // Reusable send scratch buffers for context API paths.
    const uint8_t **scratch_packets;
    uint16_t *scratch_lengths;
    PyObject **scratch_owners;
    Py_ssize_t scratch_capacity;
} xdp_context_t;

static xdp_context_t xdp_ctx = {
    .is_initialized = 0,
    .is_running = 0,
    .queue_id = 0,
    .xsks_map_fd = -1,
    .xsks_map_key = 0,
    .xsks_map_registered = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

static inline uint64_t xdp_timespec_diff_ns(const struct timespec *start, const struct timespec *end)
{
    uint64_t sec_ns = (uint64_t)(end->tv_sec - start->tv_sec) * 1000000000ULL;
    if (end->tv_nsec >= start->tv_nsec) {
        return sec_ns + (uint64_t)(end->tv_nsec - start->tv_nsec);
    }
    return sec_ns - (uint64_t)(start->tv_nsec - end->tv_nsec);
}

static inline void xdp_record_send_timing(xdp_context_t *ctx, uint64_t elapsed_ns)
{
    if (ctx == NULL) {
        return;
    }
    ctx->tx_send_calls += 1;
    ctx->tx_send_ns_total += elapsed_ns;
    if (elapsed_ns > ctx->tx_send_ns_max) {
        ctx->tx_send_ns_max = elapsed_ns;
    }
}

typedef struct {
    int mode;
    double target_rps;
    uint64_t ipg_ns;
    int burst_size;
    uint64_t burst_gap_ns;
} xdp_pacing_config_t;

typedef struct {
    double tokens;
    double max_tokens;
    double refill_rate;
    uint64_t last_refill_ns;
} xdp_token_bucket_t;

static pthread_once_t g_xdp_tsc_once = PTHREAD_ONCE_INIT;
static int g_xdp_tsc_supported = 0;
static int g_xdp_tsc_enabled = 0;
static uint64_t g_xdp_tsc_hz = 0;
static __thread uint64_t g_xdp_tsc_anchor_ns = 0;
static __thread uint64_t g_xdp_tsc_anchor_cycles = 0;

static inline uint64_t xdp_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline int xdp_env_truthy(const char *name, int fallback)
{
    const char *raw = getenv(name);
    if (raw == NULL || raw[0] == '\0') {
        return fallback;
    }
    if (
        strcmp(raw, "1") == 0 ||
        strcasecmp(raw, "true") == 0 ||
        strcasecmp(raw, "yes") == 0 ||
        strcasecmp(raw, "on") == 0
    ) {
        return 1;
    }
    return 0;
}

static inline uint64_t xdp_tsc_cycles_to_ns(uint64_t cycles)
{
    if (g_xdp_tsc_hz == 0) {
        return 0;
    }
    return (uint64_t)(((__uint128_t)cycles * 1000000000ULL) / g_xdp_tsc_hz);
}

static inline uint64_t xdp_tsc_ns_to_cycles(uint64_t ns)
{
    if (g_xdp_tsc_hz == 0) {
        return 0;
    }
    return (uint64_t)(((__uint128_t)ns * g_xdp_tsc_hz) / 1000000000ULL);
}

static inline void xdp_tsc_refresh_anchor(void)
{
    if (!g_xdp_tsc_enabled) {
        return;
    }
    g_xdp_tsc_anchor_cycles = samurai_rdtsc();
    g_xdp_tsc_anchor_ns = xdp_time_ns();
}

static void xdp_tsc_init_once(void)
{
    int want_tsc = xdp_env_truthy("SAMURAI_XDP_PACING_USE_TSC", 1);
    g_xdp_tsc_supported = samurai_tsc_invariant_supported();
    g_xdp_tsc_enabled = 0;
    g_xdp_tsc_hz = 0;
    if (!want_tsc || !g_xdp_tsc_supported) {
        return;
    }

    uint64_t c0 = samurai_rdtsc();
    uint64_t t0 = xdp_time_ns();
    struct timespec req;
    uint64_t target = t0 + 25000000ULL; /* 25 ms */
    req.tv_sec = target / 1000000000ULL;
    req.tv_nsec = target % 1000000000ULL;
    (void)clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL);
    uint64_t c1 = samurai_rdtsc();
    uint64_t t1 = xdp_time_ns();

    if (c1 > c0 && t1 > t0) {
        g_xdp_tsc_hz = (uint64_t)(((__uint128_t)(c1 - c0) * 1000000000ULL) / (t1 - t0));
    }
    if (g_xdp_tsc_hz < 1000000ULL || g_xdp_tsc_hz > 10000000000ULL) {
        g_xdp_tsc_hz = 0;
        return;
    }

    g_xdp_tsc_enabled = 1;
}

static inline void xdp_tsc_ensure_ready(void)
{
    pthread_once(&g_xdp_tsc_once, xdp_tsc_init_once);
}

static inline uint64_t xdp_time_ns_fast(void)
{
    xdp_tsc_ensure_ready();
    if (!g_xdp_tsc_enabled || g_xdp_tsc_hz == 0) {
        return xdp_time_ns();
    }

    uint64_t now_cycles = samurai_rdtsc();
    if (g_xdp_tsc_anchor_cycles == 0 || now_cycles < g_xdp_tsc_anchor_cycles) {
        xdp_tsc_refresh_anchor();
        now_cycles = samurai_rdtsc();
    }

    uint64_t max_drift_cycles = g_xdp_tsc_hz / 2U;
    if (max_drift_cycles > 0 && (now_cycles - g_xdp_tsc_anchor_cycles) > max_drift_cycles) {
        xdp_tsc_refresh_anchor();
        now_cycles = samurai_rdtsc();
    }

    return g_xdp_tsc_anchor_ns + xdp_tsc_cycles_to_ns(now_cycles - g_xdp_tsc_anchor_cycles);
}

static inline uint64_t xdp_tsc_deadline_from_ns(uint64_t target_ns)
{
    uint64_t now_ns = xdp_time_ns_fast();
    uint64_t now_cycles = samurai_rdtsc();
    if (target_ns <= now_ns) {
        return now_cycles;
    }
    return now_cycles + xdp_tsc_ns_to_cycles(target_ns - now_ns);
}

static inline void xdp_cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
    __asm__ volatile("yield" ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif
}

static inline void xdp_wait_until_ns(uint64_t target_ns)
{
    uint64_t now_ns = xdp_time_ns();
    if (now_ns >= target_ns) {
        return;
    }

    if (g_xdp_tsc_enabled) {
        uint64_t target_cycles = xdp_tsc_deadline_from_ns(target_ns);
        while (samurai_rdtsc() < target_cycles) {
            xdp_cpu_relax();
        }
        return;
    }

    while (xdp_time_ns() < target_ns) {
        xdp_cpu_relax();
    }
}

static inline void xdp_tb_init(xdp_token_bucket_t *tb, double rps, double burst, uint64_t now_ns)
{
    tb->tokens = burst;
    tb->max_tokens = burst;
    tb->refill_rate = rps / 1e9;
    tb->last_refill_ns = now_ns;
}

static inline int xdp_tb_try_consume(xdp_token_bucket_t *tb, uint64_t now_ns)
{
    double elapsed = (double)(now_ns - tb->last_refill_ns);
    tb->tokens += elapsed * tb->refill_rate;
    if (tb->tokens > tb->max_tokens) {
        tb->tokens = tb->max_tokens;
    }
    tb->last_refill_ns = now_ns;
    if (tb->tokens >= 1.0) {
        tb->tokens -= 1.0;
        return 1;
    }
    return 0;
}

static int xdp_prepare_pacing_config(
    xdp_pacing_config_t *cfg,
    int mode,
    double target_rps,
    uint64_t ipg_ns,
    int burst_size,
    uint64_t burst_gap_ns
)
{
    if (cfg == NULL) {
        return -1;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = mode;
    cfg->target_rps = target_rps;
    cfg->ipg_ns = ipg_ns;
    cfg->burst_size = burst_size;
    cfg->burst_gap_ns = burst_gap_ns;

    switch (mode) {
        case XDP_PACING_NONE:
            return 0;
        case XDP_PACING_RPS:
            if (target_rps <= 0.0) {
                return -1;
            }
            if (cfg->burst_size <= 0) {
                cfg->burst_size = 1;
            }
            return 0;
        case XDP_PACING_IPG:
            if (ipg_ns == 0) {
                return -1;
            }
            return 0;
        case XDP_PACING_BURST:
            if (cfg->burst_size <= 0) {
                return -1;
            }
            return 0;
        default:
            return -1;
    }
}

static int xdp_wait_for_pacing_slot(
    const xdp_pacing_config_t *cfg,
    xdp_token_bucket_t *tb,
    uint64_t *ipg_next_ns,
    int *burst_counter,
    uint64_t *burst_resume_ns
)
{
    if (cfg == NULL || cfg->mode == XDP_PACING_NONE) {
        return 0;
    }

    for (;;) {
        uint64_t now_ns = xdp_time_ns_fast();
        if (cfg->mode == XDP_PACING_RPS) {
            if (xdp_tb_try_consume(tb, now_ns)) {
                return 0;
            }
            if (tb->refill_rate <= 0.0) {
                return -1;
            }
            double deficit = 1.0 - tb->tokens;
            if (deficit < 0.0) {
                deficit = 0.0;
            }
            uint64_t wait_ns = (uint64_t)(deficit / tb->refill_rate);
            if (wait_ns == 0) {
                wait_ns = 1;
            }
            xdp_wait_until_ns(now_ns + wait_ns);
            continue;
        }

        if (cfg->mode == XDP_PACING_IPG) {
            if (ipg_next_ns != NULL && *ipg_next_ns > now_ns) {
                xdp_wait_until_ns(*ipg_next_ns);
                continue;
            }
            return 0;
        }

        if (cfg->mode == XDP_PACING_BURST) {
            if (
                burst_counter != NULL &&
                *burst_counter >= cfg->burst_size &&
                cfg->burst_gap_ns > 0 &&
                burst_resume_ns != NULL &&
                *burst_resume_ns > now_ns
            ) {
                xdp_wait_until_ns(*burst_resume_ns);
                continue;
            }
            if (burst_counter != NULL && *burst_counter >= cfg->burst_size) {
                *burst_counter = 0;
            }
            return 0;
        }

        return -1;
    }
}

static void xdp_update_pacing_after_send(
    const xdp_pacing_config_t *cfg,
    uint64_t *ipg_next_ns,
    int *burst_counter,
    uint64_t *burst_resume_ns
)
{
    if (cfg == NULL || cfg->mode == XDP_PACING_NONE) {
        return;
    }
    if (cfg->mode == XDP_PACING_IPG) {
        if (ipg_next_ns != NULL) {
            uint64_t now_ns = xdp_time_ns_fast();
            if (*ipg_next_ns < now_ns) {
                *ipg_next_ns = now_ns;
            }
            *ipg_next_ns += cfg->ipg_ns;
        }
        return;
    }
    if (cfg->mode == XDP_PACING_BURST && burst_counter != NULL) {
        *burst_counter += 1;
        if (*burst_counter >= cfg->burst_size && cfg->burst_gap_ns > 0 && burst_resume_ns != NULL) {
            *burst_resume_ns = xdp_time_ns_fast() + cfg->burst_gap_ns;
        }
    }
}

#define XDP_MAX_CONTEXTS 64
static xdp_context_t *g_ctx_table[XDP_MAX_CONTEXTS] = {0};
static pthread_mutex_t g_ctx_table_lock = PTHREAD_MUTEX_INITIALIZER;

static int register_ctx_handle(xdp_context_t *ctx)
{
    int handle = -1;
    pthread_mutex_lock(&g_ctx_table_lock);
    for (int i = 1; i < XDP_MAX_CONTEXTS; i++) {
        if (g_ctx_table[i] == NULL) {
            g_ctx_table[i] = ctx;
            handle = i;
            break;
        }
    }
    pthread_mutex_unlock(&g_ctx_table_lock);
    return handle;
}

static xdp_context_t *lock_ctx_by_handle(int handle)
{
    xdp_context_t *ctx = NULL;
    if (handle <= 0 || handle >= XDP_MAX_CONTEXTS) {
        return NULL;
    }

    pthread_mutex_lock(&g_ctx_table_lock);
    ctx = g_ctx_table[handle];
    if (ctx != NULL) {
        pthread_mutex_lock(&ctx->lock);
    }
    pthread_mutex_unlock(&g_ctx_table_lock);
    return ctx;
}

static xdp_context_t *remove_ctx_by_handle_locked(int handle)
{
    xdp_context_t *ctx = NULL;
    if (handle <= 0 || handle >= XDP_MAX_CONTEXTS) {
        return NULL;
    }

    pthread_mutex_lock(&g_ctx_table_lock);
    ctx = g_ctx_table[handle];
    if (ctx != NULL) {
        pthread_mutex_lock(&ctx->lock);
        g_ctx_table[handle] = NULL;
    }
    pthread_mutex_unlock(&g_ctx_table_lock);
    return ctx;
}

// ============================================================================
// BPF helpers (XSKMAP update/delete)
// ============================================================================

static int bpf_syscall(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return (int)syscall(__NR_bpf, cmd, attr, size);
}

static int bpf_obj_get_path(const char *path)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    return bpf_syscall(BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_map_update_elem_fd(int map_fd, const void *key, const void *value, uint64_t flags)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.value = (uint64_t)(uintptr_t)value;
    attr.flags = flags;
    return bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_delete_elem_fd(int map_fd, const void *key)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    return bpf_syscall(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static int register_xsk_in_xsks_map(int queue_id, int xsk_fd, char *reason, size_t reason_len)
{
    const char *map_path = getenv("SAMURAI_XDP_XSKMAP_PIN");
    int map_fd;
    int key = queue_id;
    int value = xsk_fd;

    if (map_path == NULL || map_path[0] == '\0') {
        return 0;
    }

    map_fd = bpf_obj_get_path(map_path);
    if (map_fd < 0) {
        if (reason != NULL && reason_len > 0) {
            (void)snprintf(reason, reason_len, "BPF_OBJ_GET(%s) failed: %s", map_path, strerror(errno));
        }
        return -1;
    }

    if (bpf_map_update_elem_fd(map_fd, &key, &value, BPF_ANY) < 0) {
        if (reason != NULL && reason_len > 0) {
            (void)snprintf(reason, reason_len, "xsks_map update failed: %s", strerror(errno));
        }
        close(map_fd);
        return -1;
    }

    xdp_ctx.xsks_map_fd = map_fd;
    xdp_ctx.xsks_map_key = key;
    xdp_ctx.xsks_map_registered = 1;
    return 0;
}

static int register_xsk_in_xsks_map_ctx(
    xdp_context_t *ctx,
    int queue_id,
    int xsk_fd,
    char *reason,
    size_t reason_len
)
{
    const char *map_path = getenv("SAMURAI_XDP_XSKMAP_PIN");
    int map_fd;
    int key = queue_id;
    int value = xsk_fd;

    if (map_path == NULL || map_path[0] == '\0') {
        return 0;
    }

    map_fd = bpf_obj_get_path(map_path);
    if (map_fd < 0) {
        if (reason != NULL && reason_len > 0) {
            (void)snprintf(reason, reason_len, "BPF_OBJ_GET(%s) failed: %s", map_path, strerror(errno));
        }
        return -1;
    }

    if (bpf_map_update_elem_fd(map_fd, &key, &value, BPF_ANY) < 0) {
        if (reason != NULL && reason_len > 0) {
            (void)snprintf(reason, reason_len, "xsks_map update failed: %s", strerror(errno));
        }
        close(map_fd);
        return -1;
    }

    ctx->xsks_map_fd = map_fd;
    ctx->xsks_map_key = key;
    ctx->xsks_map_registered = 1;
    return 0;
}

// ============================================================================
// Memory Barrier Helpers (for lock-free ring buffers)
// ============================================================================

#define xsk_ring_prod__needs_wakeup(r) \
    (*((r)->flags) & XDP_RING_NEED_WAKEUP)

static inline const char *xdp_mode_name(int mode)
{
    switch (mode) {
        case 0: return "SKB/Copy";
        case 1: return "Native/Zero-Copy";
        case 2: return "Offload(Requested)";
        default: return "Unknown";
    }
}

static inline uint16_t xdp_bind_mode_flags(int mode)
{
    switch (mode) {
        case 0:
            return XDP_COPY;
        case 1:
            return XDP_ZEROCOPY;
        case 2:
            /* AF_XDP has no dedicated HW-offload bind flag. */
            return XDP_ZEROCOPY;
        default:
            return XDP_COPY;
    }
}

static inline void xsk_ring_prod__submit(struct xsk_ring_prod *r, uint32_t nb)
{
    __sync_synchronize();
    *r->producer += nb;
}

static inline void xsk_ring_prod__cancel(struct xsk_ring_prod *r, uint32_t nb)
{
    if (nb == 0) {
        return;
    }
    if (r->cached_prod >= nb) {
        r->cached_prod -= nb;
    } else {
        r->cached_prod = 0;
    }
}

static inline uint32_t xsk_ring_prod__reserve(struct xsk_ring_prod *r,
                                               uint32_t nb, uint32_t *idx)
{
    if (r->cached_cons - r->cached_prod >= nb) {
        *idx = r->cached_prod;
        r->cached_prod += nb;
        return nb;
    }

    r->cached_cons = __sync_fetch_and_add(r->consumer, 0);
    
    if (r->cached_cons - r->cached_prod >= nb) {
        *idx = r->cached_prod;
        r->cached_prod += nb;
        return nb;
    }

    return 0;
}

static inline void xsk_ring_cons__release(struct xsk_ring_cons *r, uint32_t nb)
{
    __sync_synchronize();
    *r->consumer += nb;
}

static inline uint32_t xsk_ring_cons__peek(struct xsk_ring_cons *r,
                                            uint32_t nb, uint32_t *idx)
{
    uint32_t entries = __sync_fetch_and_add(r->producer, 0) - r->cached_cons;
    
    if (entries >= nb) {
        *idx = r->cached_cons;
        r->cached_cons += nb;
        return nb;
    }
    
    return 0;
}

static inline void *xsk_ring_prod__fill_addr(struct xsk_ring_prod *fill, uint32_t idx)
{
    return (void*)((uint64_t*)fill->ring + (idx & fill->mask));
}

static inline void *xsk_ring_prod__tx_desc(struct xsk_ring_prod *tx, uint32_t idx)
{
    return (void*)((struct xdp_desc*)tx->ring + (idx & tx->mask));
}

static inline void *xsk_ring_cons__comp_addr(struct xsk_ring_cons *comp, uint32_t idx)
{
    return (void*)((uint64_t*)comp->ring + (idx & comp->mask));
}

static inline void *xsk_ring_cons__rx_desc(struct xsk_ring_cons *rx, uint32_t idx)
{
    return (void*)((struct xdp_desc*)rx->ring + (idx & rx->mask));
}

// ============================================================================
// Checksum Helpers
// ============================================================================

static inline uint16_t fold_csum(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t ip_checksum(const void *data, size_t len)
{
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(const uint8_t *)ptr;
    }
    
    return fold_csum(sum);
}

static uint16_t udp_checksum(const struct iphdr *iph, 
                             const struct udphdr *udph,
                             const void *payload, size_t payload_len)
{
    uint32_t sum = 0;
    
    // Pseudo header
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_UDP);
    sum += udph->len;
    
    // UDP header
    const uint16_t *ptr = (const uint16_t *)udph;
    sum += ptr[0];
    sum += ptr[1];
    sum += ptr[2];
    // Skip checksum field
    
    // Payload
    ptr = (const uint16_t *)payload;
    size_t len = payload_len;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)ptr;
    }
    
    uint16_t result = fold_csum(sum);
    return result == 0 ? 0xFFFF : result;
}

// ============================================================================
// UMEM Management
// ============================================================================

static struct xsk_umem_info *create_umem_with_config(
    void *external_buffer,
    uint32_t frame_count,
    uint32_t frame_size,
    uint32_t headroom,
    int external_mode
)
{
    struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
    if (!umem) return NULL;

    if (frame_count == 0) frame_count = XDP_NUM_FRAMES;
    if (frame_size == 0) frame_size = XDP_FRAME_SIZE;
    if (headroom == 0) headroom = XDP_HEADROOM;
    if (frame_count > XDP_NUM_FRAMES || frame_size == 0 || headroom >= frame_size) {
        free(umem);
        errno = EINVAL;
        return NULL;
    }

    umem->frame_count = frame_count;
    umem->frame_size = frame_size;
    umem->headroom = headroom;
    umem->external_buffer = external_mode ? 1 : 0;
    umem->size = (uint64_t)frame_count * (uint64_t)frame_size;

    if (umem->external_buffer) {
        if (external_buffer == NULL) {
            free(umem);
            errno = EINVAL;
            return NULL;
        }
        umem->buffer = external_buffer;
    } else {
        if (posix_memalign(&umem->buffer, getpagesize(), (size_t)umem->size)) {
            free(umem);
            return NULL;
        }
        memset(umem->buffer, 0, (size_t)umem->size);
    }

    umem->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (umem->fd < 0) {
        if (!umem->external_buffer) free(umem->buffer);
        free(umem);
        return NULL;
    }

    struct xdp_umem_reg mr = {
        .addr = (uint64_t)umem->buffer,
        .len = umem->size,
        .chunk_size = umem->frame_size,
        .headroom = umem->headroom,
        .flags = 0
    };

    if (setsockopt(umem->fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) < 0) {
        close(umem->fd);
        if (!umem->external_buffer) free(umem->buffer);
        free(umem);
        return NULL;
    }

    int fill_size = XDP_FILL_RING_SIZE;
    if (setsockopt(umem->fd, SOL_XDP, XDP_UMEM_FILL_RING, &fill_size, sizeof(fill_size)) < 0) {
        close(umem->fd);
        if (!umem->external_buffer) free(umem->buffer);
        free(umem);
        return NULL;
    }

    int comp_size = XDP_COMP_RING_SIZE;
    if (setsockopt(umem->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &comp_size, sizeof(comp_size)) < 0) {
        close(umem->fd);
        if (!umem->external_buffer) free(umem->buffer);
        free(umem);
        return NULL;
    }

    struct xdp_mmap_offsets offsets;
    socklen_t optlen = sizeof(offsets);
    if (getsockopt(umem->fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &optlen) < 0) {
        close(umem->fd);
        if (!umem->external_buffer) free(umem->buffer);
        free(umem);
        return NULL;
    }

    void *fill_map = mmap(NULL,
                          offsets.fr.desc + XDP_FILL_RING_SIZE * sizeof(uint64_t),
                          PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                          umem->fd, XDP_UMEM_PGOFF_FILL_RING);
    if (fill_map == MAP_FAILED) {
        close(umem->fd);
        if (!umem->external_buffer) free(umem->buffer);
        free(umem);
        return NULL;
    }

    umem->fill.mask = XDP_FILL_RING_SIZE - 1;
    umem->fill.size = XDP_FILL_RING_SIZE;
    umem->fill.producer = (uint32_t*)(fill_map + offsets.fr.producer);
    umem->fill.consumer = (uint32_t*)(fill_map + offsets.fr.consumer);
    umem->fill.flags = (uint32_t*)(fill_map + offsets.fr.flags);
    umem->fill.ring = fill_map + offsets.fr.desc;
    umem->fill.cached_cons = XDP_FILL_RING_SIZE;
    umem->fill_map = fill_map;
    umem->fill_map_len = offsets.fr.desc + XDP_FILL_RING_SIZE * sizeof(uint64_t);

    void *comp_map = mmap(NULL,
                          offsets.cr.desc + XDP_COMP_RING_SIZE * sizeof(uint64_t),
                          PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                          umem->fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    if (comp_map == MAP_FAILED) {
        munmap(fill_map, offsets.fr.desc + XDP_FILL_RING_SIZE * sizeof(uint64_t));
        close(umem->fd);
        if (!umem->external_buffer) free(umem->buffer);
        free(umem);
        return NULL;
    }

    umem->comp.mask = XDP_COMP_RING_SIZE - 1;
    umem->comp.size = XDP_COMP_RING_SIZE;
    umem->comp.producer = (uint32_t*)(comp_map + offsets.cr.producer);
    umem->comp.consumer = (uint32_t*)(comp_map + offsets.cr.consumer);
    umem->comp.flags = (uint32_t*)(comp_map + offsets.cr.flags);
    umem->comp.ring = comp_map + offsets.cr.desc;
    umem->comp_map = comp_map;
    umem->comp_map_len = offsets.cr.desc + XDP_COMP_RING_SIZE * sizeof(uint64_t);

    return umem;
}

static struct xsk_umem_info *create_umem(void)
{
    return create_umem_with_config(NULL, XDP_NUM_FRAMES, XDP_FRAME_SIZE, XDP_HEADROOM, 0);
}

static void destroy_umem(struct xsk_umem_info *umem)
{
    if (!umem) return;

    if (umem->fill_map && umem->fill_map_len > 0) {
        munmap(umem->fill_map, umem->fill_map_len);
        umem->fill_map = NULL;
        umem->fill_map_len = 0;
    }
    if (umem->comp_map && umem->comp_map_len > 0) {
        munmap(umem->comp_map, umem->comp_map_len);
        umem->comp_map = NULL;
        umem->comp_map_len = 0;
    }
    if (umem->fd >= 0) close(umem->fd);
    if (!umem->external_buffer && umem->buffer) free(umem->buffer);
    free(umem);
}

// ============================================================================
// XDP Socket Management
// ============================================================================

static struct xsk_socket_info *create_xsk_socket(struct xsk_umem_info *umem,
                                                  const char *ifname, 
                                                  int queue_id,
                                                  int xdp_mode)
{
    struct xsk_socket_info *xsk = calloc(1, sizeof(*xsk));
    if (!xsk) return NULL;
    
    xsk->umem = umem;
    strncpy(xsk->ifname, ifname, IFNAMSIZ - 1);
    xsk->ifindex = if_nametoindex(ifname);
    xsk->queue_id = queue_id;
    
    if (xsk->ifindex == 0) {
        fprintf(stderr, "[XDP] Interface '%s' not found\n", ifname);
        free(xsk);
        return NULL;
    }
    
    // Create XDP socket
    xsk->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk->fd < 0) {
        fprintf(stderr, "[XDP] Failed to create AF_XDP socket: %s\n", strerror(errno));
        free(xsk);
        return NULL;
    }
    
    // Setup TX Ring
    int tx_size = XDP_TX_RING_SIZE;
    if (setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING, &tx_size, sizeof(tx_size)) < 0) {
        fprintf(stderr, "[XDP] Failed to set TX ring: %s\n", strerror(errno));
        close(xsk->fd);
        free(xsk);
        return NULL;
    }
    
    // Setup RX Ring (optional, for bidirectional communication)
    int rx_size = XDP_RX_RING_SIZE;
    if (setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING, &rx_size, sizeof(rx_size)) < 0) {
        fprintf(stderr, "[XDP] Failed to set RX ring (continuing without RX): %s\n", strerror(errno));
        // Continue without RX - we're primarily TX focused
    }
    
    // Get ring offsets
    struct xdp_mmap_offsets offsets;
    socklen_t optlen = sizeof(offsets);
    if (getsockopt(xsk->fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &optlen) < 0) {
        close(xsk->fd);
        free(xsk);
        return NULL;
    }
    
    // Map TX Ring
    void *tx_map = mmap(NULL,
                        offsets.tx.desc + XDP_TX_RING_SIZE * sizeof(struct xdp_desc),
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                        xsk->fd, XDP_PGOFF_TX_RING);
    if (tx_map == MAP_FAILED) {
        fprintf(stderr, "[XDP] Failed to mmap TX ring: %s\n", strerror(errno));
        close(xsk->fd);
        free(xsk);
        return NULL;
    }
    
    xsk->tx.mask = XDP_TX_RING_SIZE - 1;
    xsk->tx.size = XDP_TX_RING_SIZE;
    xsk->tx.producer = (uint32_t*)(tx_map + offsets.tx.producer);
    xsk->tx.consumer = (uint32_t*)(tx_map + offsets.tx.consumer);
    xsk->tx.flags = (uint32_t*)(tx_map + offsets.tx.flags);
    xsk->tx.ring = tx_map + offsets.tx.desc;
    xsk->tx_map = tx_map;
    xsk->tx_map_len = offsets.tx.desc + XDP_TX_RING_SIZE * sizeof(struct xdp_desc);

    // Map RX Ring (optional; required for RX pipeline)
    void *rx_map = mmap(NULL,
                        offsets.rx.desc + XDP_RX_RING_SIZE * sizeof(struct xdp_desc),
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                        xsk->fd, XDP_PGOFF_RX_RING);
    if (rx_map != MAP_FAILED) {
        xsk->rx.mask = XDP_RX_RING_SIZE - 1;
        xsk->rx.size = XDP_RX_RING_SIZE;
        xsk->rx.producer = (uint32_t*)(rx_map + offsets.rx.producer);
        xsk->rx.consumer = (uint32_t*)(rx_map + offsets.rx.consumer);
        xsk->rx.flags = (uint32_t*)(rx_map + offsets.rx.flags);
        xsk->rx.ring = rx_map + offsets.rx.desc;
        xsk->rx_map = rx_map;
        xsk->rx_map_len = offsets.rx.desc + XDP_RX_RING_SIZE * sizeof(struct xdp_desc);
    } else {
        xsk->rx.size = 0;
        xsk->rx.ring = NULL;
    }
    
    // Bind socket to interface
    struct sockaddr_xdp sxdp = {
        .sxdp_family = AF_XDP,
        .sxdp_ifindex = xsk->ifindex,
        .sxdp_queue_id = queue_id,
        .sxdp_flags = XDP_USE_NEED_WAKEUP
    };
    
    // AF_XDP socket mode hint for bind (copy/zerocopy).
    sxdp.sxdp_flags |= xdp_bind_mode_flags(xdp_mode);
    
    // Share UMEM with the socket
    sxdp.sxdp_shared_umem_fd = umem->fd;
    
    if (bind(xsk->fd, (struct sockaddr*)&sxdp, sizeof(sxdp)) < 0) {
        fprintf(stderr, "[XDP] Failed to bind socket to %s (queue %d): %s\n", 
                ifname, queue_id, strerror(errno));
        fprintf(stderr, "[XDP] Hint: Try running with sudo or check if XDP is supported\n");
        if (xsk->tx_map && xsk->tx_map_len > 0) {
            munmap(xsk->tx_map, xsk->tx_map_len);
            xsk->tx_map = NULL;
            xsk->tx_map_len = 0;
        }
        close(xsk->fd);
        free(xsk);
        return NULL;
    }
    
    // Initialize frame allocation tracking
    xsk->free_count = umem->frame_count;
    for (uint32_t i = 0; i < umem->frame_count; i++) {
        xsk->free_frames[i] = i;
    }
    xsk->outstanding_tx = 0;
    
    // Pre-populate the fill ring
    uint32_t fill_idx;
    if (xsk_ring_prod__reserve(&umem->fill, umem->frame_count, &fill_idx) == umem->frame_count) {
        for (uint32_t i = 0; i < umem->frame_count; i++) {
            uint64_t *addr = xsk_ring_prod__fill_addr(&umem->fill, fill_idx + i);
            *addr = (uint64_t)i * (uint64_t)umem->frame_size;
        }
        xsk_ring_prod__submit(&umem->fill, umem->frame_count);
    }
    
    if (xdp_mode == 2) {
        fprintf(stderr,
                "[XDP] Note: mode=2 (offload) requested; AF_XDP bind uses zerocopy hint, true HW offload depends on XDP program/NIC path.\n");
    }

    fprintf(stderr, "[XDP] Socket created on %s (queue %d, mode: %s)\n",
            ifname, queue_id, xdp_mode_name(xdp_mode));
    
    return xsk;
}

static void destroy_xsk_socket(struct xsk_socket_info *xsk)
{
    if (!xsk) return;

    if (xsk->tx_map && xsk->tx_map_len > 0) {
        munmap(xsk->tx_map, xsk->tx_map_len);
        xsk->tx_map = NULL;
        xsk->tx_map_len = 0;
    }
    if (xsk->rx_map && xsk->rx_map_len > 0) {
        munmap(xsk->rx_map, xsk->rx_map_len);
        xsk->rx_map = NULL;
        xsk->rx_map_len = 0;
    }
    if (xsk->fd >= 0) close(xsk->fd);
    free(xsk);
}

static int refill_rx_fill_ring(struct xsk_socket_info *xsk, struct xdp_desc *descs, uint32_t count)
{
    if (!xsk || !xsk->umem || !descs || count == 0) {
        return 0;
    }
    uint32_t fill_idx = 0;
    uint32_t reserved = xsk_ring_prod__reserve(&xsk->umem->fill, count, &fill_idx);
    if (reserved == 0) {
        return 0;
    }
    for (uint32_t i = 0; i < reserved; i++) {
        uint64_t base = descs[i].addr;
        if (base >= xsk->umem->headroom) {
            base -= xsk->umem->headroom;
        }
        uint32_t frame_id = (uint32_t)(base / xsk->umem->frame_size);
        uint64_t *fill_addr = xsk_ring_prod__fill_addr(&xsk->umem->fill, fill_idx + i);
        *fill_addr = (uint64_t)frame_id * (uint64_t)xsk->umem->frame_size;
    }
    xsk_ring_prod__submit(&xsk->umem->fill, reserved);
    return (int)reserved;
}

static int xdp_recv_packets_ctx(xdp_context_t *ctx, uint32_t max_packets, uint32_t snaplen, PyObject **out_list)
{
    if (!ctx || !ctx->xsk || !out_list) {
        return -1;
    }
    struct xsk_socket_info *xsk = ctx->xsk;
    if (xsk->rx.size == 0 || xsk->rx.ring == NULL) {
        *out_list = PyList_New(0);
        return 0;
    }
    if (max_packets == 0) {
        *out_list = PyList_New(0);
        return 0;
    }
    struct pollfd pfd = {.fd = xsk->fd, .events = POLLIN, .revents = 0};
    (void)poll(&pfd, 1, 0);

    uint32_t rx_idx = 0;
    uint32_t peeked = xsk_ring_cons__peek(&xsk->rx, max_packets, &rx_idx);
    if (peeked == 0) {
        // Try minimum one descriptor path if producer has less than requested.
        peeked = xsk_ring_cons__peek(&xsk->rx, 1, &rx_idx);
        if (peeked == 0) {
            *out_list = PyList_New(0);
            return 0;
        }
    }

    PyObject *items = PyList_New((Py_ssize_t)peeked);
    if (!items) {
        return -1;
    }
    struct xdp_desc *tmp_desc = calloc(peeked, sizeof(struct xdp_desc));
    if (!tmp_desc) {
        Py_DECREF(items);
        return -1;
    }
    uint32_t produced = 0;
    for (uint32_t i = 0; i < peeked; i++) {
        struct xdp_desc *d = xsk_ring_cons__rx_desc(&xsk->rx, rx_idx + i);
        tmp_desc[i] = *d;
        uint32_t plen = d->len;
        if (snaplen > 0 && plen > snaplen) {
            plen = snaplen;
        }
        const uint8_t *src = (const uint8_t*)xsk->umem->buffer + d->addr;
        PyObject *pkt = PyBytes_FromStringAndSize((const char*)src, (Py_ssize_t)plen);
        if (!pkt) {
            for (uint32_t j = 0; j < produced; j++) {
                PyObject *old = PyList_GET_ITEM(items, (Py_ssize_t)j);
                Py_XDECREF(old);
            }
            free(tmp_desc);
            Py_DECREF(items);
            return -1;
        }
        PyList_SET_ITEM(items, (Py_ssize_t)i, pkt);
        produced += 1;
    }
    xsk_ring_cons__release(&xsk->rx, peeked);
    (void)refill_rx_fill_ring(xsk, tmp_desc, peeked);
    free(tmp_desc);
    *out_list = items;
    return (int)peeked;
}

// ============================================================================
// Frame Allocation
// ============================================================================

static uint64_t alloc_frame(struct xsk_socket_info *xsk)
{
    if (xsk->free_count == 0) {
        // No free frames available
        return UINT64_MAX;
    }

    uint32_t idx = xsk->free_frames[--xsk->free_count];
    return (uint64_t)idx * (uint64_t)xsk->umem->frame_size;
}

static void free_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    uint64_t base = frame;
    if (base >= xsk->umem->headroom) {
        base -= xsk->umem->headroom;
    }
    uint32_t idx = (uint32_t)(base / xsk->umem->frame_size);
    if (idx >= xsk->umem->frame_count) {
        return;
    }
    if (xsk->free_count < xsk->umem->frame_count) {
        xsk->free_frames[xsk->free_count++] = idx;
    }
}

static uint32_t xdp_reap_completion_entries(
    struct xsk_socket_info *xsk,
    uint32_t max_count,
    uint32_t *frame_ids_out,
    uint32_t out_capacity,
    int recycle_frames
)
{
    if (!xsk->outstanding_tx) {
        return 0;
    }
    uint32_t want = max_count;
    if (want == 0 || want > xsk->outstanding_tx) {
        want = xsk->outstanding_tx;
    }
    if (want == 0) {
        return 0;
    }

    uint32_t idx;
    uint32_t completed = xsk_ring_cons__peek(&xsk->umem->comp, want, &idx);
    if (completed == 0) {
        return 0;
    }

    for (uint32_t i = 0; i < completed; i++) {
        uint64_t *addr = xsk_ring_cons__comp_addr(&xsk->umem->comp, idx + i);
        uint64_t base = *addr;
        if (base >= xsk->umem->headroom) {
            base -= xsk->umem->headroom;
        }
        const uint32_t frame_id = (uint32_t)(base / xsk->umem->frame_size);
        if (frame_ids_out != NULL && i < out_capacity) {
            frame_ids_out[i] = frame_id;
        }
        if (recycle_frames) {
            free_frame(xsk, *addr);
        }
    }
    xsk_ring_cons__release(&xsk->umem->comp, completed);
    xsk->outstanding_tx -= completed;
    return completed;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
    if (!xsk->outstanding_tx) return;

    uint32_t completed = xdp_reap_completion_entries(
        xsk,
        xsk->outstanding_tx,
        NULL,
        0,
        1
    );
    if (completed > 0) {
        xdp_ctx.tx_completion_events += 1;
        xdp_ctx.tx_completed_desc += completed;
    }
}

static void kick_tx(struct xsk_socket_info *xsk)
{
    if (xsk_ring_prod__needs_wakeup(&xsk->tx)) {
        sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        xdp_ctx.tx_wakeups++;
    }
}

// ============================================================================
// Packet Transmission (Core TX Path)
// ============================================================================

/**
 * Send a batch of raw packets through AF_XDP
 * @param packets Array of packet data pointers
 * @param lengths Array of packet lengths
 * @param count Number of packets to send
 * @return Number of packets successfully submitted
 */
static int xdp_send_batch(struct xsk_socket_info *xsk, 
                          const uint8_t **packets, 
                          const uint16_t *lengths,
                          int count)
{
    // Complete any outstanding transmissions first
    complete_tx(xsk);
    
    // Reserve TX descriptors
    uint32_t tx_idx;
    int batch_size = count < XDP_BATCH_SIZE ? count : XDP_BATCH_SIZE;
    
    uint32_t reserved = xsk_ring_prod__reserve(&xsk->tx, batch_size, &tx_idx);
    if (reserved == 0) {
        xdp_ctx.tx_desc_reserve_failures += 1;
        xdp_ctx.tx_backpressure_events += 1;
        kick_tx(xsk);
        return 0;
    }
    
    // Fill TX descriptors and copy packet data to UMEM
    int submitted = 0;
    for (uint32_t i = 0; i < reserved && submitted < count; i++) {
        uint64_t frame_addr = alloc_frame(xsk);
        if (frame_addr == UINT64_MAX) {
            xdp_ctx.tx_frame_alloc_failures += 1;
            xdp_ctx.tx_backpressure_events += 1;
            break;  // No more frames
        }
        
        uint16_t pkt_len = lengths[submitted];
        if (pkt_len > MAX_PACKET_SIZE) {
            pkt_len = MAX_PACKET_SIZE;
        }
        
        // Get pointer to UMEM frame buffer
        void *pkt_buffer = (uint8_t*)xsk->umem->buffer + frame_addr + xsk->umem->headroom;
        
        // Copy packet data to UMEM (this is the "copy" in Copy Mode)
        memcpy(pkt_buffer, packets[submitted], pkt_len);
        
        // Fill TX descriptor
        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx + i);
        tx_desc->addr = frame_addr + xsk->umem->headroom;
        tx_desc->len = pkt_len;
        tx_desc->options = 0;
        
        submitted++;
        xdp_ctx.tx_bytes += pkt_len;
    }
    
    if (submitted < (int)reserved) {
        xdp_ctx.tx_partial_batches += 1;
        xsk_ring_prod__cancel(&xsk->tx, reserved - (uint32_t)submitted);
    }

    // Submit TX descriptors
    if (submitted > 0) {
        xsk_ring_prod__submit(&xsk->tx, submitted);
        xsk->outstanding_tx += submitted;
        xdp_ctx.tx_packets += submitted;
    }
    
    // Kick TX to ensure packets are sent
    kick_tx(xsk);
    
    return submitted;
}

typedef struct {
    const uint8_t **packets;
    uint16_t *lengths;
    PyObject **owners;
    Py_ssize_t capacity;
} xdp_send_scratch_t;

static xdp_send_scratch_t g_send_scratch = {0};

static int ensure_send_scratch_capacity(Py_ssize_t needed)
{
    if (needed <= 0) {
        return 0;
    }
    if (g_send_scratch.capacity >= needed &&
        g_send_scratch.packets != NULL &&
        g_send_scratch.lengths != NULL) {
        return 0;
    }

    Py_ssize_t new_cap = g_send_scratch.capacity > 0 ? g_send_scratch.capacity : 64;
    while (new_cap < needed) {
        new_cap <<= 1;
    }

    const uint8_t **new_packets = (const uint8_t**)realloc(
        g_send_scratch.packets, (size_t)new_cap * sizeof(uint8_t*)
    );
    if (!new_packets) {
        return -1;
    }

    uint16_t *new_lengths = (uint16_t*)realloc(
        g_send_scratch.lengths, (size_t)new_cap * sizeof(uint16_t)
    );
    if (!new_lengths) {
        // Preserve old pointers on failure.
        g_send_scratch.packets = new_packets;
        return -1;
    }

    PyObject **new_owners = (PyObject**)realloc(
        g_send_scratch.owners, (size_t)new_cap * sizeof(PyObject*)
    );
    if (!new_owners) {
        g_send_scratch.packets = new_packets;
        g_send_scratch.lengths = new_lengths;
        return -1;
    }
    for (Py_ssize_t i = g_send_scratch.capacity; i < new_cap; i++) {
        new_owners[i] = NULL;
    }

    g_send_scratch.packets = new_packets;
    g_send_scratch.lengths = new_lengths;
    g_send_scratch.owners = new_owners;
    g_send_scratch.capacity = new_cap;
    return 0;
}

static void release_send_scratch_owners(Py_ssize_t count)
{
    if (count <= 0 || g_send_scratch.owners == NULL) {
        return;
    }
    for (Py_ssize_t i = 0; i < count; i++) {
        Py_XDECREF(g_send_scratch.owners[i]);
        g_send_scratch.owners[i] = NULL;
    }
}

static void clear_send_scratch(void)
{
    release_send_scratch_owners(g_send_scratch.capacity);
    free((void*)g_send_scratch.packets);
    free((void*)g_send_scratch.lengths);
    free((void*)g_send_scratch.owners);
    g_send_scratch.packets = NULL;
    g_send_scratch.lengths = NULL;
    g_send_scratch.owners = NULL;
    g_send_scratch.capacity = 0;
}

static void release_ctx_send_scratch_owners(xdp_context_t *ctx, Py_ssize_t count)
{
    if (ctx == NULL || count <= 0 || ctx->scratch_owners == NULL) {
        return;
    }
    for (Py_ssize_t i = 0; i < count; i++) {
        Py_XDECREF(ctx->scratch_owners[i]);
        ctx->scratch_owners[i] = NULL;
    }
}

static int ensure_ctx_send_scratch_capacity(xdp_context_t *ctx, Py_ssize_t needed)
{
    if (ctx == NULL || needed <= 0) {
        return 0;
    }
    if (ctx->scratch_capacity >= needed &&
        ctx->scratch_packets != NULL &&
        ctx->scratch_lengths != NULL &&
        ctx->scratch_owners != NULL) {
        return 0;
    }

    Py_ssize_t new_cap = ctx->scratch_capacity > 0 ? ctx->scratch_capacity : 64;
    while (new_cap < needed) {
        new_cap <<= 1;
    }

    const uint8_t **new_packets = (const uint8_t**)realloc(
        (void*)ctx->scratch_packets, (size_t)new_cap * sizeof(uint8_t*)
    );
    if (!new_packets) {
        return -1;
    }

    uint16_t *new_lengths = (uint16_t*)realloc(
        ctx->scratch_lengths, (size_t)new_cap * sizeof(uint16_t)
    );
    if (!new_lengths) {
        ctx->scratch_packets = new_packets;
        return -1;
    }

    PyObject **new_owners = (PyObject**)realloc(
        ctx->scratch_owners, (size_t)new_cap * sizeof(PyObject*)
    );
    if (!new_owners) {
        ctx->scratch_packets = new_packets;
        ctx->scratch_lengths = new_lengths;
        return -1;
    }
    for (Py_ssize_t i = ctx->scratch_capacity; i < new_cap; i++) {
        new_owners[i] = NULL;
    }

    ctx->scratch_packets = new_packets;
    ctx->scratch_lengths = new_lengths;
    ctx->scratch_owners = new_owners;
    ctx->scratch_capacity = new_cap;
    return 0;
}

static void clear_ctx_send_scratch(xdp_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    release_ctx_send_scratch_owners(ctx, ctx->scratch_capacity);
    free((void*)ctx->scratch_packets);
    free(ctx->scratch_lengths);
    free(ctx->scratch_owners);
    ctx->scratch_packets = NULL;
    ctx->scratch_lengths = NULL;
    ctx->scratch_owners = NULL;
    ctx->scratch_capacity = 0;
}

static int xdp_send_vector_locked(const uint8_t **packets, uint16_t *lengths, Py_ssize_t valid_count)
{
    int total_sent = 0;
    Py_ssize_t offset = 0;

    while (offset < valid_count) {
        int batch = (int)(valid_count - offset);
        if (batch > XDP_BATCH_SIZE) {
            batch = XDP_BATCH_SIZE;
        }

        int sent = xdp_send_batch(
            xdp_ctx.xsk,
            packets + offset,
            lengths + offset,
            batch
        );

        if (sent <= 0) {
            xdp_ctx.tx_retry_loops += 1;
            xdp_ctx.tx_backpressure_events += 1;
            complete_tx(xdp_ctx.xsk);
            sent = xdp_send_batch(
                xdp_ctx.xsk,
                packets + offset,
                lengths + offset,
                batch
            );
        }

        if (sent <= 0) {
            break;
        }
        if (sent > batch) {
            sent = batch;
        }

        total_sent += sent;
        offset += sent;
    }

    return total_sent;
}

static void complete_tx_ctx(xdp_context_t *ctx, struct xsk_socket_info *xsk)
{
    if (!xsk->outstanding_tx || ctx->external_umem_mode) return;
    uint32_t completed = xdp_reap_completion_entries(
        xsk,
        xsk->outstanding_tx,
        NULL,
        0,
        1
    );
    if (completed > 0) {
        ctx->tx_completion_events += 1;
        ctx->tx_completed_desc += completed;
    }
}

static void kick_tx_ctx(xdp_context_t *ctx, struct xsk_socket_info *xsk)
{
    if (xsk_ring_prod__needs_wakeup(&xsk->tx)) {
        sendto(xsk->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
        ctx->tx_wakeups++;
    }
}

static int xdp_send_batch_ctx(
    xdp_context_t *ctx,
    struct xsk_socket_info *xsk,
    const uint8_t **packets,
    const uint16_t *lengths,
    int count
)
{
    complete_tx_ctx(ctx, xsk);

    uint32_t tx_idx;
    int batch_size = count < XDP_BATCH_SIZE ? count : XDP_BATCH_SIZE;
    uint32_t reserved = xsk_ring_prod__reserve(&xsk->tx, batch_size, &tx_idx);
    if (reserved == 0) {
        ctx->tx_desc_reserve_failures += 1;
        ctx->tx_backpressure_events += 1;
        kick_tx_ctx(ctx, xsk);
        return 0;
    }

    int submitted = 0;
    for (uint32_t i = 0; i < reserved && submitted < count; i++) {
        uint64_t frame_addr = alloc_frame(xsk);
        if (frame_addr == UINT64_MAX) {
            ctx->tx_frame_alloc_failures += 1;
            ctx->tx_backpressure_events += 1;
            break;
        }

        uint16_t pkt_len = lengths[submitted];
        if (pkt_len > MAX_PACKET_SIZE) {
            pkt_len = MAX_PACKET_SIZE;
        }

        void *pkt_buffer = (uint8_t*)xsk->umem->buffer + frame_addr + xsk->umem->headroom;
        memcpy(pkt_buffer, packets[submitted], pkt_len);

        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx + i);
        tx_desc->addr = frame_addr + xsk->umem->headroom;
        tx_desc->len = pkt_len;
        tx_desc->options = 0;

        submitted++;
        ctx->tx_bytes += pkt_len;
    }

    if (submitted < (int)reserved) {
        ctx->tx_partial_batches += 1;
        xsk_ring_prod__cancel(&xsk->tx, reserved - (uint32_t)submitted);
    }

    if (submitted > 0) {
        xsk_ring_prod__submit(&xsk->tx, submitted);
        xsk->outstanding_tx += submitted;
        ctx->tx_packets += submitted;
    }

    kick_tx_ctx(ctx, xsk);
    return submitted;
}

static int xdp_send_vector_ctx(
    xdp_context_t *ctx,
    const uint8_t **packets,
    uint16_t *lengths,
    Py_ssize_t valid_count
)
{
    int total_sent = 0;
    Py_ssize_t offset = 0;

    while (offset < valid_count) {
        int batch = (int)(valid_count - offset);
        if (batch > XDP_BATCH_SIZE) {
            batch = XDP_BATCH_SIZE;
        }

        int sent = xdp_send_batch_ctx(ctx, ctx->xsk, packets + offset, lengths + offset, batch);
        if (sent <= 0) {
            ctx->tx_retry_loops += 1;
            ctx->tx_backpressure_events += 1;
            complete_tx_ctx(ctx, ctx->xsk);
            sent = xdp_send_batch_ctx(ctx, ctx->xsk, packets + offset, lengths + offset, batch);
        }
        if (sent <= 0) {
            break;
        }
        if (sent > batch) {
            sent = batch;
        }

        total_sent += sent;
        offset += sent;
    }

    return total_sent;
}

static int xdp_send_batch_ctx_strided(
    xdp_context_t *ctx,
    struct xsk_socket_info *xsk,
    const uint8_t *base,
    uint16_t packet_size,
    int stride,
    Py_ssize_t start_offset,
    int count
)
{
    complete_tx_ctx(ctx, xsk);

    uint32_t tx_idx;
    int batch_size = count < XDP_BATCH_SIZE ? count : XDP_BATCH_SIZE;
    uint32_t reserved = xsk_ring_prod__reserve(&xsk->tx, batch_size, &tx_idx);
    if (reserved == 0) {
        ctx->tx_desc_reserve_failures += 1;
        ctx->tx_backpressure_events += 1;
        kick_tx_ctx(ctx, xsk);
        return 0;
    }

    int submitted = 0;
    for (uint32_t i = 0; i < reserved && submitted < count; i++) {
        uint64_t frame_addr = alloc_frame(xsk);
        if (frame_addr == UINT64_MAX) {
            ctx->tx_frame_alloc_failures += 1;
            ctx->tx_backpressure_events += 1;
            break;
        }

        const uint8_t *src = base + (((size_t)(start_offset + submitted)) * (size_t)stride);
        uint16_t pkt_len = packet_size;
        if (pkt_len > MAX_PACKET_SIZE) {
            pkt_len = MAX_PACKET_SIZE;
        }

        void *pkt_buffer = (uint8_t*)xsk->umem->buffer + frame_addr + xsk->umem->headroom;
        memcpy(pkt_buffer, src, pkt_len);

        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx + i);
        tx_desc->addr = frame_addr + xsk->umem->headroom;
        tx_desc->len = pkt_len;
        tx_desc->options = 0;

        submitted++;
        ctx->tx_bytes += pkt_len;
    }

    if (submitted < (int)reserved) {
        ctx->tx_partial_batches += 1;
        xsk_ring_prod__cancel(&xsk->tx, reserved - (uint32_t)submitted);
    }

    if (submitted > 0) {
        xsk_ring_prod__submit(&xsk->tx, submitted);
        xsk->outstanding_tx += submitted;
        ctx->tx_packets += submitted;
    }

    kick_tx_ctx(ctx, xsk);
    return submitted;
}

static int xdp_send_strided_ctx(
    xdp_context_t *ctx,
    const uint8_t *base,
    uint16_t packet_size,
    int stride,
    Py_ssize_t count
)
{
    int total_sent = 0;
    Py_ssize_t offset = 0;

    while (offset < count) {
        int batch = (int)(count - offset);
        if (batch > XDP_BATCH_SIZE) {
            batch = XDP_BATCH_SIZE;
        }

        int sent = xdp_send_batch_ctx_strided(
            ctx,
            ctx->xsk,
            base,
            packet_size,
            stride,
            offset,
            batch
        );
        if (sent <= 0) {
            ctx->tx_retry_loops += 1;
            ctx->tx_backpressure_events += 1;
            complete_tx_ctx(ctx, ctx->xsk);
            sent = xdp_send_batch_ctx_strided(
                ctx,
                ctx->xsk,
                base,
                packet_size,
                stride,
                offset,
                batch
            );
        }
        if (sent <= 0) {
            break;
        }
        if (sent > batch) {
            sent = batch;
        }

        total_sent += sent;
        offset += sent;
    }

    return total_sent;
}

static int xdp_send_vector_paced_ctx(
    xdp_context_t *ctx,
    const uint8_t **packets,
    uint16_t *lengths,
    Py_ssize_t valid_count,
    const xdp_pacing_config_t *cfg
)
{
    int total_sent = 0;
    Py_ssize_t offset = 0;
    uint64_t ipg_next_ns = xdp_time_ns_fast();
    uint64_t burst_resume_ns = ipg_next_ns;
    int burst_counter = 0;
    xdp_token_bucket_t tb;
    memset(&tb, 0, sizeof(tb));

    if (cfg == NULL || cfg->mode == XDP_PACING_NONE) {
        return xdp_send_vector_ctx(ctx, packets, lengths, valid_count);
    }
    if (cfg->mode == XDP_PACING_RPS) {
        xdp_tb_init(
            &tb,
            cfg->target_rps,
            (cfg->burst_size > 0) ? (double)cfg->burst_size : 1.0,
            xdp_time_ns_fast()
        );
    }

    while (offset < valid_count) {
        if (
            xdp_wait_for_pacing_slot(
                cfg,
                &tb,
                &ipg_next_ns,
                &burst_counter,
                &burst_resume_ns
            ) < 0
        ) {
            break;
        }

        int sent = xdp_send_batch_ctx(ctx, ctx->xsk, packets + offset, lengths + offset, 1);
        if (sent <= 0) {
            ctx->tx_retry_loops += 1;
            ctx->tx_backpressure_events += 1;
            complete_tx_ctx(ctx, ctx->xsk);
            sent = xdp_send_batch_ctx(ctx, ctx->xsk, packets + offset, lengths + offset, 1);
        }
        if (sent <= 0) {
            break;
        }
        if (sent > 1) {
            sent = 1;
        }
        total_sent += sent;
        offset += sent;
        xdp_update_pacing_after_send(cfg, &ipg_next_ns, &burst_counter, &burst_resume_ns);
    }

    return total_sent;
}

static int xdp_send_strided_paced_ctx(
    xdp_context_t *ctx,
    const uint8_t *base,
    uint16_t packet_size,
    int stride,
    Py_ssize_t count,
    const xdp_pacing_config_t *cfg
)
{
    int total_sent = 0;
    Py_ssize_t offset = 0;
    uint64_t ipg_next_ns = xdp_time_ns_fast();
    uint64_t burst_resume_ns = ipg_next_ns;
    int burst_counter = 0;
    xdp_token_bucket_t tb;
    memset(&tb, 0, sizeof(tb));

    if (cfg == NULL || cfg->mode == XDP_PACING_NONE) {
        return xdp_send_strided_ctx(ctx, base, packet_size, stride, count);
    }
    if (cfg->mode == XDP_PACING_RPS) {
        xdp_tb_init(
            &tb,
            cfg->target_rps,
            (cfg->burst_size > 0) ? (double)cfg->burst_size : 1.0,
            xdp_time_ns_fast()
        );
    }

    while (offset < count) {
        if (
            xdp_wait_for_pacing_slot(
                cfg,
                &tb,
                &ipg_next_ns,
                &burst_counter,
                &burst_resume_ns
            ) < 0
        ) {
            break;
        }

        int sent = xdp_send_batch_ctx_strided(
            ctx,
            ctx->xsk,
            base,
            packet_size,
            stride,
            offset,
            1
        );
        if (sent <= 0) {
            ctx->tx_retry_loops += 1;
            ctx->tx_backpressure_events += 1;
            complete_tx_ctx(ctx, ctx->xsk);
            sent = xdp_send_batch_ctx_strided(
                ctx,
                ctx->xsk,
                base,
                packet_size,
                stride,
                offset,
                1
            );
        }
        if (sent <= 0) {
            break;
        }
        if (sent > 1) {
            sent = 1;
        }
        total_sent += sent;
        offset += sent;
        xdp_update_pacing_after_send(cfg, &ipg_next_ns, &burst_counter, &burst_resume_ns);
    }

    return total_sent;
}

static int xdp_submit_frame_ids_ctx(
    xdp_context_t *ctx,
    const uint32_t *frame_ids,
    const uint16_t *lengths,
    int count
)
{
    if (ctx == NULL || ctx->xsk == NULL || frame_ids == NULL || lengths == NULL || count <= 0) {
        return 0;
    }

    uint32_t tx_idx;
    int batch_size = count < XDP_BATCH_SIZE ? count : XDP_BATCH_SIZE;
    uint32_t reserved = xsk_ring_prod__reserve(&ctx->xsk->tx, (uint32_t)batch_size, &tx_idx);
    if (reserved == 0) {
        ctx->tx_desc_reserve_failures += 1;
        ctx->tx_backpressure_events += 1;
        kick_tx_ctx(ctx, ctx->xsk);
        return 0;
    }

    int submitted = 0;
    for (uint32_t i = 0; i < reserved && submitted < count; i++) {
        const uint32_t frame_id = frame_ids[submitted];
        if (frame_id >= ctx->xsk->umem->frame_count) {
            ctx->tx_invalid_packets += 1;
            break;
        }
        uint32_t pkt_len = lengths[submitted];
        const uint32_t max_len = ctx->xsk->umem->frame_size - ctx->xsk->umem->headroom;
        if (pkt_len == 0 || pkt_len > max_len) {
            ctx->tx_invalid_packets += 1;
            break;
        }

        const uint64_t frame_addr = (uint64_t)frame_id * (uint64_t)ctx->xsk->umem->frame_size;
        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&ctx->xsk->tx, tx_idx + i);
        tx_desc->addr = frame_addr + ctx->xsk->umem->headroom;
        tx_desc->len = pkt_len;
        tx_desc->options = 0;
        submitted++;
        ctx->tx_bytes += pkt_len;
    }

    if (submitted < (int)reserved) {
        ctx->tx_partial_batches += 1;
        xsk_ring_prod__cancel(&ctx->xsk->tx, reserved - (uint32_t)submitted);
    }
    if (submitted > 0) {
        xsk_ring_prod__submit(&ctx->xsk->tx, (uint32_t)submitted);
        ctx->xsk->outstanding_tx += (uint32_t)submitted;
        ctx->tx_packets += (uint64_t)submitted;
    }
    kick_tx_ctx(ctx, ctx->xsk);
    return submitted;
}

// ============================================================================
// Python Interface Functions
// ============================================================================

/**
 * Initialize AF_XDP socket on specified interface
 * Python: xdp_init(interface, queue_id, mode) -> bool
 */
static PyObject* py_xdp_init(PyObject* self, PyObject* args)
{
    char *ifname;
    int queue_id = 0;
    int mode = 0;  // 0 = SKB/Copy, 1 = Native/Zero-Copy, 2 = Offload(request)
    char map_reason[256];
    
    if (!PyArg_ParseTuple(args, "s|ii", &ifname, &queue_id, &mode)) {
        return NULL;
    }
    (void)self;
    
    pthread_mutex_lock(&xdp_ctx.lock);
    
    if (xdp_ctx.is_initialized) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP already initialized");
        return NULL;
    }
    
    // Check for root privileges
    if (geteuid() != 0) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_PermissionError, "Root privileges required for AF_XDP");
        return NULL;
    }

    if (mode < 0 || mode > 2) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_ValueError, "mode must be one of 0(SKB/Copy), 1(Native/Zero-Copy), 2(Offload)");
        return NULL;
    }
    
    // Increase locked memory limit
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "[XDP] Warning: Could not increase MEMLOCK limit\n");
    }
    
    // Create UMEM
    xdp_ctx.umem = create_umem();
    if (!xdp_ctx.umem) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    
    // Create XDP socket
    xdp_ctx.xsk = create_xsk_socket(xdp_ctx.umem, ifname, queue_id, mode);
    if (!xdp_ctx.xsk) {
        destroy_umem(xdp_ctx.umem);
        xdp_ctx.umem = NULL;
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }
    
    xdp_ctx.xdp_mode = mode;
    xdp_ctx.is_initialized = 1;
    xdp_ctx.is_running = 1;
    xdp_ctx.tx_packets = 0;
    xdp_ctx.tx_bytes = 0;
    xdp_ctx.tx_errors = 0;
    xdp_ctx.tx_wakeups = 0;
    xdp_ctx.tx_desc_reserve_failures = 0;
    xdp_ctx.tx_frame_alloc_failures = 0;
    xdp_ctx.tx_partial_batches = 0;
    xdp_ctx.tx_retry_loops = 0;
    xdp_ctx.tx_completion_events = 0;
    xdp_ctx.tx_completed_desc = 0;
    xdp_ctx.tx_invalid_packets = 0;
    xdp_ctx.tx_backpressure_events = 0;
    xdp_ctx.tx_send_calls = 0;
    xdp_ctx.tx_send_ns_total = 0;
    xdp_ctx.tx_send_ns_max = 0;
    xdp_ctx.queue_id = queue_id;
    xdp_ctx.xsks_map_fd = -1;
    xdp_ctx.xsks_map_key = queue_id;
    xdp_ctx.xsks_map_registered = 0;
    clock_gettime(CLOCK_MONOTONIC, &xdp_ctx.start_time);

    map_reason[0] = '\0';
    if (register_xsk_in_xsks_map(queue_id, xdp_ctx.xsk->fd, map_reason, sizeof(map_reason)) < 0) {
        destroy_xsk_socket(xdp_ctx.xsk);
        xdp_ctx.xsk = NULL;
        destroy_umem(xdp_ctx.umem);
        xdp_ctx.umem = NULL;
        xdp_ctx.is_initialized = 0;
        xdp_ctx.is_running = 0;
        pthread_mutex_unlock(&xdp_ctx.lock);
        if (map_reason[0] != '\0') {
            PyErr_SetString(PyExc_RuntimeError, map_reason);
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Failed to register AF_XDP socket into xsks_map");
        }
        return NULL;
    }
    
    pthread_mutex_unlock(&xdp_ctx.lock);
    
    Py_RETURN_TRUE;
}

/**
 * Cleanup AF_XDP resources
 * Python: xdp_cleanup() -> None
 */
static PyObject* py_xdp_cleanup(PyObject* self, PyObject* args)
{
    (void)self;
    (void)args;
    
    pthread_mutex_lock(&xdp_ctx.lock);
    
    if (!xdp_ctx.is_initialized) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        Py_RETURN_NONE;
    }
    
    xdp_ctx.is_running = 0;

    if (xdp_ctx.xsks_map_registered && xdp_ctx.xsks_map_fd >= 0) {
        (void)bpf_map_delete_elem_fd(xdp_ctx.xsks_map_fd, &xdp_ctx.xsks_map_key);
        close(xdp_ctx.xsks_map_fd);
        xdp_ctx.xsks_map_fd = -1;
        xdp_ctx.xsks_map_registered = 0;
    }
    
    destroy_xsk_socket(xdp_ctx.xsk);
    xdp_ctx.xsk = NULL;
    
    destroy_umem(xdp_ctx.umem);
    xdp_ctx.umem = NULL;
    
    xdp_ctx.is_initialized = 0;
    clear_send_scratch();
    
    pthread_mutex_unlock(&xdp_ctx.lock);
    
    fprintf(stderr, "[XDP] Cleanup complete. Stats: TX=%lu, Bytes=%lu, Errors=%lu, Wakeups=%lu\n",
            xdp_ctx.tx_packets, xdp_ctx.tx_bytes, xdp_ctx.tx_errors, xdp_ctx.tx_wakeups);
    
    Py_RETURN_NONE;
}

/**
 * Send raw packets through AF_XDP
 * Python: xdp_send(packets_list) -> int (packets sent)
 * Each packet in list is a bytes object containing the full IP packet
 */
static PyObject* py_xdp_send(PyObject* self, PyObject* args)
{
    PyObject *packets_list;
    (void)self;
    
    if (!PyArg_ParseTuple(args, "O", &packets_list)) {
        return NULL;
    }
    
    if (!PyList_Check(packets_list)) {
        PyErr_SetString(PyExc_TypeError, "Expected list of bytes objects");
        return NULL;
    }
    
    pthread_mutex_lock(&xdp_ctx.lock);
    
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }
    
    Py_ssize_t count = PyList_Size(packets_list);
    if (count == 0) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        return PyLong_FromLong(0);
    }

    if (ensure_send_scratch_capacity(count) < 0) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_NoMemory();
        return NULL;
    }

    const uint8_t **packets = g_send_scratch.packets;
    uint16_t *lengths = g_send_scratch.lengths;
    
    // Extract packet data from Python list
    Py_ssize_t valid_count = 0;
    release_send_scratch_owners(count);
    for (Py_ssize_t i = 0; i < count; i++) {
        PyObject *item = PyList_GetItem(packets_list, i);
        if (PyBytes_Check(item)) {
            Py_ssize_t pkt_len = PyBytes_GET_SIZE(item);
            if (pkt_len <= 0 || pkt_len > 65535) {
                xdp_ctx.tx_invalid_packets += 1;
                continue;
            }
            Py_INCREF(item);
            g_send_scratch.owners[valid_count] = item;
            packets[valid_count] = (const uint8_t*)PyBytes_AS_STRING(item);
            lengths[valid_count] = (uint16_t)pkt_len;
            valid_count++;
        } else {
            xdp_ctx.tx_invalid_packets += 1;
        }
    }

    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;
    Py_BEGIN_ALLOW_THREADS
    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_vector_locked(packets, lengths, valid_count);
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    Py_END_ALLOW_THREADS
    xdp_record_send_timing(&xdp_ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    release_send_scratch_owners(valid_count);
    
    pthread_mutex_unlock(&xdp_ctx.lock);
    
    return PyLong_FromLong(total_sent);
}

/**
 * Send packets from a contiguous buffer.
 * Python: xdp_send_buffer(buffer, packet_size, count) -> int
 */
static PyObject* py_xdp_send_buffer(PyObject* self, PyObject* args)
{
    Py_buffer view;
    int packet_size = 0;
    int count = 0;

    (void)self;
    if (!PyArg_ParseTuple(args, "y*ii", &view, &packet_size, &count)) {
        return NULL;
    }

    if (packet_size <= 0 || count < 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size must be > 0 and count must be >= 0");
        return NULL;
    }
    if (count == 0) {
        PyBuffer_Release(&view);
        return PyLong_FromLong(0);
    }

    if ((size_t)view.len < ((size_t)packet_size * (size_t)count)) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "buffer smaller than packet_size * count");
        return NULL;
    }
    if (packet_size > 65535) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size exceeds uint16_t limit");
        return NULL;
    }

    pthread_mutex_lock(&xdp_ctx.lock);
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }

    if (ensure_send_scratch_capacity((Py_ssize_t)count) < 0) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyBuffer_Release(&view);
        PyErr_NoMemory();
        return NULL;
    }

    const uint8_t *base = (const uint8_t*)view.buf;
    for (int i = 0; i < count; i++) {
        g_send_scratch.packets[i] = base + ((size_t)i * (size_t)packet_size);
        g_send_scratch.lengths[i] = (uint16_t)packet_size;
    }

    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;
    Py_BEGIN_ALLOW_THREADS
    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_vector_locked(g_send_scratch.packets, g_send_scratch.lengths, (Py_ssize_t)count);
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    Py_END_ALLOW_THREADS
    xdp_record_send_timing(&xdp_ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    pthread_mutex_unlock(&xdp_ctx.lock);
    PyBuffer_Release(&view);
    return PyLong_FromLong(total_sent);
}

/**
 * Send packets from a strided contiguous buffer.
 * Python: xdp_send_buffer_strided(buffer, packet_size, stride, count) -> int
 */
static PyObject* py_xdp_send_buffer_strided(PyObject* self, PyObject* args)
{
    Py_buffer view;
    int packet_size = 0;
    int stride = 0;
    int count = 0;

    (void)self;
    if (!PyArg_ParseTuple(args, "y*iii", &view, &packet_size, &stride, &count)) {
        return NULL;
    }

    if (packet_size <= 0 || stride <= 0 || count < 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size/stride must be > 0 and count must be >= 0");
        return NULL;
    }
    if (stride < packet_size) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "stride must be >= packet_size");
        return NULL;
    }
    if (count == 0) {
        PyBuffer_Release(&view);
        return PyLong_FromLong(0);
    }

    const size_t needed = ((size_t)(count - 1) * (size_t)stride) + (size_t)packet_size;
    if ((size_t)view.len < needed) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "buffer smaller than strided packet range");
        return NULL;
    }
    if (packet_size > 65535) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size exceeds uint16_t limit");
        return NULL;
    }

    pthread_mutex_lock(&xdp_ctx.lock);
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }

    if (ensure_send_scratch_capacity((Py_ssize_t)count) < 0) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyBuffer_Release(&view);
        PyErr_NoMemory();
        return NULL;
    }

    const uint8_t *base = (const uint8_t*)view.buf;
    for (int i = 0; i < count; i++) {
        g_send_scratch.packets[i] = base + ((size_t)i * (size_t)stride);
        g_send_scratch.lengths[i] = (uint16_t)packet_size;
    }

    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;
    Py_BEGIN_ALLOW_THREADS
    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_vector_locked(g_send_scratch.packets, g_send_scratch.lengths, (Py_ssize_t)count);
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    Py_END_ALLOW_THREADS
    xdp_record_send_timing(&xdp_ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    pthread_mutex_unlock(&xdp_ctx.lock);
    PyBuffer_Release(&view);
    return PyLong_FromLong(total_sent);
}

/**
 * Send packets from contiguous buffer with native pacing.
 * Python: xdp_send_buffer_paced(buffer, packet_size, count,
 *                               pacing_mode=1, target_rps=0.0,
 *                               ipg_ns=0, burst_size=1, burst_gap_ns=0) -> int
 */
static PyObject* py_xdp_send_buffer_paced(PyObject* self, PyObject* args)
{
    Py_buffer view;
    int packet_size = 0;
    int count = 0;
    int pacing_mode = XDP_PACING_RPS;
    double target_rps = 0.0;
    unsigned long long ipg_ns_ull = 0;
    int burst_size = 1;
    unsigned long long burst_gap_ns_ull = 0;
    xdp_pacing_config_t cfg;

    (void)self;
    if (!PyArg_ParseTuple(args, "y*ii|idKiK",
                          &view, &packet_size, &count,
                          &pacing_mode, &target_rps, &ipg_ns_ull, &burst_size, &burst_gap_ns_ull)) {
        return NULL;
    }
    if (packet_size <= 0 || count < 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size must be > 0 and count must be >= 0");
        return NULL;
    }
    if (count == 0) {
        PyBuffer_Release(&view);
        return PyLong_FromLong(0);
    }
    if ((size_t)view.len < ((size_t)packet_size * (size_t)count)) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "buffer smaller than packet_size * count");
        return NULL;
    }
    if (packet_size > 65535) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size exceeds uint16_t limit");
        return NULL;
    }
    if (xdp_prepare_pacing_config(
            &cfg,
            pacing_mode,
            target_rps,
            (uint64_t)ipg_ns_ull,
            burst_size,
            (uint64_t)burst_gap_ns_ull
        ) != 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(
            PyExc_ValueError,
            "invalid pacing config (mode=0:none,1:rps,2:ipg,3:burst; validate rps/ipg/burst params)"
        );
        return NULL;
    }

    pthread_mutex_lock(&xdp_ctx.lock);
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }
    if (ensure_send_scratch_capacity((Py_ssize_t)count) < 0) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyBuffer_Release(&view);
        PyErr_NoMemory();
        return NULL;
    }

    const uint8_t *base = (const uint8_t*)view.buf;
    for (int i = 0; i < count; i++) {
        g_send_scratch.packets[i] = base + ((size_t)i * (size_t)packet_size);
        g_send_scratch.lengths[i] = (uint16_t)packet_size;
    }

    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;
    Py_BEGIN_ALLOW_THREADS
    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_vector_paced_ctx(
        &xdp_ctx,
        g_send_scratch.packets,
        g_send_scratch.lengths,
        (Py_ssize_t)count,
        &cfg
    );
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    Py_END_ALLOW_THREADS
    xdp_record_send_timing(&xdp_ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    pthread_mutex_unlock(&xdp_ctx.lock);
    PyBuffer_Release(&view);
    return PyLong_FromLong(total_sent);
}

/**
 * Send packets from strided buffer with native pacing.
 * Python: xdp_send_buffer_strided_paced(buffer, packet_size, stride, count,
 *                                       pacing_mode=1, target_rps=0.0,
 *                                       ipg_ns=0, burst_size=1, burst_gap_ns=0) -> int
 */
static PyObject* py_xdp_send_buffer_strided_paced(PyObject* self, PyObject* args)
{
    Py_buffer view;
    int packet_size = 0;
    int stride = 0;
    int count = 0;
    int pacing_mode = XDP_PACING_RPS;
    double target_rps = 0.0;
    unsigned long long ipg_ns_ull = 0;
    int burst_size = 1;
    unsigned long long burst_gap_ns_ull = 0;
    xdp_pacing_config_t cfg;

    (void)self;
    if (!PyArg_ParseTuple(args, "y*iii|idKiK",
                          &view, &packet_size, &stride, &count,
                          &pacing_mode, &target_rps, &ipg_ns_ull, &burst_size, &burst_gap_ns_ull)) {
        return NULL;
    }
    if (packet_size <= 0 || stride <= 0 || count < 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size/stride must be > 0 and count must be >= 0");
        return NULL;
    }
    if (stride < packet_size) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "stride must be >= packet_size");
        return NULL;
    }
    if (count == 0) {
        PyBuffer_Release(&view);
        return PyLong_FromLong(0);
    }
    if (packet_size > 65535) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size exceeds uint16_t limit");
        return NULL;
    }
    {
        const size_t needed = ((size_t)(count - 1) * (size_t)stride) + (size_t)packet_size;
        if ((size_t)view.len < needed) {
            PyBuffer_Release(&view);
            PyErr_SetString(PyExc_ValueError, "buffer smaller than strided packet range");
            return NULL;
        }
    }
    if (xdp_prepare_pacing_config(
            &cfg,
            pacing_mode,
            target_rps,
            (uint64_t)ipg_ns_ull,
            burst_size,
            (uint64_t)burst_gap_ns_ull
        ) != 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(
            PyExc_ValueError,
            "invalid pacing config (mode=0:none,1:rps,2:ipg,3:burst; validate rps/ipg/burst params)"
        );
        return NULL;
    }

    pthread_mutex_lock(&xdp_ctx.lock);
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }

    const uint8_t *base = (const uint8_t*)view.buf;
    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;
    Py_BEGIN_ALLOW_THREADS
    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_strided_paced_ctx(
        &xdp_ctx,
        base,
        (uint16_t)packet_size,
        stride,
        (Py_ssize_t)count,
        &cfg
    );
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    Py_END_ALLOW_THREADS
    xdp_record_send_timing(&xdp_ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    pthread_mutex_unlock(&xdp_ctx.lock);
    PyBuffer_Release(&view);
    return PyLong_FromLong(total_sent);
}

/**
 * Acquire a writable UMEM TX frame for user-space in-place packet build.
 * Python: xdp_acquire_tx_frame() -> (frame_id:int, view:memoryview) | None
 */
static PyObject* py_xdp_acquire_tx_frame(PyObject* self, PyObject* args)
{
    (void)self;
    (void)args;

    pthread_mutex_lock(&xdp_ctx.lock);
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }

    complete_tx(xdp_ctx.xsk);
    uint64_t frame_addr = alloc_frame(xdp_ctx.xsk);
    if (frame_addr == UINT64_MAX) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        Py_RETURN_NONE;
    }

    uint32_t frame_id = (uint32_t)(frame_addr / xdp_ctx.xsk->umem->frame_size);
    char *frame_ptr = (char*)xdp_ctx.xsk->umem->buffer + frame_addr + xdp_ctx.xsk->umem->headroom;
    const Py_ssize_t writable_len = (Py_ssize_t)(xdp_ctx.xsk->umem->frame_size - xdp_ctx.xsk->umem->headroom);
    PyObject *view = PyMemoryView_FromMemory(frame_ptr, writable_len, PyBUF_WRITE);
    pthread_mutex_unlock(&xdp_ctx.lock);

    if (view == NULL) {
        pthread_mutex_lock(&xdp_ctx.lock);
        free_frame(xdp_ctx.xsk, frame_addr);
        pthread_mutex_unlock(&xdp_ctx.lock);
        return NULL;
    }
    return Py_BuildValue("IO", frame_id, view);
}

/**
 * Submit a previously acquired TX frame.
 * Python: xdp_submit_tx_frame(frame_id:int, length:int) -> bool
 */
static PyObject* py_xdp_submit_tx_frame(PyObject* self, PyObject* args)
{
    int frame_id = -1;
    int length = 0;
    int max_len = 0;
    (void)self;

    if (!PyArg_ParseTuple(args, "ii", &frame_id, &length)) {
        return NULL;
    }

    pthread_mutex_lock(&xdp_ctx.lock);
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }
    if (xdp_ctx.xsk == NULL || xdp_ctx.xsk->umem == NULL) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP socket context unavailable");
        return NULL;
    }
    if (frame_id < 0 || frame_id >= (int)xdp_ctx.xsk->umem->frame_count) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_ValueError, "frame_id out of range");
        return NULL;
    }
    max_len = (int)(xdp_ctx.xsk->umem->frame_size - xdp_ctx.xsk->umem->headroom);
    if (length <= 0 || length > max_len) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_ValueError, "length must be in range 1..frame_payload_capacity");
        return NULL;
    }

    complete_tx(xdp_ctx.xsk);
    uint32_t tx_idx;
    if (xsk_ring_prod__reserve(&xdp_ctx.xsk->tx, 1, &tx_idx) == 0) {
        xdp_ctx.tx_backpressure_events += 1;
        kick_tx(xdp_ctx.xsk);
        pthread_mutex_unlock(&xdp_ctx.lock);
        Py_RETURN_FALSE;
    }

    uint64_t frame_addr = (uint64_t)frame_id * (uint64_t)xdp_ctx.xsk->umem->frame_size;
    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xdp_ctx.xsk->tx, tx_idx);
    tx_desc->addr = frame_addr + xdp_ctx.xsk->umem->headroom;
    tx_desc->len = (uint32_t)length;
    tx_desc->options = 0;

    xsk_ring_prod__submit(&xdp_ctx.xsk->tx, 1);
    xdp_ctx.xsk->outstanding_tx += 1;
    xdp_ctx.tx_packets += 1;
    xdp_ctx.tx_bytes += (uint64_t)length;
    kick_tx(xdp_ctx.xsk);
    pthread_mutex_unlock(&xdp_ctx.lock);
    Py_RETURN_TRUE;
}

/**
 * Release an acquired TX frame without transmitting.
 * Python: xdp_release_tx_frame(frame_id:int) -> bool
 */
static PyObject* py_xdp_release_tx_frame(PyObject* self, PyObject* args)
{
    int frame_id = -1;
    (void)self;

    if (!PyArg_ParseTuple(args, "i", &frame_id)) {
        return NULL;
    }
    pthread_mutex_lock(&xdp_ctx.lock);
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }
    if (xdp_ctx.xsk == NULL || xdp_ctx.xsk->umem == NULL) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP socket context unavailable");
        return NULL;
    }
    if (frame_id < 0 || frame_id >= (int)xdp_ctx.xsk->umem->frame_count) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_ValueError, "frame_id out of range");
        return NULL;
    }
    free_frame(xdp_ctx.xsk, (uint64_t)frame_id * (uint64_t)xdp_ctx.xsk->umem->frame_size);
    pthread_mutex_unlock(&xdp_ctx.lock);
    Py_RETURN_TRUE;
}

/**
 * Send a batch of UDP packets (helper function)
 * Python: xdp_send_udp(target_ip, target_port, payloads, source_ports) -> int
 */
static PyObject* xdp_send_udp_common(PyObject* args)
{
    char *target_ip;
    int target_port;
    PyObject *payloads_list;
    PyObject *src_ports_list = NULL;
    
    if (!PyArg_ParseTuple(args, "siO|O", &target_ip, &target_port,
                          &payloads_list, &src_ports_list)) {
        return NULL;
    }
    
    if (!PyList_Check(payloads_list)) {
        PyErr_SetString(PyExc_TypeError, "Expected list of bytes for payloads");
        return NULL;
    }
    
    pthread_mutex_lock(&xdp_ctx.lock);
    
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }
    
    Py_ssize_t count = PyList_Size(payloads_list);
    struct in_addr dst_addr;
    inet_pton(AF_INET, target_ip, &dst_addr);
    
    // Build packets directly in UMEM and submit descriptors.
    // This removes the intermediate stack packet buffer copy.
    int total_sent = 0;
    const size_t udp_payload_cap =
        (size_t)MAX_PACKET_SIZE - sizeof(struct iphdr) - sizeof(struct udphdr);
    
    for (Py_ssize_t i = 0; i < count; i++) {
        PyObject *payload_obj = PyList_GetItem(payloads_list, i);
        if (!PyBytes_Check(payload_obj)) continue;
        
        const uint8_t *payload = (const uint8_t*)PyBytes_AS_STRING(payload_obj);
        Py_ssize_t payload_len = PyBytes_GET_SIZE(payload_obj);
        if (payload_len < 0 || (size_t)payload_len > udp_payload_cap) {
            pthread_mutex_unlock(&xdp_ctx.lock);
            PyErr_Format(
                PyExc_ValueError,
                "payload[%zd] too large for XDP UDP frame: %zd > %zu",
                i,
                payload_len,
                udp_payload_cap
            );
            return NULL;
        }
        
        // Get source port
        uint16_t src_port = 10000 + (rand() % 55000);
        if (src_ports_list && PyList_Check(src_ports_list) && 
            i < PyList_Size(src_ports_list)) {
            PyObject *port_obj = PyList_GetItem(src_ports_list, i);
            if (PyLong_Check(port_obj)) {
                src_port = (uint16_t)PyLong_AsLong(port_obj);
            }
        }
        
        // Complete pending TX to recover frames when possible.
        complete_tx(xdp_ctx.xsk);

        uint32_t tx_idx;
        if (xsk_ring_prod__reserve(&xdp_ctx.xsk->tx, 1, &tx_idx) == 0) {
            xdp_ctx.tx_desc_reserve_failures += 1;
            xdp_ctx.tx_backpressure_events += 1;
            kick_tx(xdp_ctx.xsk);
            continue;
        }

        uint64_t frame_addr = alloc_frame(xdp_ctx.xsk);
        if (frame_addr == UINT64_MAX) {
            xdp_ctx.tx_errors++;
            xdp_ctx.tx_frame_alloc_failures += 1;
            xdp_ctx.tx_backpressure_events += 1;
            xsk_ring_prod__cancel(&xdp_ctx.xsk->tx, 1);
            continue;
        }

        uint8_t *pkt_buffer = (uint8_t*)xdp_ctx.xsk->umem->buffer + frame_addr + xdp_ctx.xsk->umem->headroom;
        size_t pkt_offset = 0;
        
        // IP Header
        struct iphdr *iph = (struct iphdr*)pkt_buffer;
        iph->version = 4;
        iph->ihl = 5;
        iph->tos = 0;
        iph->tot_len = htons((uint16_t)(sizeof(struct iphdr) + sizeof(struct udphdr) + (size_t)payload_len));
        iph->id = htons(rand() & 0xFFFF);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;
        iph->saddr = htonl(rand());  // Random source IP
        iph->daddr = dst_addr.s_addr;
        iph->check = ip_checksum(iph, sizeof(struct iphdr));
        pkt_offset += sizeof(struct iphdr);
        
        // UDP Header
        struct udphdr *udph = (struct udphdr*)(pkt_buffer + pkt_offset);
        udph->source = htons(src_port);
        udph->dest = htons(target_port);
        udph->len = htons((uint16_t)(sizeof(struct udphdr) + (size_t)payload_len));
        udph->check = 0;
        pkt_offset += sizeof(struct udphdr);
        
        // Payload
        memcpy(pkt_buffer + pkt_offset, payload, (size_t)payload_len);
        pkt_offset += (size_t)payload_len;
        
        // Calculate UDP checksum
        udph->check = udp_checksum(iph, udph, pkt_buffer + sizeof(struct iphdr) + sizeof(struct udphdr), (size_t)payload_len);

        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xdp_ctx.xsk->tx, tx_idx);
        tx_desc->addr = frame_addr + xdp_ctx.xsk->umem->headroom;
        tx_desc->len = (uint32_t)pkt_offset;
        tx_desc->options = 0;

        xsk_ring_prod__submit(&xdp_ctx.xsk->tx, 1);
        xdp_ctx.xsk->outstanding_tx += 1;
        xdp_ctx.tx_packets += 1;
        xdp_ctx.tx_bytes += (uint64_t)pkt_offset;
        total_sent += 1;
        kick_tx(xdp_ctx.xsk);
    }
    
    pthread_mutex_unlock(&xdp_ctx.lock);
    
    return PyLong_FromLong(total_sent);
}

static PyObject* py_xdp_send_udp(PyObject* self, PyObject* args)
{
    (void)self;
    return xdp_send_udp_common(args);
}

/**
 * Zero-copy oriented UDP helper: directly builds packets into UMEM frames.
 * Python: xdp_send_udp_zc(target_ip, target_port, payloads, source_ports) -> int
 */
static PyObject* py_xdp_send_udp_zc(PyObject* self, PyObject* args)
{
    (void)self;
    return xdp_send_udp_common(args);
}

/**
 * Get XDP statistics
 * Python: xdp_stats() -> dict
 */
static PyObject* py_xdp_stats(PyObject* self, PyObject* args)
{
    (void)self;
    (void)args;
    
    pthread_mutex_lock(&xdp_ctx.lock);
    
    if (!xdp_ctx.is_initialized) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        Py_RETURN_NONE;
    }
    
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    
    double elapsed = (now.tv_sec - xdp_ctx.start_time.tv_sec) +
                     (now.tv_nsec - xdp_ctx.start_time.tv_nsec) / 1e9;
    
    double pps = elapsed > 0 ? xdp_ctx.tx_packets / elapsed : 0;
    double mbps = elapsed > 0 ? (xdp_ctx.tx_bytes * 8) / (elapsed * 1e6) : 0;
    
    uint64_t tx_packets = xdp_ctx.tx_packets;
    uint64_t tx_bytes = xdp_ctx.tx_bytes;
    uint64_t tx_errors = xdp_ctx.tx_errors;
    uint64_t tx_wakeups = xdp_ctx.tx_wakeups;
    uint64_t tx_desc_reserve_failures = xdp_ctx.tx_desc_reserve_failures;
    uint64_t tx_frame_alloc_failures = xdp_ctx.tx_frame_alloc_failures;
    uint64_t tx_partial_batches = xdp_ctx.tx_partial_batches;
    uint64_t tx_retry_loops = xdp_ctx.tx_retry_loops;
    uint64_t tx_completion_events = xdp_ctx.tx_completion_events;
    uint64_t tx_completed_desc = xdp_ctx.tx_completed_desc;
    uint64_t tx_invalid_packets = xdp_ctx.tx_invalid_packets;
    uint64_t tx_backpressure_events = xdp_ctx.tx_backpressure_events;
    uint64_t tx_send_calls = xdp_ctx.tx_send_calls;
    uint64_t tx_send_ns_total = xdp_ctx.tx_send_ns_total;
    uint64_t tx_send_ns_max = xdp_ctx.tx_send_ns_max;
    int xdp_mode = xdp_ctx.xdp_mode;
    int queue_id = xdp_ctx.queue_id;
    
    pthread_mutex_unlock(&xdp_ctx.lock);
    double tx_send_avg_us = tx_send_calls > 0
        ? ((double)tx_send_ns_total / (double)tx_send_calls) / 1000.0
        : 0.0;
    double tx_send_max_us = ((double)tx_send_ns_max) / 1000.0;
    
    return Py_BuildValue("{s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:d,s:d,s:d,s:d,s:d,s:i,s:i,s:s}",
                         "tx_packets", tx_packets,
                         "tx_bytes", tx_bytes,
                         "tx_errors", tx_errors,
                         "tx_wakeups", tx_wakeups,
                         "tx_desc_reserve_failures", tx_desc_reserve_failures,
                         "tx_frame_alloc_failures", tx_frame_alloc_failures,
                         "tx_partial_batches", tx_partial_batches,
                         "tx_retry_loops", tx_retry_loops,
                         "tx_completion_events", tx_completion_events,
                         "tx_completed_desc", tx_completed_desc,
                         "tx_invalid_packets", tx_invalid_packets,
                         "tx_backpressure_events", tx_backpressure_events,
                         "tx_send_calls", tx_send_calls,
                         "tx_send_ns_total", tx_send_ns_total,
                         "tx_send_ns_max", tx_send_ns_max,
                         "elapsed_seconds", elapsed,
                         "packets_per_second", pps,
                         "mbps", mbps,
                         "tx_send_avg_us", tx_send_avg_us,
                         "tx_send_max_us", tx_send_max_us,
                         "queue_id", queue_id,
                         "mode", xdp_mode,
                         "mode_name", xdp_mode_name(xdp_mode));
}

/**
 * Check if XDP is available on system
 * Python: xdp_available() -> bool
 */
static PyObject* py_xdp_available(PyObject* self, PyObject* args)
{
    (void)self;
    (void)args;
    
    // Try to create AF_XDP socket to check availability
    int fd = socket(AF_XDP, SOCK_RAW, 0);
    if (fd >= 0) {
        close(fd);
        Py_RETURN_TRUE;
    }
    
    Py_RETURN_FALSE;
}

/**
 * Get info about the system's XDP capabilities
 * Python: xdp_info() -> dict
 */
static PyObject* py_xdp_info(PyObject* self, PyObject* args)
{
    (void)self;
    (void)args;
    
    int af_xdp_available = 0;
    int is_root = geteuid() == 0;
    
    // Check AF_XDP availability
    int fd = socket(AF_XDP, SOCK_RAW, 0);
    if (fd >= 0) {
        af_xdp_available = 1;
        close(fd);
    }
    
    // Get kernel version
    struct utsname buffer;
    uname(&buffer);
    
    return Py_BuildValue("{s:i,s:i,s:s,s:i,s:i,s:i,s:i}",
                         "af_xdp_available", af_xdp_available,
                         "is_root", is_root,
                         "kernel_release", buffer.release,
                         "num_frames", XDP_NUM_FRAMES,
                         "frame_size", XDP_FRAME_SIZE,
                         "batch_size", XDP_BATCH_SIZE,
                         "headroom", XDP_HEADROOM);
}

static void cleanup_ctx_locked(xdp_context_t *ctx)
{
    clear_ctx_send_scratch(ctx);

    if (!ctx->is_initialized) {
        return;
    }

    ctx->is_running = 0;

    if (ctx->xsks_map_registered && ctx->xsks_map_fd >= 0) {
        (void)bpf_map_delete_elem_fd(ctx->xsks_map_fd, &ctx->xsks_map_key);
        close(ctx->xsks_map_fd);
        ctx->xsks_map_fd = -1;
        ctx->xsks_map_registered = 0;
    }

    destroy_xsk_socket(ctx->xsk);
    ctx->xsk = NULL;

    destroy_umem(ctx->umem);
    ctx->umem = NULL;

    ctx->is_initialized = 0;
}

static PyObject* py_xdp_create(PyObject* self, PyObject* args)
{
    char *ifname;
    int queue_id = 0;
    int mode = 0;
    char map_reason[256];
    xdp_context_t *ctx = NULL;
    int handle = -1;

    (void)self;
    if (!PyArg_ParseTuple(args, "s|ii", &ifname, &queue_id, &mode)) {
        return NULL;
    }

    if (geteuid() != 0) {
        PyErr_SetString(PyExc_PermissionError, "Root privileges required for AF_XDP");
        return NULL;
    }
    if (mode < 0 || mode > 2) {
        PyErr_SetString(PyExc_ValueError, "mode must be one of 0(SKB/Copy), 1(Native/Zero-Copy), 2(Offload)");
        return NULL;
    }

    ctx = (xdp_context_t*)calloc(1, sizeof(*ctx));
    if (!ctx) {
        PyErr_NoMemory();
        return NULL;
    }
    pthread_mutex_init(&ctx->lock, NULL);
    pthread_mutex_lock(&ctx->lock);

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "[XDP][ctx] Warning: Could not increase MEMLOCK limit\n");
    }

    ctx->umem = create_umem();
    if (!ctx->umem) {
        pthread_mutex_unlock(&ctx->lock);
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    ctx->xsk = create_xsk_socket(ctx->umem, ifname, queue_id, mode);
    if (!ctx->xsk) {
        destroy_umem(ctx->umem);
        ctx->umem = NULL;
        pthread_mutex_unlock(&ctx->lock);
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    ctx->xdp_mode = mode;
    ctx->is_initialized = 1;
    ctx->is_running = 1;
    ctx->tx_packets = 0;
    ctx->tx_bytes = 0;
    ctx->tx_errors = 0;
    ctx->tx_wakeups = 0;
    ctx->tx_desc_reserve_failures = 0;
    ctx->tx_frame_alloc_failures = 0;
    ctx->tx_partial_batches = 0;
    ctx->tx_retry_loops = 0;
    ctx->tx_completion_events = 0;
    ctx->tx_completed_desc = 0;
    ctx->tx_invalid_packets = 0;
    ctx->tx_backpressure_events = 0;
    ctx->tx_send_calls = 0;
    ctx->tx_send_ns_total = 0;
    ctx->tx_send_ns_max = 0;
    ctx->queue_id = queue_id;
    ctx->xsks_map_fd = -1;
    ctx->xsks_map_key = queue_id;
    ctx->xsks_map_registered = 0;
    clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);

    map_reason[0] = '\0';
    if (register_xsk_in_xsks_map_ctx(ctx, queue_id, ctx->xsk->fd, map_reason, sizeof(map_reason)) < 0) {
        cleanup_ctx_locked(ctx);
        pthread_mutex_unlock(&ctx->lock);
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        if (map_reason[0] != '\0') {
            PyErr_SetString(PyExc_RuntimeError, map_reason);
        } else {
            PyErr_SetString(PyExc_RuntimeError, "Failed to register AF_XDP socket into xsks_map");
        }
        return NULL;
    }

    pthread_mutex_unlock(&ctx->lock);
    handle = register_ctx_handle(ctx);
    if (handle < 0) {
        pthread_mutex_lock(&ctx->lock);
        cleanup_ctx_locked(ctx);
        pthread_mutex_unlock(&ctx->lock);
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        PyErr_SetString(PyExc_RuntimeError, "No free XDP context slots");
        return NULL;
    }

    return PyLong_FromLong(handle);
}

static PyObject* py_xdp_destroy(PyObject* self, PyObject* args)
{
    int handle = 0;
    xdp_context_t *ctx = NULL;

    (void)self;
    if (!PyArg_ParseTuple(args, "i", &handle)) {
        return NULL;
    }

    ctx = remove_ctx_by_handle_locked(handle);
    if (!ctx) {
        PyErr_SetString(PyExc_KeyError, "Invalid XDP context handle");
        return NULL;
    }

    cleanup_ctx_locked(ctx);
    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
    Py_RETURN_NONE;
}

static PyObject* py_xdp_send_ctx(PyObject* self, PyObject* args)
{
    int handle = 0;
    PyObject *packets_list;
    xdp_context_t *ctx = NULL;
    const uint8_t **packets = NULL;
    uint16_t *lengths = NULL;
    Py_ssize_t count = 0;
    Py_ssize_t valid_count = 0;
    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;

    (void)self;
    if (!PyArg_ParseTuple(args, "iO", &handle, &packets_list)) {
        return NULL;
    }
    if (!PyList_Check(packets_list)) {
        PyErr_SetString(PyExc_TypeError, "Expected list of bytes objects");
        return NULL;
    }

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        PyErr_SetString(PyExc_KeyError, "Invalid XDP context handle");
        return NULL;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP context not initialized");
        return NULL;
    }

    count = PyList_Size(packets_list);
    if (count == 0) {
        pthread_mutex_unlock(&ctx->lock);
        return PyLong_FromLong(0);
    }

    if (ensure_ctx_send_scratch_capacity(ctx, count) < 0) {
        pthread_mutex_unlock(&ctx->lock);
        PyErr_NoMemory();
        return NULL;
    }
    packets = ctx->scratch_packets;
    lengths = ctx->scratch_lengths;
    release_ctx_send_scratch_owners(ctx, count);

    for (Py_ssize_t i = 0; i < count; i++) {
        PyObject *item = PyList_GetItem(packets_list, i);
        if (PyBytes_Check(item)) {
            Py_ssize_t pkt_len = PyBytes_GET_SIZE(item);
            if (pkt_len <= 0 || pkt_len > 65535) {
                ctx->tx_invalid_packets += 1;
                continue;
            }
            Py_INCREF(item);
            ctx->scratch_owners[valid_count] = item;
            packets[valid_count] = (const uint8_t*)PyBytes_AS_STRING(item);
            lengths[valid_count] = (uint16_t)pkt_len;
            valid_count++;
        } else {
            ctx->tx_invalid_packets += 1;
        }
    }

    Py_BEGIN_ALLOW_THREADS
    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_vector_ctx(ctx, packets, lengths, valid_count);
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    Py_END_ALLOW_THREADS
    xdp_record_send_timing(ctx, xdp_timespec_diff_ns(&send_start, &send_end));

    release_ctx_send_scratch_owners(ctx, valid_count);
    pthread_mutex_unlock(&ctx->lock);
    return PyLong_FromLong(total_sent);
}

static PyObject* py_xdp_send_buffer_ctx(PyObject* self, PyObject* args)
{
    int handle = 0;
    Py_buffer view;
    int packet_size = 0;
    int count = 0;
    xdp_context_t *ctx = NULL;
    const uint8_t **packets = NULL;
    uint16_t *lengths = NULL;
    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;

    (void)self;
    if (!PyArg_ParseTuple(args, "iy*ii", &handle, &view, &packet_size, &count)) {
        return NULL;
    }

    if (packet_size <= 0 || count < 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size must be > 0 and count must be >= 0");
        return NULL;
    }
    if ((size_t)view.len < ((size_t)packet_size * (size_t)count)) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "buffer smaller than packet_size * count");
        return NULL;
    }
    if (count == 0) {
        PyBuffer_Release(&view);
        return PyLong_FromLong(0);
    }

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_KeyError, "Invalid XDP context handle");
        return NULL;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_RuntimeError, "XDP context not initialized");
        return NULL;
    }

    if (ensure_ctx_send_scratch_capacity(ctx, (Py_ssize_t)count) < 0) {
        pthread_mutex_unlock(&ctx->lock);
        PyBuffer_Release(&view);
        PyErr_NoMemory();
        return NULL;
    }
    packets = ctx->scratch_packets;
    lengths = ctx->scratch_lengths;
    release_ctx_send_scratch_owners(ctx, (Py_ssize_t)count);

    const uint8_t *base = (const uint8_t*)view.buf;
    for (int i = 0; i < count; i++) {
        packets[i] = base + ((size_t)i * (size_t)packet_size);
        lengths[i] = (uint16_t)packet_size;
    }

    Py_BEGIN_ALLOW_THREADS
    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_vector_ctx(ctx, packets, lengths, (Py_ssize_t)count);
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    Py_END_ALLOW_THREADS
    xdp_record_send_timing(ctx, xdp_timespec_diff_ns(&send_start, &send_end));

    pthread_mutex_unlock(&ctx->lock);
    PyBuffer_Release(&view);
    return PyLong_FromLong(total_sent);
}

static PyObject* py_xdp_send_buffer_strided_ctx(PyObject* self, PyObject* args)
{
    int handle = 0;
    Py_buffer view;
    int packet_size = 0;
    int stride = 0;
    int count = 0;
    xdp_context_t *ctx = NULL;
    const uint8_t **packets = NULL;
    uint16_t *lengths = NULL;
    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;

    (void)self;
    if (!PyArg_ParseTuple(args, "iy*iii", &handle, &view, &packet_size, &stride, &count)) {
        return NULL;
    }

    if (packet_size <= 0 || stride <= 0 || count < 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size/stride must be > 0 and count must be >= 0");
        return NULL;
    }
    if (stride < packet_size) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "stride must be >= packet_size");
        return NULL;
    }
    if (count == 0) {
        PyBuffer_Release(&view);
        return PyLong_FromLong(0);
    }
    if (packet_size > 65535) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size exceeds uint16_t limit");
        return NULL;
    }
    {
        const size_t needed = ((size_t)(count - 1) * (size_t)stride) + (size_t)packet_size;
        if ((size_t)view.len < needed) {
            PyBuffer_Release(&view);
            PyErr_SetString(PyExc_ValueError, "buffer smaller than strided packet range");
            return NULL;
        }
    }

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_KeyError, "Invalid XDP context handle");
        return NULL;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_RuntimeError, "XDP context not initialized");
        return NULL;
    }

    if (ensure_ctx_send_scratch_capacity(ctx, (Py_ssize_t)count) < 0) {
        pthread_mutex_unlock(&ctx->lock);
        PyBuffer_Release(&view);
        PyErr_NoMemory();
        return NULL;
    }
    packets = ctx->scratch_packets;
    lengths = ctx->scratch_lengths;
    release_ctx_send_scratch_owners(ctx, (Py_ssize_t)count);

    const uint8_t *base = (const uint8_t*)view.buf;
    for (int i = 0; i < count; i++) {
        packets[i] = base + ((size_t)i * (size_t)stride);
        lengths[i] = (uint16_t)packet_size;
    }

    Py_BEGIN_ALLOW_THREADS
    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_vector_ctx(ctx, packets, lengths, (Py_ssize_t)count);
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    Py_END_ALLOW_THREADS
    xdp_record_send_timing(ctx, xdp_timespec_diff_ns(&send_start, &send_end));

    pthread_mutex_unlock(&ctx->lock);
    PyBuffer_Release(&view);
    return PyLong_FromLong(total_sent);
}

static PyObject* py_xdp_send_buffer_paced_ctx(PyObject* self, PyObject* args)
{
    int handle = 0;
    Py_buffer view;
    int packet_size = 0;
    int count = 0;
    int pacing_mode = XDP_PACING_RPS;
    double target_rps = 0.0;
    unsigned long long ipg_ns_ull = 0;
    int burst_size = 1;
    unsigned long long burst_gap_ns_ull = 0;
    xdp_context_t *ctx = NULL;
    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;
    xdp_pacing_config_t cfg;

    (void)self;
    if (!PyArg_ParseTuple(args, "iy*ii|idKiK",
                          &handle, &view, &packet_size, &count,
                          &pacing_mode, &target_rps, &ipg_ns_ull, &burst_size, &burst_gap_ns_ull)) {
        return NULL;
    }
    if (packet_size <= 0 || count < 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size must be > 0 and count must be >= 0");
        return NULL;
    }
    if (count == 0) {
        PyBuffer_Release(&view);
        return PyLong_FromLong(0);
    }
    if ((size_t)view.len < ((size_t)packet_size * (size_t)count)) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "buffer smaller than packet_size * count");
        return NULL;
    }
    if (packet_size > 65535) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size exceeds uint16_t limit");
        return NULL;
    }
    if (xdp_prepare_pacing_config(
            &cfg,
            pacing_mode,
            target_rps,
            (uint64_t)ipg_ns_ull,
            burst_size,
            (uint64_t)burst_gap_ns_ull
        ) != 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(
            PyExc_ValueError,
            "invalid pacing config (mode=0:none,1:rps,2:ipg,3:burst; validate rps/ipg/burst params)"
        );
        return NULL;
    }

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_KeyError, "Invalid XDP context handle");
        return NULL;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_RuntimeError, "XDP context not initialized");
        return NULL;
    }
    if (ensure_ctx_send_scratch_capacity(ctx, (Py_ssize_t)count) < 0) {
        pthread_mutex_unlock(&ctx->lock);
        PyBuffer_Release(&view);
        PyErr_NoMemory();
        return NULL;
    }

    const uint8_t *base = (const uint8_t*)view.buf;
    for (int i = 0; i < count; i++) {
        ctx->scratch_packets[i] = base + ((size_t)i * (size_t)packet_size);
        ctx->scratch_lengths[i] = (uint16_t)packet_size;
    }

    Py_BEGIN_ALLOW_THREADS
    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_vector_paced_ctx(
        ctx,
        ctx->scratch_packets,
        ctx->scratch_lengths,
        (Py_ssize_t)count,
        &cfg
    );
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    Py_END_ALLOW_THREADS
    xdp_record_send_timing(ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    pthread_mutex_unlock(&ctx->lock);
    PyBuffer_Release(&view);
    return PyLong_FromLong(total_sent);
}

static PyObject* py_xdp_send_buffer_strided_paced_ctx(PyObject* self, PyObject* args)
{
    int handle = 0;
    Py_buffer view;
    int packet_size = 0;
    int stride = 0;
    int count = 0;
    int pacing_mode = XDP_PACING_RPS;
    double target_rps = 0.0;
    unsigned long long ipg_ns_ull = 0;
    int burst_size = 1;
    unsigned long long burst_gap_ns_ull = 0;
    xdp_context_t *ctx = NULL;
    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;
    xdp_pacing_config_t cfg;

    (void)self;
    if (!PyArg_ParseTuple(args, "iy*iii|idKiK",
                          &handle, &view, &packet_size, &stride, &count,
                          &pacing_mode, &target_rps, &ipg_ns_ull, &burst_size, &burst_gap_ns_ull)) {
        return NULL;
    }
    if (packet_size <= 0 || stride <= 0 || count < 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size/stride must be > 0 and count must be >= 0");
        return NULL;
    }
    if (stride < packet_size) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "stride must be >= packet_size");
        return NULL;
    }
    if (count == 0) {
        PyBuffer_Release(&view);
        return PyLong_FromLong(0);
    }
    if (packet_size > 65535) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packet_size exceeds uint16_t limit");
        return NULL;
    }
    {
        const size_t needed = ((size_t)(count - 1) * (size_t)stride) + (size_t)packet_size;
        if ((size_t)view.len < needed) {
            PyBuffer_Release(&view);
            PyErr_SetString(PyExc_ValueError, "buffer smaller than strided packet range");
            return NULL;
        }
    }
    if (xdp_prepare_pacing_config(
            &cfg,
            pacing_mode,
            target_rps,
            (uint64_t)ipg_ns_ull,
            burst_size,
            (uint64_t)burst_gap_ns_ull
        ) != 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(
            PyExc_ValueError,
            "invalid pacing config (mode=0:none,1:rps,2:ipg,3:burst; validate rps/ipg/burst params)"
        );
        return NULL;
    }

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_KeyError, "Invalid XDP context handle");
        return NULL;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_RuntimeError, "XDP context not initialized");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_strided_paced_ctx(
        ctx,
        (const uint8_t*)view.buf,
        (uint16_t)packet_size,
        stride,
        (Py_ssize_t)count,
        &cfg
    );
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    Py_END_ALLOW_THREADS
    xdp_record_send_timing(ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    pthread_mutex_unlock(&ctx->lock);
    PyBuffer_Release(&view);
    return PyLong_FromLong(total_sent);
}

static PyObject* py_xdp_stats_ctx(PyObject* self, PyObject* args)
{
    int handle = 0;
    xdp_context_t *ctx = NULL;

    (void)self;
    if (!PyArg_ParseTuple(args, "i", &handle)) {
        return NULL;
    }

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        PyErr_SetString(PyExc_KeyError, "Invalid XDP context handle");
        return NULL;
    }
    if (!ctx->is_initialized) {
        pthread_mutex_unlock(&ctx->lock);
        Py_RETURN_NONE;
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - ctx->start_time.tv_sec) +
                     (now.tv_nsec - ctx->start_time.tv_nsec) / 1e9;
    double pps = elapsed > 0 ? ctx->tx_packets / elapsed : 0;
    double mbps = elapsed > 0 ? (ctx->tx_bytes * 8) / (elapsed * 1e6) : 0;

    uint64_t tx_packets = ctx->tx_packets;
    uint64_t tx_bytes = ctx->tx_bytes;
    uint64_t tx_errors = ctx->tx_errors;
    uint64_t tx_wakeups = ctx->tx_wakeups;
    uint64_t tx_desc_reserve_failures = ctx->tx_desc_reserve_failures;
    uint64_t tx_frame_alloc_failures = ctx->tx_frame_alloc_failures;
    uint64_t tx_partial_batches = ctx->tx_partial_batches;
    uint64_t tx_retry_loops = ctx->tx_retry_loops;
    uint64_t tx_completion_events = ctx->tx_completion_events;
    uint64_t tx_completed_desc = ctx->tx_completed_desc;
    uint64_t tx_invalid_packets = ctx->tx_invalid_packets;
    uint64_t tx_backpressure_events = ctx->tx_backpressure_events;
    uint64_t tx_send_calls = ctx->tx_send_calls;
    uint64_t tx_send_ns_total = ctx->tx_send_ns_total;
    uint64_t tx_send_ns_max = ctx->tx_send_ns_max;
    int xdp_mode = ctx->xdp_mode;
    int queue_id = ctx->queue_id;

    pthread_mutex_unlock(&ctx->lock);
    double tx_send_avg_us = tx_send_calls > 0
        ? ((double)tx_send_ns_total / (double)tx_send_calls) / 1000.0
        : 0.0;
    double tx_send_max_us = ((double)tx_send_ns_max) / 1000.0;

    return Py_BuildValue("{s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:K,s:d,s:d,s:d,s:d,s:d,s:i,s:i,s:s}",
                         "tx_packets", tx_packets,
                         "tx_bytes", tx_bytes,
                         "tx_errors", tx_errors,
                         "tx_wakeups", tx_wakeups,
                         "tx_desc_reserve_failures", tx_desc_reserve_failures,
                         "tx_frame_alloc_failures", tx_frame_alloc_failures,
                         "tx_partial_batches", tx_partial_batches,
                         "tx_retry_loops", tx_retry_loops,
                         "tx_completion_events", tx_completion_events,
                         "tx_completed_desc", tx_completed_desc,
                         "tx_invalid_packets", tx_invalid_packets,
                         "tx_backpressure_events", tx_backpressure_events,
                         "tx_send_calls", tx_send_calls,
                         "tx_send_ns_total", tx_send_ns_total,
                         "tx_send_ns_max", tx_send_ns_max,
                         "elapsed_seconds", elapsed,
                         "packets_per_second", pps,
                         "mbps", mbps,
                         "tx_send_avg_us", tx_send_avg_us,
                         "tx_send_max_us", tx_send_max_us,
                         "queue_id", queue_id,
                         "mode", xdp_mode,
                         "mode_name", xdp_mode_name(xdp_mode));
}

static PyObject* py_xdp_recv_ctx(PyObject* self, PyObject* args)
{
    int handle = 0;
    int max_packets = 256;
    int snaplen = 2048;
    xdp_context_t *ctx = NULL;
    PyObject *out = NULL;
    int rc = 0;

    (void)self;
    if (!PyArg_ParseTuple(args, "i|ii", &handle, &max_packets, &snaplen)) {
        return NULL;
    }
    if (max_packets <= 0) {
        max_packets = 1;
    }
    if (max_packets > XDP_BATCH_SIZE) {
        max_packets = XDP_BATCH_SIZE;
    }
    if (snaplen <= 0) {
        snaplen = 2048;
    }

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        PyErr_SetString(PyExc_KeyError, "Invalid XDP context handle");
        return NULL;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP context not initialized");
        return NULL;
    }
    rc = xdp_recv_packets_ctx(ctx, (uint32_t)max_packets, (uint32_t)snaplen, &out);
    pthread_mutex_unlock(&ctx->lock);
    if (rc < 0 || out == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "xdp_recv_ctx failed");
        return NULL;
    }
    return out;
}

static PyObject* py_xdp_recv(PyObject* self, PyObject* args)
{
    int max_packets = 256;
    int snaplen = 2048;
    PyObject *out = NULL;
    int rc = 0;

    (void)self;
    if (!PyArg_ParseTuple(args, "|ii", &max_packets, &snaplen)) {
        return NULL;
    }
    if (max_packets <= 0) {
        max_packets = 1;
    }
    if (max_packets > XDP_BATCH_SIZE) {
        max_packets = XDP_BATCH_SIZE;
    }
    if (snaplen <= 0) {
        snaplen = 2048;
    }
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running || xdp_ctx.xsk == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }
    pthread_mutex_lock(&xdp_ctx.lock);
    rc = xdp_recv_packets_ctx(&xdp_ctx, (uint32_t)max_packets, (uint32_t)snaplen, &out);
    pthread_mutex_unlock(&xdp_ctx.lock);
    if (rc < 0 || out == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "xdp_recv failed");
        return NULL;
    }
    return out;
}

// ============================================================================
// Native Capsule API (C-to-C Fast Path)
// ============================================================================

static void xdp_native_set_err(char *err, size_t err_len, const char *msg)
{
    if (err == NULL || err_len == 0) {
        return;
    }
    (void)snprintf(err, err_len, "%s", msg ? msg : "xdp_native_error");
}

static int xdp_native_create_ctx_common(
    const char *ifname,
    int queue_id,
    int mode,
    void *external_umem,
    size_t external_umem_len,
    int frame_size,
    int headroom,
    int frame_count,
    int use_external_umem,
    char *err,
    size_t err_len
)
{
    char map_reason[256];
    xdp_context_t *ctx = NULL;
    int handle = -1;

    if (ifname == NULL || ifname[0] == '\0') {
        xdp_native_set_err(err, err_len, "interface is required");
        return -1;
    }
    if (geteuid() != 0) {
        xdp_native_set_err(err, err_len, "root privileges required for AF_XDP");
        return -1;
    }
    if (mode < 0 || mode > 2) {
        xdp_native_set_err(err, err_len, "mode must be 0/1/2");
        return -1;
    }

    ctx = (xdp_context_t*)calloc(1, sizeof(*ctx));
    if (!ctx) {
        xdp_native_set_err(err, err_len, "out of memory");
        return -1;
    }
    pthread_mutex_init(&ctx->lock, NULL);
    pthread_mutex_lock(&ctx->lock);

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "[XDP][native] Warning: Could not increase MEMLOCK limit\n");
    }

    if (use_external_umem) {
        const uint32_t fc = (frame_count > 0) ? (uint32_t)frame_count : 0u;
        const uint32_t fs = (frame_size > 0) ? (uint32_t)frame_size : 0u;
        const uint32_t hr = (headroom > 0) ? (uint32_t)headroom : 0u;
        if (external_umem == NULL || external_umem_len == 0) {
            pthread_mutex_unlock(&ctx->lock);
            pthread_mutex_destroy(&ctx->lock);
            free(ctx);
            xdp_native_set_err(err, err_len, "external umem buffer is required");
            return -1;
        }
        ctx->umem = create_umem_with_config(external_umem, fc, fs, hr, 1);
    } else {
        ctx->umem = create_umem();
    }
    if (!ctx->umem) {
        pthread_mutex_unlock(&ctx->lock);
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        xdp_native_set_err(err, err_len, "create_umem failed");
        return -1;
    }

    if (use_external_umem) {
        const uint64_t expected = (uint64_t)ctx->umem->frame_count * (uint64_t)ctx->umem->frame_size;
        if (external_umem_len < expected) {
            destroy_umem(ctx->umem);
            ctx->umem = NULL;
            pthread_mutex_unlock(&ctx->lock);
            pthread_mutex_destroy(&ctx->lock);
            free(ctx);
            xdp_native_set_err(err, err_len, "external umem buffer too small");
            return -1;
        }
    }

    ctx->xsk = create_xsk_socket(ctx->umem, (char*)ifname, queue_id, mode);
    if (!ctx->xsk) {
        destroy_umem(ctx->umem);
        ctx->umem = NULL;
        pthread_mutex_unlock(&ctx->lock);
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        xdp_native_set_err(err, err_len, "create_xsk_socket failed");
        return -1;
    }

    ctx->xdp_mode = mode;
    ctx->is_initialized = 1;
    ctx->is_running = 1;
    ctx->external_umem_mode = use_external_umem ? 1 : 0;
    ctx->tx_packets = 0;
    ctx->tx_bytes = 0;
    ctx->tx_errors = 0;
    ctx->tx_wakeups = 0;
    ctx->tx_desc_reserve_failures = 0;
    ctx->tx_frame_alloc_failures = 0;
    ctx->tx_partial_batches = 0;
    ctx->tx_retry_loops = 0;
    ctx->tx_completion_events = 0;
    ctx->tx_completed_desc = 0;
    ctx->tx_invalid_packets = 0;
    ctx->tx_backpressure_events = 0;
    ctx->tx_send_calls = 0;
    ctx->tx_send_ns_total = 0;
    ctx->tx_send_ns_max = 0;
    ctx->queue_id = queue_id;
    ctx->xsks_map_fd = -1;
    ctx->xsks_map_key = queue_id;
    ctx->xsks_map_registered = 0;
    clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);

    map_reason[0] = '\0';
    if (register_xsk_in_xsks_map_ctx(ctx, queue_id, ctx->xsk->fd, map_reason, sizeof(map_reason)) < 0) {
        cleanup_ctx_locked(ctx);
        pthread_mutex_unlock(&ctx->lock);
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        if (map_reason[0] != '\0') {
            xdp_native_set_err(err, err_len, map_reason);
        } else {
            xdp_native_set_err(err, err_len, "xsks_map registration failed");
        }
        return -1;
    }

    pthread_mutex_unlock(&ctx->lock);
    handle = register_ctx_handle(ctx);
    if (handle < 0) {
        pthread_mutex_lock(&ctx->lock);
        cleanup_ctx_locked(ctx);
        pthread_mutex_unlock(&ctx->lock);
        pthread_mutex_destroy(&ctx->lock);
        free(ctx);
        xdp_native_set_err(err, err_len, "no free context slots");
        return -1;
    }

    xdp_native_set_err(err, err_len, "");
    return handle;
}

static int xdp_native_create_ctx(
    const char *ifname,
    int queue_id,
    int mode,
    char *err,
    size_t err_len
)
{
    return xdp_native_create_ctx_common(
        ifname,
        queue_id,
        mode,
        NULL,
        0u,
        0,
        0,
        0,
        0,
        err,
        err_len
    );
}

static int xdp_native_destroy_ctx(int handle, char *err, size_t err_len)
{
    xdp_context_t *ctx = remove_ctx_by_handle_locked(handle);
    if (!ctx) {
        xdp_native_set_err(err, err_len, "invalid context handle");
        return -1;
    }

    cleanup_ctx_locked(ctx);
    pthread_mutex_unlock(&ctx->lock);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
    xdp_native_set_err(err, err_len, "");
    return 0;
}

static int xdp_native_send_buffer(
    int handle,
    const uint8_t *buffer,
    int packet_size,
    int count,
    char *err,
    size_t err_len
)
{
    xdp_context_t *ctx = NULL;
    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;

    if (buffer == NULL || packet_size <= 0 || count < 0) {
        xdp_native_set_err(err, err_len, "invalid send_buffer arguments");
        return -1;
    }
    if (count == 0) {
        xdp_native_set_err(err, err_len, "");
        return 0;
    }

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        xdp_native_set_err(err, err_len, "invalid context handle");
        return -1;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        xdp_native_set_err(err, err_len, "context not initialized");
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_strided_ctx(
        ctx,
        buffer,
        (uint16_t)((packet_size > 65535) ? 65535 : packet_size),
        packet_size,
        (Py_ssize_t)count
    );
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    xdp_record_send_timing(ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    pthread_mutex_unlock(&ctx->lock);

    xdp_native_set_err(err, err_len, "");
    return total_sent;
}

static int xdp_native_send_buffer_strided(
    int handle,
    const uint8_t *buffer,
    int packet_size,
    int stride,
    int count,
    char *err,
    size_t err_len
)
{
    xdp_context_t *ctx = NULL;
    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;

    if (buffer == NULL || packet_size <= 0 || stride <= 0 || stride < packet_size || count < 0) {
        xdp_native_set_err(err, err_len, "invalid send_buffer_strided arguments");
        return -1;
    }
    if (count == 0) {
        xdp_native_set_err(err, err_len, "");
        return 0;
    }

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        xdp_native_set_err(err, err_len, "invalid context handle");
        return -1;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        xdp_native_set_err(err, err_len, "context not initialized");
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_strided_ctx(
        ctx,
        buffer,
        (uint16_t)((packet_size > 65535) ? 65535 : packet_size),
        stride,
        (Py_ssize_t)count
    );
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    xdp_record_send_timing(ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    pthread_mutex_unlock(&ctx->lock);

    xdp_native_set_err(err, err_len, "");
    return total_sent;
}

static int xdp_native_send_vector(
    int handle,
    const uint8_t **packets,
    const uint16_t *lengths,
    int count,
    char *err,
    size_t err_len
)
{
    xdp_context_t *ctx = NULL;
    int total_sent = 0;
    struct timespec send_start;
    struct timespec send_end;

    if (packets == NULL || lengths == NULL || count < 0) {
        xdp_native_set_err(err, err_len, "invalid send_vector arguments");
        return -1;
    }
    if (count == 0) {
        xdp_native_set_err(err, err_len, "");
        return 0;
    }

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        xdp_native_set_err(err, err_len, "invalid context handle");
        return -1;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        xdp_native_set_err(err, err_len, "context not initialized");
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &send_start);
    total_sent = xdp_send_vector_ctx(ctx, packets, (uint16_t*)lengths, (Py_ssize_t)count);
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    xdp_record_send_timing(ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    pthread_mutex_unlock(&ctx->lock);

    xdp_native_set_err(err, err_len, "");
    return total_sent;
}

static int xdp_native_create_ctx_external_umem(
    const char *ifname,
    int queue_id,
    int mode,
    void *umem_buffer,
    size_t umem_buffer_len,
    int frame_size,
    int headroom,
    int frame_count,
    char *err,
    size_t err_len
)
{
    return xdp_native_create_ctx_common(
        ifname,
        queue_id,
        mode,
        umem_buffer,
        umem_buffer_len,
        frame_size,
        headroom,
        frame_count,
        1,
        err,
        err_len
    );
}

static int xdp_native_submit_frame_ids(
    int handle,
    const uint32_t *frame_ids,
    const uint16_t *lengths,
    int count,
    char *err,
    size_t err_len
)
{
    xdp_context_t *ctx = NULL;
    int total_sent = 0;
    int offset = 0;
    struct timespec send_start;
    struct timespec send_end;

    if (frame_ids == NULL || lengths == NULL || count < 0) {
        xdp_native_set_err(err, err_len, "invalid submit_frame_ids arguments");
        return -1;
    }
    if (count == 0) {
        xdp_native_set_err(err, err_len, "");
        return 0;
    }
    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        xdp_native_set_err(err, err_len, "invalid context handle");
        return -1;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        xdp_native_set_err(err, err_len, "context not initialized");
        return -1;
    }
    if (!ctx->external_umem_mode) {
        pthread_mutex_unlock(&ctx->lock);
        xdp_native_set_err(err, err_len, "submit_frame_ids requires external_umem context");
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &send_start);
    while (offset < count) {
        int batch = count - offset;
        if (batch > XDP_BATCH_SIZE) {
            batch = XDP_BATCH_SIZE;
        }
        int sent = xdp_submit_frame_ids_ctx(ctx, frame_ids + offset, lengths + offset, batch);
        if (sent <= 0) {
            ctx->tx_retry_loops += 1;
            ctx->tx_backpressure_events += 1;
            break;
        }
        total_sent += sent;
        offset += sent;
    }
    clock_gettime(CLOCK_MONOTONIC, &send_end);
    xdp_record_send_timing(ctx, xdp_timespec_diff_ns(&send_start, &send_end));
    pthread_mutex_unlock(&ctx->lock);
    xdp_native_set_err(err, err_len, "");
    return total_sent;
}

static int xdp_native_reap_completions(
    int handle,
    uint32_t *frame_ids_out,
    int max_count,
    char *err,
    size_t err_len
)
{
    xdp_context_t *ctx = NULL;
    uint32_t done = 0;

    if (max_count < 0) {
        xdp_native_set_err(err, err_len, "max_count must be >= 0");
        return -1;
    }
    if (max_count == 0) {
        xdp_native_set_err(err, err_len, "");
        return 0;
    }
    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        xdp_native_set_err(err, err_len, "invalid context handle");
        return -1;
    }
    if (!ctx->is_initialized || !ctx->is_running) {
        pthread_mutex_unlock(&ctx->lock);
        xdp_native_set_err(err, err_len, "context not initialized");
        return -1;
    }
    if (!ctx->external_umem_mode) {
        pthread_mutex_unlock(&ctx->lock);
        xdp_native_set_err(err, err_len, "reap_completions requires external_umem context");
        return -1;
    }

    done = xdp_reap_completion_entries(
        ctx->xsk,
        (uint32_t)max_count,
        frame_ids_out,
        (uint32_t)max_count,
        0
    );
    if (done > 0) {
        ctx->tx_completion_events += 1;
        ctx->tx_completed_desc += done;
    }
    pthread_mutex_unlock(&ctx->lock);
    xdp_native_set_err(err, err_len, "");
    return (int)done;
}

static int xdp_native_get_stats(int handle, xdp_native_stats *out, char *err, size_t err_len)
{
    xdp_context_t *ctx = NULL;

    if (out == NULL) {
        xdp_native_set_err(err, err_len, "stats output is null");
        return -1;
    }
    memset(out, 0, sizeof(*out));

    ctx = lock_ctx_by_handle(handle);
    if (!ctx) {
        xdp_native_set_err(err, err_len, "invalid context handle");
        return -1;
    }
    if (!ctx->is_initialized) {
        pthread_mutex_unlock(&ctx->lock);
        xdp_native_set_err(err, err_len, "context not initialized");
        return -1;
    }

    out->tx_packets = ctx->tx_packets;
    out->tx_bytes = ctx->tx_bytes;
    out->tx_errors = ctx->tx_errors;
    out->tx_wakeups = ctx->tx_wakeups;
    out->mode = ctx->xdp_mode;
    out->queue_id = ctx->queue_id;
    pthread_mutex_unlock(&ctx->lock);

    xdp_native_set_err(err, err_len, "");
    return 0;
}

static xdp_native_api_v1 g_xdp_native_api = {
    .version = XDP_NATIVE_API_VERSION,
    .create_ctx = xdp_native_create_ctx,
    .destroy_ctx = xdp_native_destroy_ctx,
    .send_buffer = xdp_native_send_buffer,
    .send_buffer_strided = xdp_native_send_buffer_strided,
    .send_vector = xdp_native_send_vector,
    .get_stats = xdp_native_get_stats,
    .create_ctx_external_umem = xdp_native_create_ctx_external_umem,
    .submit_frame_ids = xdp_native_submit_frame_ids,
    .reap_completions = xdp_native_reap_completions,
};

// Public C ABI for non-Python native bridge callers (e.g., CUDA persistent bridge).
xdp_native_api_v1* samurai_xdp_get_native_api_v1(void)
{
    return &g_xdp_native_api;
}

static PyObject* py_xdp_get_native_api(PyObject* self, PyObject* args)
{
    (void)self;
    (void)args;
    return PyCapsule_New((void*)&g_xdp_native_api, XDP_NATIVE_API_CAPSULE_NAME, NULL);
}

// ============================================================================
// Module Definition
// ============================================================================

static PyMethodDef XdpSenderMethods[] = {
    {"xdp_get_native_api", py_xdp_get_native_api, METH_NOARGS,
     "Return native C API capsule for xdp_core fast path."},
    {"xdp_create", py_xdp_create, METH_VARARGS,
     "Create independent AF_XDP context.\n"
     "Args: interface (str), queue_id (int, default=0), mode (int, default=0=Copy)\n"
     "Returns: int handle (>0)"},
    {"xdp_destroy", py_xdp_destroy, METH_VARARGS,
     "Destroy AF_XDP context by handle.\n"
     "Args: handle (int)"},
    {"xdp_send_ctx", py_xdp_send_ctx, METH_VARARGS,
     "Send packets through AF_XDP context.\n"
     "Args: handle (int), packets (list of bytes)\n"
     "Returns: int (number of packets sent)"},
    {"xdp_send_buffer_ctx", py_xdp_send_buffer_ctx, METH_VARARGS,
     "Send contiguous packet buffer through AF_XDP context.\n"
     "Args: handle (int), buffer (bytes-like), packet_size (int), count (int)\n"
     "Returns: int (number of packets sent)"},
    {"xdp_send_buffer_paced_ctx", py_xdp_send_buffer_paced_ctx, METH_VARARGS,
     "Send contiguous packet buffer through AF_XDP context with native pacing.\n"
     "Args: handle, buffer, packet_size, count, pacing_mode, target_rps, ipg_ns, burst_size, burst_gap_ns\n"
     "Returns: int (number of packets sent)"},
    {"xdp_send_buffer_strided_ctx", py_xdp_send_buffer_strided_ctx, METH_VARARGS,
     "Send strided packet buffer through AF_XDP context.\n"
     "Args: handle (int), buffer (bytes-like), packet_size (int), stride (int), count (int)\n"
     "Returns: int (number of packets sent)"},
    {"xdp_send_buffer_strided_paced_ctx", py_xdp_send_buffer_strided_paced_ctx, METH_VARARGS,
     "Send strided packet buffer through AF_XDP context with native pacing.\n"
     "Args: handle, buffer, packet_size, stride, count, pacing_mode, target_rps, ipg_ns, burst_size, burst_gap_ns\n"
     "Returns: int (number of packets sent)"},
    {"xdp_stats_ctx", py_xdp_stats_ctx, METH_VARARGS,
     "Get stats for AF_XDP context.\n"
     "Args: handle (int)\n"
     "Returns: dict"},
    {"xdp_recv_ctx", py_xdp_recv_ctx, METH_VARARGS,
     "Receive packets from AF_XDP context RX ring.\n"
     "Args: handle (int), max_packets (int, optional), snaplen (int, optional)\n"
     "Returns: list[bytes]"},

    {"xdp_init", py_xdp_init, METH_VARARGS, 
     "Initialize AF_XDP socket on interface.\n"
     "Args: interface (str), queue_id (int, default=0), mode (int, default=0=Copy)\n"
     "Returns: True on success"},
    
    {"xdp_cleanup", py_xdp_cleanup, METH_NOARGS, 
     "Cleanup AF_XDP resources and print statistics."},
    
    {"xdp_send", py_xdp_send, METH_VARARGS, 
     "Send raw packets through AF_XDP.\n"
     "Args: packets (list of bytes)\n"
     "Returns: int (number of packets sent)"},

    {"xdp_send_buffer", py_xdp_send_buffer, METH_VARARGS,
     "Send raw packets from contiguous buffer through AF_XDP.\n"
     "Args: buffer (bytes-like), packet_size (int), count (int)\n"
     "Returns: int (number of packets sent)"},
    {"xdp_send_buffer_paced", py_xdp_send_buffer_paced, METH_VARARGS,
     "Send raw packets from contiguous buffer through AF_XDP with native pacing.\n"
     "Args: buffer, packet_size, count, pacing_mode, target_rps, ipg_ns, burst_size, burst_gap_ns\n"
     "Returns: int (number of packets sent)"},
    {"xdp_send_buffer_strided", py_xdp_send_buffer_strided, METH_VARARGS,
     "Send raw packets from strided buffer through AF_XDP.\n"
     "Args: buffer (bytes-like), packet_size (int), stride (int), count (int)\n"
     "Returns: int (number of packets sent)"},
    {"xdp_send_buffer_strided_paced", py_xdp_send_buffer_strided_paced, METH_VARARGS,
     "Send raw packets from strided buffer through AF_XDP with native pacing.\n"
     "Args: buffer, packet_size, stride, count, pacing_mode, target_rps, ipg_ns, burst_size, burst_gap_ns\n"
     "Returns: int (number of packets sent)"},

    {"xdp_acquire_tx_frame", py_xdp_acquire_tx_frame, METH_NOARGS,
     "Acquire writable UMEM TX frame.\n"
     "Returns: (frame_id, memoryview) or None when no frame is available."},

    {"xdp_submit_tx_frame", py_xdp_submit_tx_frame, METH_VARARGS,
     "Submit previously acquired TX frame.\n"
     "Args: frame_id (int), length (int)\n"
     "Returns: bool"},

    {"xdp_release_tx_frame", py_xdp_release_tx_frame, METH_VARARGS,
     "Release previously acquired TX frame without sending.\n"
     "Args: frame_id (int)\n"
     "Returns: bool"},
    
    {"xdp_send_udp", py_xdp_send_udp, METH_VARARGS, 
     "Send UDP packets through AF_XDP (helper).\n"
     "Args: target_ip, target_port, payloads (list), src_ports (list, optional)\n"
     "Returns: int (number of packets sent)"},

    {"xdp_send_udp_zc", py_xdp_send_udp_zc, METH_VARARGS,
     "Send UDP packets by building directly in UMEM frames.\n"
     "Args: target_ip, target_port, payloads (list), src_ports (list, optional)\n"
     "Returns: int (number of packets sent)"},
    {"xdp_recv", py_xdp_recv, METH_VARARGS,
     "Receive packets from global AF_XDP RX ring.\n"
     "Args: max_packets (int, optional), snaplen (int, optional)\n"
     "Returns: list[bytes]"},
    
    {"xdp_stats", py_xdp_stats, METH_NOARGS, 
     "Get current XDP statistics.\n"
     "Returns: dict with packets, bytes, pps, mbps, etc."},
    
    {"xdp_available", py_xdp_available, METH_NOARGS, 
     "Check if AF_XDP is available on this system.\n"
     "Returns: bool"},
    
    {"xdp_info", py_xdp_info, METH_NOARGS, 
     "Get system XDP capabilities and configuration.\n"
     "Returns: dict with kernel info, settings, etc."},
    
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef xdpsendermodule = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "xdp_sender",
    .m_doc = "AF_XDP High-Performance Packet Sender for Samurai\n\n"
    "This module provides high-performance packet transmission using\n"
    "Linux AF_XDP sockets. Works in Copy Mode (SKB/Generic) for\n"
    "maximum compatibility with standard Linux systems.\n\n"
    "Requirements:\n"
    "  - Linux kernel >= 4.18\n"
    "  - Root privileges\n"
    "  - Standard network interface\n\n"
    "Usage:\n"
    "  import xdp_sender\n"
    "  xdp_sender.xdp_init('eth0')\n"
    "  xdp_sender.xdp_send([packet1, packet2, ...])\n"
    "  stats = xdp_sender.xdp_stats()\n"
    "  xdp_sender.xdp_cleanup()",
    .m_size = -1,
    .m_methods = XdpSenderMethods,
};

PyMODINIT_FUNC PyInit_xdp_sender(void)
{
    srand(time(NULL));
    return PyModule_Create(&xdpsendermodule);
}
