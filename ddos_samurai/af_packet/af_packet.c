/*
 * af_packet — native kernel-socket TX/RX engine (see af_packet.h).
 *
 * Extracted from the former `fast_sender` CPython extension with all Python /
 * l4_state_engine delegation removed. The transmit fast paths (L3 sendmmsg,
 * SO_TXTIME, AF_PACKET TX_RING) and the stateful RX handshake handler are kept
 * verbatim in behavior; only the CPython glue was stripped and the RX loop was
 * given a cooperative stop flag.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* sendmmsg/recvmmsg, struct mmsghdr, SO_BUSY_POLL, etc. */
#endif

#include "af_packet.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <sched.h>
#include <stdlib.h>
#include <strings.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>

/* SO_TXTIME support (kernel >= 4.19) */
#ifndef SO_TXTIME
#define SO_TXTIME 61
#endif
#ifndef SCM_TXTIME
#define SCM_TXTIME SO_TXTIME
#endif
#ifndef SOF_TXTIME_DEADLINE_MODE
#define SOF_TXTIME_DEADLINE_MODE   (1 << 0)
#endif
#ifndef SOF_TXTIME_REPORT_ERRORS
#define SOF_TXTIME_REPORT_ERRORS   (1 << 1)
#endif

#define BATCH_SIZE 1024
#define DEFAULT_STATE_TABLE_SIZE 65536
#define MAX_PACKET_SIZE 2048
#define DEFAULT_NUM_LOCKS 256
#define DEFAULT_STATE_TIMEOUT_SEC 60

/* ================================================================== */
/* env / policy helpers                                                */
/* ================================================================== */

typedef enum {
    TXRING_FLUSH_MODE_LEGACY = 0,
    TXRING_FLUSH_MODE_ADAPTIVE = 1,
} txring_flush_mode_t;

static int env_truthy(const char* value) {
    if (!value || !value[0]) return 0;
    return (
        strcmp(value, "1") == 0 ||
        strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 ||
        strcasecmp(value, "on") == 0
    );
}

static txring_flush_mode_t txring_flush_mode_from_env(void) {
    const char* mode = getenv("SAMURAI_TXRING_FLUSH_MODE");
    if (mode && mode[0]) {
        if (strcasecmp(mode, "adaptive") == 0 || strcmp(mode, "1") == 0) {
            return TXRING_FLUSH_MODE_ADAPTIVE;
        }
        return TXRING_FLUSH_MODE_LEGACY;
    }
    if (env_truthy(getenv("SAMURAI_TXRING_ADAPTIVE"))) {
        return TXRING_FLUSH_MODE_ADAPTIVE;
    }
    return TXRING_FLUSH_MODE_LEGACY;
}

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
    unsigned long long prefault_pages;
    unsigned long long smaps_kernel_page_kb;
    unsigned long long smaps_anon_hugepages_kb;
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
    .poll_timeout_ms = 0,
    .spin_limit = 64,
    .busy_poll_us = 0,
    .qdisc_bypass = 1,
};

static afpacket_hp_mode_t parse_afpacket_hp_mode(const char* raw) {
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

static int env_int_default(const char* name, int fallback) {
    const char* raw = getenv(name);
    char* endptr = NULL;
    long v;
    if (!raw || !raw[0]) return fallback;
    errno = 0;
    v = strtol(raw, &endptr, 10);
    if (errno != 0 || endptr == raw || (endptr && *endptr != '\0')) return fallback;
    if (v <= 0 || v > 1 << 20) return fallback;
    return (int)v;
}

static int env_int_range(const char* name, int fallback, int min_v, int max_v) {
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

static inline unsigned int align_up_u32(unsigned int value, unsigned int align) {
    if (align == 0U) return value;
    return ((value + align - 1U) / align) * align;
}

static unsigned int next_pow2_u32(unsigned int value) {
    if (value <= 1U) return 1U;
    value--;
    value |= value >> 1U;
    value |= value >> 2U;
    value |= value >> 4U;
    value |= value >> 8U;
    value |= value >> 16U;
    return value + 1U;
}

static void load_txring_hugepage_policy_from_env(void) {
    g_txring_hp_policy.mode = parse_afpacket_hp_mode(getenv("SAMURAI_AF_PACKET_HUGEPAGE_MODE"));
    g_txring_hp_policy.hugepage_size_kb = env_int_default("SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB", 2048);
    g_txring_hp_policy.ring_target_mb = env_int_default("SAMURAI_AF_PACKET_RING_TARGET_MB", 64);
    g_txring_hp_policy.mlock_ring = env_truthy(getenv("SAMURAI_AF_PACKET_MLOCK_RING")) ? 1 : 0;
    g_txring_hp_policy.prefault_ring = env_truthy(getenv("SAMURAI_AF_PACKET_PREFAULT_RING")) ? 1 : 0;
    g_txring_hp_policy.block_size_kb = env_int_range("SAMURAI_AF_PACKET_BLOCK_SIZE_KB", 0, 0, 262144);
    g_txring_hp_policy.frame_size = env_int_range("SAMURAI_AF_PACKET_FRAME_SIZE", 0, 0, 262144);
    g_txring_hp_policy.frames_per_block = env_int_range("SAMURAI_AF_PACKET_FRAMES_PER_BLOCK", 64, 1, 4096);
    g_txring_hp_policy.poll_timeout_ms = env_int_range("SAMURAI_AF_PACKET_POLL_TIMEOUT_MS", 0, 0, 1000);
    g_txring_hp_policy.spin_limit = env_int_range("SAMURAI_AF_PACKET_SPIN_LIMIT", 64, 0, 1000000);
    g_txring_hp_policy.busy_poll_us = env_int_range("SAMURAI_AF_PACKET_BUSY_POLL_US", 0, 0, 1000000);
    g_txring_hp_policy.qdisc_bypass = env_int_range("SAMURAI_AF_PACKET_QDISC_BYPASS", 1, 0, 1);
}

static inline uint64_t monotonic_ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

/* ================================================================== */
/* TCP state table                                                     */
/* ================================================================== */

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t state; /* 0: CLOSED, 1: SYN_SENT, 2: ESTABLISHED */
    uint32_t last_seen;
    uint16_t window_size;
    uint16_t mss;
    uint8_t ttl;
} tcp_state_t;

static tcp_state_t* state_table = NULL;
static pthread_mutex_t* state_locks = NULL;
static uint32_t state_table_size = DEFAULT_STATE_TABLE_SIZE;
static uint32_t state_lock_count = DEFAULT_NUM_LOCKS;
static uint32_t state_timeout_sec = DEFAULT_STATE_TIMEOUT_SEC;
static uint32_t state_sweep_cursor = 0;
static unsigned long long state_timeout_evictions = 0ULL;
static unsigned long long state_overwrites = 0ULL;
static unsigned long long state_sweeps = 0ULL;
static unsigned long long state_last_sweep_removed = 0ULL;
static unsigned long long state_active_entries = 0ULL;

/* Global mimicry settings */
static uint16_t global_window_size = 64240;
static uint16_t global_mss = 1460;
static uint8_t global_ttl = 64;

void afpkt_destroy_state_engine(void) {
    if (state_locks) {
        for (uint32_t i = 0; i < state_lock_count; i++) {
            pthread_mutex_destroy(&state_locks[i]);
        }
        free(state_locks);
        state_locks = NULL;
    }
    if (state_table) {
        free(state_table);
        state_table = NULL;
    }
    state_active_entries = 0ULL;
    state_timeout_evictions = 0ULL;
    state_overwrites = 0ULL;
    state_sweeps = 0ULL;
    state_last_sweep_removed = 0ULL;
    state_sweep_cursor = 0U;
}

int afpkt_configure_state_engine(uint32_t table_size, uint32_t lock_count, uint32_t timeout_sec) {
    tcp_state_t* new_table = NULL;
    pthread_mutex_t* new_locks = NULL;

    if (table_size == 0 || lock_count == 0 || timeout_sec == 0) return -1;
    if (table_size % lock_count != 0) return -1;

    new_table = (tcp_state_t*)calloc((size_t)table_size, sizeof(tcp_state_t));
    if (!new_table) return -1;
    new_locks = (pthread_mutex_t*)calloc((size_t)lock_count, sizeof(pthread_mutex_t));
    if (!new_locks) {
        free(new_table);
        return -1;
    }

    for (uint32_t i = 0; i < lock_count; i++) {
        if (pthread_mutex_init(&new_locks[i], NULL) != 0) {
            for (uint32_t j = 0; j < i; j++) {
                pthread_mutex_destroy(&new_locks[j]);
            }
            free(new_locks);
            free(new_table);
            return -1;
        }
    }

    afpkt_destroy_state_engine();
    state_table = new_table;
    state_locks = new_locks;
    state_table_size = table_size;
    state_lock_count = lock_count;
    state_timeout_sec = timeout_sec;
    return 0;
}

static inline uint32_t hash_state(uint32_t src_ip, uint16_t src_port) {
    uint32_t h = src_ip;
    h ^= (h >> 16);
    h *= 0x85ebca6b;
    h ^= (h >> 13);
    h *= 0xc2b2ae35;
    h ^= (h >> 16);
    h ^= src_port;
    return h;
}

static inline uint32_t state_segment_size(void) {
    if (state_lock_count == 0) return 0;
    return state_table_size / state_lock_count;
}

static void update_state(uint32_t src_ip, uint16_t src_port, uint32_t seq, uint32_t ack, uint8_t state, uint16_t window, uint16_t mss, uint8_t ttl) {
    if (!state_table || !state_locks || state_table_size == 0 || state_lock_count == 0) return;
    uint32_t h = hash_state(src_ip, src_port);
    uint32_t segment = h % state_lock_count;
    uint32_t segment_size = state_segment_size();
    if (segment_size == 0) return;
    uint32_t segment_start = segment * segment_size;
    uint32_t start_idx = segment_start + ((h / state_lock_count) % segment_size);

    pthread_mutex_lock(&state_locks[segment]);
    uint32_t idx = start_idx;
    int found = 0;
    uint32_t now = (uint32_t)time(NULL);

    for (uint32_t i = 0; i < segment_size; i++) {
        int timed_out = (
            state_table[idx].state != 0 &&
            (uint32_t)(now - state_table[idx].last_seen) > state_timeout_sec
        );
        int same_key = (state_table[idx].src_ip == src_ip && state_table[idx].src_port == src_port);
        if (state_table[idx].state == 0 || timed_out || same_key) {
            if (state_table[idx].state == 0) {
                state_active_entries++;
            } else if (timed_out && !same_key) {
                state_timeout_evictions++;
            }
            state_table[idx].src_ip = src_ip;
            state_table[idx].src_port = src_port;
            state_table[idx].seq = seq;
            state_table[idx].ack = ack;
            state_table[idx].state = state;
            state_table[idx].last_seen = now;
            state_table[idx].window_size = window;
            state_table[idx].mss = mss;
            state_table[idx].ttl = ttl;
            found = 1;
            break;
        }
        idx = segment_start + ((idx - segment_start + 1) % segment_size);
    }

    if (!found) { /* Overwrite if bucket is full */
        idx = start_idx;
        if (state_table[idx].state != 0) {
            state_overwrites++;
        } else {
            state_active_entries++;
        }
        state_table[idx].src_ip = src_ip;
        state_table[idx].src_port = src_port;
        state_table[idx].seq = seq;
        state_table[idx].ack = ack;
        state_table[idx].state = state;
        state_table[idx].last_seen = now;
        state_table[idx].window_size = window;
        state_table[idx].mss = mss;
        state_table[idx].ttl = ttl;
    }
    pthread_mutex_unlock(&state_locks[segment]);
}

void afpkt_set_mimicry_settings(uint16_t window, uint16_t mss, uint8_t ttl) {
    global_window_size = window;
    global_mss = mss;
    global_ttl = ttl;
}

static int sweep_state_table_internal(uint32_t max_scan) {
    if (!state_table || !state_locks || state_table_size == 0 || state_lock_count == 0) return 0;
    uint32_t segment_size = state_segment_size();
    if (segment_size == 0) return 0;
    if (max_scan == 0 || max_scan > state_table_size) max_scan = state_table_size;

    uint32_t now = (uint32_t)time(NULL);
    uint32_t removed = 0;
    for (uint32_t i = 0; i < max_scan; i++) {
        uint32_t idx = state_sweep_cursor % state_table_size;
        uint32_t segment = idx / segment_size;
        state_sweep_cursor = (state_sweep_cursor + 1U) % state_table_size;
        pthread_mutex_lock(&state_locks[segment]);
        if (state_table[idx].state != 0 &&
            (uint32_t)(now - state_table[idx].last_seen) > state_timeout_sec) {
            memset(&state_table[idx], 0, sizeof(tcp_state_t));
            removed++;
            if (state_active_entries > 0ULL) state_active_entries--;
            state_timeout_evictions++;
        }
        pthread_mutex_unlock(&state_locks[segment]);
    }
    state_sweeps++;
    state_last_sweep_removed = (unsigned long long)removed;
    return (int)removed;
}

int afpkt_sweep_state_table(uint32_t max_scan) {
    return sweep_state_table_internal(max_scan);
}

void afpkt_get_state_engine_stats(afpkt_state_stats_t* out) {
    if (!out) return;
    out->table_size = state_table_size;
    out->lock_count = state_lock_count;
    out->timeout_sec = state_timeout_sec;
    out->active_entries = state_active_entries;
    out->timeout_evictions = state_timeout_evictions;
    out->overwrites = state_overwrites;
    out->sweeps = state_sweeps;
    out->last_sweep_removed = state_last_sweep_removed;
    out->sweep_cursor = state_sweep_cursor;
}

static inline uint16_t read_be16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t read_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int afpkt_ingest_tx_packets(const uint8_t* buffer, size_t buffer_len, int packet_size, int count) {
    int updated = 0;
    if (!buffer || packet_size <= 0 || count <= 0) return 0;
    if (buffer_len < ((size_t)packet_size * (size_t)count)) return -1;

    for (int i = 0; i < count; i++) {
        const uint8_t* pkt = buffer + ((size_t)i * (size_t)packet_size);
        int pkt_len = packet_size;
        int ip_offset = -1;
        int transport_offset;
        uint8_t protocol;
        uint8_t ihl_bytes;
        uint8_t flags;
        uint32_t src_ip;
        uint16_t src_port;
        uint32_t seq;
        uint32_t ack;
        uint8_t next_state = 1;
        uint32_t next_seq;
        uint32_t next_ack;

        if (pkt_len >= 18) {
            uint16_t eth_type = read_be16(pkt + 12);
            if (eth_type == 0x8100 && pkt_len >= 22) {
                uint16_t inner_type = read_be16(pkt + 16);
                if (inner_type == 0x0800) ip_offset = 18;
            } else if (eth_type == 0x0800) {
                ip_offset = 14;
            }
        }
        if (ip_offset < 0 && pkt_len >= 20 && ((pkt[0] >> 4) & 0x0F) == 4) {
            ip_offset = 0;
        }
        if (ip_offset < 0 || pkt_len < (ip_offset + 20)) continue;
        if (((pkt[ip_offset] >> 4) & 0x0F) != 4) continue;

        ihl_bytes = (uint8_t)((pkt[ip_offset] & 0x0F) * 4);
        if (ihl_bytes < 20 || pkt_len < (ip_offset + ihl_bytes + 20)) continue;
        protocol = pkt[ip_offset + 9];
        if (protocol != 6) continue; /* TCP only */

        transport_offset = ip_offset + ihl_bytes;
        src_ip = read_be32(pkt + ip_offset + 12);
        src_port = read_be16(pkt + transport_offset);
        seq = read_be32(pkt + transport_offset + 4);
        ack = read_be32(pkt + transport_offset + 8);
        flags = pkt[transport_offset + 13];

        if ((flags & 0x10) != 0) {
            next_state = 2; /* ESTABLISHED-ish */
            next_seq = seq;
            next_ack = ack;
        } else {
            next_state = 1; /* SYN_SENT-ish */
            next_seq = seq + 1U;
            next_ack = 0U;
        }
        update_state(src_ip, src_port, next_seq, next_ack, next_state, global_window_size, global_mss, global_ttl);
        updated++;
    }
    return updated;
}

/* ================================================================== */
/* Checksums                                                           */
/* ================================================================== */

static uint16_t checksum(uint8_t *ptr, int nbytes) {
    uint32_t sum = 0;
    for (int i = 0; i < nbytes; i += 2) {
        if (i + 1 < nbytes) {
            sum += (ptr[i] << 8) | ptr[i+1];
        } else {
            sum += (ptr[i] << 8);
        }
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(uint8_t *ip_header, uint8_t *tcp_header, int tcp_len) {
    uint32_t sum = 0;
    uint8_t *src_ip = ip_header + 12;
    uint8_t *dst_ip = ip_header + 16;

    sum += (src_ip[0] << 8) | src_ip[1];
    sum += (src_ip[2] << 8) | src_ip[3];
    sum += (dst_ip[0] << 8) | dst_ip[1];
    sum += (dst_ip[2] << 8) | dst_ip[3];
    sum += 6; /* Protocol */
    sum += tcp_len;

    for (int i = 0; i < tcp_len; i += 2) {
        if (i + 1 < tcp_len) {
            sum += (tcp_header[i] << 8) | tcp_header[i+1];
        } else {
            sum += (tcp_header[i] << 8);
        }
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/* ================================================================== */
/* TX_RING context (persistent mapping)                                */
/* ================================================================== */

typedef struct {
    int sock;
    char* map;
    size_t ring_size;
    int packet_version;
    size_t frame_header_size;
    struct tpacket_req req_v2;
    struct tpacket_req3 req_v3;
    char iface[IFNAMSIZ];
    int is_setup;
    unsigned int frame_idx;
    txring_hugepage_runtime_t hp_runtime;
} ring_context_t;

static ring_context_t tx_ring_ctx = {
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

static size_t frame_header_size_for_version(int version) {
    if (version == TPACKET_V3) {
        return TPACKET_ALIGN(sizeof(struct tpacket3_hdr));
    }
    return TPACKET_ALIGN(sizeof(struct tpacket2_hdr));
}

static unsigned int tx_ring_frame_size(const ring_context_t* ctx) {
    if (ctx->packet_version == TPACKET_V3) return ctx->req_v3.tp_frame_size;
    return ctx->req_v2.tp_frame_size;
}

static unsigned int tx_ring_frame_nr(const ring_context_t* ctx) {
    if (ctx->packet_version == TPACKET_V3) return ctx->req_v3.tp_frame_nr;
    return ctx->req_v2.tp_frame_nr;
}

static unsigned int tx_ring_block_size(const ring_context_t* ctx) {
    if (ctx->packet_version == TPACKET_V3) return ctx->req_v3.tp_block_size;
    return ctx->req_v2.tp_block_size;
}

static unsigned int tx_ring_block_nr(const ring_context_t* ctx) {
    if (ctx->packet_version == TPACKET_V3) return ctx->req_v3.tp_block_nr;
    return ctx->req_v2.tp_block_nr;
}

static void reset_tx_ring_context(void) {
    memset(&tx_ring_ctx.req_v2, 0, sizeof(tx_ring_ctx.req_v2));
    memset(&tx_ring_ctx.req_v3, 0, sizeof(tx_ring_ctx.req_v3));
    tx_ring_ctx.ring_size = 0;
    tx_ring_ctx.packet_version = TPACKET_V2;
    tx_ring_ctx.frame_header_size = 0;
    tx_ring_ctx.frame_idx = 0;
    tx_ring_ctx.iface[0] = '\0';
    tx_ring_ctx.is_setup = 0;
    tx_ring_ctx.map = MAP_FAILED;
    tx_ring_ctx.sock = -1;
    tx_ring_ctx.hp_runtime.mode = AFPKT_HP_OFF;
    tx_ring_ctx.hp_runtime.effective = 0;
    tx_ring_ctx.hp_runtime.madvise_ok = 0;
    tx_ring_ctx.hp_runtime.mlock_ok = 0;
    tx_ring_ctx.hp_runtime.prefault_pages = 0ULL;
    tx_ring_ctx.hp_runtime.smaps_kernel_page_kb = 0ULL;
    tx_ring_ctx.hp_runtime.smaps_anon_hugepages_kb = 0ULL;
    (void)snprintf(tx_ring_ctx.hp_runtime.reason, sizeof(tx_ring_ctx.hp_runtime.reason), "%s", "disabled");
}

static void cleanup_tx_ring_internal(void) {
    if (tx_ring_ctx.map != MAP_FAILED && tx_ring_ctx.ring_size > 0) {
        munmap(tx_ring_ctx.map, tx_ring_ctx.ring_size);
    }
    if (tx_ring_ctx.sock >= 0) {
        close(tx_ring_ctx.sock);
    }
    reset_tx_ring_context();
}

static int set_packet_version_or_fallback(int sock, int preferred_v3) {
    int version = preferred_v3 ? TPACKET_V3 : TPACKET_V2;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) == 0) {
        return version;
    }
    if (preferred_v3) {
        int v2 = TPACKET_V2;
        if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &v2, sizeof(v2)) == 0) {
            return v2;
        }
    }
    return -1;
}

static int probe_smaps_hugepage_info(
    const void* addr,
    unsigned long long* out_kernel_page_kb,
    unsigned long long* out_anon_hugepages_kb
) {
    FILE* fp = NULL;
    char line[256];
    unsigned long long a = (unsigned long long)(uintptr_t)addr;
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
                *out_kernel_page_kb = kb;
            }
        } else if (strncmp(line, "AnonHugePages:", 14) == 0) {
            unsigned long long kb = 0ULL;
            if (sscanf(line + 14, "%llu", &kb) == 1 && out_anon_hugepages_kb) {
                *out_anon_hugepages_kb = kb;
            }
        }
    }

    fclose(fp);
    return found;
}

static void apply_txring_hugepage_policy(ring_context_t* ctx) {
    txring_hugepage_runtime_t* rt = &ctx->hp_runtime;
    unsigned long long huge_kb = 0ULL;
    unsigned long long anon_huge_kb = 0ULL;
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

    if (!ctx->is_setup || ctx->map == MAP_FAILED || ctx->ring_size == 0) {
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "ring_unavailable");
        return;
    }

    if (g_txring_hp_policy.mode == AFPKT_HP_OFF) {
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "disabled");
        return;
    }

#ifdef MADV_HUGEPAGE
    madvise_rc = madvise((void*)ctx->map, ctx->ring_size, MADV_HUGEPAGE);
    if (madvise_rc == 0) {
        rt->madvise_ok = 1;
    }
#else
    madvise_rc = -1;
#endif

    if (g_txring_hp_policy.prefault_ring) {
        page_size = (size_t)getpagesize();
        if (page_size == 0) page_size = 4096;
        for (i = 0; i < ctx->ring_size; i += page_size) {
            sink ^= ctx->map[i];
            rt->prefault_pages++;
        }
        (void)sink;
    }

    if (g_txring_hp_policy.mlock_ring) {
        mlock_rc = mlock((void*)ctx->map, ctx->ring_size);
        rt->mlock_ok = (mlock_rc == 0) ? 1 : 0;
    } else {
        mlock_rc = 0;
        rt->mlock_ok = 0;
    }

    (void)probe_smaps_hugepage_info(ctx->map, &huge_kb, &anon_huge_kb);
    rt->smaps_kernel_page_kb = huge_kb;
    rt->smaps_anon_hugepages_kb = anon_huge_kb;

    if (anon_huge_kb > 0ULL || huge_kb >= (unsigned long long)g_txring_hp_policy.hugepage_size_kb) {
        rt->effective = 1;
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "effective");
        return;
    }

    if (madvise_rc == 0) {
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "hinted_not_realized");
        return;
    }

    {
        (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "madvise_failed");
        if (g_txring_hp_policy.mlock_ring && mlock_rc != 0) {
            (void)snprintf(rt->reason, sizeof(rt->reason), "%s", "mlock_failed");
        }
    }
}

static int fill_ring_request_for_version(
    int packet_version,
    int packet_size,
    struct tpacket_req* req_v2,
    struct tpacket_req3* req_v3,
    size_t* out_frame_header_size
) {
    if (packet_size <= 0) return -1;

    size_t frame_header_size = frame_header_size_for_version(packet_version);
    unsigned int page_size = (unsigned int)getpagesize();
    unsigned int frame_min_size = (unsigned int)(packet_size + frame_header_size);
    unsigned int frame_size = 0U;
    unsigned int block_size = 0U;
    unsigned int frames_per_block = 0U;
    unsigned int block_nr = 0U;
    unsigned int target_mb = (unsigned int)(g_txring_hp_policy.ring_target_mb > 0 ? g_txring_hp_policy.ring_target_mb : 64);
    unsigned long long target_bytes = (unsigned long long)target_mb * 1024ULL * 1024ULL;
    if (page_size == 0U) page_size = 4096U;

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
    block_nr = (unsigned int)((target_bytes + (unsigned long long)block_size - 1ULL) / (unsigned long long)block_size);
    if (block_nr < 64U) {
        block_nr = 64U;
    }
    unsigned int frame_nr = block_nr * frames_per_block;
    if (frame_nr < block_nr) {
        frame_nr = block_nr; /* overflow guard */
    }

    if (packet_version == TPACKET_V3) {
        memset(req_v3, 0, sizeof(*req_v3));
        req_v3->tp_block_size = block_size;
        req_v3->tp_block_nr = block_nr;
        req_v3->tp_frame_size = frame_size;
        req_v3->tp_frame_nr = frame_nr;
        /* TX_RING path: kernel expects v3 RX-only fields to stay zero. */
        req_v3->tp_retire_blk_tov = 0;
        req_v3->tp_sizeof_priv = 0;
        req_v3->tp_feature_req_word = 0;
    } else if (packet_version == TPACKET_V2) {
        memset(req_v2, 0, sizeof(*req_v2));
        req_v2->tp_block_size = block_size;
        req_v2->tp_block_nr = block_nr;
        req_v2->tp_frame_size = frame_size;
        req_v2->tp_frame_nr = frame_nr;
    } else {
        return -1;
    }

    if (out_frame_header_size) *out_frame_header_size = frame_header_size;
    return 0;
}

static inline uint32_t tx_frame_status(const void* frame_base, int packet_version) {
    if (packet_version == TPACKET_V3) {
        const struct tpacket3_hdr* h = (const struct tpacket3_hdr*)frame_base;
        return h->tp_status;
    }
    const struct tpacket2_hdr* h = (const struct tpacket2_hdr*)frame_base;
    return h->tp_status;
}

static inline void tx_frame_prepare(
    void* frame_base,
    int packet_version,
    size_t frame_header_size,
    int packet_size
) {
    if (packet_version == TPACKET_V3) {
        struct tpacket3_hdr* h = (struct tpacket3_hdr*)frame_base;
        h->tp_next_offset = 0;
        h->tp_len = (uint32_t)packet_size;
        h->tp_snaplen = (uint32_t)packet_size;
        h->tp_mac = (uint16_t)frame_header_size;
        h->tp_net = (uint16_t)(frame_header_size + 14);
        __sync_synchronize();
        h->tp_status = TP_STATUS_SEND_REQUEST;
        return;
    }
    struct tpacket2_hdr* h = (struct tpacket2_hdr*)frame_base;
    h->tp_len = (uint32_t)packet_size;
    h->tp_snaplen = (uint32_t)packet_size;
    h->tp_mac = (uint16_t)frame_header_size;
    h->tp_net = (uint16_t)(frame_header_size + 14);
    __sync_synchronize();
    h->tp_status = TP_STATUS_SEND_REQUEST;
}

static int try_setup_tx_ring_version(const char* iface, int packet_size, const uint8_t* mac, int prefer_v3) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) return -1;

    int packet_version = set_packet_version_or_fallback(sock, prefer_v3);
    if (packet_version < 0) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }

    struct tpacket_req req_v2;
    struct tpacket_req3 req_v3;
    memset(&req_v2, 0, sizeof(req_v2));
    memset(&req_v3, 0, sizeof(req_v3));
    size_t frame_header_size = 0;
    if (fill_ring_request_for_version(packet_version, packet_size, &req_v2, &req_v3, &frame_header_size) < 0) {
        close(sock);
        errno = EINVAL;
        return -1;
    }

    int ring_rc;
    if (packet_version == TPACKET_V3) {
        ring_rc = setsockopt(sock, SOL_PACKET, PACKET_TX_RING, &req_v3, sizeof(req_v3));
    } else {
        ring_rc = setsockopt(sock, SOL_PACKET, PACKET_TX_RING, &req_v2, sizeof(req_v2));
    }
    if (ring_rc < 0) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }

    size_t ring_size;
    if (packet_version == TPACKET_V3) {
        ring_size = (size_t)req_v3.tp_block_nr * req_v3.tp_block_size;
    } else {
        ring_size = (size_t)req_v2.tp_block_nr * req_v2.tp_block_size;
    }

    char* map = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
    if (map == MAP_FAILED) {
        int saved_errno = errno;
        close(sock);
        errno = saved_errno;
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(iface);
    sll.sll_halen = ETH_ALEN;
    memcpy(sll.sll_addr, mac, 6);

    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        int saved_errno = errno;
        munmap(map, ring_size);
        close(sock);
        errno = saved_errno;
        return -1;
    }

    /* Best effort tuning knobs; not fatal if unavailable */
    {
        int qdisc_bypass = g_txring_hp_policy.qdisc_bypass ? 1 : 0;
        (void)setsockopt(sock, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass));
    }
#ifdef SO_BUSY_POLL
    if (g_txring_hp_policy.busy_poll_us > 0) {
        int busy_poll_us = g_txring_hp_policy.busy_poll_us;
        (void)setsockopt(sock, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_us, sizeof(busy_poll_us));
    }
#endif

    tx_ring_ctx.sock = sock;
    tx_ring_ctx.map = map;
    tx_ring_ctx.ring_size = ring_size;
    tx_ring_ctx.packet_version = packet_version;
    tx_ring_ctx.frame_header_size = frame_header_size;
    tx_ring_ctx.req_v2 = req_v2;
    tx_ring_ctx.req_v3 = req_v3;
    snprintf(tx_ring_ctx.iface, IFNAMSIZ, "%s", iface);
    tx_ring_ctx.is_setup = 1;
    tx_ring_ctx.frame_idx = 0;
    apply_txring_hugepage_policy(&tx_ring_ctx);
    return 0;
}

static int setup_tx_ring(const char* iface, int packet_size, const uint8_t* mac) {
    load_txring_hugepage_policy_from_env();
    if (tx_ring_ctx.is_setup) {
        unsigned int current_frame_size = tx_ring_frame_size(&tx_ring_ctx);
        size_t current_frame_header_size = tx_ring_ctx.frame_header_size;
        if (current_frame_header_size == 0) {
            current_frame_header_size = frame_header_size_for_version(tx_ring_ctx.packet_version);
        }
        if (strcmp(tx_ring_ctx.iface, iface) == 0 &&
            current_frame_size >= (unsigned int)(packet_size + current_frame_header_size)) {
            apply_txring_hugepage_policy(&tx_ring_ctx);
            return 0;
        }
        cleanup_tx_ring_internal();
    }

    if (try_setup_tx_ring_version(iface, packet_size, mac, 1) == 0) {
        return 0;
    }
    int v3_errno = errno;
    if (try_setup_tx_ring_version(iface, packet_size, mac, 0) == 0) {
        fprintf(stderr,
                "[TX_RING] TPACKET_V3 setup failed (%d: %s), falling back to TPACKET_V2\n",
                v3_errno, strerror(v3_errno));
        return 0;
    }
    return -1;
}

typedef struct {
    int attempted;
    int sent;
    unsigned long long txring_flush_call_count;
    unsigned long long txring_flush_error_count;
    int txring_flush_last_errno;
    unsigned long long txring_tp_packets;
    unsigned long long txring_tp_drops;
    int flush_mode;
    int afpacket_hugepage_mode;
    int afpacket_hugepage_effective;
} txring_send_metrics_t;

static void drain_txring_packet_stats(const ring_context_t* ctx) {
    if (!ctx || !ctx->is_setup || ctx->sock < 0) return;

    if (ctx->packet_version == TPACKET_V3) {
        struct tpacket_stats_v3 stats_v3;
        socklen_t optlen = sizeof(stats_v3);
        (void)getsockopt(ctx->sock, SOL_PACKET, PACKET_STATISTICS, &stats_v3, &optlen);
        return;
    }

    struct tpacket_stats stats_v2;
    socklen_t optlen = sizeof(stats_v2);
    (void)getsockopt(ctx->sock, SOL_PACKET, PACKET_STATISTICS, &stats_v2, &optlen);
}

static void collect_txring_packet_stats(const ring_context_t* ctx, txring_send_metrics_t* metrics) {
    if (!ctx || !metrics || !ctx->is_setup || ctx->sock < 0) return;

    if (ctx->packet_version == TPACKET_V3) {
        struct tpacket_stats_v3 stats_v3;
        socklen_t optlen = sizeof(stats_v3);
        if (getsockopt(ctx->sock, SOL_PACKET, PACKET_STATISTICS, &stats_v3, &optlen) == 0) {
            metrics->txring_tp_packets = (unsigned long long)stats_v3.tp_packets;
            metrics->txring_tp_drops = (unsigned long long)stats_v3.tp_drops;
        }
        return;
    }

    struct tpacket_stats stats_v2;
    socklen_t optlen = sizeof(stats_v2);
    if (getsockopt(ctx->sock, SOL_PACKET, PACKET_STATISTICS, &stats_v2, &optlen) == 0) {
        metrics->txring_tp_packets = (unsigned long long)stats_v2.tp_packets;
        metrics->txring_tp_drops = (unsigned long long)stats_v2.tp_drops;
    }
}

static inline int txring_flush_socket(int sock, txring_send_metrics_t* metrics) {
    ssize_t flush_ret;
    int err = 0;
    if (!metrics) return 0;

    metrics->txring_flush_call_count++;
    flush_ret = sendto(sock, NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (flush_ret < 0) {
        err = errno;
        metrics->txring_flush_error_count++;
        metrics->txring_flush_last_errno = err;
        return err;
    }
    return 0;
}

static int send_ring_optimized_core(
    const char* iface,
    const uint8_t* buffer,
    size_t buffer_len,
    int packet_size,
    int count,
    const uint8_t* mac,
    txring_send_metrics_t* metrics
) {
    if (!iface || !buffer || !mac || !metrics) {
        return -1;
    }
    if (packet_size <= 0 || count < 0) {
        return -1;
    }
    if (buffer_len < ((size_t)packet_size * (size_t)count)) {
        return -1;
    }

    memset(metrics, 0, sizeof(*metrics));
    metrics->attempted = count;
    metrics->flush_mode = (int)txring_flush_mode_from_env();

    load_txring_hugepage_policy_from_env();

    if (setup_tx_ring(iface, packet_size, mac) < 0) {
        return -1;
    }

    metrics->afpacket_hugepage_mode = tx_ring_ctx.hp_runtime.mode;
    metrics->afpacket_hugepage_effective = tx_ring_ctx.hp_runtime.effective;
    if (metrics->afpacket_hugepage_mode == AFPKT_HP_REQUIRED && metrics->afpacket_hugepage_effective <= 0) {
        metrics->sent = 0;
        return 0;
    }

    drain_txring_packet_stats(&tx_ring_ctx);

    const char* data_ptr = (const char*)buffer;
    size_t frame_header_size = tx_ring_ctx.frame_header_size;
    unsigned int frame_size = tx_ring_frame_size(&tx_ring_ctx);
    unsigned int frame_nr = tx_ring_frame_nr(&tx_ring_ctx);
    int packet_version = tx_ring_ctx.packet_version;

    struct pollfd pfd;
    pfd.fd = tx_ring_ctx.sock;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    const txring_flush_mode_t flush_mode = (txring_flush_mode_t)metrics->flush_mode;
    const unsigned int legacy_batch = 256U;
    const unsigned int adaptive_batch_min = 32U;
    const unsigned int adaptive_batch_max = 512U;
    const int spin_limit = g_txring_hp_policy.spin_limit >= 0 ? g_txring_hp_policy.spin_limit : 64;
    const int poll_timeout_base_ms = g_txring_hp_policy.poll_timeout_ms >= 0 ? g_txring_hp_policy.poll_timeout_ms : 0;
    unsigned int pending_since_flush = 0U;
    unsigned int adaptive_batch_target = legacy_batch;

    for (int i = 0; i < count; ) {
        char* frame_base = tx_ring_ctx.map + ((size_t)tx_ring_ctx.frame_idx * frame_size);

        int spins = 0;
        int poll_timeout_ms = poll_timeout_base_ms;
        while (tx_frame_status(frame_base, packet_version) != TP_STATUS_AVAILABLE) {
            if (spins < spin_limit) {
                spins++;
                __asm__ volatile("pause" ::: "memory");
                continue;
            }

            pfd.revents = 0;
            (void)poll(&pfd, 1, poll_timeout_ms);

            if (tx_frame_status(frame_base, packet_version) != TP_STATUS_AVAILABLE) {
                (void)txring_flush_socket(tx_ring_ctx.sock, metrics);
                if (poll_timeout_ms < 16) {
                    poll_timeout_ms = (poll_timeout_ms <= 0) ? 1 : (poll_timeout_ms << 1);
                } else {
                    sched_yield();
                }
            }
        }

        char* payload_ptr = frame_base + frame_header_size;
        memcpy(payload_ptr, data_ptr + ((uint64_t)i * (uint64_t)packet_size), (size_t)packet_size);
        tx_frame_prepare(frame_base, packet_version, frame_header_size, packet_size);

        pending_since_flush++;
        int should_flush = 0;
        if (flush_mode == TXRING_FLUSH_MODE_ADAPTIVE) {
            if (pending_since_flush >= adaptive_batch_target || i == count - 1) {
                should_flush = 1;
            } else if ((pfd.revents & POLLOUT) && pending_since_flush >= adaptive_batch_min) {
                should_flush = 1;
            }
        } else {
            if (pending_since_flush >= legacy_batch || i == count - 1) {
                should_flush = 1;
            }
        }

        if (should_flush) {
            (void)txring_flush_socket(tx_ring_ctx.sock, metrics);
            pending_since_flush = 0U;
        }

        metrics->sent++;
        i++;
        tx_ring_ctx.frame_idx = (tx_ring_ctx.frame_idx + 1U) % frame_nr;
    }

    collect_txring_packet_stats(&tx_ring_ctx, metrics);
    return 0;
}

/* ================================================================== */
/* L3 senders (sendmmsg / SO_TXTIME)                                   */
/* ================================================================== */

static int l3_send_sendmmsg(
    int sockfd,
    const struct sockaddr_in* addr,
    const uint8_t* buffer,
    int packet_size,
    int count,
    afpkt_tx_metrics_t* metrics
) {
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    memset(msgs, 0, sizeof(msgs));
    memset(iovecs, 0, sizeof(iovecs));

    int total_sent = 0;
    int eagain_retry_count = 0;
    int partial_send_retry_count = 0;
    const char* data_ptr = (const char*)buffer;

    for (int pkt_idx = 0; pkt_idx < count; ) {
        int batch = count - pkt_idx;
        if (batch > BATCH_SIZE) {
            batch = BATCH_SIZE;
        }

        for (int j = 0; j < batch; j++) {
            int idx = pkt_idx + j;
            iovecs[j].iov_base = (void*)(data_ptr + ((uint64_t)idx * packet_size));
            iovecs[j].iov_len = packet_size;

            msgs[j].msg_hdr.msg_name = (void*)addr;
            msgs[j].msg_hdr.msg_namelen = sizeof(*addr);
            msgs[j].msg_hdr.msg_iov = &iovecs[j];
            msgs[j].msg_hdr.msg_iovlen = 1;
        }

        int retval = sendmmsg(sockfd, msgs, batch, 0);
        if (retval < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                eagain_retry_count++;
                continue;
            }
            break;
        }

        if (retval == 0) {
            eagain_retry_count++;
            continue;
        }

        total_sent += retval;
        pkt_idx += retval;
        if (retval < batch) {
            partial_send_retry_count++;
        }
    }

    metrics->sent = total_sent;
    metrics->eagain_retry_count = eagain_retry_count;
    metrics->partial_send_retry_count = partial_send_retry_count;
    metrics->errors = count - total_sent;
    if (metrics->errors < 0) metrics->errors = 0;
    return 0;
}

static int l3_send_txtime(
    int sockfd,
    const struct sockaddr_in* addr,
    const uint8_t* buffer,
    int packet_size,
    int count,
    long long ipg_ns,
    afpkt_tx_metrics_t* metrics,
    char* err_msg,
    size_t err_msg_len
) {
    struct {
        int32_t clockid;
        uint32_t flags;
    } txtime_cfg;
    txtime_cfg.clockid = CLOCK_TAI;
    txtime_cfg.flags = SOF_TXTIME_REPORT_ERRORS;

    if (setsockopt(sockfd, SOL_SOCKET, SO_TXTIME, &txtime_cfg, sizeof(txtime_cfg)) < 0) {
        if (err_msg && err_msg_len > 0) {
            (void)snprintf(err_msg, err_msg_len, "%s", "SO_TXTIME not supported on this kernel");
        }
        return -1;
    }

    int total_sent = 0;
    int tx_errors = 0;
    const char* data_ptr = (const char*)buffer;

    struct timespec ts_tai;
    clock_gettime(CLOCK_TAI, &ts_tai);
    uint64_t txtime = (uint64_t)ts_tai.tv_sec * 1000000000ULL + (uint64_t)ts_tai.tv_nsec;
    txtime += 100000; /* schedule first packet 100us out */

    char cmsgbuf[CMSG_SPACE(sizeof(uint64_t))];

    for (int i = 0; i < count; i++) {
        struct iovec iov;
        iov.iov_base = (void*)(data_ptr + ((uint64_t)i * packet_size));
        iov.iov_len = packet_size;

        memset(cmsgbuf, 0, sizeof(cmsgbuf));

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = (void*)addr;
        msg.msg_namelen = sizeof(*addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsgbuf;
        msg.msg_controllen = sizeof(cmsgbuf);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_TXTIME;
        cmsg->cmsg_len = CMSG_LEN(sizeof(uint64_t));
        *(uint64_t *)CMSG_DATA(cmsg) = txtime;

        int ret = sendmsg(sockfd, &msg, 0);
        if (ret > 0) {
            total_sent++;
        } else {
            tx_errors++;
            if (errno == EINVAL) {
                clock_gettime(CLOCK_TAI, &ts_tai);
                txtime = (uint64_t)ts_tai.tv_sec * 1000000000ULL + (uint64_t)ts_tai.tv_nsec + 10000;
            }
        }
        txtime += (uint64_t)ipg_ns;
    }

    metrics->sent = total_sent;
    metrics->errors = tx_errors;
    return 0;
}

int afpkt_send_l3(const char* target_ip, int target_port,
                  const uint8_t* buffer, size_t buffer_len,
                  int packet_size, int count, long long ipg_ns,
                  afpkt_tx_metrics_t* metrics,
                  char* err_msg, size_t err_msg_len) {
    if (!metrics) return -1;
    memset(metrics, 0, sizeof(*metrics));
    if (err_msg && err_msg_len > 0) err_msg[0] = '\0';

    if (!target_ip || !buffer || packet_size <= 0 || count < 0) {
        if (err_msg && err_msg_len > 0) (void)snprintf(err_msg, err_msg_len, "%s", "invalid arguments");
        return -1;
    }
    if (buffer_len < ((size_t)packet_size * (size_t)count)) {
        if (err_msg && err_msg_len > 0) (void)snprintf(err_msg, err_msg_len, "%s", "buffer too small");
        return -1;
    }
    metrics->attempted = count;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)target_port);
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) <= 0) {
        if (err_msg && err_msg_len > 0) (void)snprintf(err_msg, err_msg_len, "%s", "invalid target IP");
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        if (err_msg && err_msg_len > 0) {
            (void)snprintf(err_msg, err_msg_len, "raw socket creation failed: %s", strerror(errno));
        }
        metrics->errors = count;
        return -1;
    }

    int rc;
    if (ipg_ns > 0) {
        rc = l3_send_txtime(sockfd, &addr, buffer, packet_size, count, ipg_ns, metrics, err_msg, err_msg_len);
    } else {
        rc = l3_send_sendmmsg(sockfd, &addr, buffer, packet_size, count, metrics);
    }

    close(sockfd);
    return rc;
}

int afpkt_send_ring(const char* iface,
                    const uint8_t* buffer, size_t buffer_len,
                    int packet_size, int count, const uint8_t mac[6],
                    afpkt_tx_metrics_t* metrics,
                    char* err_msg, size_t err_msg_len) {
    if (!metrics) return -1;
    memset(metrics, 0, sizeof(*metrics));
    if (err_msg && err_msg_len > 0) err_msg[0] = '\0';
    metrics->attempted = count > 0 ? count : 0;

    txring_send_metrics_t core;
    if (send_ring_optimized_core(iface, buffer, buffer_len, packet_size, count, mac, &core) < 0) {
        if (err_msg && err_msg_len > 0) {
            (void)snprintf(err_msg, err_msg_len, "%s", "send_ring_optimized_core failed");
        }
        metrics->errors = count > 0 ? count : 0;
        return -1;
    }

    metrics->sent = core.sent;
    metrics->errors = core.attempted - core.sent;
    if (metrics->errors < 0) metrics->errors = 0;
    metrics->packet_version = tx_ring_ctx.packet_version;
    metrics->txring_tp_packets = core.txring_tp_packets;
    metrics->txring_tp_drops = core.txring_tp_drops;
    return 0;
}

void afpkt_cleanup_ring(void) {
    cleanup_tx_ring_internal();
}

int afpkt_send_ring_bridge(const char* iface, const uint8_t* buffer, size_t buffer_len,
                           int packet_size, int count, const uint8_t mac[6],
                           int* out_sent, int* out_errors,
                           char* err_msg, size_t err_msg_len) {
    afpkt_tx_metrics_t metrics;
    if (afpkt_send_ring(iface, buffer, buffer_len, packet_size, count, mac,
                        &metrics, err_msg, err_msg_len) < 0) {
        if (out_sent) *out_sent = 0;
        if (out_errors) *out_errors = count > 0 ? count : 0;
        return -1;
    }
    if (out_sent) *out_sent = metrics.sent;
    if (out_errors) *out_errors = metrics.errors;
    return 0;
}

int afpkt_cleanup_ring_bridge(void) {
    cleanup_tx_ring_internal();
    return 0;
}

/* ================================================================== */
/* Stateful RX handshake handler                                       */
/* ================================================================== */

static volatile int g_rx_run = 0;
static pthread_t g_rx_thread;
static int g_rx_thread_valid = 0;

/* RX thread context: either the built-in L4 handshake handler (cb == NULL) or a
 * generic frame pump that forwards every frame to `cb` (used for L7). */
typedef struct {
    char* iface;                 /* owned; freed by the thread on exit */
    afpkt_rx_frame_cb cb;        /* NULL => built-in L4 handshake mode */
    void* user;
} rx_thread_ctx_t;

static void process_rx_packet(const uint8_t* pkt, uint32_t pkt_len, int sock, const struct sockaddr_ll* sll) {
    if (!pkt || pkt_len < 54) return;

    /* L2 parsing with VLAN support */
    uint16_t eth_type = (pkt[12] << 8) | pkt[13];
    uint32_t l2_offset = 14;
    if (eth_type == 0x8100) { /* VLAN 802.1Q */
        if (pkt_len < 58) return;
        eth_type = (pkt[16] << 8) | pkt[17];
        l2_offset = 18;
    }
    if (eth_type != 0x0800) return; /* Not IPv4 */

    const uint8_t* ip = pkt + l2_offset;
    if (ip[9] != 6) return; /* TCP */

    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (pkt_len < (uint32_t)(l2_offset + ihl + 20)) return;

    const uint8_t* tcp = ip + ihl;
    uint8_t flags = tcp[13];
    if (flags != 0x12) return; /* SYN-ACK */

    uint32_t src_ip = ntohl(*(const uint32_t*)(ip + 12));
    uint32_t dst_ip = ntohl(*(const uint32_t*)(ip + 16));
    uint16_t src_port = ntohs(*(const uint16_t*)tcp);
    uint16_t dst_port = ntohs(*(const uint16_t*)(tcp + 2));
    uint32_t seq = ntohl(*(const uint32_t*)(tcp + 4));
    uint32_t ack = ntohl(*(const uint32_t*)(tcp + 8));

    update_state(dst_ip, dst_port, ack, seq + 1, 2, global_window_size, global_mss, global_ttl);

    uint8_t ack_pkt[54];
    memset(ack_pkt, 0, sizeof(ack_pkt));
    memcpy(ack_pkt, pkt + 6, 6);
    memcpy(ack_pkt + 6, pkt, 6);
    *(uint16_t*)(ack_pkt + 12) = htons(0x0800);
    ack_pkt[14] = 0x45;
    *(uint16_t*)(ack_pkt + 16) = htons(40);
    ack_pkt[22] = global_ttl;
    ack_pkt[23] = 6;
    *(uint32_t*)(ack_pkt + 26) = htonl(dst_ip);
    *(uint32_t*)(ack_pkt + 30) = htonl(src_ip);
    *(uint16_t*)(ack_pkt + 34) = htons(dst_port);
    *(uint16_t*)(ack_pkt + 36) = htons(src_port);
    *(uint32_t*)(ack_pkt + 38) = htonl(ack);
    *(uint32_t*)(ack_pkt + 42) = htonl(seq + 1);
    ack_pkt[46] = 0x50;
    ack_pkt[47] = 0x10;
    *(uint16_t*)(ack_pkt + 48) = htons(global_window_size);
    *(uint16_t*)(ack_pkt + 24) = htons(checksum(ack_pkt + 14, 20));
    *(uint16_t*)(ack_pkt + 50) = htons(tcp_checksum(ack_pkt + 14, ack_pkt + 34, 20));

    if (sendto(sock, ack_pkt, sizeof(ack_pkt), 0, (const struct sockaddr*)sll, sizeof(*sll)) < 0) {
        /* Ignore errors */
    }
}

static void* rx_thread_func(void* arg) {
    rx_thread_ctx_t* rxc = (rx_thread_ctx_t*)arg;
    char* iface = rxc->iface;
    afpkt_rx_frame_cb cb = rxc->cb;
    void* cb_user = rxc->user;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("RX socket creation failed");
        free(iface);
        free(rxc);
        return NULL;
    }

    int version = TPACKET_V3;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        perror("setsockopt PACKET_VERSION(TPACKET_V3) failed");
        close(sock);
        free(iface);
        free(rxc);
        return NULL;
    }

    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = getpagesize();
    req.tp_frame_size = req.tp_block_size;
    req.tp_block_nr = 1024;
    req.tp_frame_nr = req.tp_block_nr;
    req.tp_retire_blk_tov = 64;
    req.tp_sizeof_priv = 0;
    req.tp_feature_req_word = 0;

    if (setsockopt(sock, SOL_PACKET, PACKET_RX_RING, (void*)&req, sizeof(req)) < 0) {
        perror("setsockopt PACKET_RX_RING failed");
        close(sock);
        free(iface);
        free(rxc);
        return NULL;
    }

    int ignore_outgoing = 1;
    if (setsockopt(sock, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_outgoing, sizeof(ignore_outgoing)) < 0) {
        /* Not fatal */
    }

    size_t rx_ring_size = (size_t)req.tp_block_size * req.tp_block_nr;
    uint8_t* map = mmap(NULL, rx_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
    if (map == MAP_FAILED) {
        perror("mmap RX_RING failed");
        close(sock);
        free(iface);
        free(rxc);
        return NULL;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(iface);
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind RX socket failed");
        munmap(map, rx_ring_size);
        close(sock);
        free(iface);
        free(rxc);
        return NULL;
    }
    free(rxc);
    rxc = NULL;

    unsigned int block_idx = 0;
    fprintf(stderr, "[RX] handler started on interface %s\n", iface);

    while (g_rx_run) {
        struct tpacket_block_desc* block_desc =
            (struct tpacket_block_desc*)(map + ((size_t)block_idx * req.tp_block_size));
        if (!(block_desc->hdr.bh1.block_status & TP_STATUS_USER)) {
            struct pollfd pfd;
            pfd.fd = sock;
            pfd.events = POLLIN;
            pfd.revents = 0;
            (void)poll(&pfd, 1, 100); /* wake periodically to observe g_rx_run */
            continue;
        }

        uint32_t num_pkts = block_desc->hdr.bh1.num_pkts;
        uint32_t offset = block_desc->hdr.bh1.offset_to_first_pkt;
        struct tpacket3_hdr* header = (struct tpacket3_hdr*)((uint8_t*)block_desc + offset);

        for (uint32_t pkt_idx = 0; pkt_idx < num_pkts; pkt_idx++) {
            uint8_t* pkt = (uint8_t*)header + header->tp_mac;
            uint32_t pkt_len = header->tp_snaplen ? header->tp_snaplen : header->tp_len;
            if (cb) {
                cb(cb_user, pkt, pkt_len);      /* L7 pump mode */
            } else {
                process_rx_packet(pkt, pkt_len, sock, &sll);  /* L4 handshake mode */
            }

            if (pkt_idx + 1 >= num_pkts) break;
            if (header->tp_next_offset == 0) break;
            header = (struct tpacket3_hdr*)((uint8_t*)header + header->tp_next_offset);
        }

        __sync_synchronize();
        block_desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
        block_idx = (block_idx + 1) % req.tp_block_nr;
    }

    munmap(map, rx_ring_size);
    close(sock);
    free(iface);
    return NULL;
}

static int afpkt_start_rx_common(const char* iface, afpkt_rx_frame_cb cb, void* user) {
    if (!iface || !iface[0]) return -1;
    if (g_rx_run) return 0; /* already running */

    rx_thread_ctx_t* rxc = (rx_thread_ctx_t*)calloc(1, sizeof(rx_thread_ctx_t));
    if (!rxc) return -1;
    rxc->iface = strdup(iface);
    if (!rxc->iface) {
        free(rxc);
        return -1;
    }
    rxc->cb = cb;
    rxc->user = user;

    g_rx_run = 1;
    if (pthread_create(&g_rx_thread, NULL, rx_thread_func, rxc) != 0) {
        g_rx_run = 0;
        free(rxc->iface);
        free(rxc);
        return -1;
    }
    g_rx_thread_valid = 1;
    return 0;
}

int afpkt_start_rx_handler(const char* iface) {
    return afpkt_start_rx_common(iface, NULL, NULL);
}

int afpkt_start_rx_pump(const char* iface, afpkt_rx_frame_cb cb, void* user) {
    if (!cb) return -1;
    return afpkt_start_rx_common(iface, cb, user);
}

void afpkt_stop_rx_handler(void) {
    if (!g_rx_run && !g_rx_thread_valid) return;
    g_rx_run = 0;
    if (g_rx_thread_valid) {
        pthread_join(g_rx_thread, NULL);
        g_rx_thread_valid = 0;
    }
}
