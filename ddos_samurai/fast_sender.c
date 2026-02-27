#define PY_SSIZE_T_CLEAN
#include <Python.h>
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
#include <pthread.h>
#include <stdlib.h>
#include <strings.h>
#include <stdint.h>
#include <time.h>
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

static const char* txring_flush_mode_name(int mode) {
    return (mode == TXRING_FLUSH_MODE_ADAPTIVE) ? "adaptive" : "legacy";
}

static const char* txring_flush_errno_name(int err) {
    if (err == 0) return "NONE";
    if (err == EAGAIN || err == EWOULDBLOCK) return "EAGAIN";
    if (err == ENOBUFS) return "ENOBUFS";
    if (err == EBUSY) return "EBUSY";
    return "OTHER";
}

static inline uint64_t monotonic_ns_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

// --- TCP State Table ---
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t state; // 0: CLOSED, 1: SYN_SENT, 2: ESTABLISHED
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

static uint32_t env_uint(const char* name, uint32_t fallback) {
    const char* raw = getenv(name);
    char* endptr = NULL;
    unsigned long parsed;
    if (!raw || !raw[0]) return fallback;
    errno = 0;
    parsed = strtoul(raw, &endptr, 10);
    if (errno != 0 || endptr == raw || (endptr && *endptr != '\0')) return fallback;
    if (parsed == 0UL) return fallback;
    if (parsed > 0x7fffffffUL) return fallback;
    return (uint32_t)parsed;
}

static void destroy_state_engine(void) {
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

static int init_state_engine(uint32_t table_size, uint32_t lock_count, uint32_t timeout_sec) {
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

    destroy_state_engine();
    state_table = new_table;
    state_locks = new_locks;
    state_table_size = table_size;
    state_lock_count = lock_count;
    state_timeout_sec = timeout_sec;
    return 0;
}

static inline uint32_t hash_state(uint32_t src_ip, uint16_t src_port) {
    // Improved hash function (Murmur-like mixing)
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
    
    if (!found) { // Overwrite if bucket is full
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

// --- TX_RING Context (Persistent Mapping) ---
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
} ring_context_t;

static ring_context_t tx_ring_ctx = {
    .is_setup = 0,
    .sock = -1,
    .map = MAP_FAILED,
    .packet_version = TPACKET_V2,
    .frame_header_size = 0,
};

static const char* packet_version_name(int version) {
    switch (version) {
        case TPACKET_V3: return "TPACKET_V3";
        case TPACKET_V2: return "TPACKET_V2";
        case TPACKET_V1: return "TPACKET_V1";
        default: return "NONE";
    }
}

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

static int fill_ring_request_for_version(
    int packet_version,
    int packet_size,
    struct tpacket_req* req_v2,
    struct tpacket_req3* req_v3,
    size_t* out_frame_header_size
) {
    if (packet_size <= 0) return -1;

    size_t frame_header_size = frame_header_size_for_version(packet_version);
    unsigned int block_size = (unsigned int)getpagesize();
    while (block_size < (unsigned int)(packet_size + frame_header_size)) {
        block_size <<= 1;
    }
    unsigned int block_nr = 4096;
    unsigned int frame_size = block_size;
    unsigned int frame_nr = block_nr;

    if (packet_version == TPACKET_V3) {
        memset(req_v3, 0, sizeof(*req_v3));
        req_v3->tp_block_size = block_size;
        req_v3->tp_block_nr = block_nr;
        req_v3->tp_frame_size = frame_size;
        req_v3->tp_frame_nr = frame_nr;
        /*
         * TX_RING path: kernel expects v3 RX-only fields to stay zero.
         * Non-zero tp_retire_blk_tov can make PACKET_TX_RING fail with EINVAL.
         */
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

// --- Checksum Helpers ---
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
    sum += 6; // Protocol
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

static PyObject* get_states_batch(PyObject* self, PyObject* args) {
    uint32_t src_ip;
    uint16_t start_port;
    uint32_t count;
    if (!PyArg_ParseTuple(args, "IHI", &src_ip, &start_port, &count)) return NULL;
    (void)self;
    if (!state_table || !state_locks || state_table_size == 0 || state_lock_count == 0) {
        PyErr_SetString(PyExc_RuntimeError, "state engine is not initialized");
        return NULL;
    }

    PyObject* seq_list = PyList_New(count);
    PyObject* ack_list = PyList_New(count);
    PyObject* state_list = PyList_New(count);
    PyObject* window_list = PyList_New(count);
    PyObject* mss_list = PyList_New(count);
    PyObject* ttl_list = PyList_New(count);
    uint32_t segment_size = state_segment_size();
    if (segment_size == 0) {
        PyErr_SetString(PyExc_RuntimeError, "invalid state engine segment size");
        return NULL;
    }

    for (uint32_t i = 0; i < count; i++) {
        uint16_t port = start_port + (i % 64512);
        uint32_t h = hash_state(src_ip, port);
        uint32_t segment = h % state_lock_count;
        uint32_t segment_start = segment * segment_size;
        uint32_t start_idx = segment_start + ((h / state_lock_count) % segment_size);
        
        uint32_t seq = 0, ack = 0;
        uint8_t state = 0;
        uint16_t window = 0, mss = 0;
        uint8_t ttl = 0;
        
        pthread_mutex_lock(&state_locks[segment]);
        uint32_t idx = start_idx;
        for (uint32_t j = 0; j < segment_size; j++) {
            if (state_table[idx].state != 0 && state_table[idx].src_ip == src_ip && state_table[idx].src_port == port) {
                seq = state_table[idx].seq;
                ack = state_table[idx].ack;
                state = state_table[idx].state;
                window = state_table[idx].window_size;
                mss = state_table[idx].mss;
                ttl = state_table[idx].ttl;
                break;
            }
            if (state_table[idx].state == 0) break; // Optimization: stop probing
            idx = segment_start + ((idx - segment_start + 1) % segment_size);
        }
        pthread_mutex_unlock(&state_locks[segment]);
        
        PyList_SetItem(seq_list, i, PyLong_FromUnsignedLong(seq));
        PyList_SetItem(ack_list, i, PyLong_FromUnsignedLong(ack));
        PyList_SetItem(state_list, i, PyLong_FromUnsignedLong(state));
        PyList_SetItem(window_list, i, PyLong_FromUnsignedLong(window));
        PyList_SetItem(mss_list, i, PyLong_FromUnsignedLong(mss));
        PyList_SetItem(ttl_list, i, PyLong_FromUnsignedLong(ttl));
    }

    return Py_BuildValue("OOOOOO", seq_list, ack_list, state_list, window_list, mss_list, ttl_list);
}

static PyObject* get_tcp_state(PyObject* self, PyObject* args) {
    uint32_t src_ip;
    uint16_t src_port;
    if (!PyArg_ParseTuple(args, "IH", &src_ip, &src_port)) return NULL;
    (void)self;
    if (!state_table || !state_locks || state_table_size == 0 || state_lock_count == 0) {
        PyErr_SetString(PyExc_RuntimeError, "state engine is not initialized");
        return NULL;
    }

    uint32_t seq = 0, ack = 0;
    uint8_t state = 0;
    uint16_t window = 0, mss = 0;
    uint8_t ttl = 0;

    uint32_t h = hash_state(src_ip, src_port);
    uint32_t segment = h % state_lock_count;
    uint32_t segment_size = state_segment_size();
    if (segment_size == 0) {
        PyErr_SetString(PyExc_RuntimeError, "invalid state engine segment size");
        return NULL;
    }
    uint32_t segment_start = segment * segment_size;
    uint32_t start_idx = segment_start + ((h / state_lock_count) % segment_size);

    pthread_mutex_lock(&state_locks[segment]);
    uint32_t idx = start_idx;
    for (uint32_t i = 0; i < segment_size; i++) {
        if (state_table[idx].state != 0 && state_table[idx].src_ip == src_ip && state_table[idx].src_port == src_port) {
            seq = state_table[idx].seq;
            ack = state_table[idx].ack;
            state = state_table[idx].state;
            window = state_table[idx].window_size;
            mss = state_table[idx].mss;
            ttl = state_table[idx].ttl;
            break;
        }
        if (state_table[idx].state == 0) break;
        idx = segment_start + ((idx - segment_start + 1) % segment_size);
    }
    pthread_mutex_unlock(&state_locks[segment]);

    return Py_BuildValue("{s:I,s:I,s:i,s:H,s:H,s:b}", "seq", seq, "ack", ack, "state", state, "window", window, "mss", mss, "ttl", ttl);
}

// --- Global Mimicry Settings ---
static uint16_t global_window_size = 64240;
static uint16_t global_mss = 1460;
static uint8_t global_ttl = 64;

static PyObject* set_mimicry_settings(PyObject* self, PyObject* args) {
    uint16_t window;
    uint16_t mss;
    uint8_t ttl;
    if (!PyArg_ParseTuple(args, "HHb", &window, &mss, &ttl)) return NULL;
    global_window_size = window;
    global_mss = mss;
    global_ttl = ttl;
    Py_RETURN_NONE;
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

static inline uint16_t read_be16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t read_be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static PyObject* configure_state_engine(PyObject* self, PyObject* args) {
    unsigned int table_size = DEFAULT_STATE_TABLE_SIZE;
    unsigned int lock_count = DEFAULT_NUM_LOCKS;
    unsigned int timeout_sec = DEFAULT_STATE_TIMEOUT_SEC;
    (void)self;
    if (!PyArg_ParseTuple(args, "III", &table_size, &lock_count, &timeout_sec)) return NULL;
    if (table_size == 0 || lock_count == 0 || timeout_sec == 0 || (table_size % lock_count) != 0) {
        PyErr_SetString(
            PyExc_ValueError,
            "Invalid state-engine config: table_size/lock_count/timeout_sec must be >0 and table_size % lock_count == 0"
        );
        return NULL;
    }
    if (init_state_engine((uint32_t)table_size, (uint32_t)lock_count, (uint32_t)timeout_sec) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to initialize state engine");
        return NULL;
    }
    return Py_BuildValue(
        "{s:I,s:I,s:I}",
        "table_size", (unsigned int)state_table_size,
        "lock_count", (unsigned int)state_lock_count,
        "timeout_sec", (unsigned int)state_timeout_sec
    );
}

static PyObject* get_state_engine_stats(PyObject* self, PyObject* args) {
    (void)self;
    (void)args;
    return Py_BuildValue(
        "{s:I,s:I,s:I,s:K,s:K,s:K,s:K,s:K,s:I}",
        "table_size", (unsigned int)state_table_size,
        "lock_count", (unsigned int)state_lock_count,
        "timeout_sec", (unsigned int)state_timeout_sec,
        "active_entries", state_active_entries,
        "timeout_evictions", state_timeout_evictions,
        "overwrites", state_overwrites,
        "sweeps", state_sweeps,
        "last_sweep_removed", state_last_sweep_removed,
        "sweep_cursor", (unsigned int)state_sweep_cursor
    );
}

static PyObject* sweep_state_table(PyObject* self, PyObject* args) {
    unsigned int max_scan = 0;
    int removed = 0;
    (void)self;
    if (!PyArg_ParseTuple(args, "|I", &max_scan)) return NULL;
    removed = sweep_state_table_internal((uint32_t)max_scan);
    return PyLong_FromLong((long)removed);
}

static PyObject* ingest_tx_packets(PyObject* self, PyObject* args) {
    Py_buffer view;
    int packet_size = 0;
    int count = 0;
    int updated = 0;
    (void)self;

    if (!PyArg_ParseTuple(args, "y*ii", &view, &packet_size, &count)) return NULL;
    if (packet_size <= 0 || count <= 0) {
        PyBuffer_Release(&view);
        return PyLong_FromLong(0);
    }
    if ((size_t)view.len < ((size_t)packet_size * (size_t)count)) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "packets buffer is smaller than packet_size * count");
        return NULL;
    }

    const uint8_t* base = (const uint8_t*)view.buf;
    for (int i = 0; i < count; i++) {
        const uint8_t* pkt = base + ((size_t)i * (size_t)packet_size);
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
        if (protocol != 6) continue; // TCP only

        transport_offset = ip_offset + ihl_bytes;
        src_ip = read_be32(pkt + ip_offset + 12);
        src_port = read_be16(pkt + transport_offset);
        seq = read_be32(pkt + transport_offset + 4);
        ack = read_be32(pkt + transport_offset + 8);
        flags = pkt[transport_offset + 13];

        if ((flags & 0x10) != 0) {
            next_state = 2; // ESTABLISHED-ish
            next_seq = seq;
            next_ack = ack;
        } else {
            next_state = 1; // SYN_SENT-ish
            next_seq = seq + 1U;
            next_ack = 0U;
        }
        update_state(src_ip, src_port, next_seq, next_ack, next_state, global_window_size, global_mss, global_ttl);
        updated++;
    }

    PyBuffer_Release(&view);
    return PyLong_FromLong((long)updated);
}

// --- RX_RING Handshake Handler ---
static void process_rx_packet(const uint8_t* pkt, uint32_t pkt_len, int sock, const struct sockaddr_ll* sll) {
    if (!pkt || pkt_len < 54) return;

    // L2 Parsing with VLAN support
    uint16_t eth_type = (pkt[12] << 8) | pkt[13];
    uint32_t l2_offset = 14;
    if (eth_type == 0x8100) { // VLAN 802.1Q
        if (pkt_len < 58) return;
        eth_type = (pkt[16] << 8) | pkt[17];
        l2_offset = 18;
    }
    if (eth_type != 0x0800) return; // Not IPv4

    const uint8_t* ip = pkt + l2_offset;
    if (ip[9] != 6) return; // TCP

    uint8_t ihl = (ip[0] & 0x0F) * 4;
    if (pkt_len < (uint32_t)(l2_offset + ihl + 20)) return;

    const uint8_t* tcp = ip + ihl;
    uint8_t flags = tcp[13];
    if (flags != 0x12) return; // SYN-ACK

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
        // Ignore errors
    }
}

static void* rx_thread_func(void* arg) {
    char* iface = (char*)arg;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("RX socket creation failed");
        free(iface);
        return NULL;
    }

    int version = TPACKET_V3;
    if (setsockopt(sock, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        perror("setsockopt PACKET_VERSION(TPACKET_V3) failed");
        close(sock);
        free(iface);
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
        return NULL;
    }

    int ignore_outgoing = 1;
    if (setsockopt(sock, SOL_PACKET, PACKET_IGNORE_OUTGOING, &ignore_outgoing, sizeof(ignore_outgoing)) < 0) {
        // Not fatal
    }

    size_t rx_ring_size = (size_t)req.tp_block_size * req.tp_block_nr;
    uint8_t* map = mmap(NULL, rx_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, sock, 0);
    if (map == MAP_FAILED) {
        perror("mmap RX_RING failed");
        close(sock);
        free(iface);
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
        return NULL;
    }

    unsigned int block_idx = 0;
    printf("[RX] Thread started on interface %s\n", iface);
    fflush(stdout);

    while (1) {
        struct tpacket_block_desc* block_desc =
            (struct tpacket_block_desc*)(map + ((size_t)block_idx * req.tp_block_size));
        if (!(block_desc->hdr.bh1.block_status & TP_STATUS_USER)) {
            usleep(10);
            continue;
        }

        uint32_t num_pkts = block_desc->hdr.bh1.num_pkts;
        uint32_t offset = block_desc->hdr.bh1.offset_to_first_pkt;
        struct tpacket3_hdr* header = (struct tpacket3_hdr*)((uint8_t*)block_desc + offset);

        for (uint32_t pkt_idx = 0; pkt_idx < num_pkts; pkt_idx++) {
            uint8_t* pkt = (uint8_t*)header + header->tp_mac;
            uint32_t pkt_len = header->tp_snaplen ? header->tp_snaplen : header->tp_len;
            process_rx_packet(pkt, pkt_len, sock, &sll);

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

static PyObject* start_rx_handler(PyObject* self, PyObject* args) {
    char* iface;
    if (!PyArg_ParseTuple(args, "s", &iface)) return NULL;

    pthread_t thread;
    if (pthread_create(&thread, NULL, rx_thread_func, strdup(iface)) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to create RX thread");
        return NULL;
    }
    pthread_detach(thread);
    Py_RETURN_NONE;
}

// --- L3 Sender (sendmmsg) ---
static PyObject* send_optimized(PyObject* self, PyObject* args) {
    int sockfd;
    Py_buffer view;
    char* target_ip;
    int target_port;
    int packet_size;
    int count;

    if (!PyArg_ParseTuple(args, "iy*siii", &sockfd, &view, &target_ip, &target_port, &packet_size, &count)) {
        return NULL;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) <= 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "Invalid IP address");
        return NULL;
    }

    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovecs[BATCH_SIZE];    
    
    memset(msgs, 0, sizeof(msgs));
    memset(iovecs, 0, sizeof(iovecs));

    int total_sent = 0;
    int eagain_retry_count = 0;
    int partial_send_retry_count = 0;
    char* data_ptr = (char*)view.buf;

    Py_BEGIN_ALLOW_THREADS

    for (int pkt_idx = 0; pkt_idx < count; ) {
        int batch = count - pkt_idx;
        if (batch > BATCH_SIZE) {
            batch = BATCH_SIZE;
        }

        for (int j = 0; j < batch; j++) {
            int idx = pkt_idx + j;
            iovecs[j].iov_base = data_ptr + ((uint64_t)idx * packet_size);
            iovecs[j].iov_len = packet_size;

            msgs[j].msg_hdr.msg_name = &addr;
            msgs[j].msg_hdr.msg_namelen = sizeof(addr);
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

    Py_END_ALLOW_THREADS

    PyBuffer_Release(&view);
    return Py_BuildValue(
        "{s:i,s:i,s:i}",
        "sent", total_sent,
        "eagain_retry_count", eagain_retry_count,
        "partial_send_retry_count", partial_send_retry_count
    );
}

// --- L3 Sender with SO_TXTIME (Kernel Pacing) ---
static PyObject* send_optimized_txtime(PyObject* self, PyObject* args) {
    int sockfd;
    Py_buffer view;
    char* target_ip;
    int target_port;
    int packet_size;
    int count;
    long long ipg_ns;  // inter-packet gap in nanoseconds

    if (!PyArg_ParseTuple(args, "iy*siiiL", &sockfd, &view, &target_ip,
                          &target_port, &packet_size, &count, &ipg_ns)) {
        return NULL;
    }

    // Enable SO_TXTIME on the socket
    struct {
        int32_t clockid;
        uint32_t flags;
    } txtime_cfg;
    txtime_cfg.clockid = CLOCK_TAI;
    txtime_cfg.flags = SOF_TXTIME_REPORT_ERRORS;

    if (setsockopt(sockfd, SOL_SOCKET, SO_TXTIME,
                   &txtime_cfg, sizeof(txtime_cfg)) < 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_OSError, "SO_TXTIME not supported on this kernel");
        return NULL;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) <= 0) {
        PyBuffer_Release(&view);
        PyErr_SetString(PyExc_ValueError, "Invalid IP address");
        return NULL;
    }

    int total_sent = 0;
    int tx_errors = 0;
    char* data_ptr = (char*)view.buf;

    // Get initial TAI time
    struct timespec ts_tai;
    clock_gettime(CLOCK_TAI, &ts_tai);
    uint64_t txtime = (uint64_t)ts_tai.tv_sec * 1000000000ULL +
                      (uint64_t)ts_tai.tv_nsec;
    // Schedule first packet 100µs from now (allow setup time)
    txtime += 100000;

    // Ancillary data buffer for SCM_TXTIME
    char cmsgbuf[CMSG_SPACE(sizeof(uint64_t))];

    Py_BEGIN_ALLOW_THREADS

    for (int i = 0; i < count; i++) {
        struct iovec iov;
        iov.iov_base = data_ptr + ((uint64_t)i * packet_size);
        iov.iov_len = packet_size;

        memset(cmsgbuf, 0, sizeof(cmsgbuf));

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &addr;
        msg.msg_namelen = sizeof(addr);
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
                // Packet too late — advance txtime and continue
                clock_gettime(CLOCK_TAI, &ts_tai);
                txtime = (uint64_t)ts_tai.tv_sec * 1000000000ULL +
                         (uint64_t)ts_tai.tv_nsec + 10000;  // 10µs buffer
            }
        }

        // Advance scheduled TX time by IPG
        txtime += (uint64_t)ipg_ns;
    }

    Py_END_ALLOW_THREADS

    PyBuffer_Release(&view);
    return Py_BuildValue("{s:i,s:i}", "sent", total_sent, "tx_errors", tx_errors);
}

// --- Check SO_TXTIME Availability ---
static PyObject* check_so_txtime(PyObject* self, PyObject* args) {
    (void)self; (void)args;

    int available = 0;
    int has_tai = 0;

    // Check SO_TXTIME
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd >= 0) {
        struct {
            int32_t clockid;
            uint32_t flags;
        } cfg;
        cfg.clockid = CLOCK_TAI;
        cfg.flags = SOF_TXTIME_REPORT_ERRORS;

        if (setsockopt(fd, SOL_SOCKET, SO_TXTIME, &cfg, sizeof(cfg)) == 0) {
            available = 1;
        }
        close(fd);
    }

    // Check CLOCK_TAI
    struct timespec ts;
    if (clock_gettime(CLOCK_TAI, &ts) == 0) {
        has_tai = 1;
    }

    return Py_BuildValue("{s:i,s:i,s:i}",
                         "so_txtime", available,
                         "clock_tai", has_tai,
                         "is_root", geteuid() == 0);
}

// --- L2 Sender (AF_PACKET TX_RING Zero-Copy) ---

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

    // Best effort; not fatal if unavailable
    int qdisc_bypass = 1;
    (void)setsockopt(sock, SOL_PACKET, PACKET_QDISC_BYPASS, &qdisc_bypass, sizeof(qdisc_bypass));

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
    return 0;
}

static int setup_tx_ring(const char* iface, int packet_size, const uint8_t* mac) {
    if (tx_ring_ctx.is_setup) {
        unsigned int current_frame_size = tx_ring_frame_size(&tx_ring_ctx);
        size_t current_frame_header_size = tx_ring_ctx.frame_header_size;
        if (current_frame_header_size == 0) {
            current_frame_header_size = frame_header_size_for_version(tx_ring_ctx.packet_version);
        }
        if (strcmp(tx_ring_ctx.iface, iface) == 0 &&
            current_frame_size >= (unsigned int)(packet_size + current_frame_header_size)) {
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

static PyObject* cleanup_ring(PyObject* self, PyObject* args) {
    (void)self;
    (void)args;
    cleanup_tx_ring_internal();
    Py_RETURN_NONE;
}

static PyObject* get_ring_info(PyObject* self, PyObject* args) {
    (void)self;
    (void)args;

    int is_setup = tx_ring_ctx.is_setup ? 1 : 0;
    int packet_version = is_setup ? tx_ring_ctx.packet_version : 0;
    const char* version_name = is_setup ? packet_version_name(packet_version) : "NONE";
    const char* iface = is_setup ? tx_ring_ctx.iface : "";
    unsigned int tp_block_size = is_setup ? tx_ring_block_size(&tx_ring_ctx) : 0;
    unsigned int tp_frame_size = is_setup ? tx_ring_frame_size(&tx_ring_ctx) : 0;
    unsigned int tp_block_nr = is_setup ? tx_ring_block_nr(&tx_ring_ctx) : 0;
    unsigned int tp_frame_nr = is_setup ? tx_ring_frame_nr(&tx_ring_ctx) : 0;
    unsigned long long ring_size = is_setup ? (unsigned long long)tx_ring_ctx.ring_size : 0ULL;
    unsigned long long frame_header_size = is_setup ? (unsigned long long)tx_ring_ctx.frame_header_size : 0ULL;

    return Py_BuildValue(
        "{s:i,s:i,s:s,s:s,s:I,s:I,s:I,s:I,s:K,s:K}",
        "is_setup", is_setup,
        "packet_version", packet_version,
        "packet_version_name", version_name,
        "iface", iface,
        "tp_block_size", tp_block_size,
        "tp_frame_size", tp_frame_size,
        "tp_block_nr", tp_block_nr,
        "tp_frame_nr", tp_frame_nr,
        "ring_size", ring_size,
        "frame_header_size", frame_header_size
    );
}

typedef struct {
    int attempted;
    int sent;
    unsigned long long txring_flush_call_count;
    unsigned long long txring_flush_error_count;
    unsigned long long txring_flush_eagain_count;
    unsigned long long txring_flush_enobufs_count;
    unsigned long long txring_flush_ebusy_count;
    unsigned long long txring_flush_other_errno_count;
    int txring_flush_last_errno;
    unsigned long long txring_tp_packets;
    unsigned long long txring_tp_drops;
    unsigned long long txring_tp_freeze_q_cnt;
    unsigned long long txring_frame_wait_ns;
    unsigned long long txring_poll_count;
    int flush_mode;
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
            metrics->txring_tp_freeze_q_cnt = (unsigned long long)stats_v3.tp_freeze_q_cnt;
        }
        return;
    }

    struct tpacket_stats stats_v2;
    socklen_t optlen = sizeof(stats_v2);
    if (getsockopt(ctx->sock, SOL_PACKET, PACKET_STATISTICS, &stats_v2, &optlen) == 0) {
        metrics->txring_tp_packets = (unsigned long long)stats_v2.tp_packets;
        metrics->txring_tp_drops = (unsigned long long)stats_v2.tp_drops;
        metrics->txring_tp_freeze_q_cnt = 0ULL;
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
        if (err == EAGAIN || err == EWOULDBLOCK) {
            metrics->txring_flush_eagain_count++;
        } else if (err == ENOBUFS) {
            metrics->txring_flush_enobufs_count++;
        } else if (err == EBUSY) {
            metrics->txring_flush_ebusy_count++;
        } else {
            metrics->txring_flush_other_errno_count++;
        }
        metrics->txring_flush_last_errno = err;
        return err;
    }
    return 0;
}

static int send_ring_optimized_core(
    const char* iface,
    Py_buffer* view,
    int packet_size,
    int count,
    const uint8_t* mac,
    txring_send_metrics_t* metrics
) {
    if (!iface || !view || !mac || !metrics) {
        PyErr_SetString(PyExc_ValueError, "invalid send_ring_optimized arguments");
        return -1;
    }
    if (packet_size <= 0 || count < 0) {
        PyErr_SetString(PyExc_ValueError, "packet_size must be > 0 and count must be >= 0");
        return -1;
    }
    if ((size_t)view->len < ((size_t)packet_size * (size_t)count)) {
        PyErr_SetString(PyExc_ValueError, "packets buffer is smaller than packet_size * count");
        return -1;
    }

    memset(metrics, 0, sizeof(*metrics));
    metrics->attempted = count;
    metrics->flush_mode = (int)txring_flush_mode_from_env();

    if (setup_tx_ring(iface, packet_size, mac) < 0) {
        PyErr_SetString(PyExc_OSError, "Failed to setup TX_RING");
        return -1;
    }

    drain_txring_packet_stats(&tx_ring_ctx);

    char* data_ptr = (char*)view->buf;
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
    const int spin_limit = 64;
    unsigned int pending_since_flush = 0U;
    int last_flush_errno = 0;

    for (int i = 0; i < count; ) {
        char* frame_base = tx_ring_ctx.map + ((size_t)tx_ring_ctx.frame_idx * frame_size);

        int spins = 0;
        int poll_timeout_ms = 0;
        uint64_t wait_start_ns = 0ULL;
        while (tx_frame_status(frame_base, packet_version) != TP_STATUS_AVAILABLE) {
            if (wait_start_ns == 0ULL) {
                wait_start_ns = monotonic_ns_now();
            }

            if (spins < spin_limit) {
                spins++;
                __asm__ volatile("pause" ::: "memory");
                continue;
            }

            pfd.revents = 0;
            (void)poll(&pfd, 1, poll_timeout_ms);
            metrics->txring_poll_count++;

            if (tx_frame_status(frame_base, packet_version) != TP_STATUS_AVAILABLE) {
                if (flush_mode == TXRING_FLUSH_MODE_ADAPTIVE) {
                    if ((pfd.revents & (POLLOUT | POLLERR | POLLHUP)) != 0 || poll_timeout_ms >= 2) {
                        last_flush_errno = txring_flush_socket(tx_ring_ctx.sock, metrics);
                    }
                } else {
                    last_flush_errno = txring_flush_socket(tx_ring_ctx.sock, metrics);
                }
                if (poll_timeout_ms < 8) {
                    poll_timeout_ms = (poll_timeout_ms == 0) ? 1 : (poll_timeout_ms << 1);
                } else {
                    sched_yield();
                }
            }
        }
        if (wait_start_ns != 0ULL) {
            metrics->txring_frame_wait_ns += (unsigned long long)(monotonic_ns_now() - wait_start_ns);
        }

        char* payload_ptr = frame_base + frame_header_size;
        memcpy(payload_ptr, data_ptr + ((uint64_t)i * (uint64_t)packet_size), (size_t)packet_size);
        tx_frame_prepare(frame_base, packet_version, frame_header_size, packet_size);

        pending_since_flush++;
        int should_flush = 0;
        if (flush_mode == TXRING_FLUSH_MODE_ADAPTIVE) {
            unsigned int adaptive_batch = (
                (last_flush_errno == EAGAIN || last_flush_errno == EWOULDBLOCK) ? 64U : 256U
            );
            if (pending_since_flush >= adaptive_batch || i == count - 1) {
                should_flush = 1;
            } else if ((pfd.revents & POLLOUT) && pending_since_flush >= 32U) {
                should_flush = 1;
            }
        } else {
            if (pending_since_flush >= legacy_batch || i == count - 1) {
                should_flush = 1;
            }
        }

        if (should_flush) {
            last_flush_errno = txring_flush_socket(tx_ring_ctx.sock, metrics);
            pending_since_flush = 0U;
        }

        metrics->sent++;
        i++;
        tx_ring_ctx.frame_idx = (tx_ring_ctx.frame_idx + 1U) % frame_nr;
    }

    collect_txring_packet_stats(&tx_ring_ctx, metrics);
    return 0;
}

static PyObject* send_ring_optimized(PyObject* self, PyObject* args) {
    char* iface;
    Py_buffer view;
    int packet_size;
    int count;
    Py_buffer mac_view;
    txring_send_metrics_t metrics;

    (void)self;
    if (!PyArg_ParseTuple(args, "sy*iiy*", &iface, &view, &packet_size, &count, &mac_view)) {
        return NULL;
    }

    if (mac_view.len != 6) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&mac_view);
        PyErr_SetString(PyExc_ValueError, "MAC address must be 6 bytes");
        return NULL;
    }

    if (send_ring_optimized_core(
            iface, &view, packet_size, count, (const uint8_t*)mac_view.buf, &metrics) < 0) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&mac_view);
        return NULL;
    }

    PyBuffer_Release(&view);
    PyBuffer_Release(&mac_view);
    return Py_BuildValue("i", metrics.sent);
}

static PyObject* send_ring_optimized_ex(PyObject* self, PyObject* args) {
    char* iface;
    Py_buffer view;
    int packet_size;
    int count;
    Py_buffer mac_view;
    txring_send_metrics_t metrics;
    int errors = 0;
    int packet_version = 0;
    const char* packet_version_str = "TPACKET_UNKNOWN";

    (void)self;
    if (!PyArg_ParseTuple(args, "sy*iiy*", &iface, &view, &packet_size, &count, &mac_view)) {
        return NULL;
    }

    if (mac_view.len != 6) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&mac_view);
        PyErr_SetString(PyExc_ValueError, "MAC address must be 6 bytes");
        return NULL;
    }

    if (send_ring_optimized_core(
            iface, &view, packet_size, count, (const uint8_t*)mac_view.buf, &metrics) < 0) {
        PyBuffer_Release(&view);
        PyBuffer_Release(&mac_view);
        return NULL;
    }

    PyBuffer_Release(&view);
    PyBuffer_Release(&mac_view);

    errors = metrics.attempted - metrics.sent;
    if (errors < 0) errors = 0;
    packet_version = tx_ring_ctx.packet_version;
    packet_version_str = packet_version_name(packet_version);

    return Py_BuildValue(
        "{s:i,s:i,s:i,s:K,s:K,s:K,s:K,s:K,s:K,s:i,s:s,s:K,s:K,s:K,s:K,s:K,s:s,s:i,s:s}",
        "attempted", metrics.attempted,
        "sent", metrics.sent,
        "errors", errors,
        "txring_flush_call_count", metrics.txring_flush_call_count,
        "txring_flush_error_count", metrics.txring_flush_error_count,
        "txring_flush_eagain_count", metrics.txring_flush_eagain_count,
        "txring_flush_enobufs_count", metrics.txring_flush_enobufs_count,
        "txring_flush_ebusy_count", metrics.txring_flush_ebusy_count,
        "txring_flush_other_errno_count", metrics.txring_flush_other_errno_count,
        "txring_flush_last_errno", metrics.txring_flush_last_errno,
        "txring_flush_last_errno_name", txring_flush_errno_name(metrics.txring_flush_last_errno),
        "txring_tp_packets", metrics.txring_tp_packets,
        "txring_tp_drops", metrics.txring_tp_drops,
        "txring_tp_freeze_q_cnt", metrics.txring_tp_freeze_q_cnt,
        "txring_frame_wait_ns", metrics.txring_frame_wait_ns,
        "txring_poll_count", metrics.txring_poll_count,
        "flush_mode", txring_flush_mode_name(metrics.flush_mode),
        "txring_packet_version", packet_version,
        "txring_packet_version_name", packet_version_str
    );
}

// --- Module Definition ---
static PyMethodDef FastSenderMethods[] = {
    {"send_optimized", send_optimized, METH_VARARGS, "Send packets using sendmmsg (L3)"},
    {"send_optimized_txtime", send_optimized_txtime, METH_VARARGS,
     "Send packets using SO_TXTIME kernel pacing (L3).\n"
     "Args: sockfd, buffer, target_ip, target_port, packet_size, count, ipg_ns\n"
     "Returns: dict with 'sent' and 'tx_errors' counts."},
    {"send_ring_optimized", send_ring_optimized, METH_VARARGS, "Send packets using AF_PACKET TX_RING (L2 Zero-Copy)"},
    {"send_ring_optimized_ex", send_ring_optimized_ex, METH_VARARGS,
     "Send packets using AF_PACKET TX_RING (L2 Zero-Copy) and return detailed counters."},
    {"cleanup_ring", cleanup_ring, METH_VARARGS, "Cleanup persistent TX_RING context"},
    {"get_ring_info", get_ring_info, METH_NOARGS, "Return active TX_RING setup details including packet version."},
    {"configure_state_engine", configure_state_engine, METH_VARARGS, "Configure state table size/locks/timeout."},
    {"get_state_engine_stats", get_state_engine_stats, METH_NOARGS, "Return state-engine counters and active entries."},
    {"ingest_tx_packets", ingest_tx_packets, METH_VARARGS, "Ingest transmitted packets and update CPU state table."},
    {"sweep_state_table", sweep_state_table, METH_VARARGS, "Sweep stale state entries by timeout and return removed count."},
    {"get_tcp_state", get_tcp_state, METH_VARARGS, "Get TCP state from the state table"},
    {"get_states_batch", get_states_batch, METH_VARARGS, "Get multiple TCP states in one call"},
    {"start_rx_handler", start_rx_handler, METH_VARARGS, "Start the background RX handler thread"},
    {"set_mimicry_settings", set_mimicry_settings, METH_VARARGS, "Set global TCP mimicry settings (Window, MSS, TTL)"},
    {"check_so_txtime", check_so_txtime, METH_NOARGS,
     "Check SO_TXTIME / CLOCK_TAI availability.\n"
     "Returns: dict with 'so_txtime', 'clock_tai', 'is_root' keys."},
    {NULL, NULL, 0, NULL}
};

static void fast_sender_free(void* module) {
    (void)module;
    cleanup_tx_ring_internal();
    destroy_state_engine();
}

static struct PyModuleDef fastsendermodule = {
    PyModuleDef_HEAD_INIT,
    "fast_sender",
    "High performance packet sender module for DDoSamurai",
    -1,
    FastSenderMethods,
    NULL,
    NULL,
    NULL,
    fast_sender_free
};

PyMODINIT_FUNC PyInit_fast_sender(void) {
    uint32_t cfg_table = env_uint("SAMURAI_STATE_TABLE_SIZE", DEFAULT_STATE_TABLE_SIZE);
    uint32_t cfg_locks = env_uint("SAMURAI_STATE_LOCK_COUNT", DEFAULT_NUM_LOCKS);
    uint32_t cfg_timeout = env_uint("SAMURAI_STATE_TIMEOUT_SEC", DEFAULT_STATE_TIMEOUT_SEC);

    if (cfg_table == 0 || cfg_locks == 0 || cfg_timeout == 0 || (cfg_table % cfg_locks) != 0) {
        cfg_table = DEFAULT_STATE_TABLE_SIZE;
        cfg_locks = DEFAULT_NUM_LOCKS;
        cfg_timeout = DEFAULT_STATE_TIMEOUT_SEC;
    }
    if (init_state_engine(cfg_table, cfg_locks, cfg_timeout) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to initialize state engine");
        return NULL;
    }
    return PyModule_Create(&fastsendermodule);
}
