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
    
    // Timing
    struct timespec start_time;
    
    // Configuration
    int xdp_mode;  // 0 = SKB/Generic, 1 = Native (DRV)
    int xsks_map_fd;
    int xsks_map_key;
    int xsks_map_registered;
} xdp_context_t;

static xdp_context_t xdp_ctx = {
    .is_initialized = 0,
    .is_running = 0,
    .xsks_map_fd = -1,
    .xsks_map_key = 0,
    .xsks_map_registered = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER
};

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

static struct xsk_umem_info *create_umem(void)
{
    struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
    if (!umem) return NULL;
    
    // Allocate aligned buffer
    umem->size = XDP_NUM_FRAMES * XDP_FRAME_SIZE;
    if (posix_memalign(&umem->buffer, getpagesize(), umem->size)) {
        free(umem);
        return NULL;
    }
    memset(umem->buffer, 0, umem->size);
    
    // Create UMEM socket
    umem->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (umem->fd < 0) {
        free(umem->buffer);
        free(umem);
        return NULL;
    }
    
    // Register UMEM
    struct xdp_umem_reg mr = {
        .addr = (uint64_t)umem->buffer,
        .len = umem->size,
        .chunk_size = XDP_FRAME_SIZE,
        .headroom = XDP_HEADROOM,
        .flags = 0
    };
    
    if (setsockopt(umem->fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) < 0) {
        close(umem->fd);
        free(umem->buffer);
        free(umem);
        return NULL;
    }
    
    // Setup Fill Ring
    int fill_size = XDP_FILL_RING_SIZE;
    if (setsockopt(umem->fd, SOL_XDP, XDP_UMEM_FILL_RING, &fill_size, sizeof(fill_size)) < 0) {
        close(umem->fd);
        free(umem->buffer);
        free(umem);
        return NULL;
    }
    
    // Setup Completion Ring
    int comp_size = XDP_COMP_RING_SIZE;
    if (setsockopt(umem->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &comp_size, sizeof(comp_size)) < 0) {
        close(umem->fd);
        free(umem->buffer);
        free(umem);
        return NULL;
    }
    
    // Get ring offsets
    struct xdp_mmap_offsets offsets;
    socklen_t optlen = sizeof(offsets);
    if (getsockopt(umem->fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &optlen) < 0) {
        close(umem->fd);
        free(umem->buffer);
        free(umem);
        return NULL;
    }
    
    // Map Fill Ring
    void *fill_map = mmap(NULL,
                          offsets.fr.desc + XDP_FILL_RING_SIZE * sizeof(uint64_t),
                          PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                          umem->fd, XDP_UMEM_PGOFF_FILL_RING);
    if (fill_map == MAP_FAILED) {
        close(umem->fd);
        free(umem->buffer);
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
    
    // Map Completion Ring
    void *comp_map = mmap(NULL,
                          offsets.cr.desc + XDP_COMP_RING_SIZE * sizeof(uint64_t),
                          PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                          umem->fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    if (comp_map == MAP_FAILED) {
        munmap(fill_map, offsets.fr.desc + XDP_FILL_RING_SIZE * sizeof(uint64_t));
        close(umem->fd);
        free(umem->buffer);
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
    if (umem->buffer) free(umem->buffer);
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
        // munmap...
        close(xsk->fd);
        free(xsk);
        return NULL;
    }
    
    // Initialize frame allocation tracking
    xsk->free_count = XDP_NUM_FRAMES;
    for (uint32_t i = 0; i < XDP_NUM_FRAMES; i++) {
        xsk->free_frames[i] = i;
    }
    xsk->outstanding_tx = 0;
    
    // Pre-populate the fill ring
    uint32_t fill_idx;
    if (xsk_ring_prod__reserve(&umem->fill, XDP_NUM_FRAMES, &fill_idx) == XDP_NUM_FRAMES) {
        for (uint32_t i = 0; i < XDP_NUM_FRAMES; i++) {
            uint64_t *addr = xsk_ring_prod__fill_addr(&umem->fill, fill_idx + i);
            *addr = i * XDP_FRAME_SIZE;
        }
        xsk_ring_prod__submit(&umem->fill, XDP_NUM_FRAMES);
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
    if (xsk->fd >= 0) close(xsk->fd);
    free(xsk);
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
    return (uint64_t)idx * XDP_FRAME_SIZE;
}

static void free_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    uint64_t base = frame;
    if (base >= XDP_HEADROOM) {
        base -= XDP_HEADROOM;
    }
    uint32_t idx = (uint32_t)(base / XDP_FRAME_SIZE);
    if (idx >= XDP_NUM_FRAMES) {
        return;
    }
    if (xsk->free_count < XDP_NUM_FRAMES) {
        xsk->free_frames[xsk->free_count++] = idx;
    }
}

static void complete_tx(struct xsk_socket_info *xsk)
{
    if (!xsk->outstanding_tx) return;
    
    uint32_t idx;
    uint32_t completed = xsk_ring_cons__peek(&xsk->umem->comp, 
                                              xsk->outstanding_tx, &idx);
    
    if (completed > 0) {
        for (uint32_t i = 0; i < completed; i++) {
            uint64_t *addr = xsk_ring_cons__comp_addr(&xsk->umem->comp, idx + i);
            free_frame(xsk, *addr);
        }
        xsk_ring_cons__release(&xsk->umem->comp, completed);
        xsk->outstanding_tx -= completed;
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
        kick_tx(xsk);
        return 0;
    }
    
    // Fill TX descriptors and copy packet data to UMEM
    int submitted = 0;
    for (uint32_t i = 0; i < reserved && submitted < count; i++) {
        uint64_t frame_addr = alloc_frame(xsk);
        if (frame_addr == UINT64_MAX) {
            break;  // No more frames
        }
        
        uint16_t pkt_len = lengths[submitted];
        if (pkt_len > MAX_PACKET_SIZE) {
            pkt_len = MAX_PACKET_SIZE;
        }
        
        // Get pointer to UMEM frame buffer
        void *pkt_buffer = xsk->umem->buffer + frame_addr + XDP_HEADROOM;
        
        // Copy packet data to UMEM (this is the "copy" in Copy Mode)
        memcpy(pkt_buffer, packets[submitted], pkt_len);
        
        // Fill TX descriptor
        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx + i);
        tx_desc->addr = frame_addr + XDP_HEADROOM;
        tx_desc->len = pkt_len;
        tx_desc->options = 0;
        
        submitted++;
        xdp_ctx.tx_bytes += pkt_len;
    }
    
    if (submitted < (int)reserved) {
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

    g_send_scratch.packets = new_packets;
    g_send_scratch.lengths = new_lengths;
    g_send_scratch.capacity = new_cap;
    return 0;
}

static void clear_send_scratch(void)
{
    free((void*)g_send_scratch.packets);
    free((void*)g_send_scratch.lengths);
    g_send_scratch.packets = NULL;
    g_send_scratch.lengths = NULL;
    g_send_scratch.capacity = 0;
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
    for (Py_ssize_t i = 0; i < count; i++) {
        PyObject *item = PyList_GetItem(packets_list, i);
        if (PyBytes_Check(item)) {
            packets[valid_count] = (const uint8_t*)PyBytes_AS_STRING(item);
            lengths[valid_count] = (uint16_t)PyBytes_GET_SIZE(item);
            valid_count++;
        }
    }

    int total_sent = xdp_send_vector_locked(packets, lengths, valid_count);
    
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

    int total_sent = xdp_send_vector_locked(g_send_scratch.packets, g_send_scratch.lengths, (Py_ssize_t)count);
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

    uint32_t frame_id = (uint32_t)(frame_addr / XDP_FRAME_SIZE);
    char *frame_ptr = (char*)xdp_ctx.xsk->umem->buffer + frame_addr + XDP_HEADROOM;
    PyObject *view = PyMemoryView_FromMemory(frame_ptr, MAX_PACKET_SIZE, PyBUF_WRITE);
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
    (void)self;

    if (!PyArg_ParseTuple(args, "ii", &frame_id, &length)) {
        return NULL;
    }
    if (frame_id < 0 || frame_id >= XDP_NUM_FRAMES) {
        PyErr_SetString(PyExc_ValueError, "frame_id out of range");
        return NULL;
    }
    if (length <= 0 || length > MAX_PACKET_SIZE) {
        PyErr_SetString(PyExc_ValueError, "length must be in range 1..MAX_PACKET_SIZE");
        return NULL;
    }

    pthread_mutex_lock(&xdp_ctx.lock);
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }

    complete_tx(xdp_ctx.xsk);
    uint32_t tx_idx;
    if (xsk_ring_prod__reserve(&xdp_ctx.xsk->tx, 1, &tx_idx) == 0) {
        kick_tx(xdp_ctx.xsk);
        pthread_mutex_unlock(&xdp_ctx.lock);
        Py_RETURN_FALSE;
    }

    uint64_t frame_addr = (uint64_t)frame_id * XDP_FRAME_SIZE;
    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xdp_ctx.xsk->tx, tx_idx);
    tx_desc->addr = frame_addr + XDP_HEADROOM;
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
    if (frame_id < 0 || frame_id >= XDP_NUM_FRAMES) {
        PyErr_SetString(PyExc_ValueError, "frame_id out of range");
        return NULL;
    }

    pthread_mutex_lock(&xdp_ctx.lock);
    if (!xdp_ctx.is_initialized || !xdp_ctx.is_running) {
        pthread_mutex_unlock(&xdp_ctx.lock);
        PyErr_SetString(PyExc_RuntimeError, "XDP not initialized");
        return NULL;
    }
    free_frame(xdp_ctx.xsk, (uint64_t)frame_id * XDP_FRAME_SIZE);
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
            kick_tx(xdp_ctx.xsk);
            continue;
        }

        uint64_t frame_addr = alloc_frame(xdp_ctx.xsk);
        if (frame_addr == UINT64_MAX) {
            xdp_ctx.tx_errors++;
            xsk_ring_prod__cancel(&xdp_ctx.xsk->tx, 1);
            continue;
        }

        uint8_t *pkt_buffer = (uint8_t*)xdp_ctx.xsk->umem->buffer + frame_addr + XDP_HEADROOM;
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
        tx_desc->addr = frame_addr + XDP_HEADROOM;
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
    int xdp_mode = xdp_ctx.xdp_mode;
    
    pthread_mutex_unlock(&xdp_ctx.lock);
    
    return Py_BuildValue("{s:K,s:K,s:K,s:K,s:d,s:d,s:d,s:i,s:s}",
                         "tx_packets", tx_packets,
                         "tx_bytes", tx_bytes,
                         "tx_errors", tx_errors,
                         "tx_wakeups", tx_wakeups,
                         "elapsed_seconds", elapsed,
                         "packets_per_second", pps,
                         "mbps", mbps,
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

// ============================================================================
// Module Definition
// ============================================================================

static PyMethodDef XdpSenderMethods[] = {
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
