#ifndef DDOS_SAMURAI_AF_PACKET_H
#define DDOS_SAMURAI_AF_PACKET_H

/*
 * af_packet — kernel-socket TX/RX engine for Samurai.
 *
 * This is the native, Python-free successor of the old `fast_sender` CPython
 * extension. It provides packet transmission and stateful handshake completion
 * over plain kernel sockets, for NIC environments where AF_XDP or DPDK are not
 * available. Two transmit paths are exposed:
 *
 *   - L3 raw-socket `sendmmsg` (default): portable, works on any NIC, sends the
 *     L3 (IPv4) packet pool produced by cpu_native. Optional SO_TXTIME kernel
 *     pacing.
 *   - L2 AF_PACKET TX_RING (zero-copy): requires full L2 frames + destination
 *     MAC + interface; higher throughput with hugepage-backed rings.
 *
 * The stateful side runs an RX_RING handler that captures inbound SYN-ACKs and
 * auto-completes the TCP 3-way handshake, tracking flow state in a lock-striped
 * hash table. This lets the kernel-socket path drive stateful L4 tests.
 *
 * All entry points are plain C (no CPython dependency).
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* TCP state engine                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t table_size;
    uint32_t lock_count;
    uint32_t timeout_sec;
    unsigned long long active_entries;
    unsigned long long timeout_evictions;
    unsigned long long overwrites;
    unsigned long long sweeps;
    unsigned long long last_sweep_removed;
    uint32_t sweep_cursor;
} afpkt_state_stats_t;

/* Configure (or reconfigure) the state table. table_size % lock_count must be
 * 0 and all args must be > 0. Returns 0 on success, -1 on invalid args/alloc. */
int afpkt_configure_state_engine(uint32_t table_size, uint32_t lock_count, uint32_t timeout_sec);
void afpkt_destroy_state_engine(void);

/* Fill *out with the current counters. Safe to call even if unconfigured. */
void afpkt_get_state_engine_stats(afpkt_state_stats_t* out);

/* Evict up to max_scan (0 = whole table) stale entries; returns removed count. */
int afpkt_sweep_state_table(uint32_t max_scan);

/* Parse the transmitted L2/L3 packet buffer and seed/advance TCP state for each
 * TCP packet found. Returns the number of state entries updated. */
int afpkt_ingest_tx_packets(const uint8_t* buffer, size_t buffer_len, int packet_size, int count);

/* Global TCP mimicry knobs applied to synthesized ACKs / seeded state. */
void afpkt_set_mimicry_settings(uint16_t window, uint16_t mss, uint8_t ttl);

/* ------------------------------------------------------------------ */
/* Stateful RX handler                                                 */
/* ------------------------------------------------------------------ */

/* Start the background RX_RING thread on `iface`. It captures SYN-ACKs and
 * replies with a synthesized ACK, completing the handshake. Idempotent; a
 * second call while running is a no-op. Returns 0 on success, -1 on failure. */
int afpkt_start_rx_handler(const char* iface);

/* Generic RX pump: same RX_RING capture path, but every inbound L2 frame is
 * delivered verbatim to `cb` instead of the built-in L4 handshake logic. This
 * is the L7 integration point — an L7 engine (l7_emu_native custom_tcp) feeds
 * these frames into ingest_custom_tcp_rx_frame_raw and drives replies via the
 * TX path. `cb` runs on the RX thread and must not block. Returns 0 / -1. */
typedef void (*afpkt_rx_frame_cb)(void* user, const uint8_t* frame, uint32_t len);
int afpkt_start_rx_pump(const char* iface, afpkt_rx_frame_cb cb, void* user);

/* Signal the RX handler/pump to stop and join. Safe if not running. */
void afpkt_stop_rx_handler(void);

/* ------------------------------------------------------------------ */
/* Per-shard AF_PACKET wire (shared-nothing custom_tcp)                */
/* ------------------------------------------------------------------ */

/* A per-shard AF_PACKET wire. Each shard opens its OWN socket bound to `iface`
 * and drives RX/TX inline on its own thread — no shared RX pump thread, no
 * shared TX ring, no cross-shard state. RX is filtered by a classic BPF program
 * to inbound IPv4/TCP frames whose TCP destination port (i.e. OUR ephemeral
 * source port) lies in [src_port_lo, src_port_hi]. When shards use disjoint
 * port ranges each inbound frame is accepted by exactly one shard's socket, so
 * every flow's return traffic lands on the shard that opened it — deterministic
 * demux without RSS/fanout hashing. Requires CAP_NET_RAW. */
typedef struct afpkt_wire afpkt_wire_t;

/* Open a wire on `iface`, filtered to TCP dst-port range [lo, hi] (inclusive).
 * The socket is non-blocking and ignores outgoing frames. The interface source
 * MAC is resolved and used to complete TX frames. Returns 0 and sets *out_wire
 * on success; -1 on failure (*out_wire left NULL). */
int afpkt_wire_open(const char* iface, uint16_t src_port_lo, uint16_t src_port_hi,
                    afpkt_wire_t** out_wire);

/* Non-blocking drain of up to `max` inbound frames into `out_frames` (a
 * max*stride byte buffer), writing each frame's length to out_lens[i]. Returns
 * the number of frames read (>=0, 0 when idle) or -1 on a fatal error. */
int afpkt_wire_recv(afpkt_wire_t* wire, uint8_t* out_frames, uint16_t stride,
                    uint16_t* out_lens, uint16_t max);

/* Transmit `count` L2 frames laid out at `base` with `stride` bytes between
 * frames (each `packet_size` bytes). The (dst,src) Ethernet MACs are completed
 * from `dst_mac` and the wire's resolved source MAC. Returns the number of
 * frames sent (>=0) or -1 on a fatal error. */
int afpkt_wire_send(afpkt_wire_t* wire, const uint8_t* base, size_t packet_size,
                    size_t stride, uint32_t count, const uint8_t dst_mac[6]);

/* Close the wire and free all resources. Safe on NULL. */
void afpkt_wire_close(afpkt_wire_t* wire);

/* ------------------------------------------------------------------ */
/* Transmit                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    int attempted;
    int sent;
    int errors;
    int eagain_retry_count;
    int partial_send_retry_count;
    int packet_version;                 /* TX_RING path only */
    unsigned long long txring_tp_packets;
    unsigned long long txring_tp_drops;
} afpkt_tx_metrics_t;

/* L3 transmit over a raw AF_INET/SOCK_RAW/IPPROTO_RAW socket created internally.
 * `buffer` holds `count` back-to-back IPv4 packets of `packet_size` bytes each.
 * ipg_ns > 0 selects the SO_TXTIME kernel-paced path; otherwise batched
 * sendmmsg is used. Returns 0 on success, -1 on setup failure (metrics/err
 * populated). Requires CAP_NET_RAW. */
int afpkt_send_l3(const char* target_ip, int target_port,
                  const uint8_t* buffer, size_t buffer_len,
                  int packet_size, int count, long long ipg_ns,
                  afpkt_tx_metrics_t* metrics,
                  char* err_msg, size_t err_msg_len);

/* L2 transmit over an AF_PACKET TX_RING bound to `iface`. `buffer` holds `count`
 * full Ethernet frames of `packet_size` bytes each; `mac` is the source MAC.
 * Returns 0 on success, -1 on setup failure. Requires CAP_NET_RAW. */
int afpkt_send_ring(const char* iface,
                    const uint8_t* buffer, size_t buffer_len,
                    int packet_size, int count, const uint8_t mac[6],
                    afpkt_tx_metrics_t* metrics,
                    char* err_msg, size_t err_msg_len);

/* Tear down the persistent TX_RING mapping/socket. */
void afpkt_cleanup_ring(void);

/* Stable C-ABI bridge for the CUDA GPU worker, which links these as weak
 * symbols and falls back to AF_PACKET TX_RING transmission when present. Thin
 * wrappers over afpkt_send_ring / afpkt_cleanup_ring with an int-out signature
 * (kept separate so the GPU struct-of-fn-pointers ABI stays stable). */
int afpkt_send_ring_bridge(const char* iface, const uint8_t* buffer, size_t buffer_len,
                           int packet_size, int count, const uint8_t mac[6],
                           int* out_sent, int* out_errors,
                           char* err_msg, size_t err_msg_len);
int afpkt_cleanup_ring_bridge(void);

#ifdef __cplusplus
}
#endif

#endif /* DDOS_SAMURAI_AF_PACKET_H */
