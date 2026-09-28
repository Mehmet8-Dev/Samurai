/**
 * XDP Kernel Program for Samurai
 * ==================================
 * 
 * This eBPF/XDP program is loaded into the kernel to redirect
 * packets to AF_XDP sockets for high-performance processing.
 * 
 * Compilation:
 *   clang -O2 -target bpf -c xdp_prog.c -o xdp_prog.o
 * 
 * Loading:
 *   ip link set dev <iface> xdp obj xdp_prog.o sec xdp_sock
 * 
 * Unloading:
 *   ip link set dev <iface> xdp off
 * 
 * Note: This program is for Copy Mode operation.
 * For Native/Zero-Copy mode, the NIC driver must support XDP.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ============================================================================
// BPF Maps
// ============================================================================

/**
 * XSK Map - Maps queue IDs to AF_XDP sockets
 * This map is used to redirect packets to the appropriate XDP socket.
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);  // Up to 64 queues
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

/**
 * Statistics Map - Track packet counts and bytes
 */
struct xdp_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} xdp_stats_map SEC(".maps");

/**
 * Configuration Map - Runtime configuration
 */
struct xdp_config {
    __u32 redirect_all;     // 1 = redirect all packets, 0 = filter
    __u32 target_port;      // Target port for filtering (0 = all)
    __u32 target_proto;     // Target protocol (0 = all, 6 = TCP, 17 = UDP)
    __u32 reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_config);
} xdp_config_map SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Update statistics
 */
static __always_inline void update_stats(__u64 bytes)
{
    __u32 key = 0;
    struct xdp_stats *stats = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if (stats) {
        stats->rx_packets++;
        stats->rx_bytes += bytes;
    }
}

// ============================================================================
// XDP Programs
// ============================================================================

/**
 * Main XDP Socket Program
 * 
 * This program redirects incoming packets to the AF_XDP socket
 * bound to the current queue. Used for RX path in bidirectional
 * communication scenarios.
 */
SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Get packet length
    __u64 pkt_len = data_end - data;
    
    // Update stats
    update_stats(pkt_len);
    
    // Redirect packet to the socket bound to the current queue
    // If no socket is bound, XDP_PASS lets the packet through to the kernel
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

/**
 * Filtered XDP Program
 * 
 * Only redirects packets matching configured criteria.
 * This can be used to filter only specific traffic for XDP processing.
 */
SEC("xdp_sock_filter")
int xdp_sock_filter_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Get configuration
    __u32 key = 0;
    struct xdp_config *config = bpf_map_lookup_elem(&xdp_config_map, &key);
    
    // If redirect_all is set, skip filtering
    if (config && config->redirect_all) {
        update_stats(data_end - data);
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
    }
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    if (iph->ihl < 5)
        return XDP_PASS;
    if ((void *)iph + (iph->ihl * 4) > data_end)
        return XDP_PASS;
    
    // Check protocol filter
    if (config && config->target_proto != 0 && iph->protocol != config->target_proto)
        return XDP_PASS;
    
    // Check port filter (if configured)
    if (config && config->target_port != 0) {
        __u16 dst_port = 0;
        
        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (void *)iph + (iph->ihl * 4);
            if ((void *)(udph + 1) > data_end)
                return XDP_PASS;
            dst_port = bpf_ntohs(udph->dest);
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
            if ((void *)(tcph + 1) > data_end)
                return XDP_PASS;
            dst_port = bpf_ntohs(tcph->dest);
        }
        
        if (dst_port != config->target_port)
            return XDP_PASS;
    }
    
    // Packet matches criteria - redirect to XDP socket
    update_stats(data_end - data);
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

/**
 * Pass-through XDP Program
 * 
 * Simply passes all packets to the kernel. Used when we only
 * need AF_XDP for TX (transmit) without RX filtering.
 */
SEC("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx)
{
    return XDP_PASS;
}

/**
 * Drop All XDP Program
 * 
 * Drops all incoming packets. Useful for testing or when
 * the interface is used purely for TX.
 */
SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md *ctx)
{
    return XDP_DROP;
}

// ============================================================================
// License
// ============================================================================

char _license[] SEC("license") = "GPL";
