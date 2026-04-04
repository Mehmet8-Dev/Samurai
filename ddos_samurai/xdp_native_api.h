#ifndef SAMURAI_XDP_NATIVE_API_H
#define SAMURAI_XDP_NATIVE_API_H

#include <stddef.h>
#include <stdint.h>

#define XDP_NATIVE_API_VERSION 1
#define XDP_NATIVE_API_CAPSULE_NAME "ddos_samurai.xdp_sender.native_api.v1"

typedef struct {
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
    uint64_t tx_wakeups;
    int mode;
    int queue_id;
} xdp_native_stats;

typedef struct xdp_native_api_v1 {
    int version;
    int (*create_ctx)(const char *ifname, int queue_id, int mode, char *err, size_t err_len);
    int (*destroy_ctx)(int handle, char *err, size_t err_len);
    int (*send_buffer)(int handle, const uint8_t *buffer, int packet_size, int count, char *err, size_t err_len);
    int (*send_vector)(int handle, const uint8_t **packets, const uint16_t *lengths, int count, char *err, size_t err_len);
    int (*get_stats)(int handle, xdp_native_stats *out, char *err, size_t err_len);
} xdp_native_api_v1;

#endif /* SAMURAI_XDP_NATIVE_API_H */
