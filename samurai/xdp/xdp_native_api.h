#ifndef SAMURAI_XDP_NATIVE_API_H
#define SAMURAI_XDP_NATIVE_API_H

#include <stddef.h>
#include <stdint.h>

#define XDP_NATIVE_API_VERSION 2
#define XDP_NATIVE_API_CAPSULE_NAME "samurai.xdp_sender.native_api.v1"

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
    int (*send_buffer_strided)(
        int handle,
        const uint8_t *buffer,
        int packet_size,
        int stride,
        int count,
        char *err,
        size_t err_len
    );
    int (*send_vector)(int handle, const uint8_t **packets, const uint16_t *lengths, int count, char *err, size_t err_len);
    int (*get_stats)(int handle, xdp_native_stats *out, char *err, size_t err_len);
    int (*create_ctx_external_umem)(
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
    );
    int (*submit_frame_ids)(
        int handle,
        const uint32_t *frame_ids,
        const uint16_t *lengths,
        int count,
        char *err,
        size_t err_len
    );
    int (*reap_completions)(
        int handle,
        uint32_t *frame_ids_out,
        int max_count,
        char *err,
        size_t err_len
    );
    int (*recv_frames)(
        int handle,
        uint8_t *buffer,
        int frame_stride,
        uint16_t *lengths_out,
        int max_count,
        int snaplen,
        char *err,
        size_t err_len
    );
} xdp_native_api_v1;

#endif /* SAMURAI_XDP_NATIVE_API_H */
