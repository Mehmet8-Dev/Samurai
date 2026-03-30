#ifndef SAMURAI_XDP_CORE_H
#define SAMURAI_XDP_CORE_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdint.h>

typedef struct {
    const char *interface;
    int queue_id;
    int mode;
    const char *mode2_policy; /* "soft" | "hard" */
    int need_wakeup;
    int batch_size;
} xdp_core_open_cfg;

typedef struct {
    int code;
    char message[160];
} xdp_core_err;

typedef struct {
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t tx_errors;
    uint64_t tx_wakeups;
} xdp_core_stats_snapshot;

typedef struct {
    char status[16];  /* supported | unsupported | unknown */
    char reason[96];
} xdp_probe_result;

typedef struct xdp_core_handle xdp_core_handle;

xdp_core_handle *xdp_core_open(const xdp_core_open_cfg *cfg, xdp_core_err *err);
int xdp_core_send_buffer(
    xdp_core_handle *h,
    const uint8_t *buf,
    int pkt_size,
    int count,
    xdp_core_err *err
);
int xdp_core_send_vector(
    xdp_core_handle *h,
    const uint8_t **pkts,
    const uint16_t *lens,
    int count,
    xdp_core_err *err
);
int xdp_core_close(xdp_core_handle *h, xdp_core_err *err);
int xdp_core_stats(xdp_core_handle *h, xdp_core_stats_snapshot *out, xdp_core_err *err);
int xdp_core_probe_mode2(const char *iface, xdp_probe_result *out, xdp_core_err *err);

int xdp_core_mode_requested(const xdp_core_handle *h);
int xdp_core_mode_effective(const xdp_core_handle *h);
const char *xdp_core_mode2_policy(const xdp_core_handle *h);
const char *xdp_core_mode2_probe_status(const xdp_core_handle *h);
const char *xdp_core_mode2_probe_reason(const xdp_core_handle *h);

#endif /* SAMURAI_XDP_CORE_H */
