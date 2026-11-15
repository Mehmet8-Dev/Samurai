#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SAMURAI_PACING_PCT_SLOTS 1024

enum samurai_pacing_mode_t {
  SAMURAI_PACING_NONE = 0,
  SAMURAI_PACING_RPS = 1,
  SAMURAI_PACING_IPG = 2,
  SAMURAI_PACING_BURST = 3,
};

enum samurai_jitter_model_t {
  SAMURAI_JITTER_NONE = 0,
  SAMURAI_JITTER_UNIFORM = 1,
  SAMURAI_JITTER_GAUSSIAN = 2,
  SAMURAI_JITTER_EXPONENTIAL = 3,
};

typedef struct samurai_pacing_config_t {
  uint8_t mode;
  double target_rps;
  uint64_t ipg_ns;
  uint32_t burst_size;
  uint64_t burst_gap_ns;
  uint8_t jitter_model;         /* enum samurai_jitter_model_t */
  double jitter_pct;            /* [0.0, 1.0] fraction of base gap as max jitter */
  uint8_t use_so_txtime;        /* kernel ETF / SO_TXTIME offload intent flag */
  uint8_t disable_busywait;     /* 0 = hybrid sleep+spin (default), 1 = sleep only */
  uint32_t token_bucket_burst;  /* optional token bucket burst override (0 = auto) */
} samurai_pacing_config_t;

typedef struct samurai_pacing_token_bucket_t {
  double tokens;
  double max_tokens;
  double refill_rate_per_ns;
  uint64_t last_refill_ns;
} samurai_pacing_token_bucket_t;

typedef struct samurai_pacing_state_t {
  uint64_t next_deadline_ns;
  uint64_t sent;
  uint32_t burst_cursor;
  uint64_t sleep_calls;
  uint64_t busywait_cycles;
  uint64_t last_send_ns;
  uint64_t ipg_min_ns;
  uint64_t ipg_max_ns;
  double ipg_sum_ns;
  uint64_t ipg_count;
  double jitter_sum_ns;
  uint64_t jitter_count;
  uint64_t rng_state[2];
  uint8_t rng_seeded;
  uint8_t tb_initialized;
  samurai_pacing_token_bucket_t tb;
  uint64_t pct_ring[SAMURAI_PACING_PCT_SLOTS];
  uint32_t pct_ring_idx;
  uint32_t pct_ring_len;
} samurai_pacing_state_t;

/** Run one-time timing & TSC calibration (safe under concurrent callers). */
void samurai_pacing_calibrate(void);

/** Fast monotonic timestamp in nanoseconds (TSC-anchored when available). */
uint64_t samurai_pacing_monotonic_now_ns(void);

/** Precision hybrid wait (clock_nanosleep + pause/yield spin) until absolute monotonic target_ns. */
void samurai_pacing_precision_wait_for_state_ns(samurai_pacing_state_t* state,
                                                uint64_t target_ns,
                                                uint8_t disable_busywait);

/** Initialize per-thread pacing state, PRNG, token bucket, and IPG telemetry. */
void samurai_pacing_init(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg);

/** Glitchlessly reconfigure rate/pacing parameters on a running warm state (window transition). */
void samurai_pacing_reconfigure(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg);

/** Wait until the next packet deadline and record IPG/jitter telemetry. */
void samurai_pacing_wait_next(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg);

/** Adaptive rate scaling under high kernel/NIC drop rate (>5%). */
void samurai_pacing_adjust_rate(samurai_pacing_state_t* state, samurai_pacing_config_t* cfg, double drop_rate_pct);

/** Non-blocking per-state token bucket consume check. */
int samurai_pacing_tb_try_consume(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg, uint64_t now_ns);

/** Compute 99th-percentile pacing jitter (|actual_ipg - intended_ipg|) in nanoseconds. */
double samurai_pacing_get_jitter_p99_ns(const samurai_pacing_state_t* state);

/** Compute mean IPG in nanoseconds recorded by this state. */
double samurai_pacing_get_mean_ipg_ns(const samurai_pacing_state_t* state);

/** Inspection helpers for calibration diagnostics. */
uint64_t samurai_pacing_tsc_hz(void);
uint64_t samurai_pacing_spin_threshold_ns(void);

/**
 * Public C ABI hooks weak-linked by libgpu_packet_cuda.so (host_api.cuh)
 * and any other dlopen'd native backends.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("default")))
#endif
uint64_t samurai_pacing_time_ns(void);

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("default")))
#endif
void samurai_pacing_precision_wait_ns(uint64_t target_ns);

#ifdef __cplusplus
}
#endif
