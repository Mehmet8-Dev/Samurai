#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum samurai_pacing_mode_t {
  SAMURAI_PACING_NONE = 0,
  SAMURAI_PACING_RPS = 1,
  SAMURAI_PACING_IPG = 2,
  SAMURAI_PACING_BURST = 3,
};

typedef struct samurai_pacing_config_t {
  uint8_t mode;
  double target_rps;
  uint64_t ipg_ns;
  uint32_t burst_size;
  uint64_t burst_gap_ns;
} samurai_pacing_config_t;

typedef struct samurai_pacing_state_t {
  uint64_t next_deadline_ns;
  uint64_t sent;
  uint32_t burst_cursor;
  uint64_t sleep_calls;
} samurai_pacing_state_t;

uint64_t samurai_pacing_monotonic_now_ns(void);
void samurai_pacing_init(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg);
void samurai_pacing_wait_next(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg);

#ifdef __cplusplus
}
#endif
