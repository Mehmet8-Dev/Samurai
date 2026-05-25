#include "pacing_engine.h"

#include <errno.h>
#include <time.h>

static uint64_t sleep_to_ns(uint64_t now_ns, uint64_t target_ns, uint64_t* sleep_calls) {
  if (target_ns <= now_ns) {
    return now_ns;
  }
  uint64_t remain = target_ns - now_ns;
  struct timespec ts;
  ts.tv_sec = (time_t)(remain / 1000000000ull);
  ts.tv_nsec = (long)(remain % 1000000000ull);
  while (clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, &ts) == EINTR) {
  }
  if (sleep_calls) {
    *sleep_calls += 1ull;
  }
  return samurai_pacing_monotonic_now_ns();
}

uint64_t samurai_pacing_monotonic_now_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0ull;
  }
  return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

void samurai_pacing_init(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg) {
  (void)cfg;
  if (!state) {
    return;
  }
  state->next_deadline_ns = samurai_pacing_monotonic_now_ns();
  state->sent = 0ull;
  state->burst_cursor = 0u;
  state->sleep_calls = 0ull;
}

void samurai_pacing_wait_next(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg) {
  if (!state || !cfg) {
    return;
  }
  const uint8_t mode = cfg->mode;
  uint64_t now_ns = samurai_pacing_monotonic_now_ns();

  if (mode == SAMURAI_PACING_NONE) {
    state->sent += 1ull;
    return;
  }

  if (mode == SAMURAI_PACING_RPS && cfg->target_rps > 0.0) {
    const uint64_t gap = (uint64_t)(1000000000.0 / cfg->target_rps);
    if (state->next_deadline_ns == 0ull || state->next_deadline_ns < now_ns) {
      state->next_deadline_ns = now_ns;
    }
    state->next_deadline_ns += gap;
    (void)sleep_to_ns(now_ns, state->next_deadline_ns, &state->sleep_calls);
    state->sent += 1ull;
    return;
  }

  if (mode == SAMURAI_PACING_IPG && cfg->ipg_ns > 0ull) {
    if (state->next_deadline_ns == 0ull || state->next_deadline_ns < now_ns) {
      state->next_deadline_ns = now_ns;
    }
    state->next_deadline_ns += cfg->ipg_ns;
    (void)sleep_to_ns(now_ns, state->next_deadline_ns, &state->sleep_calls);
    state->sent += 1ull;
    return;
  }

  if (mode == SAMURAI_PACING_BURST && cfg->burst_size > 0u) {
    state->burst_cursor += 1u;
    if (state->burst_cursor >= cfg->burst_size) {
      state->burst_cursor = 0u;
      if (cfg->burst_gap_ns > 0ull) {
        (void)sleep_to_ns(now_ns, now_ns + cfg->burst_gap_ns, &state->sleep_calls);
      }
    }
    state->sent += 1ull;
    return;
  }

  state->sent += 1ull;
}

