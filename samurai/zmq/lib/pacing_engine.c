#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "pacing_engine.h"
#include "samurai_tsc.h"

#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define SAMURAI_PACING_CALIBRATION_ITERS 512

static pthread_once_t g_calib_once = PTHREAD_ONCE_INIT;
static uint64_t g_spin_threshold_ns = 15000ull;
static uint64_t g_calib_syscall_overhead_ns = 0ull;
static uint64_t g_calib_sleep_overhead_ns = 0ull;
static int g_tsc_supported = 0;
static int g_tsc_enabled = 0;
static uint64_t g_tsc_hz = 0ull;

static __thread uint64_t t_tsc_anchor_ns = 0ull;
static __thread uint64_t t_tsc_anchor_cycles = 0ull;
static __thread uint64_t t_last_fast_ns = 0ull;

static inline uint64_t wall_monotonic_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0ull;
  }
  return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static int parse_env_truthy(const char* value, int default_val) {
  if (!value || !value[0]) {
    return default_val;
  }
  if (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 ||
      strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0) {
    return 1;
  }
  if (strcmp(value, "0") == 0 || strcasecmp(value, "false") == 0 ||
      strcasecmp(value, "no") == 0 || strcasecmp(value, "off") == 0) {
    return 0;
  }
  return default_val;
}

static inline void cpu_relax_pause(void) {
#if defined(__x86_64__) || defined(__i386__)
  __asm__ volatile("pause" ::: "memory");
#elif defined(__aarch64__)
  __asm__ volatile("yield" ::: "memory");
#else
  __asm__ volatile("" ::: "memory");
#endif
}

static inline uint64_t tsc_cycles_to_ns(uint64_t cycles) {
  if (g_tsc_hz == 0ull) {
    return 0ull;
  }
  return (uint64_t)((((__uint128_t)cycles) * 1000000000ull) / g_tsc_hz);
}

static inline uint64_t tsc_ns_to_cycles(uint64_t ns) {
  if (g_tsc_hz == 0ull) {
    return 0ull;
  }
  return (uint64_t)((((__uint128_t)ns) * g_tsc_hz) / 1000000000ull);
}

static inline void tsc_refresh_anchor(void) {
  if (!g_tsc_enabled) {
    return;
  }
  t_tsc_anchor_cycles = samurai_rdtsc();
  t_tsc_anchor_ns = wall_monotonic_ns();
}

static void calibrate_once_impl(void) {
  const int want_tsc = parse_env_truthy(getenv("SAMURAI_PACING_USE_TSC"), 1);
  g_tsc_supported = samurai_tsc_invariant_supported();
  g_tsc_hz = 0ull;
  g_tsc_enabled = 0;

  if (want_tsc && g_tsc_supported) {
#if defined(__aarch64__)
    const uint64_t cntfrq = samurai_arm_cntfrq();
    if (cntfrq >= 1000000ull && cntfrq <= 10000000000ull) {
      g_tsc_hz = cntfrq;
      g_tsc_enabled = 1;
    }
#endif
    if (g_tsc_hz == 0ull) {
      const uint64_t c0 = samurai_rdtsc();
      const uint64_t t0 = wall_monotonic_ns();
      struct timespec req;
      const uint64_t target = t0 + 10000000ull; /* 10 ms calibration window */
      req.tv_sec = (time_t)(target / 1000000000ull);
      req.tv_nsec = (long)(target % 1000000000ull);
      while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL) == EINTR) {
      }
      const uint64_t c1 = samurai_rdtsc();
      const uint64_t t1 = wall_monotonic_ns();
      if (c1 > c0 && t1 > t0) {
        g_tsc_hz = (uint64_t)((((__uint128_t)(c1 - c0)) * 1000000000ull) / (t1 - t0));
      }
      if (g_tsc_hz < 1000000ull || g_tsc_hz > 20000000000ull) {
        g_tsc_hz = 0ull;
      } else {
        g_tsc_enabled = 1;
      }
    }
  }

  /* Measure clock_gettime overhead */
  uint64_t sum = 0ull;
  for (int i = 0; i < SAMURAI_PACING_CALIBRATION_ITERS; ++i) {
    const uint64_t t0 = wall_monotonic_ns();
    const uint64_t t1 = wall_monotonic_ns();
    if (t1 >= t0) {
      sum += (t1 - t0);
    }
  }
  g_calib_syscall_overhead_ns = sum / SAMURAI_PACING_CALIBRATION_ITERS;

  /* Measure clock_nanosleep wakeup overshoot */
  uint64_t sleep_sum = 0ull;
  const int sleep_iters = 20;
  for (int i = 0; i < sleep_iters; ++i) {
    const uint64_t target = wall_monotonic_ns() + 1000ull;
    struct timespec req;
    req.tv_sec = (time_t)(target / 1000000000ull);
    req.tv_nsec = (long)(target % 1000000000ull);
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &req, NULL) == EINTR) {
    }
    const uint64_t actual = wall_monotonic_ns();
    if (actual > target) {
      sleep_sum += (actual - target);
    }
  }
  g_calib_sleep_overhead_ns = sleep_sum / (uint64_t)sleep_iters;

  /* Hybrid spin threshold = max(15 us, 2x wakeup overshoot), capped at 100 us */
  uint64_t thresh = g_calib_sleep_overhead_ns * 2ull;
  if (thresh < 15000ull) {
    thresh = 15000ull;
  }
  if (thresh > 100000ull) {
    thresh = 100000ull;
  }
  g_spin_threshold_ns = thresh;
}

void samurai_pacing_calibrate(void) {
  (void)pthread_once(&g_calib_once, calibrate_once_impl);
}

uint64_t samurai_pacing_tsc_hz(void) {
  samurai_pacing_calibrate();
  return g_tsc_hz;
}

uint64_t samurai_pacing_spin_threshold_ns(void) {
  samurai_pacing_calibrate();
  return g_spin_threshold_ns;
}

uint64_t samurai_pacing_monotonic_now_ns(void) {
  samurai_pacing_calibrate();
  if (!g_tsc_enabled || g_tsc_hz == 0ull) {
    return wall_monotonic_ns();
  }
  uint64_t now_cycles = samurai_rdtsc();
  if (t_tsc_anchor_cycles == 0ull || now_cycles < t_tsc_anchor_cycles) {
    tsc_refresh_anchor();
    now_cycles = samurai_rdtsc();
  }
  const uint64_t max_drift_cycles = g_tsc_hz / 2ull;
  if (max_drift_cycles > 0ull && (now_cycles - t_tsc_anchor_cycles) > max_drift_cycles) {
    tsc_refresh_anchor();
    now_cycles = samurai_rdtsc();
  }
  uint64_t fast_ns = t_tsc_anchor_ns + tsc_cycles_to_ns(now_cycles - t_tsc_anchor_cycles);
  if (fast_ns < t_last_fast_ns) {
    fast_ns = t_last_fast_ns;
  }
  t_last_fast_ns = fast_ns;
  return fast_ns;
}

static inline uint64_t tsc_deadline_from_ns(uint64_t target_ns) {
  const uint64_t now_ns = samurai_pacing_monotonic_now_ns();
  const uint64_t now_cycles = samurai_rdtsc();
  if (target_ns <= now_ns) {
    return now_cycles;
  }
  return now_cycles + tsc_ns_to_cycles(target_ns - now_ns);
}

/* ========================================================================== */
/* Thread-Safe Per-State PRNG (xorshift128+) & Jitter Models                  */
/* ========================================================================== */

static void rng_ensure_seeded(samurai_pacing_state_t* state) {
  if (state->rng_seeded) {
    return;
  }
  const uint64_t seed0 = wall_monotonic_ns() ^ (uint64_t)(uintptr_t)state ^ ((uint64_t)pthread_self() << 13);
  uint64_t s0 = seed0 ? seed0 : 0xDEADBEEFCAFEBABEull;
  uint64_t s1 = s0 * 6364136223846793005ull + 1442695040888963407ull;
  if (s1 == 0ull) {
    s1 = 0xCAFEBABEDEADBEEFull;
  }
  state->rng_state[0] = s0;
  state->rng_state[1] = s1;
  state->rng_seeded = 1u;
}

static inline uint64_t state_xorshift128plus(samurai_pacing_state_t* state) {
  uint64_t a = state->rng_state[0];
  const uint64_t b = state->rng_state[1];
  state->rng_state[0] = b;
  a ^= a << 23;
  state->rng_state[1] = a ^ b ^ (a >> 17) ^ (b >> 26);
  return state->rng_state[1] + b;
}

static inline double rng_uniform(samurai_pacing_state_t* state) {
  return (double)(state_xorshift128plus(state) >> 11) * (1.0 / 9007199254740992.0);
}

static inline double rng_gaussian(samurai_pacing_state_t* state, double mean, double sigma) {
  double u1 = rng_uniform(state);
  const double u2 = rng_uniform(state);
  if (u1 < 1e-100) {
    u1 = 1e-100;
  }
  return mean + sigma * sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
}

static inline double rng_exponential(samurai_pacing_state_t* state, double mean) {
  double u = rng_uniform(state);
  if (u < 1e-100) {
    u = 1e-100;
  }
  return -mean * log(u);
}

static int64_t calc_jitter_ns(samurai_pacing_state_t* state, uint64_t base_ns, uint8_t model, double pct) {
  if (model == SAMURAI_JITTER_NONE || pct <= 0.0 || base_ns == 0ull) {
    return 0;
  }
  if (pct > 1.0) {
    pct = 1.0;
  }
  rng_ensure_seeded(state);
  const double bound = (double)base_ns * pct;
  double j = 0.0;
  switch (model) {
    case SAMURAI_JITTER_UNIFORM:
      j = bound * (2.0 * rng_uniform(state) - 1.0);
      break;
    case SAMURAI_JITTER_GAUSSIAN:
      j = rng_gaussian(state, 0.0, bound / 3.0);
      if (j > bound) j = bound;
      if (j < -bound) j = -bound;
      break;
    case SAMURAI_JITTER_EXPONENTIAL:
      j = rng_exponential(state, bound * 0.5) - (bound * 0.5);
      if (j > bound) j = bound;
      if (j < -bound) j = -bound;
      break;
    default:
      return 0;
  }
  return (int64_t)j;
}

static inline uint64_t add_jitter_saturating_u64(uint64_t base, int64_t jitter) {
  if (jitter >= 0) {
    const uint64_t uj = (uint64_t)jitter;
    if (base > UINT64_MAX - uj) {
      return UINT64_MAX;
    }
    return base + uj;
  }
  const uint64_t neg = (uint64_t)(-(jitter + 1)) + 1ull;
  if (neg >= base) {
    return 0ull;
  }
  return base - neg;
}

/* ========================================================================== */
/* Token Bucket + IPG/Jitter Telemetry                                        */
/* ========================================================================== */

static void tb_configure(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg, uint64_t now_ns) {
  if (!state || !cfg) {
    return;
  }
  double rps = cfg->target_rps;
  if (cfg->mode == SAMURAI_PACING_IPG && cfg->ipg_ns > 0ull) {
    rps = 1e9 / (double)cfg->ipg_ns;
  }
  if (rps <= 0.0) {
    state->tb.tokens = 0.0;
    state->tb.max_tokens = 1.0;
    state->tb.refill_rate_per_ns = 0.0;
    state->tb.last_refill_ns = now_ns;
    state->tb_initialized = 1u;
    return;
  }
  double burst = 1.0;
  if (cfg->token_bucket_burst > 0u) {
    burst = (double)cfg->token_bucket_burst;
  } else if (cfg->burst_size > 1u) {
    burst = (double)cfg->burst_size;
  }
  state->tb.tokens = burst;
  state->tb.max_tokens = burst;
  state->tb.refill_rate_per_ns = rps / 1e9;
  state->tb.last_refill_ns = now_ns;
  state->tb_initialized = 1u;
}

int samurai_pacing_tb_try_consume(samurai_pacing_state_t* state,
                                  const samurai_pacing_config_t* cfg,
                                  uint64_t now_ns) {
  if (!state || !cfg) {
    return 1;
  }
  if (!state->tb_initialized) {
    tb_configure(state, cfg, now_ns);
  }
  if (state->tb.refill_rate_per_ns <= 0.0) {
    return 1;
  }
  if (now_ns > state->tb.last_refill_ns) {
    const double elapsed = (double)(now_ns - state->tb.last_refill_ns);
    state->tb.tokens += elapsed * state->tb.refill_rate_per_ns;
    if (state->tb.tokens > state->tb.max_tokens) {
      state->tb.tokens = state->tb.max_tokens;
    }
    state->tb.last_refill_ns = now_ns;
  }
  if (state->tb.tokens >= 1.0) {
    state->tb.tokens -= 1.0;
    return 1;
  }
  return 0;
}

static void record_ipg_sample(samurai_pacing_state_t* state, uint64_t actual_ns, uint64_t intended_ns) {
  if (state->ipg_count == 0ull || actual_ns < state->ipg_min_ns) {
    state->ipg_min_ns = actual_ns;
  }
  if (actual_ns > state->ipg_max_ns) {
    state->ipg_max_ns = actual_ns;
  }
  state->ipg_sum_ns += (double)actual_ns;
  state->ipg_count += 1ull;

  if (intended_ns > 0ull) {
    const double diff = (double)actual_ns - (double)intended_ns;
    const double absdiff = diff < 0.0 ? -diff : diff;
    state->jitter_sum_ns += absdiff;
    state->jitter_count += 1ull;

    const uint32_t idx = state->pct_ring_idx % SAMURAI_PACING_PCT_SLOTS;
    state->pct_ring[idx] = (uint64_t)absdiff;
    state->pct_ring_idx += 1u;
    if (state->pct_ring_len < SAMURAI_PACING_PCT_SLOTS) {
      state->pct_ring_len += 1u;
    }
  }
}

static int cmp_u64(const void* a, const void* b) {
  const uint64_t va = *(const uint64_t*)a;
  const uint64_t vb = *(const uint64_t*)b;
  return (va > vb) - (va < vb);
}

double samurai_pacing_get_jitter_p99_ns(const samurai_pacing_state_t* state) {
  if (!state || state->pct_ring_len == 0u) {
    return 0.0;
  }
  uint32_t n = state->pct_ring_len;
  if (n > SAMURAI_PACING_PCT_SLOTS) {
    n = SAMURAI_PACING_PCT_SLOTS;
  }
  uint64_t sorted[SAMURAI_PACING_PCT_SLOTS];
  memcpy(sorted, state->pct_ring, (size_t)n * sizeof(uint64_t));
  qsort(sorted, (size_t)n, sizeof(uint64_t), cmp_u64);
  uint32_t idx = (uint32_t)(0.99 * (double)(n - 1u));
  if (idx >= n) {
    idx = n - 1u;
  }
  return (double)sorted[idx];
}

double samurai_pacing_get_mean_ipg_ns(const samurai_pacing_state_t* state) {
  if (!state || state->ipg_count == 0ull) {
    return 0.0;
  }
  return state->ipg_sum_ns / (double)state->ipg_count;
}

/* ========================================================================== */
/* Hybrid Sleep + Busy-Wait Precision Engine                                  */
/* ========================================================================== */

void samurai_pacing_precision_wait_for_state_ns(samurai_pacing_state_t* state,
                                                uint64_t target_ns,
                                                uint8_t disable_busywait) {
  samurai_pacing_calibrate();
  const uint64_t now = samurai_pacing_monotonic_now_ns();
  if (now >= target_ns) {
    return;
  }

  const uint64_t remaining = target_ns - now;
  const uint64_t spin_thresh = disable_busywait ? 0ull : g_spin_threshold_ns;

  /* Phase 1: kernel sleep for bulk of wait */
  if (disable_busywait || remaining > spin_thresh + 5000ull) {
    const uint64_t wake_at = target_ns - spin_thresh;
    struct timespec ts;
    ts.tv_sec = (time_t)(wake_at / 1000000000ull);
    ts.tv_nsec = (long)(wake_at % 1000000000ull);
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {
    }
    if (state) {
      state->sleep_calls += 1ull;
    }
  }

  if (disable_busywait) {
    return;
  }

  /* Phase 2: deterministic short tail spin using TSC when available */
  if (g_tsc_enabled && g_tsc_hz > 0ull) {
    const uint64_t target_cycles = tsc_deadline_from_ns(target_ns);
    while (samurai_rdtsc() < target_cycles) {
      cpu_relax_pause();
      if (state) {
        state->busywait_cycles += 1ull;
      }
    }
    return;
  }

  while (samurai_pacing_monotonic_now_ns() < target_ns) {
    cpu_relax_pause();
    if (state) {
      state->busywait_cycles += 1ull;
    }
  }
}

uint64_t samurai_pacing_time_ns(void) {
  return samurai_pacing_monotonic_now_ns();
}

void samurai_pacing_precision_wait_ns(uint64_t target_ns) {
  samurai_pacing_precision_wait_for_state_ns(NULL, target_ns, 0u);
}

/* ========================================================================== */
/* Public Lifecycle & Wait API                                                */
/* ========================================================================== */

void samurai_pacing_init(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg) {
  samurai_pacing_calibrate();
  if (!state) {
    return;
  }
  memset(state, 0, sizeof(*state));
  const uint64_t now_ns = samurai_pacing_monotonic_now_ns();
  state->next_deadline_ns = now_ns;
  state->last_send_ns = 0ull;
  state->ipg_min_ns = UINT64_MAX;
  rng_ensure_seeded(state);
  if (cfg) {
    tb_configure(state, cfg, now_ns);
  }
}

void samurai_pacing_reconfigure(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg) {
  samurai_pacing_calibrate();
  if (!state) {
    return;
  }
  const uint64_t now_ns = samurai_pacing_monotonic_now_ns();
  state->next_deadline_ns = now_ns;
  state->burst_cursor = 0u;
  state->last_send_ns = now_ns;
  if (cfg) {
    tb_configure(state, cfg, now_ns);
  }
}

void samurai_pacing_wait_next(samurai_pacing_state_t* state, const samurai_pacing_config_t* cfg) {
  if (!state || !cfg) {
    return;
  }
  const uint8_t mode = cfg->mode;
  uint64_t now_ns = samurai_pacing_monotonic_now_ns();

  if (mode == SAMURAI_PACING_NONE) {
    state->sent += 1ull;
    state->last_send_ns = now_ns;
    return;
  }

  uint64_t intended_gap = 0ull;
  if (mode == SAMURAI_PACING_RPS && cfg->target_rps > 0.0) {
    intended_gap = (uint64_t)(1000000000.0 / cfg->target_rps);
  } else if (mode == SAMURAI_PACING_IPG && cfg->ipg_ns > 0ull) {
    intended_gap = cfg->ipg_ns;
  } else if (mode == SAMURAI_PACING_BURST && cfg->burst_size > 0u) {
    state->burst_cursor += 1u;
    if (state->burst_cursor >= cfg->burst_size) {
      state->burst_cursor = 0u;
      if (cfg->burst_gap_ns > 0ull) {
        const int64_t jitter = calc_jitter_ns(state, cfg->burst_gap_ns, cfg->jitter_model, cfg->jitter_pct);
        const uint64_t base_deadline =
            (now_ns > UINT64_MAX - cfg->burst_gap_ns) ? UINT64_MAX : (now_ns + cfg->burst_gap_ns);
        const uint64_t deadline = add_jitter_saturating_u64(base_deadline, jitter);
        samurai_pacing_precision_wait_for_state_ns(state, deadline, cfg->disable_busywait);
        const uint64_t done_ns = samurai_pacing_monotonic_now_ns();
        if (state->last_send_ns > 0ull && done_ns >= state->last_send_ns) {
          record_ipg_sample(state, done_ns - state->last_send_ns, cfg->burst_gap_ns);
        }
        state->last_send_ns = done_ns;
      } else {
        state->last_send_ns = now_ns;
      }
    } else {
      state->last_send_ns = now_ns;
    }
    state->sent += 1ull;
    return;
  }

  if (intended_gap > 0ull) {
    const uint64_t catchup_limit =
        (intended_gap <= UINT64_MAX / 2ull) ? (intended_gap * 2ull) : intended_gap;
    if (state->next_deadline_ns == 0ull ||
        (now_ns > state->next_deadline_ns && (now_ns - state->next_deadline_ns) > catchup_limit)) {
      state->next_deadline_ns = now_ns;
    }
    state->next_deadline_ns = (state->next_deadline_ns > UINT64_MAX - intended_gap)
                                  ? UINT64_MAX
                                  : (state->next_deadline_ns + intended_gap);
    const int64_t jitter = calc_jitter_ns(state, intended_gap, cfg->jitter_model, cfg->jitter_pct);
    const uint64_t target_ns = add_jitter_saturating_u64(state->next_deadline_ns, jitter);
    samurai_pacing_precision_wait_for_state_ns(state, target_ns, cfg->disable_busywait);
    const uint64_t done_ns = samurai_pacing_monotonic_now_ns();
    if (state->last_send_ns > 0ull && done_ns >= state->last_send_ns) {
      record_ipg_sample(state, done_ns - state->last_send_ns, intended_gap);
    }
    state->last_send_ns = done_ns;
    state->sent += 1ull;
    return;
  }

  state->last_send_ns = now_ns;
  state->sent += 1ull;
}

void samurai_pacing_adjust_rate(samurai_pacing_state_t* state, samurai_pacing_config_t* cfg, double drop_rate_pct) {
  if (!cfg || drop_rate_pct < 0.0) {
    return;
  }
  if (drop_rate_pct > 5.0) {
    double factor = 1.0 - (drop_rate_pct / 200.0);
    if (factor < 0.5) {
      factor = 0.5;
    }
    if (cfg->mode == SAMURAI_PACING_RPS && cfg->target_rps > 0.0) {
      cfg->target_rps *= factor;
    } else if (cfg->mode == SAMURAI_PACING_IPG && cfg->ipg_ns > 0ull) {
      cfg->ipg_ns = (uint64_t)((double)cfg->ipg_ns / factor);
    }
    if (state) {
      tb_configure(state, cfg, samurai_pacing_monotonic_now_ns());
    }
  }
}
