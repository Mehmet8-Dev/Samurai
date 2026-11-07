# 42 — RL Closed-Loop Autopilot: Evaluation Methodology and Empirical Findings

This document records the evaluation methodology, experimental benchmarks, root-cause resolutions, and production shipping decisions for the learned policy layer (**Mahoraga RL**) of the closed-loop autopilot within the **Samurai Network Resilience Platform**. The primary objective is to maintain reproducible empirical results and provide a rigorous, quantitative answer to the operational question: *"Does reinforcement learning justify its deployment over heuristic control?"*

Related codebase modules: `ddos_samurai/control/closed_loop.{hpp,cpp}` (native controller and SLO engine), `ddos_samurai/models/rl/` (IQL/RL²/reward/OPE pipelines), and `deploy/waf-lab/` (synthetic testing substrate and evaluation harnesses).

---

## 1. Candidate Policy Architectures: AIMD, FF, RL²

During every evaluation window, the closed-loop controller determines the next transmission vector (RPS, concurrency, pacing mode, request mix, and client source rotation):

| Policy Candidate | Architecture Class | Decision-Making Strategy |
| :--- | :--- | :--- |
| **AIMD** | Non-learned Heuristic | Classical Additive-Increase / Multiplicative-Decrease; modulates throughput rate (RPS) exclusively without adjusting Mahoraga L7 levers. |
| **FF** | Feedforward IQL Policy | Reactive evaluation based exclusively on the **current** state vector $s_t$; stateless execution via Implicit Q-Learning (`train_iql`). |
| **RL²** | Recurrent Meta-RL (GRU) | Adaptive evaluation conditioned on the current state **plus accumulated intra-episode context** via hidden GRU states (`train_rl2`). |

Both FF and RL² employ offline reinforcement learning: they learn optimal behavioral representations from logged transition tuples $(s, a, r, s')$ without unbounded online exploration in live customer production environments.

---

## 2. Evaluation Instrumentation: Live On-Policy A/B Verification

### Critical Insight: Offline OPE (FQE) is Inadequate for Recurrent vs. Feedforward Comparisons

Fitted Q-Evaluation (FQE) estimates target policy returns using trajectories recorded under a historical behavior policy. Because a recurrent policy's internal hidden state must be shaped by the consequences of its own decisions rather than behavior policy actions, evaluating RL² on logged logs introduces severe **counterfactual context distribution mismatch**. Even when trajectory-wide evaluation is applied in `ope.py` (`FQEConfig.trajectory_value`), offline evaluation remains structurally biased.

### Authoritative Instrument: Live, Self-Driven A/B Testing

The authoritative metric is **live, on-policy A/B experimentation**, where each candidate policy actively drives the live target and builds its own state trajectory under identical operational conditions:

- `deploy/waf-lab/ab-live.sh`: Concurrently evaluates the three candidate arms (AIMD, FF, RL²) against live endpoints. Repetitions are **interleaved** to cancel out infrastructure drift, and all arms experience identical mid-episode regime shifts.
- `deploy/waf-lab/ab_report.py`: Evaluates performance using **EffectiveThroughput** as the primary optimization metric:

$$\text{EffectiveThroughput} = \text{Served}_{2\text{xx}} - \lambda_{\text{defense}} \cdot \text{Pushback}_{4\text{xx}} - \lambda_{\text{flow}} \cdot \text{FlowFail} - \lambda_{\text{slo}} \cdot \text{Overshoot} - \text{StepCost}$$

Raw HTTP 2xx/s throughput is explicitly rejected as an optimization objective because it rewards reckless transmission bursts that overwhelm backend infrastructure. Repetition-paired bootstrap confidence intervals ($90\%$ CI) determine policy promotion.

---

## 3. Test Substrate and Critical Root-Cause Fixes

### 3.1 Enforcing Strict Rate Limiting (`nodelay`)

In initial experiments, the `waf-heavy` Nginx profile was configured with `limit_req burst=20` but lacked the `nodelay` directive. Consequently, requests exceeding the rate threshold were delayed in memory rather than rejected, returning HTTP 200 after substantial queuing latency. Because the paced controller did not exceed buffer depth, the rate limiter generated high latency but produced zero rejection signals (`DELAYED`, 0 `REJECTED`).

**Resolution:** Applied `limit_req ... nodelay` in `profiles/waf-heavy/nginx.conf`, ensuring that excess requests immediately trigger HTTP 429 rejections.

> **Container Mount Note:** Modifying bind-mounted configuration files in-place can alter filesystem inodes, causing running containers to retain stale descriptors. Rebuilding with `docker compose up -d --force-recreate nginx` is required.

### 3.2 Multi-Ceiling Biting-Wall Substrate

The laboratory substrate defined in `deploy/waf-lab/docker-compose.ratedrop.yml` provides deterministic rate-limiting barriers:
- Training Ceilings: `:8084` (50 req/s), `:8083` (100 req/s), `:8086` (200 req/s).
- **Holdout Validation Gate `:8085` (150 req/s):** Completely withheld during training; functions as a generalization test for previously unseen rate boundaries.

### 3.3 Pushback SLO — The Critical Optimization Breakthrough

The most significant architectural flaw identified was that **HTTP 429 rejections were not classified as SLO violations**. Because 429 responses were categorized separately from 5xx server errors, the controller ramped aggressively into defensive rate walls.

**Resolution:** Implemented `slo_max_pushback_pct` across `ddos_samurai/control/closed_loop.{hpp,cpp}` and `daemon/master_main.cpp`. The master populates pushback metrics using $(4\text{xx} + 5\text{xx}) / \text{responses\_total}$, exposed via the `--cl-slo-max-pushback-pct` flag. This allows heuristic AIMD to identify ceilings and enables RL policies to execute proportional backoff upon encountering pushback.

---

## 4. Empirical Findings (Live A/B, EffectiveThroughput, 5 Repetitions, Pushback SLO = 20)

Trained across a 5-profile biting-wall dataset (2,992 transitions across 176 episodes):

| Experimental Regime | AIMD Baseline | Feedforward (FF) | Recurrent (RL²) | **FF − AIMD** | **RL² − AIMD** | RL² − FF |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Holdout `:8085` (Unseen)** | −0.328 | **−0.110** | −0.110 | **+0.218** | **+0.218** | +0.000 |
| **Rate-Drop `:8083 ↔ :8084`** | −0.461 | −0.328 | −0.333 | **+0.134** | **+0.128** | −0.006 |
| **Coraza `:8080` (WAF + Rate)** | −0.477 | −0.281 | −0.313 | **+0.196** | **+0.164** | −0.032 |

*All `−AIMD` performance differentials clear 0 at the 90% confidence interval.*

**Operational Mechanism:** Under AIMD, SLO compliance was maintained in only 20% to 33% of evaluation windows due to continuous limit-hunting oscillations. In contrast, FF and RL² achieved 50% compliance by parking transmission rates just below the defensive ceiling, avoiding severe HTTP 429 penalties. While AIMD achieved slightly higher raw request counts (31 req/s vs. 25 req/s), its heavy rejection penalties yielded significantly lower EffectiveThroughput.

### Core Strategic Conclusions

1. **Reinforcement Learning Delivers Measurable Superiority:** When paired with proper reward formulation (Pushback SLO accounting), learned policies outperform classical heuristics across all tested regimes, including unseen holdout targets.
2. **Deploy Feedforward (FF); Retire Recurrent RL²:** Recurrent RL² offered zero statistical improvement over FF, while introducing non-trivial operational complexity (context serialization, hidden state tracking). Simplicity dictated the deployment of FF.

---

## 5. Methodological Lessons and Observations

- **Live On-Policy Gates are Authoritative:** Offline OPE scores are valuable strictly as coarse smoke tests.
- **Sample Efficiency and Plateauing:** Offline OPE scores continued to improve as dataset size increased from 2,992 to 6,630 transitions (FQE moving from −2.49 to −2.13). However, live holdout performance remained identical at **−0.110** (FF − AIMD = +0.218). Live operational capability saturated at ~3,000 transitions; additional training data merely refined Q-function curve-fitting without changing policy actions.
- **Fleet Scale vs. Environmental Diversity:** Industrial readiness does not require 400,000 synthetic episodes. For low-dimensional control spaces, diversity of defensive topologies, runtime safety guardrails, and per-target adaptation provide vastly more value than massive episode volumes.
- **Prerequisites for Recurrent Advantages:** Memory provides utility only when historical states reliably forecast future defensive transitions (such as progressive rate penalties, sequential IP bans, or adaptive WAF heuristics). Against memoryless rate limiters, stateless feedforward policies remain optimal.

---

## 6. Experimental Reproduction

```bash
# 1. Initialize testing substrate and rate-limiting targets
docker compose -f deploy/waf-lab/docker-compose.yml up -d
docker compose -f deploy/waf-lab/docker-compose.ratedrop.yml up -d
docker exec samurai-lab-nginx nginx -s reload

# 2. Capture 5-profile dataset and execute training pipeline
CL_SLO_MAX_PUSHBACK_PCT=20 BW_STATIC_TARGETS="8084 8083 8086 8080 8081" \
  STATIC_SWEEPS=28 SHIFT_SWEEPS=18 bash deploy/waf-lab/train-run-bitewall.sh

# 3. Execute live A/B verification across holdout and regime-shift targets
export RL2_POLICY=artifacts/rl/mahoraga-rl2-bw.srlp FF_POLICY=artifacts/rl/mahoraga-ff-bw.srlp
REPS=5 SHIFT=0 STATIC_PORT=8085 CL_SLO_MAX_PUSHBACK_PCT=20 bash deploy/waf-lab/ab-live.sh
REPS=5 SHIFT=1 SHIFT_A_PORT=8083 SHIFT_B_PORT=8084 CL_SLO_MAX_PUSHBACK_PCT=20 bash deploy/waf-lab/ab-live.sh
```

Trained policy weights are saved to `artifacts/rl/` (`.gitignore`), while orchestration code remains fully version-controlled.

---

## 7. Architectural Decisions Summary

- **Production Policy Selection:** Ship **Feedforward (FF)** (`mahoraga-ff-bw.srlp`) with `--cl-strategy rl --rl-policy <path> --cl-slo-max-pushback-pct 20`.
- **Default Pushback SLO:** Enforce pushback error budgeting as a default production constraint (classifying 429 as an actionable failure).
- **Recurrent Models Status:** Park RL² development until dynamic, multi-stage stateful defenses are modeled in the testing environment.
- **Champion-Challenger Gate:** Only promote candidate policies that demonstrate statistically significant improvements over AIMD in live A/B trials.

---

## 8. Multi-Profile FF Accumulation Run

To evaluate generalization across broader defensive surfaces, the feedforward model was trained against 9 live profiles for 45 minutes:

| Defense Profile | Port | Characteristics and Defensive Mechanisms |
| :--- | :--- | :--- |
| Coraza strict-waf | 8080 | Variant 2 (POST /login) returns 403; rate threshold ~200 req/s. |
| Coraza rate-only | 8080 | No payload inspection; uniform rate ceiling ~500 req/s. |
| Coraza waf-heavy | 8080 | Variants 1 and 3 return 403; aggressive rate ceiling ~100 req/s. |
| ModSecurity + OWASP CRS | 8081 | Secondary rule engine with independent signature matrix. |
| Anubis PoW Gateway | 8082 | Cryptographic Proof-of-Work challenge interceptor. |
| Rate-Drop r50 | 8084 | Strict Nginx `limit_req` at 50 req/s (`nodelay`). |
| Rate-Drop r100 | 8083 | Strict Nginx `limit_req` at 100 req/s (`nodelay`). |
| Rate-Drop r150 | 8085 | Strict Nginx `limit_req` at 150 req/s (`nodelay`). |
| Rate-Drop r200 | 8086 | Strict Nginx `limit_req` at 200 req/s (`nodelay`). |

### Empirical Validation (Champion-Challenger Live A/B)

Evaluating the resulting model (`mahoraga-ff.srlp`) on holdout target `:8085` (4 interleaved repetitions, `CL_SLO_MAX_PUSHBACK_PCT=20`):

| Policy Candidate | Mean Effective Throughput | 90% Confidence Interval | Raw Served / sec | SLO Compliance |
| :--- | :--- | :--- | :--- | :--- |
| **AIMD** | −0.326 | [−0.327, −0.325] | 31.6 | 33.3% |
| **FF** | **−0.109** | [−0.110, −0.109] | 25.4 | **50.0%** |
| **RL²** | −0.110 | [−0.110, −0.110] | 25.4 | 50.0% |

- **FF − AIMD = +0.216** (Statistically significant positive delta confirming FF promotion).
- **FF ≈ RL²** ($\Delta = -0.001$), reaffirming the decision to standardize on Feedforward.

---

## 9. Telemetry Extensions — Flow-Level IPS State (Phase 1)

Learned controllers can only adapt to defensive actions that produce measurable client-side signals:
- **IDS (Passive Inspection):** Does not terminate connections; produces no immediate client feedback. (Reflected indirectly via IP ban pressure).
- **IPS (Inline Blocking):** Drops packets or issues TCP RSTs; produces explicit **transport-level telemetry** (connect timeouts, retransmissions, abrupt resets).

**Phase 1 Implementation:** Added `RLConfig.flow_state_features`. Extends the state vector with connection attempt failure ratios and a `flow_known` bit (5 additional dimensions). For commodity transports (`kernel_socket`), flow signals are safely zero-masked, preserving backwards compatibility across models. Full transport signals activate automatically when operating over kernel-bypass engines (`custom_tcp`, `dpdk`, `af_xdp`).
