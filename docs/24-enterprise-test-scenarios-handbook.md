# 24 - Enterprise Test Scenarios Handbook

![Samurai End-to-End System Architecture](assets/diagrams/samurai_system_architecture.svg)

## Purpose

This handbook provides an operational framework for planning and executing enterprise-grade network resilience, capacity, and defense validation evaluations using the Samurai Network Resilience Platform (`./build/cli/samurai`).

Goals:

- Differentiate between ad-hoc traffic generation and structured enterprise resilience testing.
- Integrate technical parameters with business risk management, formal authorization, rollback protocols, and executive reporting.
- Present realistic, production-relevant scenarios that remain strictly within authorized, ethical testing boundaries.
- Establish a shared technical vocabulary among test operators, platform engineers, and leadership.

This handbook is strictly intended for authorized, documented, and isolated staging, pre-production, and laboratory environments.

## Target Audience

- Performance and Systems Engineers
- Platform Engineering and Site Reliability Engineering (SRE) Teams
- Blue Teams, SOC Analysts, and Defensive Security Engineers
- Enterprise Network and Infrastructure Architects
- Professional Services Teams conducting resilience and capacity verification audits

## Scope and Boundaries

This document:

- Is not an unauthorized attack or exploitation guide.
- Does not authorize arbitrary traffic generation across public networks.
- Avoids offensive disruption guides in favor of defensive resilience and capacity engineering.

All scenarios:

- Utilize private IP addresses, dedicated staging VIPs, and controlled lab networks.
- Focus on verifying defenses, measuring saturation thresholds, and ensuring service continuity.
- Assume signed rules of engagement, defined maintenance windows, and established rollback owners.

## Core Principles of Enterprise Testing

Technical execution alone does not constitute an enterprise test. A test is considered professional only when the following criteria are satisfied:

1. Written and signed authorization is locked in advance.
2. Target scopes, network paths, and maintenance windows are explicitly defined.
3. Success metrics, failure guardrails, and abort criteria are established beforehand.
4. Dedicated rollback owners and emergency abort controllers are active.
5. All execution artifacts and telemetry traces are archived immutably.
6. Test outcomes are communicated through both technical metrics and business impact narratives.

Operational Rules:

- No signed authorization = No test execution.
- No emergency rollback plan = No production or pre-production testing window.
- No reference baseline = Meaningless benchmark comparisons.
- No predefined acceptance criteria = The test remains purely observational.

## Enterprise Test Categories

| Test Type | Operational Goal | Primary Artifact / Output |
|---|---|---|
| Smoke / Readiness | Verify environment, routes, and dependencies | Clean preflight confirmation |
| Baseline | Characterize steady-state performance | Reference latency and throughput curves |
| Capacity Test | Locate infrastructure bottlenecks and saturation points | Saturation knee and cliff analysis |
| Longevity / Soak | Validate endurance, memory leaks, and drift | Multi-hour drift and degradation report |
| Defense Verification | Confirm WAF, rate limits, and scrubbers function under load | Policy effectiveness and false-positive audit |
| Post-Change Regression | Ensure new code releases do not degrade line-rate | Delta comparison report |
| Incident Drill / GameDay | Evaluate cross-team coordination and runbooks | Incident response timeline report |

## Rules of Engagement Workflow

Every enterprise resilience evaluation must follow a disciplined operational progression:

1. Define business objectives and critical user journeys.
2. Formulate technical scope, network interfaces, and concurrency limits.
3. Secure written authorization from infrastructure stakeholders.
4. Classify test environment: Lab, Staging, Pre-Production, or Dedicated Maintenance Window.
5. Capture a clean baseline under normal load.
6. Increase traffic load incrementally using graduated steps.
7. Monitor operational guardrails in real time.
8. Trigger immediate abort and rollback if guardrails are breached.
9. Publish comprehensive findings incorporating technical metrics and business impact analysis.

## Pre-Test Planning Questionnaire

### Business Dimension

- Which revenue-critical user journey or service is under evaluation?
- What is the business impact if the test causes unintended degradation?
- During which maintenance hours is testing authorized?
- Who possesses the authority to command an emergency abort?

### Technical Dimension

- Is the target environment isolated staging, or an active pre-production replica?
- Are edge ingress, WAF, load balancers, and upstream proxies mapped out?
- Do steady-state baseline metrics exist for comparative analysis?
- Which dataplane backend (e.g., AF_XDP, TX_RING) is expected during execution?
- Which monitoring dashboards and metric alerts will track guardrails?

### Operational Dimension

- What dedicated communication bridge will teams use (`Slack/Teams/voice bridge`)?
- Who acts as Incident Commander during the testing window?
- Who executes the rollback plan if downstream nodes destabilize?
- Where will execution reports, PCAP captures, and dashboard snapshots be archived?

## Enterprise Guardrails

Enterprise testing must never focus solely on driving peak throughput. The following operational guardrails must be continuously monitored:

- Client request error rate percentage
- Upstream gateway timeout frequency
- HTTP `5xx` internal server error spikes
- WAF false-positive challenge and block rates
- Load balancer health-check failures and node eviction
- Database connection pool exhaustion and queue backlogs
- Application worker crashes or container restarts
- CPU throttling, memory exhaustion, and NIC packet drop counters

Operational rule:
If traffic volume increases while upstream service quality degrades beyond guardrails, the test is not successful.

## Enterprise Acceptance Criteria

Predefine operational thresholds before initiating load:

- `pass`: The infrastructure sustains target concurrency and throughput within SLA latency limits.
- `pass_with_constraints`: The service remains stable, but specific tuning or capacity ceilings were identified.
- `fail`: The target failed to sustain load, or defense mechanisms did not activate as designed.
- `abort`: The test was intentionally terminated early due to guardrail violations.

## Enterprise Scenario Design Formula

Every enterprise resilience scenario should be specified across seven core dimensions:

1. Business Objective
2. Technical Target
3. Traffic Workload Model
4. Success Criteria
5. Abort Criteria
6. Required Artifacts
7. Recommended Next Actions

## Example Scenario 1 - Enterprise E-Commerce Campaign Readiness Test

### Business Context

Prior to a major promotional event or seasonal sale, an enterprise e-commerce platform must ensure that its core user funnel:

- Homepage
- Category browsing
- Product detail pages
- Shopping cart
- User authentication
- Checkout submission API

can sustain projected peak traffic without performance degradation or service outage.

The operational objective is not to force an outage, but to resolve critical capacity questions:

- Up to what concurrency level does the infrastructure scale smoothly?
- Do edge CDNs, WAF appliances, and load balancers distribute load symmetrically?
- Is critical checkout traffic isolated from high-volume catalog browsing?
- Where is the first architectural bottleneck during traffic surges?

### Scope and Constraints

- Dedicated pre-production environment with production parity.
- Explicit private target VIP: `10.20.30.40`.
- Synthetic traffic containing zero real customer credentials or PII.
- Payment gateway integration connected to a mock sandbox provider.

### Traffic Composition Model

Realistic enterprise e-commerce traffic is never uniform. A representative distribution:

- `50%` Catalog browsing: Homepage, category filters, product detail views.
- `20%` Product catalog search queries.
- `15%` User login and session refresh operations.
- `10%` Cart modifications and additions.
- `5%` Checkout submission API (directed to sandbox provider).

### Technical Validation Objectives

- Ingress load balancer connection queue depth.
- Edge cache hit ratio vs. origin forward rates.
- API gateway rate-limiting stability.
- Response latency percentiles (p95, p99) along the checkout path.
- WAF challenge accuracy without false-positive blocking of legitimate browsing.

### Abort Criteria

Immediately terminate execution if:

- Checkout sandbox API response times exceed 3000 ms over a 30-second window.
- Aggregate HTTP `5xx` response codes exceed 1.0% of total volume.
- Backend load balancers evict healthy nodes due to failed health probes.
- Upstream database connection backlogs exceed safe operating limits.

### Required Artifacts

- Comprehensive execution report (`run_report.json` and `run_report.md`).
- Ingress load balancer dashboard snapshots.
- Latency percentile and HTTP status code distribution charts.
- WAF decision and challenge logs.
- Archived application and Samurai engine logs.

### Expected Outcome Classifications

- Catalog browsing scales smoothly, but checkout API times out:
  Finding: Insufficient queue isolation between browsing and transactional traffic.
- WAF blocks traffic, but produces false positives on customer logins:
  Finding: Behavioral rate-limiting rules require targeted tuning.
- Ingress layer remains stable, but application workers exhaust memory:
  Finding: Application service layer is the primary capacity bottleneck.

### Operational Walkthrough - Pre-Production Maintenance Window

The following procedure demonstrates a controlled, multi-stage resilience evaluation.

Environment Assumptions:
- Pre-production VIP: `10.20.30.40`
- TLS termination enabled at ingress
- Checkout sandbox backend isolated
- Authorized test window: 22:00 - 23:00 UTC

#### Baseline Configuration File

`artifacts/configs/ecommerce_preprod_baseline.yaml`:

```yaml
target: 10.20.30.40
port: 443
attack_vector: http
http_scheme: https
http_method: GET
http_path:
  - /
  - /category/promotions
  - /product/sku-1001
  - /login
  - /cart
  - /api/checkout/health
http_concurrency: 120
http_timeout: 3.0
workers: 8
count: 80000
rps: 2000
profile: web-stress
run_report: true
run_report_format: both
run_report_dir: artifacts/reports/ecommerce_preprod
log: artifacts/logs/ecommerce_preprod_baseline.log
```

#### Step 1: Bounded Smoke Verification

```bash
./build/cli/samurai \
  --config config/samurai.conf.example \
  --worker l7 \
  --target 10.10.40.12 \
  --port 443 \
  --count 100 \
  --confirm
```

Validation objectives:
- Confirm configuration parses cleanly.
- Verify target IP, port, and URL paths are accepted.
- Validate worker allocation prior to initiating traffic.

#### Step 2: Reference Baseline Run

```bash
./build/cli/samurai \
  --config artifacts/configs/ecommerce_preprod_baseline.yaml \
  --confirm
```

Post-run validation:
- Archive `run_report.json` and `run_report.md`.
- Export ingress controller metrics and latency percentiles.
- Verify zero guardrail violations.

#### Step 3: Controlled Incremental Ramp-Up

Gradually increase load to projected peak volumes:

```bash
./build/cli/samurai \
  --config artifacts/configs/ecommerce_preprod_baseline.yaml \
  --rps 2600 \
  --count 120000 \
  --run-report-dir artifacts/reports/ecommerce_preprod_step2 \
  --log artifacts/logs/ecommerce_preprod_step2.log \
  --confirm
```

#### Professional Evaluation Matrix

| Metric Observation | Technical Diagnosis | Business Impact | Remediation Action |
|---|---|---|---|
| Browsing remains stable; checkout latency surges | Inadequate queue separation on upstream routers | Checkout funnel degrades during sales surges | Implement dedicated upstream ingress pool for checkout |
| WAF challenges spike on `/login` | Heuristic rate limits tuned too aggressively | Legitimate returning customers cannot log in | Tune rate-limiting thresholds on auth endpoints |
| Zero `5xx` errors, but p99 latency climbs steeply | Application workers approaching concurrency saturation | Sub-optimal customer experience | Configure auto-scaling rules with lower CPU thresholds |

#### Executive Summary Statement

"Pre-production campaign readiness testing demonstrated that catalog browsing remains stable at 2,600 RPS. However, checkout API health probes exhibited latency degradation under sustained concurrency. Prior to the promotion, we recommend isolating checkout upstream pools and implementing dedicated ingress priority queuing."

### GPU-Accelerated E-Commerce Workloads

In high-volume e-commerce testing, GPU hardware acceleration acts as a high-density packet generator and traffic modeler rather than a full stateful browser stack:

- Synthesizing massive catalog browsing and payload variance.
- Stressing edge reverse proxies, CDN points of presence, and ingress load balancers.
- Comparing CPU vs. GPU packet generation pipelines.
- Identifying bottlenecks across PCIe bus, host pinned memory, and NIC queues.

#### GPU Workload 1 - High-Density Catalog Browsing Baseline

Stresses edge caching and ingress distribution using GPU packet synthesis.

`artifacts/configs/ecommerce_gpu_browse_baseline.yaml`:

```yaml
target: 10.20.30.40
port: 443
protocol: tcp
attack_vector: basic
compute_backend: cuda
workers: 6
count: 1200000
rps: 2500
gpu_template_pool_size_l4: 24
gpu_ring_capacity: 4
gpu_batch_size: 100000
gpu_stream_count: 3
gpu_pipeline_depth: 2
gpu_pinned_max_mb: 512
run_report: true
run_report_format: both
run_report_dir: artifacts/reports/ecommerce_gpu_browse
log: artifacts/logs/ecommerce_gpu_browse.log
```

Bounded GPU smoke validation:

```bash
./build/cli/samurai \
  --worker gpu \
  --target 10.20.30.40 \
  --port 443 \
  --count 1000 \
  --confirm
```

Live baseline run:

```bash
./build/cli/samurai \
  --config artifacts/configs/ecommerce_gpu_browse_baseline.yaml \
  --confirm
```

#### GPU Workload 2 - Edge Layer Warmup and Capacity Evaluation

Evaluates whether CDN edges and ingress load balancers can handle sudden traffic surges without cache thrashing.

```bash
./build/cli/samurai \
  --target 10.20.30.40 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 4 \
  --count 800000 \
  --gpu-template-pool-size-l4 16 \
  --gpu-ring-capacity 4 \
  --gpu-batch-size 65536 \
  --gpu-stream-count 2 \
  --gpu-pipeline-depth 2 \
  --gpu-pinned-max-mb 256 \
  --run-report \
  --run-report-dir artifacts/reports/ecommerce_gpu_edge_warmup \
  --confirm \
  --log artifacts/logs/ecommerce_gpu_edge_warmup.log
```

#### GPU Workload 3 - Extended Endurance Soak Test

Validates host DMA memory and GPU ring stability under sustained 1-hour generation:

```bash
./build/cli/samurai \
  --target 10.20.30.40 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 6 \
  --count 50000000 \
  --rps 3000 \
  --gpu-template-pool-size-l4 24 \
  --gpu-ring-capacity 5 \
  --gpu-batch-size 120000 \
  --gpu-stream-count 3 \
  --gpu-pipeline-depth 3 \
  --gpu-pinned-max-mb 768 \
  --soak-profile 1h \
  --soak-warmup-s 180 \
  --soak-snapshot-interval 15 \
  --soak-max-error-rate-pct 0.5 \
  --soak-max-pps-drop-pct 10 \
  --soak-max-pinned-growth-mb 256 \
  --soak-max-backlog 12000 \
  --run-report \
  --run-report-dir artifacts/reports/ecommerce_gpu_soak \
  --confirm \
  --log artifacts/logs/ecommerce_gpu_soak.log
```

#### GPU Workload 4 - CPU vs GPU A/B Comparative Analysis

Determines whether GPU offloading delivers measurable efficiency gains over CPU generation.

CPU Reference:

```bash
./build/cli/samurai \
  --target 10.20.30.40 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --workers 6 \
  --count 1200000 \
  --run-report \
  --run-report-dir artifacts/reports/ecommerce_cpu_ab \
  --confirm \
  --log artifacts/logs/ecommerce_cpu_ab.log
```

GPU Accelerated Counterpart:

```bash
./build/cli/samurai \
  --target 10.20.30.40 \
  --port 443 \
  --protocol tcp \
  --attack-vector basic \
  --compute-backend cuda \
  --workers 6 \
  --count 1200000 \
  --gpu-template-pool-size-l4 24 \
  --gpu-ring-capacity 4 \
  --gpu-batch-size 100000 \
  --gpu-stream-count 3 \
  --gpu-pipeline-depth 2 \
  --gpu-pinned-max-mb 512 \
  --run-report \
  --run-report-dir artifacts/reports/ecommerce_gpu_ab \
  --confirm \
  --log artifacts/logs/ecommerce_gpu_ab.log
```

## Example Scenario 2 - Defensive Security and SOC / MDR Resilience Audit

### Business Context

A cybersecurity operations center (SOC) or Managed Detection and Response (MDR) provider must validate defense automation, telemetry pipelines, and escalation workflows:

- Do defensive rate-limiting and challenge rules activate accurately under load?
- Does the security information and event management (SIEM) pipeline drop telemetry events during traffic surges?
- Do security analysts receive automated escalations within acceptable SLA windows?
- Does the architecture successfully isolate malicious traffic without disrupting legitimate customer services?

### Scope and Constraints

- Isolated customer staging testbed or contractual lab network.
- Approved destination IP and CIDR allowlists.
- Explicit maintenance window and active Incident Commander.
- Pre-authorized traffic patterns and headers.

### Technical Validation Objectives

- Verify inline WAF, traffic filtering appliances, and rate-limiting rules engage correctly.
- Ensure protection policies trigger without causing false-positive blocking of valid traffic.
- Detect event loss or processing backpressure in telemetry ingestion queues.
- Measure latency between traffic onset and security analyst alert generation.

### Abort Criteria

- Telemetry pipeline event loss exceeds 5.0%.
- Defensive policies inadvertently block core internal API endpoints.
- Excessive alert noise risks masking legitimate production anomalies.
- Customer SLA thresholds are breached.

### Required Artifacts

- Formal execution report (`run_report.json` and `run_report.md`).
- WAF and firewall policy enforcement logs.
- SIEM telemetry ingestion latency charts.
- Security operations incident escalation timeline.
- Comprehensive findings summary.

### Operational Walkthrough - Defense Validation Window

Environment Assumptions:
- Testing VIP: `10.50.60.70`
- Upstream WAF and policy evaluation engine active
- Dedicated private network testing environment
- Active escalation bridge on standby

#### Configuration Specification

`artifacts/configs/defense_validation_http2.yaml`:

```yaml
target: 10.50.60.70
port: 443
attack_vector: http2
http_scheme: https
http_path:
  - /
  - /status
  - /api/v1/events
profile: web-bypass
tls_profile: chrome_120
h2_profile: chrome_120
h2_transport: hyper-h2
http2_concurrency: 240
http2_connections: 6
http2_streams_per_conn: 40
workers: 6
count: 60000
run_report: true
run_report_format: both
run_report_dir: artifacts/reports/defense_validation
log: artifacts/logs/defense_validation_http2.log
```

#### Step 1: Bounded Smoke Verification

```bash
./build/cli/samurai \
  --worker l7 \
  --l7-protocol http2 \
  --target 10.30.10.5 \
  --port 443 \
  --count 100 \
  --confirm
```

#### Step 2: Live Defense Validation Run

```bash
./build/cli/samurai \
  --config artifacts/configs/defense_validation_http2.yaml \
  --confirm
```

During execution, the security team simultaneously tracks:
- WAF challenge and drop statistics.
- SIEM ingestion queue depth.
- Telemetry backpressure and worker CPU utilization.
- Time elapsed until SOC dashboard alerts trigger.

#### Step 3: Comparative Threshold Evaluation

Re-execute with modified concurrency to evaluate whether defense triggers depend on instantaneous burst rate or aggregate volume:

```bash
./build/cli/samurai \
  --config artifacts/configs/defense_validation_http2.yaml \
  --http2-concurrency 120 \
  --count 30000 \
  --run-report-dir artifacts/reports/defense_validation_step2 \
  --log artifacts/logs/defense_validation_step2.log \
  --confirm
```

#### Defensive Evaluation Matrix

| Metric Observation | Technical Diagnosis | Business Impact | Remediation Action |
|---|---|---|---|
| Mitigation triggers cleanly, but SIEM events are delayed | Policy works, but telemetry pipeline is saturated | Forensic investigation is delayed during active incidents | Scale telemetry ingestion queue workers |
| Challenges activate rapidly, but legitimate health checks fail | Broad, unsegmented policy rules | Essential microservices experience transient outages | Whitelist internal health-check endpoints |
| SOC alert generation takes > 10 minutes | Complex correlation rule evaluation delays notification | Slower Mean Time to Respond (MTTR) | Optimize SIEM streaming correlation rules |

#### Executive Summary Statement

"The edge defense layer successfully mitigated simulated traffic surges according to policy. However, telemetry ingestion delays produced a 12-minute gap between mitigation enforcement and SOC dashboard visibility. We recommend allocating additional pipeline workers to the SIEM log forwarders to ensure real-time visibility."

## Enterprise Artifact Repository Structure

Maintain a structured, centralized repository for all test artifacts:

```text
artifacts/
├── configs/
│   ├── ecommerce_preprod_baseline.yaml
│   └── defense_validation_http2.yaml
├── reports/
│   ├── ecommerce_preprod/
│   └── defense_validation/
├── logs/
│   ├── ecommerce_preprod_baseline.log
│   └── defense_validation_http2.log
└── snapshots/
    ├── ingress_dashboards/
    └── siem_timelines/
```

Operational standards:
- Dedicate separate configuration files to each test profile.
- Output each execution phase into an isolated, timestamped report directory.
- Use unified test run identifiers across log files and dashboard screenshots.

## Graduated Workload Ramp-Up Principles

Never apply peak traffic volume immediately. Follow a disciplined ramp-up curve:

1. Smoke test: Verify end-to-end connectivity.
2. Baseline run: Confirm steady-state metrics.
3. Graduated ramp-up: Step through 25%, 50%, and 75% of target volume.
4. Target peak load: Evaluate system behavior at 100% capacity.
5. Longevity soak: Validate endurance across an extended duration.

Operational Rule:
Validate behavior before volume; verify stability before introducing stress.

## Dual-Track Reporting: Technical and Business Communication

Enterprise test reports must present findings in two distinct formats:

### Technical Summary

- Exact transmission backends and kernel drivers utilized.
- Operational guardrails tracked and violation thresholds.
- Concrete pass/fail metrics across latency, error rate, and throughput.
- Physical bottlenecks identified (e.g., PCIe bus, socket buffer, DB connection pool).

### Business Impact Summary

- Projected impact on real customer transactions and revenue funnels.
- Specific microservices or functional business areas exposed to risk.
- Implications for upcoming sales campaigns, SLAs, or security compliance audits.
- Prioritized engineering recommendations with estimated remediation effort.

## Reusable Enterprise Scenario Template

```text
Scenario Name:
Business Objective:
Target Environment:
Authorization / Scope Reference:
Technical Validation Goals:
Traffic Workload Model:
Acceptance Criteria:
Abort Criteria:
Rollback Controller:
Required Artifacts:
Next Actions:
```

## Recommended Reading Hierarchy

To maximize the effectiveness of this handbook, review related documentation in sequence:

- Understand organizational purpose and strategy: This handbook (`docs/24-enterprise-test-scenarios-handbook.md`)
- Select operational execution commands: `docs/22-cli-operational-playbook.md`
- Evaluate benchmark validity and acceptance: `docs/23-benchmark-acceptance-handbook.md`
- Clarify ethical constraints and target safety: `docs/07-safety.md`

## Summary

Enterprise-grade network testing is fundamentally a risk management and systems engineering discipline. High-value resilience programs succeed by asking the right architectural questions, defining firm operational guardrails, verifying defenses under realistic conditions, and delivering actionable, executive-ready insights.

Core Principles of Excellence:
- Initiated with explicit authorization
- Governed by strict operational guardrails
- Safeguarded by proven rollback plans
- Concluded with actionable business impact analysis
