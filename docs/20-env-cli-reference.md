# Environment Variables and CLI Complete Reference

![Samurai CLI Execution & Worker Lifecycle](assets/diagrams/samurai_cli_lifecycle.svg)

This document provides a consolidated reference for all CLI command-line flags and all `SAMURAI_*` environment variables used in the Samurai Network Resilience Platform (`./build/ddos_samurai/cli/samurai`).

Scope:
- Total CLI options: `394`
- Total referenced `SAMURAI_*` environment variables: `111`

## 1) Execution Commands

Primary entrypoint:

```bash
./build/ddos_samurai/cli/samurai [FLAGS]
```

Common command examples:

```bash
# Display profiles
./build/ddos_samurai/cli/samurai --list-profiles

# Dry-run / safe parser and configuration check
./build/ddos_samurai/cli/samurai --dry-run -t 10.0.0.10 -p 443 --attack-vector http

# Self-test suite execution
./build/ddos_samurai/cli/samurai --self-test

# Standalone live benchmark execution
./build/ddos_samurai/cli/samurai --role standalone -t 10.0.0.10 -p 443 --attack-vector http --workers 4

# Master node initialization
./build/ddos_samurai/cli/samurai --role master --control-listen 0.0.0.0:5099 --management-api-enable

# Slave / Worker node connection
./build/ddos_samurai/cli/samurai --role slave --control-endpoints 10.0.0.5:5099 --cluster-secret xxxx
```

Command catalog by workload profile:

```bash
# Layer 4 basic stateful/stateless stream
./build/ddos_samurai/cli/samurai --attack-vector basic -t 10.0.0.10 -p 443 --protocol tcp --count 100000

# HTTP/1.1 workload
./build/ddos_samurai/cli/samurai --attack-vector http -t 10.0.0.10 -p 443 --http-scheme https --http-concurrency 200

# HTTP/2 multiplexed stream
./build/ddos_samurai/cli/samurai --attack-vector http2 -t 10.0.0.10 -p 443 --http2-concurrency 200

# WebSocket persistent connection
./build/ddos_samurai/cli/samurai --attack-vector websocket -t 10.0.0.10 -p 443 --ws-concurrency 100

# QUIC / HTTP/3 native session
./build/ddos_samurai/cli/samurai --attack-vector quic -t 10.0.0.10 -p 443 --quic-concurrency 100

# DNS query storm
./build/ddos_samurai/cli/samurai --attack-vector dns -t 10.0.0.53 -p 53 --dns-name example.com --dns-qtype A AAAA

# Amplification resilience evaluation
./build/ddos_samurai/cli/samurai --attack-vector dns-amp -t 10.0.0.53 -p 53 --reflector-file reflectors.txt

# Anomaly inspection suite
./build/ddos_samurai/cli/samurai --attack-vector anomaly -t 10.0.0.10 -p 443 --anomaly-suite

# PCAP replay engine
./build/ddos_samurai/cli/samurai --attack-vector pcap-replay --pcap-file sample.pcap --pcap-timing topspeed

# Run report generation
./build/ddos_samurai/cli/samurai -t 10.0.0.10 -p 443 --run-report --run-report-format both --run-report-dir reports

# License information
./build/ddos_samurai/cli/samurai --license-info

# License activation
./build/ddos_samurai/cli/samurai --license-activate --license-key SAM-XXXX-XXXX-XXXX-XXXX
```

## 2) All CLI Flags

Notes:
- Variables displayed in the `ENV` column represent default bindings read directly by the parser.
- Flags that do not read an environment variable at parser initialization may still be synchronized at runtime via `sync_runtime_env(...)`; see Section 3 for the exhaustive list.

### General Options

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--config` | `-` | `-` | - | Path to the YAML configuration file from which settings are parsed. |
| `--list-profiles` | `False` | `-` | - | List all available enterprise resilience and stress test profiles. |
| `-t, --target` | `-` | `-` | - | Target IP address or hostname (can also be defined in config). |
| `-p, --port` | `-` | `-` | - | Target destination port (can also be defined in config). |
| `--source-port` | `0` | `-` | - | Source port (0: random ephemeral port). |
| `-c, --count` | `10` | `-` | - | Total packet or request count (per-iteration batch size in soak profiles). |
| `-P, --protocol` | `tcp` | `tcp, udp, icmp` | - | Transport layer protocol (tcp, udp, or icmp). |
| `-d, --delay` | `0` | `-` | - | Delay between transmissions in seconds (mutually exclusive with RPS). |
| `--payload` | `-` | `-` | - | Static payload buffer to transmit with each request. |
| `--payload-file` | `-` | `-` | - | Path to newline-delimited payload file sampled across requests. |
| `--tcp-flags` | `S` | `S, A, F, R, SA, FA, RA, PA, U, E, C` | - | TCP header control flags (e.g., S, A, F, R, SA, FA, RA, PA, U, E, C). |
| `--ttl` | `-` | `-` | - | IPv4/IPv6 Time To Live / Hop Limit value. |
| `--tos` | `-` | `-` | - | IP Type of Service / DSCP decimal value (e.g., 16). |
| `--window` | `-` | `-` | - | TCP advertised window size in bytes. |
| `--os-fingerprint` | `False` | `-` | - | Enable OS network stack fingerprint randomization. |
| `--pad` | `0` | `-` | - | Minimum packet padding threshold in bytes. |
| `--ninja-mode` | `False` | `-` | - | Enable automated challenge evaluation (Ninja Mode) via headless browser. |
| `--fragment` | `False` | `-` | - | Enable IP fragmentation on the native CPU dataplane. |
| `--fragment-size` | `800` | `-` | - | Fragment payload chunk size in bytes (Default: 800). |
| `--attack-vector` | `basic` | `basic, http, http2, dns, websocket, quic, slowloris, slow-post, slow-read, ntp-amp, ssdp-amp, dns-amp, memcached-amp, ldap-amp, anomaly, pcap-replay` | - | Packet generation vector engine selection. |
| `--dns-name` | `example.com` | `-` | - | Query target domain name for DNS vectors. |
| `--dns-qtype` | `['A']` | `-` | - | DNS query types (multiple values supported: A, AAAA, MX, TXT, NS). |
| `--dns-edns` | `False` | `-` | - | Include EDNS0 OPT pseudo-record in DNS headers. |
| `--dns-nord` | `False` | `-` | - | Clear the Recursion Desired bit (rd=0) in DNS headers. |
| `--http-path` | `['/']` | `-` | - | HTTP target request path(s) (multiple entries supported). |
| `--http-method` | `GET` | `-` | - | HTTP request method (GET, POST, HEAD, PUT, DELETE). |
| `--http-concurrency` | `50` | `-` | - | Concurrent HTTP connections per worker process. |
| `--http-timeout` | `5.0` | `-` | - | HTTP request timeout threshold in seconds. |
| `--http-retries` | `0` | `-` | - | Number of HTTP request retry attempts on transient network failure. |
| `--http-scheme` | `http` | `http, https` | - | Protocol scheme for HTTP requests (http or https). |
| `--http-verify` | `true` | `-` | - | TLS/SSL certificate validation flag (true or false). |
| `--rps` | `0` | `-` | - | Target aggregate requests/packets per second (0: unthrottled line-rate). |
| `--jitter` | `0.0` | `-` | - | Randomized timing jitter ratio (0.0 to 1.0). |
| `--ramp` | `0.0` | `-` | - | Linear rate ramp-up duration in seconds. |
| `--profile` | `custom` | `web-stress, web-bypass, stateful-exhaustion, volumetric-udp, dns-infrastructure, slow-exhaustion, amplification-simulation, custom` | - | Enterprise resilience test profile preset (Default: custom). |
| `--scenario-file` | `-` | `-` | - | Persona-based user scenario YAML definition file. |
| `--scenario-mode` | `off` | `off, shadow, enforce` | - | Scenario execution enforcement mode. |
| `--scenario-vus` | `0` | `-` | - | Target virtual users concurrency (0: extract from scenario file). |
| `--scenario-ramp-seconds` | `0` | `-` | - | Virtual user ramp-up duration in seconds. |
| `--scenario-max-session-seconds` | `0` | `-` | - | Maximum session lifespan in seconds. |
| `--scenario-sla-profile` | `-` | `-` | - | SLA profile name or inline JSON SLA criteria override. |
| `--scenario-seed` | `1337` | `-` | - | Deterministic random seed for scenario execution flow. |
| `--role` | `standalone` | `standalone, master, slave` | - | Distributed cluster role selection. |
| `--confirm` | `False` | `-` | - | Acknowledge terms of engagement and bypass interactive prompt. |
| `--dry-run` | `False` | `-` | - | Validate configuration, construct sample packet buffers, and exit safely. |
| `-v, --verbose` | `False` | `-` | - | Enable detailed debug logging output. |
| `--log` | `samurai_logs.txt` | `-` | - | Destination file path for execution log events. |
| `--workers` | `12` | `-` | - | Number of worker processes spawned (Default: 12). |
| `--tls-profile` | `none` | `none, chrome_120, firefox_120, safari_17` | - | TLS / JA3 client handshake fingerprint emulation profile. |
| `--h2-profile` | `none` | `none, chrome_120, firefox_120, safari_17` | - | HTTP/2 SETTINGS frame fingerprint profile name. |
| `--h2-transport` | `auto` | `auto, httpx, hyper-h2` | - | HTTP/2 transport engine: auto, httpx, or hyper-h2. |
| `--ja3-profile` | `-` | `none, chrome_120, firefox_120, safari_17` | - | Deprecated alias for `--tls-profile`. |
| `--ech` | `False` | `-` | - | Enable Encrypted Client Hello (ECH) TLS extension (experimental). |
| `--http2-concurrency` | `100` | `-` | - | Concurrent multiplexed streams per worker for HTTP/2. |
| `--http2-connections` | `1` | `-` | - | Connection pool size for HTTP/2 sessions. |
| `--http2-streams-per-conn` | `100` | `-` | - | Maximum concurrent multiplexed streams per connection. |
| `--l7-profile-file` | `-` | `-` | - | JSON specification path for Layer 7 emulation engine. |
| `--l7-template-mode` | `compat` | `compat, profile` | - | Layer 7 emulation compilation mode: compat or profile. |
| `--ws-path` | `/` | `-` | - | URL endpoint path for WebSocket handshake. |
| `--ws-message` | `ping` | `-` | - | Payload message frame for WebSocket connections. |
| `--ws-concurrency` | `50` | `-` | - | Concurrent persistent WebSocket connection count. |
| `--ws-scenario` | `False` | `-` | - | Enable WebSocket state machine scenario (auth -> subscribe -> ping/pong). |
| `--ws-auth-message` | `-` | `-` | - | Authentication payload message for WebSocket state machine. |
| `--ws-subscribe-message` | `-` | `-` | - | Subscription message frame(s) for WebSocket scenario. |
| `--ws-ping-count` | `1` | `-` | - | Total ping frames dispatched per WebSocket session. |
| `--ws-await-response` | `False` | `-` | - | Block and await frame receipt after sending in WebSocket scenario. |
| `--quic-path` | `/` | `-` | - | Resource path for QUIC / HTTP/3 queries. |
| `--quic-method` | `GET` | `-` | - | HTTP request method for QUIC / HTTP/3. |
| `--quic-concurrency` | `50` | `-` | - | Concurrent stream count for QUIC / HTTP/3. |
| `--quic-streams-per-conn` | `0` | `-` | - | Multiplexed streams per native QUIC connection (0: auto). |
| `--quic-requests-per-conn` | `0` | `-` | - | Total requests per QUIC connection before rotation (0: keep alive). |
| `--quic-conn-pool-size` | `1` | `-` | - | Native QUIC connection pool capacity per worker. |
| `--quic-expect-status-min` | `200` | `-` | - | Minimum valid HTTP status code threshold for QUIC responses. |
| `--quic-expect-status-max` | `399` | `-` | - | Maximum valid HTTP status code threshold for QUIC responses. |
| `--quic-require-response-headers` | `True` | `-` | - | Enforce validation of incoming QUIC headers and status code. |
| `--quic-require-response-body` | `False` | `-` | - | Enforce mandatory non-empty body payload in QUIC responses. |
| `--quic-min-response-body-bytes` | `0` | `-` | - | Minimum body payload length in bytes for QUIC validation. |
| `--quic-expect-header-name` | `-` | `-` | - | Case-insensitive expected header key in QUIC response. |
| `--quic-expect-header-value-contains` | `-` | `-` | - | Expected substring within `--quic-expect-header-name` value. |
| `--quic-expect-body-substring` | `-` | `-` | - | Required substring pattern inside QUIC response body. |
| `--slowloris-concurrency` | `200` | `-` | - | Target concurrent slow connection count for Slowloris vector. |
| `--stealth-mode` | `False` | `-` | - | Deprecated (no-op). |
| `--payload-mutation` | `False` | `-` | - | Mutate packet payload bytes dynamically on each request. |
| `--proxy-list` | `-` | `-` | - | Path to newline-delimited forward proxy server list. |
| `--aggressive-mode` | `False` | `-` | - | Aggressive transmission mode prioritizing throughput over backpressure. |
| `--connection-pool` | `100` | `-` | - | Maximum TCP connection pool ceiling. |
| `--burst-mode` | `False` | `-` | - | High-intensity burst transmission mode. |
| `--spoof-ip` | `-` | `-` | - | Static spoofed source IPv4 address (e.g., 10.0.0.1). |
| `--realistic-spoof` | `False` | `-` | - | Source address spoofing using realistic autonomous system ranges. |
| `--evasion-techniques` | `-` | `case, url, comment` | - | Deprecated (no-op). |
| `--compute-backend` | `cpu` | `cpu, cuda` | - | Packet generation hardware accelerator: cpu or cuda. |
| `--stateful` | `False` | `-` | - | Enable full 3-way handshake stateful TCP engine (Viper-State). |
| `--sender-backend` | `xdp` | `xdp` | - | Raw network transmitter backend (mandatory: xdp). |
| `--sender-fallback-policy` | `fail` | `fail` | - | Backend fallback policy on failure (mandatory: fail). |
| `--stateful-runtime-backend` | `afxdp` | `afxdp` | - | Stateful connection tracking runtime backend (mandatory: afxdp). |
| `--dataplane-core-mode` | `required` | `off, auto, required` | - | Dataplane core engine enforcement mode (mandatory: required). |
| `--afpacket-hugepage-mode` | `off` | `off, auto, required` | - | AF_PACKET TX_RING hugepage memory allocation policy. |
| `--afpacket-hugepage-size-kb` | `2048` | `-` | `SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB` | AF_PACKET hugepage chunk size in kB (Default: 2048). |
| `--afpacket-ring-target-mb` | `64` | `-` | `SAMURAI_AF_PACKET_RING_TARGET_MB` | AF_PACKET TX_RING aggregate buffer allocation in MB (Default: 64). |
| `--afpacket-block-size-kb` | `0` | `-` | `SAMURAI_AF_PACKET_BLOCK_SIZE_KB` | AF_PACKET TX_RING block size in kB (0: auto). |
| `--afpacket-frame-size` | `0` | `-` | `SAMURAI_AF_PACKET_FRAME_SIZE` | AF_PACKET TX_RING frame slot size in bytes (0: auto). |
| `--afpacket-frames-per-block` | `64` | `-` | `SAMURAI_AF_PACKET_FRAMES_PER_BLOCK` | Target frames per ring block during auto configuration. |
| `--afpacket-poll-timeout-ms` | `1` | `-` | `SAMURAI_AF_PACKET_POLL_TIMEOUT_MS` | Base poll timeout in milliseconds for ring buffer space. |
| `--afpacket-spin-limit` | `2000` | `-` | `SAMURAI_AF_PACKET_SPIN_LIMIT` | Spin loop iteration ceiling before falling back to poll. |
| `--afpacket-busy-poll-us` | `0` | `-` | `SAMURAI_AF_PACKET_BUSY_POLL_US` | SO_BUSY_POLL microsecond parameter (0: disabled). |
| `--afpacket-qdisc-bypass` | `True` | `-` | - | Enable PACKET_QDISC_BYPASS on raw socket descriptors. |
| `--no-afpacket-qdisc-bypass` | `True` | `-` | - | Disable PACKET_QDISC_BYPASS kernel bypass flag. |
| `--afpacket-mlock-ring` | `False` | `-` | - | Lock ring memory pages into physical RAM with mlock. |
| `--no-afpacket-mlock-ring` | `False` | `-` | - | Disable mlock on ring buffer allocations. |
| `--afpacket-prefault-ring` | `True` | `-` | - | Prefault mmap pages during ring initialization. |
| `--no-afpacket-prefault-ring` | `True` | `-` | - | Disable ring memory page prefaulting. |
| `--lab-profile` | `off` | `off, dedicated` | `SAMURAI_LAB_PROFILE` | Laboratory deployment profile: off (dev) or dedicated (strict benchmark). |
| `--dp-queue-strategy` | `rr` | `rr, pin, map` | `SAMURAI_DP_QUEUE_STRATEGY` | Dataplane queue distribution: rr (round-robin), pin, or map. |
| `--dp-queues` | `1` | `-` | `SAMURAI_DP_QUEUES` | Active dataplane NIC queue count. |
| `--dp-queue-map` | `-` | `-` | `SAMURAI_DP_QUEUE_MAP` | Explicit worker to queue mapping specification (e.g., '1:0,2:1,3:2'). |
| `--xdp-enable` | `False` | `-` | - | Enable AF_XDP zero-copy transmission pipeline. |
| `--xdp-interface` | `-` | `-` | - | Dedicated network interface name for AF_XDP (e.g., eth0). |
| `--xdp-queue-id` | `0` | `-` | - | Hardware queue index for AF_XDP socket (Default: 0). |
| `--xdp-mode` | `0` | `0, 1, 2` | `SAMURAI_XDP_MODE` | AF_XDP attachment mode: 0 (SKB/Copy), 1 (Native/DRV), 2 (Hardware Offload). |
| `--xdp-attach-bpf` | `True` | `-` | - | Automatically compile and attach eBPF filter at startup. |
| `--no-xdp-attach-bpf` | `True` | `-` | - | Skip automated eBPF program attachment. |
| `--xdp-bpf-section` | `xdp_sock` | `-` | `SAMURAI_XDP_BPF_SECTION` | eBPF ELF section name to load (Default: xdp_sock). |
| `--xdp-bpf-obj` | `-` | `-` | `SAMURAI_XDP_BPF_OBJ` | Path to compiled XDP eBPF ELF binary. |
| `--xdp-xskmap-pin` | `-` | `-` | `SAMURAI_XDP_XSKMAP_PIN` | Path to pinned bpffs xsks_map file. |
| `--state-engine-mode, --engine-mode` | `auto` | `auto, required` | `SAMURAI_STATE_ENGINE_MODE` | Layer 4 state tracking engine mode: auto or required. |
| `--state-table-size` | `65536` | `-` | `SAMURAI_STATE_TABLE_SIZE` | State engine hash table bucket capacity. |
| `--state-lock-count` | `256` | `-` | `SAMURAI_STATE_LOCK_COUNT` | State table striped mutex lock partitions. |
| `--state-timeout-sec` | `60` | `-` | `SAMURAI_STATE_TIMEOUT_SEC` | Inactive connection state eviction timeout in seconds. |
| `--state-sweep-interval-ms` | `1000` | `-` | `SAMURAI_STATE_SWEEP_INTERVAL_MS` | Dead connection reclamation sweep period in milliseconds. |
| `--custom-tcp-mode` | `required` | `off, auto, required` | `SAMURAI_CUSTOM_TCP_MODE` | Userspace Custom TCP stack mode: off, auto, or required. |
| `--topo-spec-json` | `-` | `-` | - | ASTF-style client/server network topology JSON specification. |
| `--topo-seed` | `-1` | `-` | - | Deterministic seed for topology tuple generation. |
| `--topo-strict, --no-topo-strict` | `True` | `-` | - | Enforce strict schema validation on topology input. |
| `--custom-tcp-backend` | `af_xdp` | `af_xdp` | `SAMURAI_CUSTOM_TCP_BACKEND` | Custom TCP stack transmission backend (mandatory: af_xdp). |
| `--custom-tcp-initial-rto-ms` | `250` | `-` | `SAMURAI_CUSTOM_TCP_INITIAL_RTO_MS` | Initial Retransmission Timeout (RTO) in milliseconds. |
| `--custom-tcp-max-retransmits` | `5` | `-` | `SAMURAI_CUSTOM_TCP_MAX_RETRANSMITS` | Maximum retransmission retry budget before abort. |
| `--custom-tcp-connect-timeout-ms` | `3000` | `-` | `SAMURAI_CUSTOM_TCP_CONNECT_TIMEOUT_MS` | TCP 3-way handshake SYN-ACK timeout threshold in milliseconds. |
| `--custom-tcp-idle-timeout-ms` | `30000` | `-` | `SAMURAI_CUSTOM_TCP_IDLE_TIMEOUT_MS` | Established connection idle timeout threshold in milliseconds. |
| `--kpi-gate-profile` | `off` | `off, dev, ci_safe, developer_fallback, dedicated_lab, persistent_stream_strict` | `SAMURAI_KPI_GATE_PROFILE` | KPI validation gate criteria profile. |
| `--kpi-hard-fail` | `False` | `-` | - | Return non-zero exit code if KPI validation thresholds fail. |
| `--l7-engine` | `python` | `python, c_state` | `SAMURAI_L7_ENGINE` | Layer 7 state machine engine runtime: python or c_state. |
| `--l7-http2-engine` | `auto` | `python, c_state, auto` | `SAMURAI_L7_HTTP2_ENGINE` | HTTP/2 state engine selection: python, c_state, or auto. |
| `--l7-quic-engine` | `auto` | `python, c_state, auto` | `SAMURAI_L7_QUIC_ENGINE` | QUIC engine implementation: python, c_state, or auto. |
| `--l7-quic-require-native` | `False` | `-` | `SAMURAI_L7_QUIC_REQUIRE_NATIVE` | Enforce native C QUIC implementation without python bridge fallback. |
| `--l7-quic-auto-bridge` | `False` | `-` | `SAMURAI_L7_QUIC_AUTO_BRIDGE` | Enable automatic Python bridge fallback if native QUIC is missing. |
| `--l7-quic-bridge-autopromote` | `False` | `-` | `SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE` | Automatically promote bridge implementation in capability matrix. |
| `--l7-fallback-policy` | `allow` | `allow, fail` | `SAMURAI_L7_FALLBACK_POLICY` | Fallback policy for C to Python Layer 7 transitions: allow or fail. |
| `--l7-capability-strict` | `False` | `-` | `SAMURAI_L7_CAPABILITY_STRICT` | Strict capability validation: fail immediately if features are missing. |
| `--l7-session-repeats` | `1` | `-` | - | Number of session execution loops per virtual user. |
| `--l7-max-active-sessions` | `0` | `-` | - | Ceiling on concurrent active Layer 7 sessions (0: unconstrained). |
| `--gpu-template-pool-size-l4` | `10` | `-` | `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4` | CUDA Layer 4 packet template pool capacity. |
| `--gpu-template-pool-size-l7` | `50` | `-` | `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7` | CUDA Layer 7 packet template pool capacity. |
| `--gpu-ring-capacity` | `3` | `-` | `SAMURAI_GPU_RING_CAPACITY` | Producer-consumer ring buffer depth for CUDA generation. |
| `--gpu-batch-size` | `100000` | `-` | `SAMURAI_GPU_BATCH` | Packet batch allocation size per GPU kernel launch. |
| `--gpu-stream-count` | `3` | `-` | `SAMURAI_GPU_STREAMS` | CUDA stream count allocated for concurrent copy/compute overlap. |
| `--gpu-pipeline-depth` | `2` | `-` | `SAMURAI_GPU_PIPELINE_DEPTH` | Ready batch pipeline queue threshold. |
| `--gpu-full-variation, --no-gpu-full-variation` | `True` | `-` | `SAMURAI_GPU_FULL_VARIATION` | Generate full IP/TCP header entropy on the GPU kernel hot-path. |
| `--gpu-pinned-max-mb` | `512` | `-` | `SAMURAI_GPU_PINNED_MAX_MB` | Pinned host RAM buffer allocation limit in MB. |
| `--gpu-packet-zerocopy-output, --no-gpu-packet-zerocopy-output` | `False` | `-` | `SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT` | Enable mapped host zero-copy buffer output for CUDA pipeline. |
| `--gpu-kernel-mode` | `batch` | `batch, persistent` | `SAMURAI_GPU_KERNEL_MODE` | CUDA kernel execution paradigm: batch or persistent. |
| `--gpu-stream-api` | `compat` | `compat, stream` | `SAMURAI_GPU_STREAM_API` | GPU stream API mode: compat (wrapper) or stream (native lifecycle). |
| `--gpu-epoch-ms` | `50` | `-` | `SAMURAI_GPU_EPOCH_MS` | Quota epoch duration in milliseconds for persistent kernel mode. |
| `--gpu-queue-count` | `1` | `-` | `SAMURAI_GPU_QUEUE_COUNT` | Ring queue count per GPU worker in persistent mode. |
| `--gpu-heartbeat-ms` | `500` | `-` | `SAMURAI_GPU_HEARTBEAT_MS` | Persistent kernel heartbeat publication period in milliseconds. |
| `--gpu-no-progress-ms` | `2000` | `-` | `SAMURAI_GPU_NO_PROGRESS_MS` | Watchdog timeout for persistent kernel stall recovery. |
| `--gpu-rng-seed` | `1234` | `-` | `SAMURAI_GPU_RNG_SEED` | Deterministic random seed for GPU payload generation. |
| `--gpu-defense-mode` | `off` | `on, off` | `SAMURAI_GPU_DEFENSE_MODE` | Hardware-accelerated traffic inspection and classifier mode: on or off. |
| `--gpu-classifier-runtime` | `tensorrt` | `tensorrt` | `SAMURAI_GPU_CLASSIFIER_RUNTIME` | Neural network classifier runtime (tensorrt). |
| `--gpu-classifier-engine-path` | `-` | `-` | `SAMURAI_GPU_CLASSIFIER_ENGINE_PATH` | File path to pre-compiled TensorRT .engine serialized model. |
| `--gpu-rdma-mode` | `auto` | `auto, direct, host_staging, doca_gpunetio` | `SAMURAI_GPU_RDMA_MODE` | GPUDirect RDMA transport mode: auto, direct, host_staging, or doca_gpunetio. |
| `--gpu-rdma-strict, --no-gpu-rdma-strict` | `False` | `-` | `SAMURAI_GPU_RDMA_STRICT` | Strict RDMA enforcement: fail immediately without staging fallback. |
| `--gpu-batch-max` | `1024` | `-` | `SAMURAI_GPU_BATCH_MAX` | Maximum dynamic batch size for classifier inference. |
| `--gpu-batch-flush-timeout-ms` | `2` | `-` | `SAMURAI_GPU_BATCH_FLUSH_TIMEOUT_MS` | Classifier dynamic batch flush timeout in milliseconds. |
| `--gpu-rx-pipeline` | `off` | `on, off` | `SAMURAI_GPU_RX_PIPELINE` | NIC RX to GPU hardware classifier pipeline mode: on or off. |
| `--gpu-rx-iface` | `-` | `-` | `SAMURAI_GPU_RX_IFACE` | Ingress capture interface for GPU RX pipeline (Default: default route). |
| `--gpu-rx-duration-s` | `10` | `-` | `SAMURAI_GPU_RX_DURATION_S` | Execution duration in seconds for GPU RX capture. |
| `--gpu-rx-batch-size` | `256` | `-` | `SAMURAI_GPU_RX_BATCH_SIZE` | Packet classification batch size for GPU RX pipeline. |
| `--gpu-rx-max-packets` | `100000` | `-` | `SAMURAI_GPU_RX_MAX_PACKETS` | Maximum packet intake ceiling for GPU RX pipeline. |
| `--gpu-rx-snaplen` | `2048` | `-` | `SAMURAI_GPU_RX_SNAPLEN` | Capture snapshot length in bytes for GPU RX pipeline. |
| `--gpu-vector-engine` | `gpu_cuda` | `gpu_cuda` | - | GPU vector traffic generation planner engine. |

### IP Spoofing Options

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--spoof` | `False` | `-` | - | Enable source IP address spoofing (Default mode: realistic). |
| `--spoof-mode` | `realistic` | `random, realistic, subnet, list` | - | Source IP spoofing distribution mode. |
| `--spoof-subnet` | `-` | `-` | - | CIDR subnet definition for 'subnet' spoofing mode (e.g., 192.168.1.0/24). |
| `--spoof-list-file` | `-` | `-` | - | File path containing source IP addresses for 'list' mode. |

### Amplification Simulation Options

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--reflector-file` | `-` | `-` | - | File path containing reflector server IP endpoints for amplification simulation. |

### Distributed Control Plane

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--control-listen` | `0.0.0.0:5099` | `-` | - | Master gRPC server listening address and port (Default: 0.0.0.0:5099). |
| `--control-endpoints` | `-` | `-` | - | Slave target master endpoints (e.g., host1:5099,host2:5099). |
| `--cluster-secret` | `-` | `-` | `SAMURAI_CLUSTER_SECRET` | Cluster mutual authentication token across nodes. |
| `--control-tls-cert` | `-` | `-` | - | gRPC server TLS certificate path (PEM format). |
| `--control-tls-key` | `-` | `-` | - | gRPC server TLS private key path (PEM format). |
| `--control-tls-ca` | `-` | `-` | - | gRPC TLS CA certificate bundle for slave node verification. |
| `--control-tls-client-ca` | `-` | `-` | - | Client CA bundle for master node mutual TLS (mTLS) enforcement. |
| `--control-tls-client-cert` | `-` | `-` | - | Client TLS certificate path for mTLS connections. |
| `--control-tls-client-key` | `-` | `-` | - | Client TLS private key path for mTLS connections. |
| `--control-require-client-auth` | `False` | `-` | - | Enforce mandatory client certificate validation on master gRPC server. |
| `--control-insecure` | `False` | `-` | - | Permit unencrypted plaintext gRPC transport (development/isolated lab only). |
| `--heartbeat-interval-ms` | `2000` | `-` | - | Slave heartbeat reporting interval in milliseconds. |
| `--heartbeat-timeout-ms` | `6000` | `-` | - | Master node heartbeat expiration threshold in milliseconds. |
| `--worker-registration-timeout-s` | `30` | `-` | - | Timeout budget in seconds for slave registration during startup. |
| `--master-poll-interval-ms` | `250` | `-` | - | Master shard status polling loop interval in milliseconds. |
| `--control-max-workers` | `0` | `-` | - | Master gRPC thread pool capacity (0: auto-tuned). |
| `--control-dispatch-workers` | `32` | `-` | - | Master concurrency limit for parallel shard dispatch RPCs. |
| `--control-stop-grace-s` | `1.0` | `-` | - | Master graceful shutdown period for gRPC server in seconds. |
| `--worker-status-probe` | `True` | `-` | - | Periodic GetWorkerStatus probe to track shard completion fallback. |
| `--stop-shard-retries` | `3` | `-` | - | Retry attempts for StopShard RPC on graceful termination. |
| `--stop-shard-retry-delay-ms` | `250` | `-` | - | Delay between StopShard retry attempts in milliseconds. |
| `--slave-master-timeout-s` | `30` | `-` | - | Slave abort threshold in seconds after losing master heartbeat. |
| `--stats-stream-enable` | `True` | `-` | - | Enable real-time streaming stats RPC from slave to master. |
| `--stats-stream-interval-ms` | `500` | `-` | - | Real-time statistics stream push interval in milliseconds. |
| `--distributed-metrics-textfile` | `-` | `-` | - | Master Prometheus textfile metrics export path. |
| `--distributed-metrics-prefix` | `samurai_distributed` | `-` | - | Prometheus metric naming prefix for distributed measurements. |
| `--shard-kpi-max-error-rate-pct` | `-1.0` | `-` | - | Per-shard KPI gate maximum allowable error rate percentage (-1: disabled). |
| `--shard-kpi-fail-on-exitcode` | `True` | `-` | - | Mark shard as failed if worker process exit code is non-zero. |
| `--management-api-enable` | `False` | `-` | - | Enable master runtime management REST/HTTP API. |
| `--management-api-listen` | `127.0.0.1:8089` | `-` | - | Management API listening address and port (host:port). |
| `--management-api-auth-token` | `-` | `-` | `SAMURAI_MANAGEMENT_API_AUTH_TOKEN` | Bearer token secret for management API authentication. |
| `--management-api-admin-token` | `-` | `-` | `SAMURAI_MANAGEMENT_API_ADMIN_TOKEN` | Dedicated admin role Bearer token for management API. |
| `--management-api-operator-token` | `-` | `-` | `SAMURAI_MANAGEMENT_API_OPERATOR_TOKEN` | Dedicated operator role Bearer token for management API. |
| `--management-api-viewer-token` | `-` | `-` | `SAMURAI_MANAGEMENT_API_VIEWER_TOKEN` | Dedicated viewer read-only Bearer token for management API. |
| `--management-api-jwt-secret` | `-` | `-` | `SAMURAI_MANAGEMENT_API_JWT_SECRET` | HMAC-SHA256 secret for management API JWT verification. |
| `--management-api-jwt-role-claim` | `role` | `-` | - | JWT claim name representing authorization role. |
| `--management-api-jwt-tenant-claim` | `tenant_namespace` | `-` | - | JWT claim name representing tenant isolation namespace. |
| `--management-api-trusted-identity-secret` | `-` | `-` | `SAMURAI_MANAGEMENT_API_TRUSTED_IDENTITY_SECRET` | Shared secret to validate reverse proxy SSO headers. |
| `--management-api-trusted-identity-secret-header` | `x-samurai-auth-proxy-secret` | `-` | - | Header key for trusted reverse proxy secret validation. |
| `--management-api-trusted-identity-role-header` | `x-auth-request-role` | `-` | - | Header key for proxy-injected role identity. |
| `--management-api-trusted-identity-tenant-header` | `x-auth-request-tenant` | `-` | - | Header key for proxy-injected tenant identity. |
| `--management-api-live-interval-ms` | `1000` | `-` | - | Live SSE and WebSocket metrics broadcast interval in milliseconds. |
| `--management-events-max` | `200` | `-` | - | Maximum event log history capacity retained in memory. |
| `--control-rbac-enable` | `False` | `-` | - | Enable Role-Based Access Control (RBAC) on gRPC control plane. |
| `--control-rbac-default-role` | `viewer` | `admin, operator, viewer, worker` | - | Fallback role assigned when secret token does not match. |
| `--control-rbac-admin-secret` | `-` | `-` | `SAMURAI_CONTROL_RBAC_ADMIN_SECRET` | Secret token mapped to RBAC admin privileges. |
| `--control-rbac-operator-secret` | `-` | `-` | `SAMURAI_CONTROL_RBAC_OPERATOR_SECRET` | Secret token mapped to RBAC operator privileges. |
| `--control-rbac-viewer-secret` | `-` | `-` | `SAMURAI_CONTROL_RBAC_VIEWER_SECRET` | Secret token mapped to RBAC viewer read-only privileges. |
| `--control-rbac-worker-secret` | `-` | `-` | `SAMURAI_CONTROL_RBAC_WORKER_SECRET` | Secret token mapped to RBAC worker node operations. |
| `--control-jwt-secret` | `-` | `-` | `SAMURAI_CONTROL_JWT_SECRET` | JWT HMAC secret for gRPC control plane authentication. |
| `--control-jwt-role-claim` | `role` | `-` | - | Claim key used to parse authorization role in gRPC JWT. |
| `--control-jwt-tenant-claim` | `tenant_namespace` | `-` | - | Claim key used to parse tenant namespace in gRPC JWT. |
| `--ha-enable` | `False` | `-` | - | Enable High Availability (HA) leader election framework for master. |
| `--ha-mode` | `static` | `static, file-lock, redis, etcd, raft` | - | HA election backend: static, file-lock, redis, etcd, or raft. |
| `--ha-node-id` | `-` | `-` | - | HA cluster node identifier (Default: machine hostname). |
| `--ha-peer-nodes` | `-` | `-` | - | CSV list of peer node identifiers for static leader election. |
| `--ha-lease-path` | `/tmp/samurai_master_lease.json` | `-` | - | File lock lease state path for file-lock HA mode. |
| `--ha-lease-seconds` | `15.0` | `-` | - | Lease Time-to-Live (TTL) duration in seconds for HA leadership. |
| `--ha-renew-interval-s` | `5.0` | `-` | - | Lease renewal interval in seconds for active leader. |
| `--ha-wait-for-leader` | `True` | `-` | - | Enable follower nodes to await leader lease expiration for failover. |
| `--ha-acquire-timeout-s` | `0.0` | `-` | - | Maximum time budget in seconds to acquire leadership (0: indefinite). |
| `--ha-retry-interval-s` | `1.0` | `-` | - | Retry delay between leader acquisition attempts in seconds. |
| `--ha-redis-url` | `redis://127.0.0.1:6379/0` | `-` | - | Redis connection URL for redis HA mode. |
| `--ha-redis-key` | `samurai:ha:master` | `-` | - | Redis key name representing master leader lock. |
| `--ha-etcd-endpoints` | `127.0.0.1:2379` | `-` | - | CSV list of etcd cluster endpoints (host:port). |
| `--ha-etcd-key` | `samurai/ha/master` | `-` | - | Key path in etcd key-value store for master lease. |
| `--ha-etcd-timeout-s` | `3.0` | `-` | - | Client request timeout in seconds for etcd transactions. |
| `--ha-raft-listen` | `127.0.0.1:7000` | `-` | - | Listening address and port for native Raft consensus RPC. |
| `--ha-raft-peers` | `-` | `-` | - | CSV list of Raft peers in format node-id@host:port. |
| `--ha-raft-election-timeout-min-ms` | `900` | `-` | - | Lower bound for randomized Raft election timeout in milliseconds. |
| `--ha-raft-election-timeout-max-ms` | `1500` | `-` | - | Upper bound for randomized Raft election timeout in milliseconds. |
| `--ha-raft-heartbeat-interval-ms` | `250` | `-` | - | Raft leader append entries heartbeat period in milliseconds. |
| `--ha-raft-snapshot-threshold` | `2048` | `-` | - | Committed entry threshold to trigger Raft log compaction. |
| `--ha-raft-snapshot-keep-entries` | `512` | `-` | - | Number of trailing log entries retained in memory post-compaction. |
| `--multi-master-enable` | `False` | `-` | - | Enable multi-region multi-master coordinator backed by Redis. |
| `--multi-master-region-id` | `-` | `-` | `SAMURAI_MULTI_MASTER_REGION_ID` | Geographic region identifier for master node (e.g., eu-central). |
| `--multi-master-redis-url` | `redis://127.0.0.1:6379/0` | `-` | `SAMURAI_MULTI_MASTER_REDIS_URL` | Redis URL for multi-master cluster state coordination. |
| `--multi-master-namespace` | `default` | `-` | `SAMURAI_MULTI_MASTER_NAMESPACE` | Key prefix namespace for multi-master state isolation. |
| `--multi-master-heartbeat-ttl-s` | `15` | `-` | `SAMURAI_MULTI_MASTER_HEARTBEAT_TTL_S` | Region registration heartbeat TTL in seconds. |
| `--multi-master-dequeue-max` | `3` | `-` | `SAMURAI_MULTI_MASTER_DEQUEUE_MAX` | Maximum delegated tasks pulled per coordinator polling tick. |
| `--control-rbac-audit-log-path` | `-` | `-` | `SAMURAI_CONTROL_RBAC_AUDIT_LOG_PATH` | File path for append-only JSONL RBAC security audit events. |
| `--control-rbac-audit-success` | `False` | `-` | - | Log successful operations in addition to rejected requests. |
| `--control-tls-watch-files` | `True` | `-` | - | Monitor TLS certificates on disk and hot-reload gRPC credentials. |
| `--control-tls-reload-interval-s` | `2.0` | `-` | `SAMURAI_CONTROL_TLS_RELOAD_INTERVAL_S` | File watcher check period for certificate updates in seconds. |
| `--job-timeout-s` | `0` | `-` | - | Maximum execution lifespan for distributed jobs in seconds (0: unlimited). |
| `--job-queue-json` | `-` | `-` | - | Multi-job JSON batch configuration specification string. |
| `--shard-unit-count` | `0` | `-` | - | Micro-shard packet allocation for dynamic rebalancing (0: auto). |
| `--shard-strategy` | `equal` | `equal, capability, region` | - | Shard scheduling algorithm: equal, capability, or region. |
| `--region-aware-routing` | `False` | `-` | - | Route shards based on proximity between target and worker regions. |
| `--worker-region` | `-` | `-` | `SAMURAI_WORKER_REGION` | Node locality label (e.g., eu-west-1, us-east-1). |
| `--target-region` | `-` | `-` | `SAMURAI_TARGET_REGION` | Target service region for region-aware shard placement. |
| `--cross-region-heartbeat-factor` | `1.6` | `-` | - | Multiplier applied to heartbeat timeout for cross-region nodes. |
| `--on-worker-loss` | `continue` | `abort, continue` | - | Policy on worker node loss: abort benchmark or record loss and continue. |
| `--control-discovery-k8s` | `False` | `-` | - | Discover master endpoints dynamically using Kubernetes API endpoints. |
| `--control-k8s-namespace` | `default` | `-` | - | Kubernetes namespace for dynamic cluster discovery. |
| `--control-k8s-selector` | `-` | `-` | - | Kubernetes label selector for worker pod discovery (e.g., app=samurai-worker). |
| `--control-k8s-port` | `5099` | `-` | - | Target service port for Kubernetes endpoint discovery (Default: 5099). |
| `--tenant-namespace` | `-` | `-` | `SAMURAI_TENANT_NAMESPACE` | Multi-tenant isolation namespace for control plane resources. |
| `--control-autoscale-enable` | `False` | `-` | - | Dynamically autoscale Kubernetes worker replicas based on shard load. |
| `--control-autoscale-namespace` | `default` | `-` | - | Target Kubernetes namespace for worker autoscaling. |
| `--control-autoscale-target-kind` | `deployment` | `deployment, statefulset` | - | Target Kubernetes resource kind: deployment or statefulset. |
| `--control-autoscale-target-name` | `-` | `-` | - | Target workload resource name in Kubernetes. |
| `--control-autoscale-min-replicas` | `1` | `-` | - | Minimum worker replica floor for autoscaling. |
| `--control-autoscale-max-replicas` | `100` | `-` | - | Maximum worker replica ceiling for autoscaling. |
| `--control-autoscale-step` | `1` | `-` | - | Pod replica step increment/decrement for scale adjustments. |
| `--control-autoscale-cooldown-s` | `15.0` | `-` | - | Stabilization cooldown duration in seconds between scaling actions. |
| `--control-autoscale-shards-per-worker` | `4` | `-` | - | Capacity model target: scheduled shards per worker pod. |
| `--control-autoscale-idle-scale-down-s` | `60.0` | `-` | - | Idle duration threshold before scaling down to minimum replica floor. |

### Traffic Model (Mamba-2 Planner v1)

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--traffic-model` | `none` | `none, mamba2` | - | Stateful traffic generation planner model: none or mamba2. (Runtime integration is disabled; use training/mamba2_monolith.py). |
| `--traffic-model-checkpoint` | `-` | `-` | - | Model checkpoint weight file path. |
| `--traffic-model-config` | `-` | `-` | - | Model architecture configuration YAML path. |
| `--traffic-model-device` | `cpu` | `cpu` | - | Model inference execution device (v1: cpu only). |
| `--traffic-model-seed` | `1337` | `-` | - | Deterministic random seed for traffic sequence generation. |
| `--traffic-model-label-mix` | `benign=0.4,evasive=0.4,aggressive=0.2` | `-` | - | Traffic persona proportion distribution ratio. |
| `--traffic-model-session-len` | `24` | `-` | - | Maximum event token sequence length per generated session. |
| `--traffic-model-planner-batch` | `128` | `-` | - | Session generation batch size per inference pass. |
| `--traffic-model-timeout-ms` | `2500` | `-` | - | Planner model inference timeout in milliseconds. |
| `--traffic-model-fallback` | `static` | `static, fail` | - | Policy on inference timeout or error: static template or fail. |
| `--traffic-model-export-events` | `-` | `-` | - | JSONL destination path for generated synthetic event tokens. |
| `--traffic-model-dataset-capture` | `-` | `-` | - | Capture runtime worker events directly into a training JSONL dataset. |
| `--traffic-model-pcap-profile` | `-` | `-` | - | PCAP feature extraction profile identifier for dataset ingestion. |
| `--traffic-model-dry-validate` | `False` | `-` | - | Execute planner sequence generation and validation without network transmission. |

### GPU PCAP Generator (Test)

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--gpu-pcap` | `False` | `-` | - | Synthesize binary PCAP trace on GPU accelerator and exit without transmission. |
| `--gpu-pcap-duration` | `10` | `-` | - | Generated trace virtual capture duration in seconds. |
| `--gpu-pcap-pps` | `10000` | `-` | - | Target packets per second rate encoded into PCAP timestamps. |
| `--gpu-pcap-mode` | `mix` | `mix, tcp, udp` | - | Network traffic layer composition: mix, tcp, or udp. |
| `--gpu-pcap-src-ip` | `192.168.1.100` | `-` | - | Base source IPv4 address. |
| `--gpu-pcap-dst-ip` | `-` | `-` | - | Destination IPv4 address (Default: `--target` or 127.0.0.1). |
| `--gpu-pcap-tcp-port` | `0` | `-` | - | Target TCP port (0: defaults to `--port` or 80). |
| `--gpu-pcap-udp-port` | `0` | `-` | - | Target UDP port (0: defaults to `--port` or 53). |
| `--gpu-pcap-chunk` | `200000` | `-` | - | Packet buffer generation chunk size per kernel iteration. |
| `--gpu-pcap-seed` | `0` | `-` | - | Random seed for PCAP packet generation (0: randomized). |
| `--gpu-pcap-flow-count` | `4096` | `-` | - | Size of synthetic flow table pool for diverse IP/port tuples. |
| `--gpu-pcap-realistic` | `False` | `-` | - | High-realism flow modeling (TTL/TOS jitter, stateful TCP sequences, valid UDP checksums). |
| `--gpu-pcap-udp-checksum` | `False` | `-` | - | Compute standard RFC 768 UDP checksums inside GPU kernel. |
| `--gpu-pcap-variable-size` | `False` | `-` | - | Enable realistic bimodal packet size distribution modeling. |
| `--gpu-pcap-mtu` | `1500` | `-` | - | Maximum Layer 3 MTU threshold (128 to 1500 bytes). |
| `--gpu-pcap-size-profile` | `mixed` | `mixed, web, dns` | - | Packet size distribution model: mixed, web, or dns. |
| `--gpu-pcap-realism-report` | `False` | `-` | - | Calculate V3 realism score metrics and export JSON evaluation report. |
| `--gpu-pcap-realism-baseline` | `-` | `-` | - | Reference real-world PCAP trace to compute statistical similarity. |
| `--gpu-pcap-realism-sample` | `100000` | `-` | - | Maximum packet sample window inspected during realism evaluation. |
| `--gpu-pcap-realism-out` | `-` | `-` | - | Destination path for realism evaluation report JSON. |
| `--gpu-pcap-out` | `-` | `-` | - | Destination file path for generated PCAP trace. |
| `--gpu-pcap-run-report` | `False` | `-` | - | Produce structured benchmark execution report for GPU PCAP synthesis. |
| `--gpu-pcap-run-report-format` | `both` | `json, md, both` | - | Output format for execution report: json, md, or both. |
| `--gpu-pcap-run-report-out` | `-` | `-` | - | File path prefix for PCAP generator execution report. |

### Pacing Options (Deterministic Timing)

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--pacing-mode` | `none` | `none, rps, ipg, burst` | - | Packet transmission pacing engine: none (unthrottled), rps, ipg, or burst. |
| `--ipg` | `0` | `-` | - | Precise Inter-Packet Gap in nanoseconds (used with `--pacing-mode ipg`). |
| `--burst-size` | `64` | `-` | - | Packet quantum transmitted per burst cycle (Default: 64). |
| `--burst-gap` | `0` | `-` | - | Inter-burst pause interval in nanoseconds. |
| `--jitter-model` | `none` | `none, uniform, gaussian, exponential` | - | Statistical distribution model applied to timing jitter. |
| `--jitter-pct` | `0.0` | `-` | - | Timing jitter variance factor (0.0 to 1.0) applied across base interval. |
| `--pin-cpu` | `-1` | `-` | - | Bind the pacing thread to a specific dedicated CPU core (-1: auto). |
| `--use-so-txtime` | `False` | `-` | - | Offload packet scheduling to Linux kernel SO_TXTIME / ETF hardware queues. |

### Safety Options

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--allow-target` | `[]` | `-` | - | Explicit authorized target IP or CIDR range (can be specified multiple times). |
| `--allow-public-target` | `False` | `-` | - | Allow test execution against public routable IP targets (restricted to authorized tests). |
| `--safety-global-deny-target` | `[]` | `-` | - | Unconditionally blacklisted destination IP or CIDR addresses. |
| `--safety-auto-abort` | `True` | `-` | - | Automatically terminate all workers if guardrail anomaly alerts trigger. |
| `--disable-safety-auto-abort` | `False` | `-` | - | Disable automatic worker termination upon telemetry guardrail alarms. |

### Anomaly Packet Options

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--anomaly-types` | `-` | `-` | - | Bitmask or list of anomaly patterns (0: InvalidIHL, 1: InvalidIPLen, 2: InvalidIPVer, 3: InvalidProto, 4: TCPFlagAbuse, 5: InvalidTCPOffset, 6: OverlapFrags, 7: TinyFrags, 8: LandAttack, 9: InvalidChecksum, 10: TTLAnomaly, 11: MalformedOptions). |
| `--anomaly-intensity` | `75` | `-` | - | Degree of protocol malformation intensity (0 to 100, Default: 75). |
| `--anomaly-suite` | `False` | `-` | - | Enable complete anomaly stress test suite (standard, overlapping, and tiny fragments). |

### PCAP Replay Options

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--pcap-file` | `-` | `-` | - | Path to source PCAP or PCAP-NG capture file. |
| `--pcap-timing` | `original` | `original, topspeed, multiplier, rps` | - | Replay timing strategy: original (inter-packet delta), topspeed, multiplier, or rps. |
| `--pcap-speed` | `1.0` | `-` | - | Replay speed factor for multiplier timing mode (e.g., 2.0 = 2x line speed). |
| `--pcap-loops` | `1` | `-` | - | Number of replay iterations (0: continuous loop). |
| `--pcap-max-packets` | `0` | `-` | - | Maximum packet count to replay from trace (0: replay entire file). |
| `--pcap-filter-proto` | `-` | `-` | - | Protocol filter for replay filtering (tcp, udp, icmp). |
| `--pcap-filter-src-ip` | `-` | `-` | - | Filter packets by source IP or CIDR block. |
| `--pcap-filter-dst-ip` | `-` | `-` | - | Filter packets by destination IP or CIDR block. |
| `--pcap-filter-src-port` | `-` | `-` | - | Filter packets matching specific source port. |
| `--pcap-filter-dst-port` | `-` | `-` | - | Filter packets matching specific destination port. |
| `--pcap-filter-min-len` | `0` | `-` | - | Discard packets with frame length smaller than threshold in bytes. |
| `--pcap-filter-max-len` | `0` | `-` | - | Discard packets with frame length larger than threshold in bytes (0: unlimited). |
| `--pcap-strip-eth` | `False` | `-` | - | Strip L2 Ethernet frame headers and transmit as raw L3 IP packets. |
| `--pcap-use-l2` | `False` | `-` | - | Transmit raw packets via L2 TX_RING sockets preserving original Ethernet headers. |
| `--pcap-no-flow-aware` | `False` | `-` | - | Disable TCP stateful sequence and acknowledgment delta rewriting during replay. |
| `--pcap-src-ip-override` | `-` | `-` | - | Overwrite source IP of all replayed frames with specified IP. |
| `--pcap-src-port-override` | `-` | `-` | - | Overwrite source port of all replayed frames with specified port. |
| `--pcap-batch-size` | `512` | `-` | - | Batch transmission size for timing-aware replay mode (Default: 512). |
| `--pcap-info` | `False` | `-` | - | Print capture metadata summary and exit without transmission. |

### Reporting and Self-Test Options

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--self-test` | `False` | `-` | - | Execute automated unit test discovery suite and exit. |
| `--run-report` | `False` | `-` | - | Generate formal run report artifact upon benchmark completion. |
| `--run-report-format` | `both` | `json, md, both` | - | Report serialization format: json, md, or both. |
| `--run-report-out` | `-` | `-` | - | Base filename prefix for run report artifacts (without file extension). |
| `--run-report-dir` | `reports/runs` | `-` | - | Destination directory path for report artifacts (Default: reports/runs). |
| `--soak-profile` | `none` | `none, 1h, 6h, 24h` | - | Soak longevity test profile with predefined validation criteria (1h, 6h, 24h). |
| `--soak-snapshot-interval` | `0` | `-` | - | Telemetry snapshot logging period in seconds (0: profile default). |
| `--soak-warmup-s` | `0` | `-` | - | Warmup duration in seconds before locking baseline performance metrics. |
| `--soak-max-error-rate-pct` | `-` | `-` | - | Soak pass/fail criterion: maximum allowable error percentage. |
| `--soak-max-pps-drop-pct` | `-` | `-` | - | Soak pass/fail criterion: maximum allowable PPS degradation relative to baseline. |
| `--soak-max-rss-growth-mb` | `-` | `-` | - | Soak pass/fail criterion: maximum permissible resident memory (RSS) expansion. |
| `--soak-max-vram-growth-mb` | `-` | `-` | - | Soak pass/fail criterion: maximum permissible GPU VRAM memory expansion. |
| `--soak-max-pinned-growth-mb` | `-` | `-` | - | Soak pass/fail criterion: maximum permissible pinned host buffer expansion. |
| `--soak-max-backlog` | `-` | `-` | - | Soak pass/fail criterion: maximum unconsumed packet queue backlog ceiling. |
| `--loss-telemetry` | `auto` | `auto, 0, 1` | - | Interface packet loss telemetry collection mode: auto, 0, or 1. |
| `--loss-iface` | `-` | `-` | - | Network interface tracked for packet loss telemetry (Default: primary route). |
| `--loss-fail-pct` | `5.0` | `-` | - | Packet loss threshold percentage triggering benchmark failure (Default: 5%). |
| `--loss-report-out` | `-` | `-` | - | File path to export structured loss telemetry measurements as JSON. |

### Fault Injection

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--fault-inject` | `[]` | `sender-restart, nic-blip, gpu-stream-error, mix` | - | Inject simulated infrastructure faults during soak testing. |
| `--fault-after-s` | `0.0` | `-` | - | Delay in seconds before triggering fault injection (0: disabled). |
| `--fault-duration-s` | `2.0` | `-` | - | Duration of simulated fault condition in seconds. |

### License Management

| Flag | Default | Choices | ENV | Description |
|---|---|---|---|---|
| `--license-key` | `-` | `-` | `SAMURAI_LICENSE_KEY` | License activation key string (SAM-XXXX-XXXX-XXXX-XXXX). |
| `--license-file` | `-` | `-` | - | Path to file containing product license key string. |
| `--license-info` | `False` | `-` | - | Display current license entitlement details and exit. |
| `--license-deactivate` | `False` | `-` | - | Deactivate active license on current node and exit. |
| `--license-activate` | `False` | `-` | - | Activate node entitlement using provided license key and exit. |
| `--license-account` | `False` | `-` | - | Display enterprise account status, allocated nodes, and subscription term. |
| `--license-trial` | `False` | `-` | - | Initialize 14-day evaluation license on current node. |

## 3) All CLI Environment Variables (`SAMURAI_*`)

This table catalogs all environment variables recognized by the runtime architecture across `ddos_samurai/cli/*.py` and native components:

| Environment Variable | Associated CLI Flag(s) | Code Reference |
|---|---|---|
| `SAMURAI_AF_PACKET_BLOCK_SIZE_KB` | `--afpacket-block-size-kb` | `ddos_samurai/cli/args.py:876`<br>`ddos_samurai/cli/env.py:103` |
| `SAMURAI_AF_PACKET_BUSY_POLL_US` | `--afpacket-busy-poll-us` | `ddos_samurai/cli/args.py:906`<br>`ddos_samurai/cli/env.py:108` |
| `SAMURAI_AF_PACKET_FRAMES_PER_BLOCK` | `--afpacket-frames-per-block` | `ddos_samurai/cli/args.py:888`<br>`ddos_samurai/cli/env.py:105` |
| `SAMURAI_AF_PACKET_FRAME_SIZE` | `--afpacket-frame-size` | `ddos_samurai/cli/args.py:882`<br>`ddos_samurai/cli/env.py:104` |
| `SAMURAI_AF_PACKET_HUGEPAGE_MODE` | - | `ddos_samurai/cli/args.py:853`<br>`ddos_samurai/cli/env.py:100` |
| `SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB` | `--afpacket-hugepage-size-kb` | `ddos_samurai/cli/args.py:864`<br>`ddos_samurai/cli/env.py:101` |
| `SAMURAI_AF_PACKET_MLOCK_RING` | - | `ddos_samurai/cli/args.py:937`<br>`ddos_samurai/cli/env.py:110` |
| `SAMURAI_AF_PACKET_POLL_TIMEOUT_MS` | `--afpacket-poll-timeout-ms` | `ddos_samurai/cli/args.py:894`<br>`ddos_samurai/cli/env.py:106` |
| `SAMURAI_AF_PACKET_PREFAULT_RING` | - | `ddos_samurai/cli/args.py:952`<br>`ddos_samurai/cli/env.py:111` |
| `SAMURAI_AF_PACKET_QDISC_BYPASS` | - | `ddos_samurai/cli/args.py:922`<br>`ddos_samurai/cli/env.py:109` |
| `SAMURAI_AF_PACKET_RING_TARGET_MB` | `--afpacket-ring-target-mb` | `ddos_samurai/cli/args.py:870`<br>`ddos_samurai/cli/env.py:102` |
| `SAMURAI_AF_PACKET_SPIN_LIMIT` | `--afpacket-spin-limit` | `ddos_samurai/cli/args.py:900`<br>`ddos_samurai/cli/env.py:107` |
| `SAMURAI_CLUSTER_SECRET` | `--cluster-secret` | `ddos_samurai/cli/args.py:121` |
| `SAMURAI_CONTROL_JWT_SECRET` | `--control-jwt-secret` | `ddos_samurai/cli/args.py:405` |
| `SAMURAI_CONTROL_RBAC_ADMIN_SECRET` | `--control-rbac-admin-secret` | `ddos_samurai/cli/args.py:381` |
| `SAMURAI_CONTROL_RBAC_AUDIT_LOG_PATH` | `--control-rbac-audit-log-path` | `ddos_samurai/cli/args.py:591` |
| `SAMURAI_CONTROL_RBAC_OPERATOR_SECRET` | `--control-rbac-operator-secret` | `ddos_samurai/cli/args.py:387` |
| `SAMURAI_CONTROL_RBAC_VIEWER_SECRET` | `--control-rbac-viewer-secret` | `ddos_samurai/cli/args.py:393` |
| `SAMURAI_CONTROL_RBAC_WORKER_SECRET` | `--control-rbac-worker-secret` | `ddos_samurai/cli/args.py:399` |
| `SAMURAI_CONTROL_TLS_RELOAD_INTERVAL_S` | `--control-tls-reload-interval-s` | `ddos_samurai/cli/args.py:610` |
| `SAMURAI_CUSTOM_TCP_BACKEND` | `--custom-tcp-backend` | `ddos_samurai/cli/args.py:1080`<br>`ddos_samurai/cli/env.py:141` |
| `SAMURAI_CUSTOM_TCP_CONNECT_TIMEOUT_MS` | `--custom-tcp-connect-timeout-ms` | `ddos_samurai/cli/args.py:1098` |
| `SAMURAI_CUSTOM_TCP_IDLE_TIMEOUT_MS` | `--custom-tcp-idle-timeout-ms` | `ddos_samurai/cli/args.py:1104` |
| `SAMURAI_CUSTOM_TCP_INITIAL_RTO_MS` | `--custom-tcp-initial-rto-ms` | `ddos_samurai/cli/args.py:1086` |
| `SAMURAI_CUSTOM_TCP_MAX_RETRANSMITS` | `--custom-tcp-max-retransmits` | `ddos_samurai/cli/args.py:1092` |
| `SAMURAI_CUSTOM_TCP_MODE` | `--custom-tcp-mode` | `ddos_samurai/cli/args.py:1056`<br>`ddos_samurai/cli/env.py:140` |
| `SAMURAI_DATAPLANE_CORE_ENABLE` | - | `ddos_samurai/cli/env.py:97` |
| `SAMURAI_DATAPLANE_CORE_MODE` | - | `ddos_samurai/cli/args.py:842`<br>`ddos_samurai/cli/env.py:96` |
| `SAMURAI_DP_QUEUES` | `--dp-queues` | `ddos_samurai/cli/args.py:969`<br>`ddos_samurai/cli/env.py:115` |
| `SAMURAI_DP_QUEUE_MAP` | `--dp-queue-map` | `ddos_samurai/cli/args.py:975`<br>`ddos_samurai/cli/env.py:116` |
| `SAMURAI_DP_QUEUE_STRATEGY` | `--dp-queue-strategy` | `ddos_samurai/cli/args.py:963`<br>`ddos_samurai/cli/env.py:114` |
| `SAMURAI_GPU_BATCH` | `--gpu-batch-size` | `ddos_samurai/cli/args.py:1258`<br>`ddos_samurai/cli/args.py:1259`<br>`ddos_samurai/cli/env.py:39` |
| `SAMURAI_GPU_BATCH_FLUSH_TIMEOUT_MS` | `--gpu-batch-flush-timeout-ms` | `ddos_samurai/cli/args.py:1378`<br>`ddos_samurai/cli/env.py:78` |
| `SAMURAI_GPU_BATCH_MAX` | `--gpu-batch-max` | `ddos_samurai/cli/args.py:1372`<br>`ddos_samurai/cli/env.py:77` |
| `SAMURAI_GPU_CLASSIFIER_ENGINE_PATH` | `--gpu-classifier-engine-path` | `ddos_samurai/cli/args.py:1354`<br>`ddos_samurai/cli/env.py:71` |
| `SAMURAI_GPU_CLASSIFIER_RUNTIME` | `--gpu-classifier-runtime` | `ddos_samurai/cli/args.py:1348`<br>`ddos_samurai/cli/env.py:70` |
| `SAMURAI_GPU_DEFENSE_MODE` | `--gpu-defense-mode` | `ddos_samurai/cli/args.py:1342`<br>`ddos_samurai/cli/env.py:69` |
| `SAMURAI_GPU_EPOCH_MS` | `--gpu-epoch-ms` | `ddos_samurai/cli/args.py:1312`<br>`ddos_samurai/cli/env.py:61` |
| `SAMURAI_GPU_FULL_VARIATION` | `--gpu-full-variation, --no-gpu-full-variation` | `ddos_samurai/cli/args.py:1276`<br>`ddos_samurai/cli/env.py:42` |
| `SAMURAI_GPU_HEARTBEAT_MS` | `--gpu-heartbeat-ms` | `ddos_samurai/cli/args.py:1324`<br>`ddos_samurai/cli/env.py:63` |
| `SAMURAI_GPU_KERNEL_MODE` | `--gpu-kernel-mode` | `ddos_samurai/cli/args.py:1291`<br>`ddos_samurai/cli/args.py:1298`<br>`ddos_samurai/cli/env.py:51` |
| `SAMURAI_GPU_NO_PROGRESS_MS` | `--gpu-no-progress-ms` | `ddos_samurai/cli/args.py:1330`<br>`ddos_samurai/cli/env.py:64` |
| `SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT` | `--gpu-packet-zerocopy-output, --no-gpu-packet-zerocopy-output` | `ddos_samurai/cli/args.py:1288`<br>`ddos_samurai/cli/args.py:1289`<br>`ddos_samurai/cli/env.py:44` |
| `SAMURAI_GPU_PINNED_MAX_MB` | `--gpu-pinned-max-mb` | `ddos_samurai/cli/args.py:1282`<br>`ddos_samurai/cli/args.py:1283`<br>`ddos_samurai/cli/env.py:43` |
| `SAMURAI_GPU_PIPELINE_DEPTH` | `--gpu-pipeline-depth` | `ddos_samurai/cli/args.py:1270`<br>`ddos_samurai/cli/env.py:41` |
| `SAMURAI_GPU_QUEUE_COUNT` | `--gpu-queue-count` | `ddos_samurai/cli/args.py:1318`<br>`ddos_samurai/cli/env.py:62` |
| `SAMURAI_GPU_RDMA_MODE` | `--gpu-rdma-mode` | `ddos_samurai/cli/args.py:1360`<br>`ddos_samurai/cli/env.py:75` |
| `SAMURAI_GPU_RDMA_STRICT` | `--gpu-rdma-strict, --no-gpu-rdma-strict` | `ddos_samurai/cli/args.py:1366`<br>`ddos_samurai/cli/env.py:76` |
| `SAMURAI_GPU_RING_CAPACITY` | `--gpu-ring-capacity` | `ddos_samurai/cli/args.py:1252`<br>`ddos_samurai/cli/args.py:1253`<br>`ddos_samurai/cli/env.py:38` |
| `SAMURAI_GPU_RNG_SEED` | `--gpu-rng-seed` | `ddos_samurai/cli/args.py:1336`<br>`ddos_samurai/cli/args.py:1337`<br>`ddos_samurai/cli/env.py:65` |
| `SAMURAI_GPU_RX_BATCH_SIZE` | `--gpu-rx-batch-size` | `ddos_samurai/cli/args.py:1402`<br>`ddos_samurai/cli/env.py:85` |
| `SAMURAI_GPU_RX_DURATION_S` | `--gpu-rx-duration-s` | `ddos_samurai/cli/args.py:1396`<br>`ddos_samurai/cli/env.py:84` |
| `SAMURAI_GPU_RX_IFACE` | `--gpu-rx-iface` | `ddos_samurai/cli/args.py:1390`<br>`ddos_samurai/cli/env.py:83` |
| `SAMURAI_GPU_RX_MAX_PACKETS` | `--gpu-rx-max-packets` | `ddos_samurai/cli/args.py:1408`<br>`ddos_samurai/cli/env.py:86` |
| `SAMURAI_GPU_RX_PIPELINE` | `--gpu-rx-pipeline` | `ddos_samurai/cli/args.py:1384`<br>`ddos_samurai/cli/env.py:82` |
| `SAMURAI_GPU_RX_SNAPLEN` | `--gpu-rx-snaplen` | `ddos_samurai/cli/args.py:1414`<br>`ddos_samurai/cli/env.py:87` |
| `SAMURAI_GPU_STREAMS` | `--gpu-stream-count` | `ddos_samurai/cli/args.py:1264`<br>`ddos_samurai/cli/env.py:40` |
| `SAMURAI_GPU_STREAM_API` | `--gpu-stream-api` | `ddos_samurai/cli/args.py:1300`<br>`ddos_samurai/cli/args.py:1307`<br>`ddos_samurai/cli/env.py:52` |
| `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4` | `--gpu-template-pool-size-l4` | `ddos_samurai/cli/args.py:1240`<br>`ddos_samurai/cli/args.py:1241`<br>`ddos_samurai/cli/env.py:36` |
| `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7` | `--gpu-template-pool-size-l7` | `ddos_samurai/cli/args.py:1246`<br>`ddos_samurai/cli/args.py:1247`<br>`ddos_samurai/cli/env.py:37` |
| `SAMURAI_GPU_TX_BACKEND` | - | `ddos_samurai/cli/env.py:53`<br>`ddos_samurai/cli/env.py:59`<br>`ddos_samurai/cli/validation.py:704`<br>`ddos_samurai/cli/validation.py:712` |
| `SAMURAI_GPU_TX_BACKEND_STRICT` | - | `ddos_samurai/cli/env.py:54`<br>`ddos_samurai/cli/env.py:60`<br>`ddos_samurai/cli/validation.py:706`<br>`ddos_samurai/cli/validation.py:723` |
| `SAMURAI_GPU_VECTOR_ENGINE` | - | `ddos_samurai/cli/args.py:1417` |
| `SAMURAI_KPI_GATE_PROFILE` | `--kpi-gate-profile` | `ddos_samurai/cli/args.py:1110`<br>`ddos_samurai/cli/env.py:126` |
| `SAMURAI_KPI_HARD_FAIL` | - | `ddos_samurai/cli/env.py:127` |
| `SAMURAI_L7_CAPABILITY_STRICT` | `--l7-capability-strict` | `ddos_samurai/cli/args.py:1163`<br>`ddos_samurai/cli/env.py:135` |
| `SAMURAI_L7_ENGINE` | `--l7-engine` | `ddos_samurai/cli/args.py:1121`<br>`ddos_samurai/cli/env.py:128` |
| `SAMURAI_L7_FALLBACK_POLICY` | `--l7-fallback-policy` | `ddos_samurai/cli/args.py:1157`<br>`ddos_samurai/cli/env.py:134` |
| `SAMURAI_L7_HTTP2_ENGINE` | `--l7-http2-engine` | `ddos_samurai/cli/args.py:1127`<br>`ddos_samurai/cli/env.py:129` |
| `SAMURAI_L7_QUIC_AUTO_BRIDGE` | `--l7-quic-auto-bridge` | `ddos_samurai/cli/args.py:1145`<br>`ddos_samurai/cli/env.py:132` |
| `SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE` | `--l7-quic-bridge-autopromote` | `ddos_samurai/cli/args.py:1151`<br>`ddos_samurai/cli/env.py:133` |
| `SAMURAI_L7_QUIC_ENGINE` | `--l7-quic-engine` | `ddos_samurai/cli/args.py:1133`<br>`ddos_samurai/cli/env.py:130` |
| `SAMURAI_L7_QUIC_REQUIRE_NATIVE` | `--l7-quic-require-native` | `ddos_samurai/cli/args.py:1139`<br>`ddos_samurai/cli/env.py:131` |
| `SAMURAI_LAB_PROFILE` | `--lab-profile` | `ddos_samurai/cli/args.py:957`<br>`ddos_samurai/cli/env.py:113` |
| `SAMURAI_LICENSE_KEY` | `--license-key` | `ddos_samurai/cli/app.py:32`<br>`ddos_samurai/cli/app.py:165`<br>`ddos_samurai/cli/app.py:182`<br>`ddos_samurai/cli/args.py:1813` |
| `SAMURAI_LOSS_FAIL_PCT` | - | `ddos_samurai/cli/env.py:24` |
| `SAMURAI_LOSS_IFACE` | - | `ddos_samurai/cli/env.py:27`<br>`ddos_samurai/cli/env.py:29` |
| `SAMURAI_LOSS_REPORT_OUT` | - | `ddos_samurai/cli/env.py:32`<br>`ddos_samurai/cli/env.py:34` |
| `SAMURAI_LOSS_TELEMETRY` | - | `ddos_samurai/cli/env.py:23` |
| `SAMURAI_MANAGEMENT_API_ADMIN_TOKEN` | `--management-api-admin-token` | `ddos_samurai/cli/args.py:298` |
| `SAMURAI_MANAGEMENT_API_AUTH_TOKEN` | `--management-api-auth-token` | `ddos_samurai/cli/args.py:292` |
| `SAMURAI_MANAGEMENT_API_JWT_SECRET` | `--management-api-jwt-secret` | `ddos_samurai/cli/args.py:316` |
| `SAMURAI_MANAGEMENT_API_OPERATOR_TOKEN` | `--management-api-operator-token` | `ddos_samurai/cli/args.py:304` |
| `SAMURAI_MANAGEMENT_API_TRUSTED_IDENTITY_SECRET` | `--management-api-trusted-identity-secret` | `ddos_samurai/cli/args.py:334` |
| `SAMURAI_MANAGEMENT_API_VIEWER_TOKEN` | `--management-api-viewer-token` | `ddos_samurai/cli/args.py:310` |
| `SAMURAI_MULTI_MASTER_DEQUEUE_MAX` | `--multi-master-dequeue-max` | `ddos_samurai/cli/args.py:585` |
| `SAMURAI_MULTI_MASTER_HEARTBEAT_TTL_S` | `--multi-master-heartbeat-ttl-s` | `ddos_samurai/cli/args.py:579` |
| `SAMURAI_MULTI_MASTER_NAMESPACE` | `--multi-master-namespace` | `ddos_samurai/cli/args.py:573` |
| `SAMURAI_MULTI_MASTER_REDIS_URL` | `--multi-master-redis-url` | `ddos_samurai/cli/args.py:567` |
| `SAMURAI_MULTI_MASTER_REGION_ID` | `--multi-master-region-id` | `ddos_samurai/cli/args.py:561` |
| `SAMURAI_PROM_TEXTFILE_RESULTS` | - | `ddos_samurai/cli/reporting.py:20` |
| `SAMURAI_QUIC_BUILD_MODE` | - | `ddos_samurai/cli/validation.py:657`<br>`ddos_samurai/cli/validation.py:659`<br>`ddos_samurai/cli/validation.py:660` |
| `SAMURAI_SENDER_BACKEND` | - | `ddos_samurai/cli/env.py:92` |
| `SAMURAI_SENDER_FALLBACK_POLICY` | - | `ddos_samurai/cli/env.py:93` |
| `SAMURAI_STATEFUL_RUNTIME_BACKEND` | - | `ddos_samurai/cli/args.py:830`<br>`ddos_samurai/cli/env.py:139` |
| `SAMURAI_STATE_ENGINE_MODE` | `--state-engine-mode, --engine-mode` | `ddos_samurai/cli/args.py:1026` |
| `SAMURAI_STATE_LOCK_COUNT` | `--state-lock-count` | `ddos_samurai/cli/args.py:1038`<br>`ddos_samurai/cli/env.py:89` |
| `SAMURAI_STATE_SWEEP_INTERVAL_MS` | `--state-sweep-interval-ms` | `ddos_samurai/cli/args.py:1050`<br>`ddos_samurai/cli/env.py:91` |
| `SAMURAI_STATE_TABLE_SIZE` | `--state-table-size` | `ddos_samurai/cli/args.py:1032`<br>`ddos_samurai/cli/env.py:88` |
| `SAMURAI_STATE_TIMEOUT_SEC` | `--state-timeout-sec` | `ddos_samurai/cli/args.py:1044`<br>`ddos_samurai/cli/env.py:90` |
| `SAMURAI_TARGET_REGION` | `--target-region` | `ddos_samurai/cli/args.py:655` |
| `SAMURAI_TENANT_NAMESPACE` | `--tenant-namespace` | `ddos_samurai/cli/args.py:696` |
| `SAMURAI_WORKER_REGION` | `--worker-region` | `ddos_samurai/cli/args.py:649` |
| `SAMURAI_XDP_ATTACH_BPF` | - | `ddos_samurai/cli/args.py:1001`<br>`ddos_samurai/cli/env.py:121` |
| `SAMURAI_XDP_BPF_OBJ` | `--xdp-bpf-obj` | `ddos_samurai/cli/args.py:1012`<br>`ddos_samurai/cli/env.py:123` |
| `SAMURAI_XDP_BPF_SECTION` | `--xdp-bpf-section` | `ddos_samurai/cli/args.py:1006`<br>`ddos_samurai/cli/env.py:122` |
| `SAMURAI_XDP_ENABLE` | - | `ddos_samurai/cli/env.py:117` |
| `SAMURAI_XDP_INTERFACE` | - | `ddos_samurai/cli/env.py:118` |
| `SAMURAI_XDP_MODE` | `--xdp-mode` | `ddos_samurai/cli/args.py:985`<br>`ddos_samurai/cli/env.py:120` |
| `SAMURAI_XDP_QUEUE_ID` | - | `ddos_samurai/cli/env.py:119` |
| `SAMURAI_XDP_XSKMAP_PIN` | `--xdp-xskmap-pin` | `ddos_samurai/cli/args.py:1018`<br>`ddos_samurai/cli/env.py:124` |

## 4) Precedence and Value Resolution Rules

General evaluation hierarchy (highest to lowest):
1. Command-line flag argument
2. YAML configuration file entry (`--config`)
3. Environment variable or parser default

License evaluation hierarchy:
`--license-key` > `SAMURAI_LICENSE_KEY` > `~/.samurai/license.key`.

Control plane security note:
Sensitive token credentials and secrets should be injected via environment variables rather than command-line arguments to prevent exposure in process listing tables (e.g., `SAMURAI_CLUSTER_SECRET`, `SAMURAI_MANAGEMENT_API_*`).

## 5) ZMQ Worker and DOCA/DPU-GPU Native Environment Notes

The following environment variables govern internal IPC communications across native ZMQ workers and accelerated CUDA/DOCA hardware pipelines:

### ZMQ Worker Runtime

- `SAMURAI_ZMQ_WORKER_DIR`
  - Directory search path for compiled native worker binaries.
  - Overridden if `zmq_worker_search_dir` is declared in configuration.
- `SAMURAI_XDP_NATIVE_LIB`
  - Explicit path override for the AF_XDP native sender shared library.

Default IPC endpoints declared in `ddos_samurai/zmq/wire.py`:

- `ipc:///tmp/samurai_jobs_<kind>`
- `ipc:///tmp/samurai_events_<kind>`

Architecture reference: `docs/36-zmq-worker-architecture.md`

### DOCA/GPUNetIO and DPU/GPU Contract

- `SAMURAI_GPU_DOCA_ENABLE`
- `SAMURAI_GPU_DOCA_DEVICE`
- `SAMURAI_GPU_DOCA_GPU_ID`
- `SAMURAI_GPU_DOCA_SHIM_SO`
- `SAMURAI_GPU_DOCA_RX_QUEUE_ID`
- `SAMURAI_GPU_DOCA_RX_QUEUE_COUNT`
- `SAMURAI_GPU_DOCA_RX_DEVICE_PATH`
- `SAMURAI_GPU_DOCA_RX_DEVICE_PATH_STRICT`
- `SAMURAI_GPU_DOCA_FLOW_STEERING`
- `SAMURAI_GPU_DOCA_FLOW_STEERING_STRICT`
- `SAMURAI_GPU_DOCA_FLOW_PROTO_MASK`
- `SAMURAI_GPU_DOCA_FLOW_PORT_DEVARGS`
- `SAMURAI_GPU_DOCA_FLOW_STREAMS_MULTI_PIPE`
- `SAMURAI_GPU_DOCA_FLOW_SHIM_SO`
- `SAMURAI_GPU_JOB_ENDPOINT`
- `SAMURAI_DPU_STATE_PUBLISH`
- `SAMURAI_DPU_TCP_RX_FEEDBACK`
- `SAMURAI_DPU_TCP_PASSIVE_OPEN`
- `SAMURAI_DPU_TCP_PASSIVE_OPEN_TIMEOUT_MS`
- `SAMURAI_DPU_CONTRACT_RDMA`
- `SAMURAI_DPU_CONTRACT_RDMA_SPEC`
- `SAMURAI_GPU_CONTRACT_EXPORT_KIND`
- `SAMURAI_GPU_CONTRACT_EXPORT_SPEC`
- `SAMURAI_GPU_CONTRACT_EXPORT_PATH`

Strict operating configuration for hardware benchmarking:

1. `SAMURAI_GPU_TX_BACKEND=doca_gpunetio`
2. `SAMURAI_GPU_TX_BACKEND_STRICT=1`
3. `SAMURAI_GPU_DOCA_ENABLE=1`
4. `SAMURAI_GPU_DOCA_DEVICE` configured with PCI BDF address
5. `--xdp-interface` explicitly provided

This strict combination eliminates unverified fallback paths and guarantees fail-visible termination if required hardware acceleration cannot be engaged.

DOCA Worker Runtime Flags:

- `--gpu-job-endpoint`
- `--dpu-state-publish 0|1`
- `--dpu-contract-rdma`
- `--dpu-contract-rdma-spec <spec>`
- `--dpu-tcp-rx-feedback`
- `--no-dpu-tcp-rx-feedback`
- `--dpu-tcp-passive-open`
- `--doca-interface <iface>`
- `--doca-device <device>`
- `--doca-queue-id <id>`
- `--doca-rx-queue-id <id>`
- `--doca-gpu-id <id>`
- `--doca-batch-size <n>`

Architecture reference: `docs/37-dpu-gpu-dataplane-architecture.md`

## 6) Maintenance Guidelines

This reference document is maintained via parser introspection in `ddos_samurai.cli.args.build_parser()` and environment variable scans across the codebase. When adding new command-line flags or environment bindings, update this document accordingly.
