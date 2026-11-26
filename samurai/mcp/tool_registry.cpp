#include "tool_registry.hpp"

#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "discovery_tools.hpp"
#include "runtime_tools.hpp"
#include "scenario_tools.hpp"

namespace samurai::mcp {

namespace {

using samurai::core::json::Value;

Value EmptyObjectSchema() {
  Value s = Value::Object();
  s.set("type", Value::Str("object"));
  s.set("properties", Value::Object());
  return s;
}

Value PropStr(const char* desc, const std::vector<std::string>& enum_vals = {}) {
  Value p = Value::Object();
  p.set("type", Value::Str("string"));
  if (desc && desc[0]) p.set("description", Value::Str(desc));
  if (!enum_vals.empty()) {
    Value e = Value::Array();
    for (const auto& v : enum_vals) e.push_back(Value::Str(v));
    p.set("enum", std::move(e));
  }
  return p;
}

Value PropInt(const char* desc) {
  Value p = Value::Object();
  p.set("type", Value::Str("integer"));
  if (desc && desc[0]) p.set("description", Value::Str(desc));
  return p;
}

Value PropNum(const char* desc) {
  Value p = Value::Object();
  p.set("type", Value::Str("number"));
  if (desc && desc[0]) p.set("description", Value::Str(desc));
  return p;
}

Value PropBool(const char* desc) {
  Value p = Value::Object();
  p.set("type", Value::Str("boolean"));
  if (desc && desc[0]) p.set("description", Value::Str(desc));
  return p;
}

Value PropArray(const char* desc, const char* item_type) {
  Value p = Value::Object();
  p.set("type", Value::Str("array"));
  if (desc && desc[0]) p.set("description", Value::Str(desc));
  Value items = Value::Object();
  items.set("type", Value::Str(item_type));
  p.set("items", std::move(items));
  return p;
}

Value SchemaWithProps(Value props, const std::vector<std::string>& required = {}) {
  Value s = Value::Object();
  s.set("type", Value::Str("object"));
  s.set("properties", std::move(props));
  if (!required.empty()) {
    Value req = Value::Array();
    for (const auto& r : required) req.push_back(Value::Str(r));
    s.set("required", std::move(req));
  }
  return s;
}

std::string ReadSkillMarkdown(const std::string& rel_path, const std::string& fallback_text) {
  std::vector<std::string> prefixes;
  if (const char* env_skills = std::getenv("SAMURAI_SKILLS_DIR")) {
    if (env_skills[0] != '\0') {
      const std::string root(env_skills);
      if (rel_path.rfind("skills/", 0) == 0) {
        prefixes.push_back(root + "/" + rel_path.substr(7));
      }
      prefixes.push_back(root);
    }
  }
  prefixes.push_back(".");
  char buf[4096] = {0};
  const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n > 0) {
    std::string p(buf, static_cast<std::size_t>(n));
    const auto slash = p.find_last_of('/');
    if (slash != std::string::npos) {
      const std::string dir = p.substr(0, slash);
      prefixes.push_back(dir + "/../../..");
      prefixes.push_back(dir + "/../..");
      prefixes.push_back(dir + "/..");
      prefixes.push_back("/usr/local/share/samurai");
    }
  }
  for (const auto& pre : prefixes) {
    // Allow SAMURAI_SKILLS_DIR pointing directly to the skills folder as well as project root.
    std::ifstream in(pre.find("SKILL.md") != std::string::npos ? pre : (pre + "/" + rel_path));
    if (in.is_open()) {
      std::ostringstream oss;
      oss << in.rdbuf();
      return oss.str();
    }
  }
  return fallback_text;
}

void AddCustomTcpSchemaProps(Value& props) {
  props.set("custom_tcp_wire", PropStr(
      "Custom TCP wire backend (default: 'af_xdp' using SKB/copy mode).",
      {"af_xdp", "af_packet", "dpdk", "in_memory"}));
  props.set("xdp_mode", PropStr(
      "AF_XDP bind mode: 'skb'/'copy' (0, default), 'native'/'zerocopy' (1), or 'offload' (2).",
      {"skb", "copy", "native", "zerocopy", "offload"}));
  props.set("custom_tcp_iface", PropStr(
      "Network interface for custom_tcp / AF_XDP RX+TX (sets SAMURAI_CUSTOM_TCP_RX_IFACE & SAMURAI_XDP_INTERFACE; auto-detected from route if omitted)."));
  props.set("custom_tcp_src_ip", PropStr(
      "Source IPv4 override for custom_tcp (sets SAMURAI_CUSTOM_TCP_SRC_IP; auto-detected from route if omitted)."));
  props.set("custom_tcp_dst_mac", PropStr(
      "Destination MAC override for custom_tcp (sets SAMURAI_CUSTOM_TCP_DST_MAC; auto-detected from ARP if omitted)."));
  props.set("custom_tcp_src_mac", PropStr(
      "Source MAC override for custom_tcp (sets SAMURAI_CUSTOM_TCP_SRC_MAC; auto-detected from interface if omitted)."));
  props.set("xdp_queue_id", PropInt(
      "AF_XDP NIC RX/TX queue ID (sets SAMURAI_XDP_QUEUE_ID, default: 0)."));
  props.set("auto_custom_tcp_env", PropBool(
      "Automatically detect route interface, source IP, and MAC env vars when custom_tcp or af_xdp is active (default: true)."));
}

void AddAllowTargetProps(Value& props) {
  props.set("allow_target", PropStr(
      "Explicit per-call authorization for an external/enterprise target (IPv4, CIDR like 203.0.113.0/24, or hostname/wildcard domain like api.example.com). Public targets stay fail-closed unless explicitly authorized via allow_target/allow_targets or SAMURAI_MCP_ALLOW_TARGETS (SAMURAI_MCP_DENY_TARGETS always wins)."));
  props.set("allow_targets", PropArray(
      "Array of explicitly authorized external/enterprise targets (IPv4, CIDR, or domain/hostname) for this call.", "string"));
}

}  // namespace

void RegisterAllTools(McpServer& server,
                      AutopilotManager& autopilot,
                      ClusterManager& cluster,
                      const SafetyConfig& safety) {
  // 1. Worker & binary discovery
  server.RegisterTool({
      "samurai_list_workers",
      "Discover compiled native C++17 Samurai dataplane workers (cpu, afpacket, afxdp, dpdk, gpu, doca, l7, scenario, telco, defense), daemons, and benchmark binaries.",
      EmptyObjectSchema(),
      [](const Value& a) { return HandleListWorkers(a); },
  });

  // 2. Profile catalog
  server.RegisterTool({
      "samurai_list_profiles",
      "List Samurai's built-in corporate L4, L7, and 4G/5G carrier-telecom workload profiles.",
      EmptyObjectSchema(),
      [](const Value& a) { return HandleListProfiles(a); },
  });

  // 3. Full-control target-facing test & benchmark runner (all 10 workers, L7/TLS, Telco 5G, GPU BAR1, IPFIX, KPI gates)
  {
    Value props = Value::Object();
    props.set("worker", PropStr("Dataplane worker backend (default: cpu).", AllowedWorkers()));
    props.set("target", PropStr("Private/loopback IPv4, or explicitly authorized public IPv4/CIDR/hostname (pass allow_target/allow_targets to authorize external targets)."));
    AddAllowTargetProps(props);
    props.set("port", PropInt("Target TCP/UDP port (1-65535)."));
    props.set("protocol", PropStr("L4/L7/Telco protocol (default: udp).", AllowedProtocols()));
    props.set("vector", PropStr("Workload/attack vector label (e.g. flood, basic, http, http2, dns, slowloris, sctp-flood)."));
    props.set("count", PropInt("Packet/request budget (default limit 100000000 or SAMURAI_MCP_MAX_COUNT; 0=unlimited up to uint32 wire limit)."));
    props.set("duration_s", PropNum("Optional enterprise soak test duration in seconds (runs timed rounds / continuous execution until elapsed)."));
    props.set("async", PropBool("When true, start as a background soak job and return job_id immediately (monitor via samurai_job_status / samurai_job_stop)."));
    props.set("size", PropInt("Packet size in bytes (1-65535)."));
    props.set("rps", PropNum("Target rate in packets/requests per second (0 = max speed)."));
    props.set("pin_cpu", PropInt("Pin dataplane worker to a specific CPU core index."));
    props.set("profile", PropStr("Optional built-in profile name from samurai_list_profiles."));
    props.set("config", PropStr("Optional tuning config file path (--config PATH, e.g. samurai.conf)."));
    props.set("iface", PropStr("Network interface / DPDK port for worker TX/RX (--iface NAME)."));
    props.set("transport", PropStr("Dataplane transport override (--transport MODE: af_packet|dpdk|dpdk_direct|loopback|custom_tcp|kernel_socket|geforce_p2p)."));
    props.set("dpdk_port", PropInt("DPDK port ID override (--dpdk-port)."));
    props.set("dpdk_queue", PropInt("DPDK TX queue ID override (--dpdk-queue)."));
    props.set("log_level", PropStr("Log verbosity override (--log-level).", {"trace", "debug", "info", "warn", "error"}));
    // L7 / TLS / HTTP2 / QUIC
    props.set("l7_protocol", PropStr("L7 protocol override.", {"http1", "http2", "quic", "dns"}));
    props.set("l7_profile_file", PropStr("Optional L7/Scenario JSON profile file path (--l7-profile-file)."));
    props.set("l7_payload_file", PropStr("Optional raw L7 request bytes file path (--l7-payload-file)."));
    props.set("scheme", PropStr("L7 URL scheme override.", {"http", "https"}));
    props.set("host_header", PropStr("L7 Host header / TLS SNI override."));
    props.set("verify_tls", PropBool("Verify peer TLS certificate (default: false)."));
    props.set("concurrency", PropInt("L7 parallel lanes/threads."));
    props.set("max_connections", PropInt("L7 connection pool size."));
    props.set("max_streams", PropInt("L7 HTTP/2 or HTTP/3 concurrent streams per connection."));
    props.set("l7_timeout_ms", PropInt("L7 per-request timeout in ms."));
    props.set("keepalive", PropBool("Reuse L7 connections across requests."));
    // 4G/5G Carrier Telecom
    props.set("telco_subscribers", PropInt("Telco subscriber count."));
    props.set("telco_subscriber_start", PropInt("Telco starting subscriber index."));
    props.set("telco_cps", PropInt("Telco subscriber setup rate (CPS)."));
    props.set("telco_duration_ms", PropInt("Telco bounded test duration in ms."));
    props.set("vlan_s", PropInt("Telco outer QinQ S-VLAN base."));
    props.set("vlan_c", PropInt("Telco inner QinQ C-VLAN base."));
    props.set("sctp_rate", PropInt("Target rate for SCTP associations/chunks (S1-AP/NG-AP)."));
    props.set("diameter_rate", PropInt("Target rate for Diameter CCR transactions (Ro/Gx)."));
    props.set("sip_rate", PropInt("Target rate for SIP INVITE calls (VoLTE/IMS)."));
    props.set("enable_srtp", PropBool("Enable SRTP encrypted audio media stream."));
    props.set("teid_start", PropInt("Starting 4G/5G GTP-U TEID."));
    props.set("teid_count", PropInt("Number of GTP-U TEIDs to cycle."));
    props.set("qfi", PropInt("5G NR QoS Flow Identifier (QFI) in GTP-U 0x85 extension header."));
    props.set("ue_subnet", PropStr("Inner UE subnet for GTP-U encapsulation (e.g. 10.60.0.0/16)."));
    props.set("gtpu_vlan", PropStr("GTP-U VLAN tag ('S' or 'S:C' QinQ)."));
    props.set("gtpu_inner_proto", PropStr("GTP-U inner IP protocol.", {"udp", "tcp", "icmp"}));
    props.set("telco_base_ip", PropStr("Telco subscriber base IPv4."));
    props.set("telco_gateway_ip", PropStr("Telco BNG/UPF gateway IPv4."));
    // GPU / CUDA
    props.set("gpu_bar1_p2p", PropBool("Enable GeForce BAR1 P2P GPU-to-NIC zero-copy DMA (gpu worker)."));
    props.set("gpu_persistent", PropBool("Enable zero-CPU persistent CUDA dataplane kernel (gpu worker)."));
    // Live IPFIX / NetFlow
    props.set("ipfix_enabled", PropBool("Enable live UDP IPFIX/NetFlow telemetry export."));
    props.set("ipfix_collector", PropStr("Private/loopback IPv4 address of the IPFIX/NetFlow collector."));
    props.set("ipfix_port", PropInt("IPFIX collector UDP port (default: 4739)."));
    props.set("ipfix_sample_rate", PropInt("IPFIX 1-in-N packet sampling rate."));
    props.set("ipfix_netflow_v9", PropBool("Emit NetFlow v9 instead of IPFIX v10."));
    props.set("ipfix_domain_id", PropInt("IPFIX observation domain ID."));
    // KPI Gates
    props.set("kpi_min_rate_accuracy", PropNum("Fail KPI gate if rate_accuracy_pct < threshold."));
    props.set("kpi_max_loss_pct", PropNum("Fail KPI gate if estimated wire loss % > threshold."));
    props.set("kpi_max_errors", PropInt("Fail KPI gate if errors > threshold."));
    props.set("kpi_min_sent", PropInt("Fail KPI gate if packets/requests sent < threshold."));
    props.set("kpi_min_tls_handshakes", PropInt("Fail KPI gate if TLS handshakes < threshold."));
    props.set("kpi_min_dns_queries", PropInt("Fail KPI gate if DNS queries < threshold."));
    props.set("kpi_min_dhcp_leases", PropInt("Fail KPI gate if DHCP leases < threshold."));
    props.set("kpi_max_tcp_overflows", PropInt("Fail KPI gate if TCP overflows > threshold."));
    // Custom TCP / AF_XDP wire configuration & auto-discovery
    AddCustomTcpSchemaProps(props);
    props.set("timeout_s", PropInt("Subprocess/soak wall-clock timeout in seconds (5-86400, default: auto-sized above duration_s or 30s)."));
    server.RegisterTool({
        "samurai_run_benchmark",
        "Execute a real, live, fail-closed Samurai dataplane test (or long-running enterprise soak) against private or per-call authorized public targets using any of the 10 native workers.",
        SchemaWithProps(std::move(props)),
        [safety](const Value& a) { return HandleRunBenchmark(a, safety); },
    });
  }

  // 4. RFC 2544 / 3511 / 8219 compliance suite
  {
    Value props = Value::Object();
    props.set("suite", PropStr("RFC suite to run.", {"all", "rfc2544", "rfc3511", "rfc8219"}));
    props.set("target", PropStr("Authorized private/loopback or allow_target-permitted IPv4/domain target (required)."));
    AddAllowTargetProps(props);
    props.set("port", PropInt("Target port (default: 80)."));
    props.set("worker", PropStr("Worker backend (e.g. l7, cpu, dpdk, telco)."));
    props.set("protocol", PropStr("Protocol override (e.g. http1, http2, udp, tcp)."));
    props.set("rps", PropNum("Target peak RPS ceiling for RFC 2544/3511 trials."));
    props.set("count", PropInt("Requests/packets per RFC trial (default: 1000)."));
    props.set("keepalive", PropBool("Reuse L7 connections across requests."));
    props.set("timeout_s", PropInt("RFC suite timeout in seconds (5-86400, default: 120)."));
    props.set("live_dataplane", PropBool("Must be true to confirm live dataplane RFC trials."));
    server.RegisterTool({
        "samurai_run_rfc_suite",
        "Execute Samurai's native RFC 2544 (throughput), RFC 3511 (firewall CPS), and RFC 8219 (IPv6) compliance benchmark suite against a live target.",
        SchemaWithProps(std::move(props), {"target", "live_dataplane"}),
        [safety](const Value& a) { return HandleRunRfcSuite(a, safety); },
    });
  }

  // 5. Reproducible L4 userspace TCP flow scaling benchmark
  {
    Value props = Value::Object();
    props.set("scale", PropStr("Benchmark scale: '100k' (~0.1s sanity check) or '1m' (1M active TCP flows @ 605 B/flow).", {"100k", "1m"}));
    server.RegisterTool({
        "samurai_bench_tcp_flows",
        "Reproduce Samurai's 64-shard userspace TCP flow benchmark (100k quick check or full 1,000,000 active flows @ ~605 B/flow).",
        SchemaWithProps(std::move(props)),
        [](const Value& a) { return HandleBenchTcpFlows(a); },
    });
  }

  // 6. Reproducible L7 Shared-Nothing userspace benchmark
  {
    Value props = Value::Object();
    props.set("proto", PropStr("Userspace L7 protocol.", {"h1", "h2"}));
    props.set("flows", PropInt("Number of flows (100-200000, default: 5000)."));
    server.RegisterTool({
        "samurai_bench_l7_userspace",
        "Run Samurai's Shared-Nothing L7 userspace benchmark (HTTP/1.1 RFC 7230 or HTTP/2 nghttp2) and report CPS, RPS, P50/P95/P99 latency, and VmRSS.",
        SchemaWithProps(std::move(props)),
        [](const Value& a) { return HandleBenchL7Userspace(a); },
    });
  }

  // 7. Cluster service/node/worker/shard discovery (real samurai_master endpoints)
  {
    Value props = Value::Object();
    props.set("host", PropStr("Private/loopback IPv4 (or allow_target-authorized) address of samurai_master (default: 127.0.0.1)."));
    AddAllowTargetProps(props);
    props.set("port", PropInt("Management API HTTP port (default: 8089)."));
    props.set("auth_token", PropStr("Optional Bearer token (falls back to SAMURAI_MANAGEMENT_API_*_TOKEN)."));
    props.set("include_events", PropBool("Include /v1/cluster/events log (default: false)."));
    props.set("include_metrics", PropBool("Include Prometheus /metrics scrape (default: false)."));
    server.RegisterTool({
        "samurai_cluster_discover",
        "Discover live cluster topology, registered worker nodes, heartbeats, regions, active shards, and optional Prometheus metrics from samurai_master (:8089).",
        SchemaWithProps(std::move(props)),
        [&cluster, safety](const Value& a) { return cluster.HandleDiscover(a, safety); },
    });
    // Backwards-compatible alias
    server.RegisterTool({
        "samurai_cluster_status",
        "Alias for samurai_cluster_discover: inspect samurai_master /healthz, /v1/cluster/summary, /v1/cluster/workers, and /v1/cluster/shards.",
        SchemaWithProps(Value::Object()),
        [&cluster, safety](const Value& a) { return cluster.HandleDiscover(a, safety); },
    });
  }

  // 8. Provision new worker nodes into the cluster
  {
    Value props = Value::Object();
    props.set("host", PropStr("samurai_master private/loopback (or allow_target-authorized) IPv4 (default: 127.0.0.1)."));
    AddAllowTargetProps(props);
    props.set("port", PropInt("Management API HTTP port (default: 8089)."));
    props.set("node_hosts", PropStr("Comma-separated private/RFC1918 IPv4 addresses of new nodes to provision."));
    props.set("ssh_user", PropStr("SSH username on target lab nodes (default: root)."));
    props.set("ssh_key_path", PropStr("Optional SSH private key path on the master host."));
    props.set("worker_kind", PropStr("Dataplane worker kind to deploy ('bundle' for all workers, or specific worker name)."));
    props.set("worker_region", PropStr("Optional region tag for the newly joined nodes (e.g. eu-central, tr-ist)."));
    props.set("auth_token", PropStr("Optional Operator/Admin Bearer token."));
    props.set("timeout_s", PropInt("Provisioning timeout per host in seconds (2-60, default: 10)."));
    server.RegisterTool({
        "samurai_cluster_provision_node",
        "Add new worker nodes to a running Samurai cluster via POST /v1/cluster/provision (fail-closed: only private/RFC1918 node IPs permitted).",
        SchemaWithProps(std::move(props), {"node_hosts"}),
        [&cluster, safety](const Value& a) { return cluster.HandleProvisionNode(a, safety); },
    });
  }

  // 9. Live multi-worker shard reconfiguration
  {
    Value props = Value::Object();
    props.set("host", PropStr("samurai_master private/loopback (or allow_target-authorized) IPv4 (default: 127.0.0.1)."));
    AddAllowTargetProps(props);
    props.set("port", PropInt("Management API HTTP port (default: 8089)."));
    props.set("shard_id", PropStr("Optional active shard ID to reconfigure (omit for cluster-wide update)."));
    props.set("worker_id", PropStr("Optional worker ID filter."));
    props.set("target_rps", PropNum("New target RPS setpoint."));
    props.set("concurrency", PropInt("New L7 concurrency level."));
    props.set("request_mix", PropInt("New Mahoraga request_mix variant index."));
    props.set("source_rotation", PropInt("New source rotation mode."));
    props.set("pacing_mode", PropInt("New pacing mode."));
    Value p_obj = Value::Object();
    p_obj.set("type", Value::Str("object"));
    p_obj.set("description", Value::Str("Optional raw params object forwarded to /v1/shards/reconfigure."));
    props.set("params", std::move(p_obj));
    props.set("auth_token", PropStr("Optional Operator/Admin Bearer token."));
    server.RegisterTool({
        "samurai_cluster_reconfigure",
        "Coordinate multiple active worker shards in real time via POST /v1/shards/reconfigure (live RPS, concurrency, and Mahoraga shaping updates).",
        SchemaWithProps(std::move(props)),
        [&cluster, safety](const Value& a) { return cluster.HandleReconfigure(a, safety); },
    });
  }

  // 10. Emergency cluster-wide abort
  {
    Value props = Value::Object();
    props.set("host", PropStr("samurai_master private/loopback (or allow_target-authorized) IPv4 (default: 127.0.0.1)."));
    AddAllowTargetProps(props);
    props.set("port", PropInt("Management API HTTP port (default: 8089)."));
    props.set("auth_token", PropStr("Optional Operator/Admin Bearer token."));
    server.RegisterTool({
        "samurai_cluster_abort",
        "Safely abort active distributed jobs across all cluster workers via POST /v1/jobs/abort.",
        SchemaWithProps(std::move(props)),
        [&cluster, safety](const Value& a) { return cluster.HandleAbort(a, safety); },
    });
  }

  // 11. In-process multi-worker sharding & autoscale planner
  {
    Value props = Value::Object();
    props.set("mode", PropStr("Sharding mode: 'packets' (L4/L7) or 'telco' (subscriber/CGNAT/BNG partitioning).", {"packets", "telco"}));
    props.set("strategy", PropStr("Assignment strategy: 'equal', 'capability', or 'region'.", {"equal", "capability", "region"}));
    props.set("target_region", PropStr("Target PoP/region for locality-aware sharding (e.g. 'eu-central', 'tr-ist')."));
    props.set("total_count", PropInt("Total packet/request budget (packets mode)."));
    props.set("total_subscribers", PropInt("Total subscriber count (telco mode)."));
    props.set("protocol", PropStr("Telco protocol (telco mode, e.g. gtpu, pppoe, dhcp, sctp, diameter, sip-rtp)."));
    props.set("target_cps", PropInt("Telco subscriber setup CPS (telco mode)."));
    props.set("pool_profile", PropStr("Isolated CGNAT/BNG lab pool preset.", {"linear", "regional-bng", "national-cgnat"}));
    Value w_arr = Value::Object();
    w_arr.set("type", Value::Str("array"));
    w_arr.set("description", Value::Str("Array of worker IDs or objects {worker_id, region, capacity_score, gpu_available, xdp_available}."));
    props.set("workers", std::move(w_arr));
    props.set("min_replicas", PropInt("Autoscale minimum worker replicas (default: 1)."));
    props.set("max_replicas", PropInt("Autoscale maximum worker replicas (default: 32)."));
    props.set("shards_per_worker", PropInt("Target shards per worker for autoscale calculation (default: 2)."));
    server.RegisterTool({
        "samurai_cluster_plan_shards",
        "Plan multi-worker shard distribution (equal/capability/region or 4G/5G telco CGNAT/BNG subscriber pools) and compute native AutoscaleController replica recommendations in-process.",
        SchemaWithProps(std::move(props), {"workers"}),
        [&cluster](const Value& a) { return cluster.HandlePlanShards(a); },
    });
  }

  // 12. Local loopback multi-worker mesh lifecycle (start / scale / status / stop)
  {
    Value props = Value::Object();
    props.set("action", PropStr("Lifecycle action: start, scale, status, or stop.", {"start", "scale", "status", "stop"}));
    props.set("slaves", PropInt("Desired number of local samurai_slave worker nodes (0-16, default: 2)."));
    props.set("worker_kind", PropStr("Worker flavor for local slaves ('bundle' for all workers, or specific worker name)."));
    props.set("worker_region", PropStr("Region label for local slave nodes (default: local-lab)."));
    props.set("control_port", PropInt("Loopback ZMQ control port for samurai_master (default: 5099)."));
    props.set("management_port", PropInt("Loopback HTTP Management API port (default: 8089)."));
    server.RegisterTool({
        "samurai_cluster_local_mesh",
        "Spin up, dynamically scale (add/remove slave nodes), inspect, or tear down a loopback-only (127.0.0.1) distributed samurai_master + N samurai_slave cluster for multi-worker coordination.",
        SchemaWithProps(std::move(props)),
        [&cluster](const Value& a) { return cluster.HandleLocalMesh(a); },
    });
  }

  // 13. Distributed multi-worker job execution via samurai_master
  {
    Value props = Value::Object();
    props.set("worker", PropStr("Worker flavor required across cluster slaves (default: cpu).", AllowedWorkers()));
    props.set("target", PropStr("Private/loopback IPv4, or allow_target-authorized IPv4/CIDR/domain."));
    AddAllowTargetProps(props);
    props.set("port", PropInt("Target port (1-65535)."));
    props.set("protocol", PropStr("L4/L7/Telco protocol (default: udp).", AllowedProtocols()));
    props.set("count", PropInt("Total distributed packet/request count split across workers (0 allowed for timed telco)."));
    props.set("size", PropInt("Packet size in bytes (default: 64)."));
    props.set("control_listen", PropStr("ZMQ control bind endpoint (default: tcp://127.0.0.1:5099)."));
    props.set("management_listen", PropStr("Optional HTTP Management API bind (e.g. 127.0.0.1:8089)."));
    props.set("insecure_control", PropBool("Permit non-loopback control bind without CURVE."));
    props.set("expect_workers", PropInt("Wait for N slave workers to register before dispatching shards (default: 1)."));
    props.set("wait_workers_s", PropInt("Max seconds to wait for slave workers (default: 15)."));
    props.set("shard_strategy", PropStr("Multi-worker sharding strategy.", {"equal", "capability", "region"}));
    props.set("target_region", PropStr("Target region for region-aware shard routing."));
    props.set("iface", PropStr("Network interface / DPDK port forwarded to worker shards."));
    props.set("transport", PropStr("Dataplane transport forwarded to workers (kernel_socket|custom_tcp|dpdk|af_xdp|af_packet|loopback)."));
    // Distributed Scenario / L7 JSON
    {
      Value sc_obj = Value::Object();
      sc_obj.set("type", Value::Str("object"));
      sc_obj.set("description", Value::Str("Inline Scenario Engine JSON spec distributed to all cluster workers."));
      props.set("scenario", std::move(sc_obj));
    }
    props.set("scenario_file", PropStr("Path to a Scenario Engine JSON file (read on master and distributed inline to all workers)."));
    props.set("l7_profile_file", PropStr("Alias for scenario_file."));
    props.set("concurrency", PropInt("L7/Scenario concurrency per shard."));
    props.set("max_connections", PropInt("L7 connection pool size per shard."));
    props.set("l7_timeout_ms", PropInt("L7/Scenario per-request timeout in ms."));
    props.set("scheme", PropStr("L7 URL scheme override.", {"http", "https"}));
    props.set("host_header", PropStr("L7 Host header / TLS SNI override."));
    props.set("keepalive", PropBool("Reuse L7 connections across requests."));
    props.set("verify_tls", PropBool("Verify peer TLS certificate."));
    // Distributed Telco & IPFIX
    props.set("telco_subscribers", PropInt("Total 4G/5G subscribers partitioned across workers."));
    props.set("telco_cps", PropInt("Cluster-wide subscriber setup CPS."));
    props.set("telco_duration_ms", PropInt("Timed telco run duration in ms."));
    props.set("telco_pool_profile", PropStr("CGNAT/BNG lab pool preset.", {"linear", "regional-bng", "national-cgnat"}));
    props.set("sctp_rate", PropInt("SCTP target rate."));
    props.set("diameter_rate", PropInt("Diameter CCR target rate."));
    props.set("sip_rate", PropInt("SIP target rate."));
    props.set("enable_srtp", PropBool("Enable SRTP encrypted media."));
    props.set("teid_start", PropInt("Starting GTP-U TEID."));
    props.set("teid_count", PropInt("GTP-U TEID count."));
    props.set("qfi", PropInt("5G NR QFI."));
    props.set("ipfix_enabled", PropBool("Enable live UDP IPFIX/NetFlow export."));
    props.set("ipfix_collector", PropStr("Private/loopback IPFIX collector IPv4."));
    props.set("ipfix_port", PropInt("IPFIX collector UDP port."));
    props.set("ipfix_sample_rate", PropInt("IPFIX 1:N sampling rate."));
    props.set("ipfix_netflow_v9", PropBool("Emit NetFlow v9 instead of IPFIX v10."));
    // Distributed Closed-Loop Autopilot / Mahoraga RL
    props.set("closed_loop", PropBool("Enable distributed Closed-Loop Autopilot across connected workers."));
    props.set("cl_strategy", PropStr("Closed-loop strategy.", {"aimd", "binsearch", "rl"}));
    props.set("cl_window_s", PropInt("Seconds per measured closed-loop window."));
    props.set("cl_live_reconfigure", PropBool("Drive closed-loop transitions via live ReconfigureShard RPCs."));
    props.set("cl_min_rps", PropNum("Closed-loop min RPS floor."));
    props.set("cl_max_rps", PropNum("Closed-loop max RPS ceiling."));
    props.set("cl_initial_rps", PropNum("Closed-loop initial RPS."));
    props.set("cl_slo_max_error_pct", PropNum("SLO max error %."));
    props.set("cl_slo_max_loss_pct", PropNum("SLO max wire loss %."));
    props.set("cl_slo_max_latency_ms", PropNum("SLO max P99 latency ms."));
    props.set("cl_slo_max_pushback_pct", PropNum("SLO max 4xx/5xx pushback %."));
    props.set("cl_aimd_max_windows", PropInt("Max AIMD windows."));
    props.set("cl_binsearch_max_windows", PropInt("Max binary-search windows."));
    props.set("rl_policy", PropStr("Path to SRLP RL policy weights for cl_strategy='rl'."));
    props.set("cl_rl_max_jump_factor", PropNum("RL shield max upward jump factor."));
    props.set("cl_lever_shield", PropBool("Enable Mahoraga LeverShield on distributed RL runs."));
    props.set("cl_online_adapt", PropBool("Enable serving-time continual online adaptation."));
    props.set("cl_novelty", PropBool("Enable open-vocabulary novelty defense detection."));
    props.set("timeout_s", PropInt("Subprocess wall-clock timeout in seconds (5-86400, default: 45)."));
    server.RegisterTool({
        "samurai_cluster_run_job",
        "Dispatch and execute a real distributed multi-worker test job via samurai_master across connected samurai_slave nodes (supports all 10 workers, shard strategies, 4G/5G telco pools, IPFIX, and distributed Closed-Loop AIMD/BinSearch/Mahoraga RL).",
        SchemaWithProps(std::move(props)),
        [&cluster, safety](const Value& a) { return cluster.HandleRunDistributedJob(a, safety); },
    });
  }

  // 13-17. Autopilot / Mahoraga RL tools
  {
    Value props = Value::Object();
    props.set("strategy", PropStr("Closed-loop strategy: aimd, binsearch, or rl (Mahoraga RL + safety shield).", {"aimd", "binsearch", "rl"}));
    props.set("min_rps", PropNum("Minimum RPS floor (default: 10)."));
    props.set("max_rps", PropNum("Maximum RPS ceiling (default: 100000)."));
    props.set("initial_rps", PropNum("Optional initial RPS setpoint (0 = min_rps)."));
    props.set("slo_max_error_pct", PropNum("SLO max error % (0 = disabled)."));
    props.set("slo_max_loss_pct", PropNum("SLO max wire loss % (0 = disabled)."));
    props.set("slo_min_rate_accuracy_pct", PropNum("SLO min pacing accuracy % (0 = disabled)."));
    props.set("slo_max_latency_ms", PropNum("SLO max P99 latency in ms (0 = disabled)."));
    props.set("slo_max_pushback_pct", PropNum("SLO max 4xx/5xx defense pushback % (0 = disabled)."));
    props.set("aimd_increase_rps", PropNum("AIMD additive step in RPS."));
    props.set("aimd_backoff", PropNum("Multiplicative decrease factor in (0, 1), default: 0.5."));
    props.set("aimd_max_windows", PropInt("Optional max windows for AIMD (0 = unbounded)."));
    props.set("binsearch_tolerance_rps", PropNum("Binary search convergence tolerance in RPS."));
    props.set("binsearch_max_windows", PropInt("Binary search max windows (default: 24)."));
    props.set("rl_max_jump_factor", PropNum("RL safety shield max upward jump multiplier (default: 2.0)."));
    props.set("policy_path", PropStr("Optional path to exported SRLP native RL policy weights (MLP or RL^2 GRU)."));
    props.set("lever_shield", PropBool("Enable Mahoraga LeverShield WAF path-block reflex (default: true)."));
    props.set("honored_success_floor", PropNum("LeverShield 2xx floor below which a variant is marked path-blocked (default: 0.10)."));
    props.set("variant_count", PropInt("Categorical request_mix variant count (default: 5)."));
    props.set("explore", PropBool("Enable deterministic Mahoraga RL lever exploration across extra shaping dimensions."));
    props.set("explore_seed", PropInt("Deterministic seed for RL exploration (default: 42)."));
    server.RegisterTool({
        "samurai_autopilot_create",
        "Create a native C++17 Closed-Loop Autopilot / Mahoraga RL Agent session (AIMD, Binary Search, or RL+Shield with optional SRLP MLP/RL^2 GRU policy and LeverShield).",
        SchemaWithProps(std::move(props)),
        [&autopilot](const Value& a) { return autopilot.HandleCreate(a); },
    });
  }

  {
    Value props = Value::Object();
    props.set("session_id", PropStr("Autopilot session ID returned by samurai_autopilot_create."));
    props.set("valid", PropBool("Whether the measured window sample is valid (default: true)."));
    props.set("actual_rps", PropNum("Achieved RPS in the measured window."));
    props.set("attempted", PropNum("Total attempted requests/packets in the window."));
    props.set("errors", PropNum("Total errors observed in the window."));
    props.set("error_pct", PropNum("Explicit error % (negative = derive from errors/attempted)."));
    props.set("loss_pct", PropNum("Wire loss % (negative = unknown)."));
    props.set("rate_accuracy_pct", PropNum("Pacing accuracy % (negative = unknown)."));
    props.set("latency_p99_ms", PropNum("Measured P99 latency in ms (negative = unknown)."));
    props.set("pushback_pct", PropNum("Defense 429/503 pushback % (negative = unknown)."));
    props.set("rl_action_rps", PropNum("Optional external RL agent proposed RPS setpoint (governed by the native safety shield)."));
    props.set("rate_limited_ratio", PropNum("Mahoraga defense signal: 429 ratio in [0,1]."));
    props.set("overload_ratio", PropNum("Mahoraga defense signal: 503 ratio in [0,1]."));
    props.set("conn_drop_ratio", PropNum("Mahoraga defense signal: connection drop ratio in [0,1] (updates ban EWMA)."));
    props.set("reset_pressure", PropNum("Mahoraga defense signal: TCP RST / H2 reset ratio."));
    props.set("challenge_rate", PropNum("Mahoraga defense signal: WAF challenge ratio."));
    props.set("variant_applied", PropInt("request_mix variant index applied during this window (feeds LeverShield)."));
    props.set("success_ratio", PropNum("2xx success ratio in [0,1] for variant_applied (feeds LeverShield)."));
    Value rl_levers = Value::Object();
    rl_levers.set("type", Value::Str("object"));
    rl_levers.set("description", Value::Str("Optional external RL proposals for extra kActionFields (concurrency, request_mix, source_rotation, pacing_mode, auth_mode, evasion_tactic)."));
    props.set("rl_levers", std::move(rl_levers));
    server.RegisterTool({
        "samurai_autopilot_step",
        "Advance a Closed-Loop Autopilot / Mahoraga RL session by one measured window; runs SRLP policy inference (or external RL proposal), applies the native SLO & LeverShield safety guards, and returns the shielded 7-D action.",
        SchemaWithProps(std::move(props), {"session_id"}),
        [&autopilot](const Value& a) { return autopilot.HandleStep(a); },
    });
  }

  {
    Value props = Value::Object();
    props.set("session_id", PropStr("Autopilot session ID."));
    props.set("worker", PropStr("Dataplane worker backend (default: l7).", AllowedWorkers()));
    props.set("target", PropStr("Private/loopback IPv4 or allow_target-authorized external IPv4/domain."));
    AddAllowTargetProps(props);
    props.set("port", PropInt("Target port (default: 8080)."));
    props.set("protocol", PropStr("Protocol (default: http1).", AllowedProtocols()));
    props.set("l7_protocol", PropStr("Optional L7 protocol override.", {"http1", "http2", "quic", "dns"}));
    {
      Value sc_obj = Value::Object();
      sc_obj.set("type", Value::Str("object"));
      sc_obj.set("description", Value::Str("Optional inline Scenario Engine JSON spec executed for this autopilot window."));
      props.set("scenario", std::move(sc_obj));
    }
    props.set("scenario_file", PropStr("Optional Scenario Engine JSON file path for this autopilot window."));
    props.set("l7_profile_file", PropStr("Alias for scenario_file."));
    props.set("iface", PropStr("Optional network interface override (--iface)."));
    props.set("transport", PropStr("Optional dataplane transport override (--transport)."));
    props.set("window_s", PropNum("Window duration in seconds used to compute packet count from setpoint_rps (0.2-3600s, default: 1.0)."));
    props.set("count", PropInt("Optional explicit packet/request count override."));
    props.set("concurrency", PropInt("L7 concurrency."));
    props.set("keepalive", PropBool("L7 keepalive."));
    props.set("rl_action_rps", PropNum("Optional external RL agent proposed next RPS."));
    props.set("timeout_s", PropInt("Subprocess timeout in seconds."));
    server.RegisterTool({
        "samurai_autopilot_run_window",
        "Execute one live, safety-gated Samurai dataplane window at the session's current setpoint_rps, feed the measured JSON telemetry into ClosedLoopController + RL/LeverShield, and return both live metrics and the next shielded setpoint.",
        SchemaWithProps(std::move(props), {"session_id"}),
        [&autopilot, safety](const Value& a) { return autopilot.HandleRunWindow(a, safety); },
    });
  }

  {
    Value props = Value::Object();
    props.set("session_id", PropStr("Optional session ID (omit to list all active sessions)."));
    server.RegisterTool({
        "samurai_autopilot_status",
        "Inspect active Closed-Loop Autopilot / RL sessions, current setpoints, best SLO-green RPS, and LeverShield memory.",
        SchemaWithProps(std::move(props)),
        [&autopilot](const Value& a) { return autopilot.HandleStatus(a); },
    });
  }

  {
    Value props = Value::Object();
    props.set("session_id", PropStr("Autopilot session ID to reset or delete."));
    props.set("delete", PropBool("When true, permanently remove the session instead of resetting episode state."));
    server.RegisterTool({
        "samurai_autopilot_reset",
        "Reset an Autopilot / RL episode (clearing controller state, RL^2 GRU hidden context, and LeverShield memory) or delete the session.",
        SchemaWithProps(std::move(props), {"session_id"}),
        [&autopilot](const Value& a) { return autopilot.HandleReset(a); },
    });
  }

  // 18-20. Scenario Engine tools
  {
    Value props = Value::Object();
    Value sc_obj = Value::Object();
    sc_obj.set("type", Value::Str("object"));
    sc_obj.set("description", Value::Str("Inline Scenario Engine JSON spec (personas, flows, load_model, sla)."));
    props.set("scenario", std::move(sc_obj));
    props.set("scenario_file", PropStr("Path to a Scenario Engine JSON file (alternative to inline 'scenario')."));
    props.set("workers", PropInt("Number of virtual workers to schedule sessions across (1-64, default: 1)."));
    props.set("sessions_per_worker", PropInt("Sessions compiled per worker (1-256, default: 2)."));
    props.set("seed", PropInt("Deterministic RNG seed for weighted persona/flow scheduling (default: 42)."));
    props.set("include_plans", PropBool("Include full compiled packed session event arrays in the response (default: false)."));
    server.RegisterTool({
        "samurai_scenario_compile",
        "Parse, validate, and compile a multi-step Scenario Engine JSON specification (personas, flows, steps, token capture, think-time, L4/L7 primitives) in-process via native samurai_scenario.",
        SchemaWithProps(std::move(props)),
        [](const Value& a) { return HandleScenarioCompile(a); },
    });
  }

  {
    Value props = Value::Object();
    Value sc_obj = Value::Object();
    sc_obj.set("type", Value::Str("object"));
    sc_obj.set("description", Value::Str("Inline Scenario Engine JSON spec to validate and run live."));
    props.set("scenario", std::move(sc_obj));
    props.set("scenario_file", PropStr("Path to a Scenario Engine JSON file."));
    props.set("target", PropStr("Private/loopback IPv4, or explicitly authorized public IPv4/CIDR/domain (requires allow_target/allow_targets or SAMURAI_MCP_ALLOW_TARGETS)."));
    AddAllowTargetProps(props);
    props.set("port", PropInt("Target port (default: 8080)."));
    props.set("count", PropInt("Bounded request/session budget (default: 100; limit 100000000 or SAMURAI_MCP_MAX_COUNT)."));
    props.set("duration_s", PropNum("Optional enterprise soak test duration in seconds (loops scenario flows continuously across rounds until elapsed)."));
    props.set("async", PropBool("When true, start as a background soak job and return job_id immediately (poll/stop via samurai_job_status / samurai_job_stop)."));
    props.set("rps", PropNum("Optional target RPS pacing cap."));
    props.set("concurrency", PropInt("Optional concurrency override."));
    props.set("iface", PropStr("Optional network interface override (--iface)."));
    props.set("transport", PropStr("Optional dataplane transport override (--transport)."));
    props.set("config", PropStr("Optional tuning config file path (--config)."));
    AddCustomTcpSchemaProps(props);
    props.set("timeout_s", PropInt("Subprocess/soak wall-clock timeout in seconds (5-86400, default: auto-sized above duration_s or 30s)."));
    server.RegisterTool({
        "samurai_scenario_run",
        "Validate in-process and execute a live multi-step persona Scenario or long-running enterprise soak (HTTP/1.1, HTTP/2, QUIC/H3, L4 TCP, cookie/JWT token binding, SLA checks) against loopback/RFC1918 or explicitly authorized external targets.",
        SchemaWithProps(std::move(props)),
        [safety](const Value& a) { return HandleScenarioRun(a, safety); },
    });
  }

  {
    Value props = Value::Object();
    Value sla_obj = Value::Object();
    sla_obj.set("type", Value::Str("object"));
    sla_obj.set("description", Value::Str("Scenario SLA object (min_completion_rate, max_step_fail_ratio, max_latency_p95_ms, max_connect_timeout_ratio, max_retransmit_ratio)."));
    props.set("sla", std::move(sla_obj));
    props.set("sessions_started", PropInt("Total started virtual user sessions."));
    props.set("sessions_completed", PropInt("Total completed virtual user sessions."));
    props.set("step_attempted", PropInt("Total executed scenario steps."));
    props.set("step_failed", PropInt("Total failed scenario steps."));
    props.set("latency_p95_ms", PropNum("Observed P95 latency in ms (omit or negative if unavailable)."));
    props.set("tcp_connect_attempts", PropInt("TCP connect attempts (L4 scenarios)."));
    props.set("tcp_connect_established", PropInt("TCP established connections."));
    props.set("tcp_retransmit_count", PropInt("TCP retransmit count."));
    props.set("tcp_timeout_close_count", PropInt("TCP timeout-closed connections."));
    server.RegisterTool({
        "samurai_scenario_evaluate_sla",
        "Evaluate a Scenario Engine SLA contract against observed session/step/latency/TCP counters in-process via native evaluate_sla_native().",
        SchemaWithProps(std::move(props), {"sla"}),
        [](const Value& a) { return HandleScenarioEvaluateSla(a); },
    });
  }

  // 21. Fail-closed API & Docker service discovery
  {
    Value props = Value::Object();
    props.set("target", PropStr("Single private/loopback IPv4, host.docker.internal, or allow_target-authorized public IPv4/domain."));
    props.set("targets", PropArray("Array of private/loopback IPv4, host.docker.internal, or allow_target-authorized public targets.", "string"));
    AddAllowTargetProps(props);
    props.set("ports", PropArray("TCP ports to check on explicit target/targets (default: common HTTP/API ports).", "integer"));
    props.set("discover_docker", PropBool("Inspect running Docker containers and their network IPs/ports via /var/run/docker.sock (default: true when no explicit target/targets provided)."));
    props.set("docker_socket", PropStr("Unix socket path for Docker Engine API (default: /var/run/docker.sock)."));
    props.set("name_filter", PropStr("Case-insensitive substring filter on Docker container name or image."));
    props.set("network_filter", PropStr("Case-insensitive substring filter on Docker network name."));
    props.set("probe_http", PropBool("Perform HTTP/1.1 probing on open TCP ports (default: true)."));
    props.set("probe_openapi", PropBool("Probe OpenAPI/Swagger endpoints (/openapi.json, /swagger.json, /v3/api-docs, etc.) and extract routes (default: true)."));
    props.set("probe_non_http_ports", PropBool("Also send HTTP probes to well-known database/SSH ports like 5432/6379 (default: false)."));
    props.set("probe_paths", PropArray("Additional HTTP paths to probe on open services.", "string"));
    props.set("replace_default_paths", PropBool("When true, probe only 'probe_paths' instead of merging with built-in health/API paths (default: false)."));
    props.set("host_header", PropStr("Optional HTTP Host header override for probed services."));
    props.set("auth_token", PropStr("Optional Bearer token sent as Authorization header during HTTP discovery probes."));
    props.set("connect_timeout_ms", PropInt("Non-blocking TCP connect timeout in ms (50-5000, default: 400)."));
    props.set("request_timeout_ms", PropInt("HTTP read timeout per probe in ms (100-10000, default: 1500)."));
    props.set("include_body_preview", PropBool("Include truncated sanitized response body previews (default: true)."));
    props.set("generate_scenario", PropBool("Synthesize a ready-to-run samurai_scenario_worker JSON skeleton from discovered live GET routes (default: true)."));
    server.RegisterTool({
        "samurai_discover_apis",
        "Discover local Docker network containers/ports and inspect HTTP APIs (private/loopback by default; external targets permitted when explicitly passed via allow_target/allow_targets; TCP reachability, service fingerprinting, OpenAPI/Swagger route extraction, health probes, and Scenario JSON synthesis).",
        SchemaWithProps(std::move(props)),
        [safety](const Value& a) { return HandleDiscoverApis(a, safety); },
    });
  }

  // 22-23. Background async soak job inspection & graceful cancellation
  {
    Value props = Value::Object();
    props.set("job_id", PropStr("Optional async job ID (omit to list all active and completed soak jobs)."));
    server.RegisterTool({
        "samurai_job_status",
        "Inspect status, elapsed time, and final telemetry/report of an async enterprise soak job started with async=true.",
        SchemaWithProps(std::move(props)),
        [](const Value& a) { return HandleJobStatus(a); },
    });
  }
  {
    Value props = Value::Object();
    props.set("job_id", PropStr("Async job ID to stop gracefully."));
    server.RegisterTool({
        "samurai_job_stop",
        "Stop a running async enterprise soak job cleanly (sends SIGTERM/SIGKILL to worker subprocess and returns collected job state).",
        SchemaWithProps(std::move(props), {"job_id"}),
        [](const Value& a) { return HandleJobStop(a); },
    });
  }
}

void RegisterSkillsAndPrompts(McpServer& server) {
  struct SkillDef {
    const char* slug;
    const char* rel_path;
    const char* desc;
  };
  static const SkillDef kSkills[] = {
      {"samurai-netbench", "skills/samurai-netbench/SKILL.md",
       "Core Samurai L4/L7/RFC benchmarking, host discovery, and evidence-boundary workflow."},
      {"samurai-cluster-orchestrator", "skills/samurai-cluster-orchestrator/SKILL.md",
       "Distributed cluster discovery, node provisioning, multi-worker sharding, autoscaling, and live shard coordination."},
      {"samurai-autopilot-rl", "skills/samurai-autopilot-rl/SKILL.md",
       "Closed-Loop Autopilot (AIMD/BinSearch/Mahoraga RL), SRLP MLP/RL^2 GRU inference, and LeverShield WAF reflex."},
      {"samurai-scenario-author", "skills/samurai-scenario-author/SKILL.md",
       "Multi-step Web/Mobile persona scenario authoring, JWT/cookie binding, in-process compilation, and SLA verification."},
      {"samurai-hardware-dataplane", "skills/samurai-hardware-dataplane/SKILL.md",
       "Complete catalog & orchestration playbook for all 10 native dataplane workers (cpu, afpacket, afxdp, dpdk, gpu CUDA/BAR1 P2P, doca, l7, scenario, telco 4G/5G CUPS, defense VAE)."},
  };

  for (const auto& s : kSkills) {
    const std::string uri = std::string("samurai://skills/") + s.slug;
    const std::string rel = s.rel_path;
    const std::string desc = s.desc;
    server.RegisterResource({
        uri,
        s.slug,
        desc,
        "text/markdown",
        [rel, desc]() { return ReadSkillMarkdown(rel, "# " + rel + "\n\n" + desc + "\n"); },
    });
    server.RegisterPrompt({
        s.slug,
        desc,
        [rel, desc](const Value&) { return ReadSkillMarkdown(rel, "# " + rel + "\n\n" + desc + "\n"); },
    });
  }
}

}  // namespace samurai::mcp
