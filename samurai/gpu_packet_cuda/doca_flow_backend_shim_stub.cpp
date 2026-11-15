#include "doca_flow_backend_api.h"

#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

#if defined(__has_include)
#if __has_include(<doca_error.h>) && __has_include(<doca_flow.h>)
#define SAMURAI_HAS_DOCA_FLOW_HEADERS 1
#include <doca_error.h>
#include <doca_flow.h>
#else
#define SAMURAI_HAS_DOCA_FLOW_HEADERS 0
#endif
#else
#define SAMURAI_HAS_DOCA_FLOW_HEADERS 0
#endif

namespace {

inline void write_err(char* err, size_t err_len, const std::string& msg) {
  if (err == nullptr || err_len == 0u) {
    return;
  }
  const size_t n = std::min(err_len - 1u, msg.size());
  std::memcpy(err, msg.data(), n);
  err[n] = '\0';
}

inline std::string env_string_or(const char* name, const char* defv) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return std::string(defv ? defv : "");
  }
  return std::string(raw);
}

inline uint32_t env_u32(const char* name, uint32_t defv) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return defv;
  }
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(raw, &end, 10);
  if (end == raw || (end && *end != '\0')) {
    return defv;
  }
  if (parsed > static_cast<unsigned long>(std::numeric_limits<uint32_t>::max())) {
    return defv;
  }
  return static_cast<uint32_t>(parsed);
}

inline void dedupe_queue_ids(std::vector<uint16_t>& queue_ids) {
  std::sort(queue_ids.begin(), queue_ids.end());
  queue_ids.erase(std::unique(queue_ids.begin(), queue_ids.end()), queue_ids.end());
}

constexpr uint32_t kProtoTcp = 1u << 0;
constexpr uint32_t kProtoUdp = 1u << 1;
constexpr uint32_t kProtoIcmp = 1u << 2;

#if SAMURAI_HAS_DOCA_FLOW_HEADERS

std::mutex g_flow_program_lock;

struct ActiveFlowSession {
  struct PipeState {
    uint16_t pipe_queue = 0u;
    doca_flow_pipe* pipe = nullptr;
    std::vector<doca_flow_pipe_entry*> entries;
  };

  bool active = false;
  std::string iface;
  std::string device_name;
  std::vector<uint16_t> queue_ids;
  uint32_t proto_mask = 0u;
  std::string stream_rule_sig;
  bool streams_multi_pipe = false;
  doca_flow_cfg* flow_cfg = nullptr;
  doca_flow_port* port = nullptr;
  std::vector<PipeState> pipes;
};

ActiveFlowSession g_session{};

inline const char* doca_err_name(doca_error_t rc) {
#if defined(DOCA_ERROR_NAME_MAX_SIZE)
  (void)DOCA_ERROR_NAME_MAX_SIZE;
#endif
  const char* name = doca_error_get_name(rc);
  return name ? name : "unknown";
}

inline doca_error_t cfg_call(doca_error_t rc, const char* what, char* err, size_t err_len) {
  if (rc == DOCA_SUCCESS) {
    return rc;
  }
  write_err(err, err_len, std::string(what) + " failed: " + doca_err_name(rc));
  return rc;
}

inline std::string build_devargs(const char* iface, const char* device_name) {
  const std::string explicit_devargs = env_string_or("SAMURAI_GPU_DOCA_FLOW_PORT_DEVARGS", "");
  if (!explicit_devargs.empty()) {
    return explicit_devargs;
  }
  const std::string prefer_iface = env_string_or("SAMURAI_GPU_DOCA_FLOW_PORT_DEVARGS_FROM_IFACE", "1");
  const bool use_iface = (prefer_iface == "1" || prefer_iface == "true" || prefer_iface == "yes");
  if (use_iface && iface && *iface) {
    return std::string(iface);
  }
  return std::string(device_name ? device_name : "");
}

inline int queue_for_index(const std::vector<uint16_t>& queue_ids, size_t idx) {
  if (queue_ids.empty()) {
    return -1;
  }
  return static_cast<int>(queue_ids[idx % queue_ids.size()]);
}

inline bool session_matches(
    const ActiveFlowSession& s,
    const char* iface,
    const char* device_name,
    const std::vector<uint16_t>& queue_ids,
    uint32_t proto_mask,
    const std::string& stream_rule_sig,
    bool streams_multi_pipe) {
  return s.active && s.iface == (iface ? iface : "") && s.device_name == (device_name ? device_name : "") &&
      s.queue_ids == queue_ids && s.proto_mask == proto_mask && s.stream_rule_sig == stream_rule_sig &&
      s.streams_multi_pipe == streams_multi_pipe;
}

inline void cleanup_session(ActiveFlowSession& s) {
  if (!s.active) {
    return;
  }
  for (auto& pipe_state : s.pipes) {
    for (doca_flow_pipe_entry* e : pipe_state.entries) {
      if (e) {
        (void)doca_flow_pipe_rm_entry(pipe_state.pipe_queue, nullptr, e);
      }
    }
    pipe_state.entries.clear();
    if (pipe_state.pipe) {
      (void)doca_flow_pipe_destroy(pipe_state.pipe);
      pipe_state.pipe = nullptr;
    }
  }
  s.pipes.clear();
  if (s.port) {
    (void)doca_flow_port_stop(s.port);
    s.port = nullptr;
  }
  (void)doca_flow_destroy();
  if (s.flow_cfg) {
    (void)doca_flow_cfg_destroy(s.flow_cfg);
    s.flow_cfg = nullptr;
  }
  s.iface.clear();
  s.device_name.clear();
  s.queue_ids.clear();
  s.proto_mask = 0u;
  s.stream_rule_sig.clear();
  s.streams_multi_pipe = false;
  s.active = false;
}

struct ProtoRule {
  uint32_t bit;
  doca_flow_l4_meta meta;
  uint32_t rss_flags;
};

struct StreamRuleProtoEntry {
  uint32_t stream_id = 0u;
  uint32_t proto_bit = 0u;
  doca_flow_l4_meta l4_meta = DOCA_FLOW_L4_META_TCP;
  uint32_t rss_flags = 0u;
  uint32_t ipv4_dst_be = 0u;
  uint16_t l4_dst_port_be = 0u;
  uint16_t rxq_id = 0u;
};

inline bool queue_id_allowed(const std::vector<uint16_t>& queue_ids, uint16_t qid) {
  return std::find(queue_ids.begin(), queue_ids.end(), qid) != queue_ids.end();
}

inline uint32_t flow_proto_mask_to_rss_flags(uint32_t proto_bit) {
  if (proto_bit == kProtoTcp) {
    return DOCA_FLOW_RSS_IP | DOCA_FLOW_RSS_TCP;
  }
  if (proto_bit == kProtoUdp) {
    return DOCA_FLOW_RSS_IP | DOCA_FLOW_RSS_UDP;
  }
  return DOCA_FLOW_RSS_IP;
}

inline doca_flow_l4_meta flow_proto_mask_to_meta(uint32_t proto_bit) {
  if (proto_bit == kProtoUdp) {
    return DOCA_FLOW_L4_META_UDP;
  }
  if (proto_bit == kProtoIcmp) {
    return DOCA_FLOW_L4_META_ICMP;
  }
  return DOCA_FLOW_L4_META_TCP;
}

inline std::string stream_rules_signature(
    const samurai_doca_flow_stream_rule_v1* rules,
    int rule_count) {
  if (rules == nullptr || rule_count <= 0) {
    return std::string();
  }
  std::string sig;
  sig.reserve(static_cast<size_t>(rule_count) * 48u);
  for (int i = 0; i < rule_count; ++i) {
    const auto& r = rules[static_cast<size_t>(i)];
    sig.append(std::to_string(r.stream_id));
    sig.push_back(':');
    sig.append(std::to_string(r.proto_mask));
    sig.push_back(':');
    sig.append(std::to_string(r.ipv4_dst_be));
    sig.push_back(':');
    sig.append(std::to_string(r.l4_dst_port_be));
    sig.push_back(':');
    sig.append(std::to_string(r.rxq_id));
    sig.push_back(';');
  }
  return sig;
}

inline bool expand_stream_rules(
    const std::vector<uint16_t>& queue_ids,
    const samurai_doca_flow_stream_rule_v1* rules,
    int rule_count,
    std::vector<StreamRuleProtoEntry>& out,
    std::string& why) {
  out.clear();
  if (rules == nullptr || rule_count <= 0) {
    why = "empty stream rules";
    return false;
  }
  out.reserve(static_cast<size_t>(rule_count) * 2u);
  for (int i = 0; i < rule_count; ++i) {
    const auto& rule = rules[static_cast<size_t>(i)];
    if (rule.proto_mask == 0u) {
      why = "stream rule proto_mask cannot be zero";
      return false;
    }
    if (!queue_id_allowed(queue_ids, rule.rxq_id)) {
      why = "stream rule queue id is not part of configured RX queues";
      return false;
    }
    const std::array<uint32_t, 3> proto_bits{{kProtoTcp, kProtoUdp, kProtoIcmp}};
    for (uint32_t bit : proto_bits) {
      if ((rule.proto_mask & bit) == 0u) {
        continue;
      }
      StreamRuleProtoEntry entry{};
      entry.stream_id = rule.stream_id;
      entry.proto_bit = bit;
      entry.l4_meta = flow_proto_mask_to_meta(bit);
      entry.rss_flags = flow_proto_mask_to_rss_flags(bit);
      entry.ipv4_dst_be = rule.ipv4_dst_be;
      entry.l4_dst_port_be = rule.l4_dst_port_be;
      entry.rxq_id = rule.rxq_id;
      if (bit == kProtoIcmp && entry.l4_dst_port_be != 0u) {
        why = "ICMP stream rule cannot set dst_port";
        return false;
      }
      out.push_back(entry);
    }
  }
  if (out.empty()) {
    why = "stream rules did not expand to any protocol entry";
    return false;
  }
  return true;
}

inline int program_flow_rules(
    const char* iface,
    const char* device_name,
    const std::vector<uint16_t>& queue_ids,
    uint32_t proto_mask,
    const std::string& stream_rule_sig,
    char* err,
    size_t err_len) {
  if (queue_ids.size() < 2u) {
    write_err(err, err_len, "flow steering requires at least two RX queues");
    return -1;
  }

  const uint16_t pipe_queue = static_cast<uint16_t>(env_u32("SAMURAI_GPU_DOCA_FLOW_PIPE_QUEUE", 0u));
  const uint16_t pipe_queues = static_cast<uint16_t>(
      std::max<uint32_t>(1u, env_u32("SAMURAI_GPU_DOCA_FLOW_PIPE_QUEUES", static_cast<uint32_t>(queue_ids.size()))));
  const uint32_t nr_entries =
      std::max<uint32_t>(8u, env_u32("SAMURAI_GPU_DOCA_FLOW_NR_ENTRIES", static_cast<uint32_t>(queue_ids.size() + 4u)));
  const std::string mode_args = env_string_or("SAMURAI_GPU_DOCA_FLOW_MODE_ARGS", "vnf,hws");
  const std::string pipe_name = env_string_or("SAMURAI_GPU_DOCA_FLOW_PIPE_NAME", "samurai_proto_rss");
  const std::string devargs = build_devargs(iface, device_name);

  if (devargs.empty()) {
    write_err(err, err_len, "empty DOCA flow devargs; set SAMURAI_GPU_DOCA_FLOW_PORT_DEVARGS");
    return -1;
  }

  if (session_matches(g_session, iface, device_name, queue_ids, proto_mask, stream_rule_sig, false)) {
    return 0;
  }
  cleanup_session(g_session);

  doca_flow_cfg* flow_cfg = nullptr;
  doca_flow_port_cfg* port_cfg = nullptr;
  doca_flow_port* port = nullptr;
  doca_flow_pipe_cfg* pipe_cfg = nullptr;
  doca_flow_pipe* pipe = nullptr;
  std::vector<doca_flow_pipe_entry*> entries;

  doca_error_t rc = cfg_call(doca_flow_cfg_create(&flow_cfg), "doca_flow_cfg_create", err, err_len);
  if (rc != DOCA_SUCCESS) {
    return -1;
  }
  rc = cfg_call(doca_flow_cfg_set_pipe_queues(flow_cfg, pipe_queues), "doca_flow_cfg_set_pipe_queues", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(doca_flow_cfg_set_mode_args(flow_cfg, mode_args.c_str()), "doca_flow_cfg_set_mode_args", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(doca_flow_init(flow_cfg), "doca_flow_init", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }

  rc = cfg_call(doca_flow_port_cfg_create(&port_cfg), "doca_flow_port_cfg_create", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(
      doca_flow_port_cfg_set_devargs(port_cfg, devargs.c_str()),
      "doca_flow_port_cfg_set_devargs",
      err,
      err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_port_cfg_destroy(port_cfg);
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(doca_flow_port_start(port_cfg, &port), "doca_flow_port_start", err, err_len);
  doca_flow_port_cfg_destroy(port_cfg);
  port_cfg = nullptr;
  if (rc != DOCA_SUCCESS) {
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }

  rc = cfg_call(doca_flow_pipe_cfg_create(&pipe_cfg, port), "doca_flow_pipe_cfg_create", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_port_stop(port);
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(doca_flow_pipe_cfg_set_name(pipe_cfg, pipe_name.c_str()), "doca_flow_pipe_cfg_set_name", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    doca_flow_port_stop(port);
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC), "doca_flow_pipe_cfg_set_type", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    doca_flow_port_stop(port);
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(doca_flow_pipe_cfg_set_is_root(pipe_cfg, true), "doca_flow_pipe_cfg_set_is_root", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    doca_flow_port_stop(port);
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, nr_entries), "doca_flow_pipe_cfg_set_nr_entries", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    doca_flow_port_stop(port);
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }

  doca_flow_match pipe_match{};
  doca_flow_match pipe_match_mask{};
  pipe_match.parser_meta.outer_l4_type = static_cast<doca_flow_l4_meta>(std::numeric_limits<uint32_t>::max());
  pipe_match_mask.parser_meta.outer_l4_type = static_cast<doca_flow_l4_meta>(std::numeric_limits<uint32_t>::max());
  rc = cfg_call(
      doca_flow_pipe_cfg_set_match(pipe_cfg, &pipe_match, &pipe_match_mask),
      "doca_flow_pipe_cfg_set_match",
      err,
      err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    doca_flow_port_stop(port);
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }

  rc = cfg_call(doca_flow_pipe_create(pipe_cfg, nullptr, nullptr, &pipe), "doca_flow_pipe_create", err, err_len);
  doca_flow_pipe_cfg_destroy(pipe_cfg);
  pipe_cfg = nullptr;
  if (rc != DOCA_SUCCESS) {
    doca_flow_port_stop(port);
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }

  const std::array<ProtoRule, 3> rules = {{
      {kProtoTcp, DOCA_FLOW_L4_META_TCP, DOCA_FLOW_RSS_IP | DOCA_FLOW_RSS_TCP},
      {kProtoUdp, DOCA_FLOW_L4_META_UDP, DOCA_FLOW_RSS_IP | DOCA_FLOW_RSS_UDP},
      {kProtoIcmp, DOCA_FLOW_L4_META_ICMP, DOCA_FLOW_RSS_IP},
  }};

  uint16_t q_storage[1] = {0u};
  size_t added = 0u;
  for (const ProtoRule& rule : rules) {
    if ((proto_mask & rule.bit) == 0u) {
      continue;
    }
    const int q = queue_for_index(queue_ids, added);
    if (q < 0) {
      continue;
    }
    q_storage[0] = static_cast<uint16_t>(q);

    doca_flow_match entry_match{};
    entry_match.parser_meta.outer_l4_type = rule.meta;

    doca_flow_fwd fwd{};
    fwd.type = DOCA_FLOW_FWD_RSS;
    fwd.rss_queues = q_storage;
    fwd.num_of_queues = 1;
#if defined(DOCA_FLOW_HAVE_RSS_OUTER_INNER_FLAGS) || defined(DOCA_FLOW_RSS_IP)
    fwd.rss_outer_flags = rule.rss_flags;
#else
    fwd.rss_flags = rule.rss_flags;
#endif

    doca_flow_pipe_entry* entry = nullptr;
    rc = cfg_call(
        doca_flow_pipe_add_entry(
            pipe_queue,
            pipe,
            &entry_match,
            nullptr,
            nullptr,
            &fwd,
            DOCA_FLOW_NO_WAIT,
            nullptr,
            &entry),
        "doca_flow_pipe_add_entry",
        err,
        err_len);
    if (rc != DOCA_SUCCESS) {
      for (doca_flow_pipe_entry* e : entries) {
        if (e) {
          (void)doca_flow_pipe_rm_entry(pipe_queue, nullptr, e);
        }
      }
      if (pipe) {
        (void)doca_flow_pipe_destroy(pipe);
      }
      (void)doca_flow_port_stop(port);
      (void)doca_flow_destroy();
      (void)doca_flow_cfg_destroy(flow_cfg);
      return -1;
    }
    entries.push_back(entry);
    added += 1u;
  }

  if (added == 0u) {
    write_err(err, err_len, "proto_mask did not select any supported protocol rule (tcp/udp/icmp)");
    if (pipe) {
      (void)doca_flow_pipe_destroy(pipe);
    }
    (void)doca_flow_port_stop(port);
    (void)doca_flow_destroy();
    (void)doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }

  rc = cfg_call(
      doca_flow_entries_process(
          port,
          pipe_queue,
          static_cast<uint64_t>(env_u32("SAMURAI_GPU_DOCA_FLOW_PROCESS_TIMEOUT_US", 1000u)),
          static_cast<uint32_t>(added)),
      "doca_flow_entries_process",
      err,
      err_len);
  if (rc != DOCA_SUCCESS) {
    for (doca_flow_pipe_entry* e : entries) {
      if (e) {
        (void)doca_flow_pipe_rm_entry(pipe_queue, nullptr, e);
      }
    }
    if (pipe) {
      (void)doca_flow_pipe_destroy(pipe);
    }
    (void)doca_flow_port_stop(port);
    (void)doca_flow_destroy();
    (void)doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }

  g_session.active = true;
  g_session.iface = iface ? iface : "";
  g_session.device_name = device_name ? device_name : "";
  g_session.queue_ids = queue_ids;
  g_session.proto_mask = proto_mask;
  g_session.stream_rule_sig = stream_rule_sig;
  g_session.streams_multi_pipe = false;
  g_session.flow_cfg = flow_cfg;
  g_session.port = port;
  g_session.pipes.clear();
  g_session.pipes.push_back(ActiveFlowSession::PipeState{pipe_queue, pipe, std::move(entries)});
  return 0;
}

inline int program_flow_rules_streams(
    const char* iface,
    const char* device_name,
    const std::vector<uint16_t>& queue_ids,
    const samurai_doca_flow_stream_rule_v1* rules,
    int rule_count,
    char* err,
    size_t err_len) {
  std::vector<StreamRuleProtoEntry> entries_expanded;
  std::string expand_why;
  if (!expand_stream_rules(queue_ids, rules, rule_count, entries_expanded, expand_why)) {
    write_err(err, err_len, expand_why.empty() ? "invalid stream rules" : expand_why);
    return -1;
  }
  const std::string rule_sig = stream_rules_signature(rules, rule_count);
  uint32_t union_proto_mask = 0u;
  for (const auto& e : entries_expanded) {
    union_proto_mask |= e.proto_bit;
  }

  if (queue_ids.size() < 2u) {
    write_err(err, err_len, "flow steering requires at least two RX queues");
    return -1;
  }

  const uint16_t pipe_queue = static_cast<uint16_t>(env_u32("SAMURAI_GPU_DOCA_FLOW_PIPE_QUEUE", 0u));
  const uint16_t pipe_queues = static_cast<uint16_t>(
      std::max<uint32_t>(1u, env_u32("SAMURAI_GPU_DOCA_FLOW_PIPE_QUEUES", static_cast<uint32_t>(queue_ids.size()))));
  const uint32_t nr_entries = std::max<uint32_t>(
      static_cast<uint32_t>(entries_expanded.size() + 8u),
      env_u32("SAMURAI_GPU_DOCA_FLOW_NR_ENTRIES", static_cast<uint32_t>(entries_expanded.size() + 8u)));
  const std::string mode_args = env_string_or("SAMURAI_GPU_DOCA_FLOW_MODE_ARGS", "vnf,hws");
  const std::string pipe_name = env_string_or("SAMURAI_GPU_DOCA_FLOW_PIPE_NAME", "samurai_stream_rss");
  const std::string devargs = build_devargs(iface, device_name);
  const std::string multi_pipe_raw = env_string_or("SAMURAI_GPU_DOCA_FLOW_STREAMS_MULTI_PIPE", "0");
  const bool streams_multi_pipe = (
      multi_pipe_raw == "1" || multi_pipe_raw == "true" || multi_pipe_raw == "yes" || multi_pipe_raw == "on");

  if (devargs.empty()) {
    write_err(err, err_len, "empty DOCA flow devargs; set SAMURAI_GPU_DOCA_FLOW_PORT_DEVARGS");
    return -1;
  }

  if (session_matches(g_session, iface, device_name, queue_ids, union_proto_mask, rule_sig, streams_multi_pipe)) {
    return 0;
  }
  cleanup_session(g_session);

  doca_flow_cfg* flow_cfg = nullptr;
  doca_flow_port_cfg* port_cfg = nullptr;
  doca_flow_port* port = nullptr;
  std::vector<ActiveFlowSession::PipeState> pipe_states;

  doca_error_t rc = cfg_call(doca_flow_cfg_create(&flow_cfg), "doca_flow_cfg_create", err, err_len);
  if (rc != DOCA_SUCCESS) {
    return -1;
  }
  rc = cfg_call(doca_flow_cfg_set_pipe_queues(flow_cfg, pipe_queues), "doca_flow_cfg_set_pipe_queues", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(doca_flow_cfg_set_mode_args(flow_cfg, mode_args.c_str()), "doca_flow_cfg_set_mode_args", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(doca_flow_init(flow_cfg), "doca_flow_init", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }

  rc = cfg_call(doca_flow_port_cfg_create(&port_cfg), "doca_flow_port_cfg_create", err, err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(
      doca_flow_port_cfg_set_devargs(port_cfg, devargs.c_str()),
      "doca_flow_port_cfg_set_devargs",
      err,
      err_len);
  if (rc != DOCA_SUCCESS) {
    doca_flow_port_cfg_destroy(port_cfg);
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }
  rc = cfg_call(doca_flow_port_start(port_cfg, &port), "doca_flow_port_start", err, err_len);
  doca_flow_port_cfg_destroy(port_cfg);
  port_cfg = nullptr;
  if (rc != DOCA_SUCCESS) {
    doca_flow_destroy();
    doca_flow_cfg_destroy(flow_cfg);
    return -1;
  }

  auto cleanup_local = [&]() {
    for (auto& ps : pipe_states) {
      for (doca_flow_pipe_entry* e : ps.entries) {
        if (e) {
          (void)doca_flow_pipe_rm_entry(ps.pipe_queue, nullptr, e);
        }
      }
      ps.entries.clear();
      if (ps.pipe) {
        (void)doca_flow_pipe_destroy(ps.pipe);
        ps.pipe = nullptr;
      }
    }
    pipe_states.clear();
    if (port) {
      (void)doca_flow_port_stop(port);
      port = nullptr;
    }
    (void)doca_flow_destroy();
    if (flow_cfg) {
      (void)doca_flow_cfg_destroy(flow_cfg);
      flow_cfg = nullptr;
    }
  };

  auto add_pipe = [&](const std::string& name, uint16_t target_pipe_queue, const std::vector<const StreamRuleProtoEntry*>& rules_for_pipe) {
    if (rules_for_pipe.empty()) {
      return true;
    }
    doca_flow_pipe_cfg* pipe_cfg = nullptr;
    doca_flow_pipe* pipe = nullptr;
    std::vector<doca_flow_pipe_entry*> entries;

    doca_error_t pipe_rc = cfg_call(doca_flow_pipe_cfg_create(&pipe_cfg, port), "doca_flow_pipe_cfg_create", err, err_len);
    if (pipe_rc != DOCA_SUCCESS) {
      return false;
    }
    pipe_rc = cfg_call(doca_flow_pipe_cfg_set_name(pipe_cfg, name.c_str()), "doca_flow_pipe_cfg_set_name", err, err_len);
    if (pipe_rc != DOCA_SUCCESS) {
      doca_flow_pipe_cfg_destroy(pipe_cfg);
      return false;
    }
    pipe_rc = cfg_call(doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_BASIC), "doca_flow_pipe_cfg_set_type", err, err_len);
    if (pipe_rc != DOCA_SUCCESS) {
      doca_flow_pipe_cfg_destroy(pipe_cfg);
      return false;
    }
    pipe_rc = cfg_call(doca_flow_pipe_cfg_set_is_root(pipe_cfg, true), "doca_flow_pipe_cfg_set_is_root", err, err_len);
    if (pipe_rc != DOCA_SUCCESS) {
      doca_flow_pipe_cfg_destroy(pipe_cfg);
      return false;
    }
    const uint32_t desired_entries = std::max<uint32_t>(
        static_cast<uint32_t>(rules_for_pipe.size() + 8u),
        nr_entries);
    pipe_rc = cfg_call(
        doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, desired_entries),
        "doca_flow_pipe_cfg_set_nr_entries",
        err,
        err_len);
    if (pipe_rc != DOCA_SUCCESS) {
      doca_flow_pipe_cfg_destroy(pipe_cfg);
      return false;
    }

    doca_flow_match pipe_match{};
    doca_flow_match pipe_match_mask{};
    pipe_match.parser_meta.outer_l4_type = static_cast<doca_flow_l4_meta>(std::numeric_limits<uint32_t>::max());
    pipe_match_mask.parser_meta.outer_l4_type = static_cast<doca_flow_l4_meta>(std::numeric_limits<uint32_t>::max());
    pipe_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
    pipe_match_mask.outer.ip4.dst_ip = std::numeric_limits<uint32_t>::max();
    pipe_match_mask.outer.tcp.l4_port.dst_port = std::numeric_limits<uint16_t>::max();
    pipe_match_mask.outer.udp.l4_port.dst_port = std::numeric_limits<uint16_t>::max();
    pipe_rc = cfg_call(
        doca_flow_pipe_cfg_set_match(pipe_cfg, &pipe_match, &pipe_match_mask),
        "doca_flow_pipe_cfg_set_match",
        err,
        err_len);
    if (pipe_rc != DOCA_SUCCESS) {
      doca_flow_pipe_cfg_destroy(pipe_cfg);
      return false;
    }

    pipe_rc = cfg_call(doca_flow_pipe_create(pipe_cfg, nullptr, nullptr, &pipe), "doca_flow_pipe_create", err, err_len);
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    if (pipe_rc != DOCA_SUCCESS) {
      return false;
    }

    for (const StreamRuleProtoEntry* entry_rule : rules_for_pipe) {
      uint16_t q_storage[1] = {entry_rule->rxq_id};
      doca_flow_match entry_match{};
      entry_match.parser_meta.outer_l4_type = entry_rule->l4_meta;
      entry_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
      if (entry_rule->ipv4_dst_be != 0u) {
        entry_match.outer.ip4.dst_ip = entry_rule->ipv4_dst_be;
      }
      if (entry_rule->proto_bit == kProtoTcp && entry_rule->l4_dst_port_be != 0u) {
        entry_match.outer.tcp.l4_port.dst_port = entry_rule->l4_dst_port_be;
      } else if (entry_rule->proto_bit == kProtoUdp && entry_rule->l4_dst_port_be != 0u) {
        entry_match.outer.udp.l4_port.dst_port = entry_rule->l4_dst_port_be;
      }

      doca_flow_fwd fwd{};
      fwd.type = DOCA_FLOW_FWD_RSS;
      fwd.rss_queues = q_storage;
      fwd.num_of_queues = 1;
#if defined(DOCA_FLOW_HAVE_RSS_OUTER_INNER_FLAGS) || defined(DOCA_FLOW_RSS_IP)
      fwd.rss_outer_flags = entry_rule->rss_flags;
#else
      fwd.rss_flags = entry_rule->rss_flags;
#endif

      doca_flow_pipe_entry* entry = nullptr;
      pipe_rc = cfg_call(
          doca_flow_pipe_add_entry(
              target_pipe_queue,
              pipe,
              &entry_match,
              nullptr,
              nullptr,
              &fwd,
              DOCA_FLOW_NO_WAIT,
              nullptr,
              &entry),
          "doca_flow_pipe_add_entry(stream)",
          err,
          err_len);
      if (pipe_rc != DOCA_SUCCESS) {
        for (doca_flow_pipe_entry* e : entries) {
          if (e) {
            (void)doca_flow_pipe_rm_entry(target_pipe_queue, nullptr, e);
          }
        }
        if (pipe) {
          (void)doca_flow_pipe_destroy(pipe);
        }
        return false;
      }
      entries.push_back(entry);
    }

    pipe_rc = cfg_call(
        doca_flow_entries_process(
            port,
            target_pipe_queue,
            static_cast<uint64_t>(env_u32("SAMURAI_GPU_DOCA_FLOW_PROCESS_TIMEOUT_US", 1000u)),
            static_cast<uint32_t>(entries.size())),
        "doca_flow_entries_process(stream)",
        err,
        err_len);
    if (pipe_rc != DOCA_SUCCESS) {
      for (doca_flow_pipe_entry* e : entries) {
        if (e) {
          (void)doca_flow_pipe_rm_entry(target_pipe_queue, nullptr, e);
        }
      }
      if (pipe) {
        (void)doca_flow_pipe_destroy(pipe);
      }
      return false;
    }

    pipe_states.push_back(ActiveFlowSession::PipeState{target_pipe_queue, pipe, std::move(entries)});
    return true;
  };

  if (!streams_multi_pipe) {
    std::vector<const StreamRuleProtoEntry*> refs;
    refs.reserve(entries_expanded.size());
    for (const auto& e : entries_expanded) {
      refs.push_back(&e);
    }
    if (!add_pipe(pipe_name, pipe_queue, refs)) {
      cleanup_local();
      return -1;
    }
  } else {
    const std::array<uint32_t, 3> proto_bits{{kProtoTcp, kProtoUdp, kProtoIcmp}};
    const std::array<const char*, 3> proto_suffix{{"tcp", "udp", "icmp"}};
    size_t created = 0u;
    size_t group_idx = 0u;
    for (size_t i = 0; i < proto_bits.size(); ++i) {
      if ((union_proto_mask & proto_bits[i]) == 0u) {
        continue;
      }
      std::vector<const StreamRuleProtoEntry*> refs;
      for (const auto& e : entries_expanded) {
        if (e.proto_bit == proto_bits[i]) {
          refs.push_back(&e);
        }
      }
      if (refs.empty()) {
        continue;
      }
      const std::string sub_pipe_name = pipe_name + "_" + proto_suffix[i];
      const uint16_t sub_pipe_queue =
          static_cast<uint16_t>((static_cast<uint32_t>(pipe_queue) + static_cast<uint32_t>(group_idx)) % pipe_queues);
      if (!add_pipe(sub_pipe_name, sub_pipe_queue, refs)) {
        cleanup_local();
        return -1;
      }
      created += 1u;
      group_idx += 1u;
    }
    if (created == 0u) {
      write_err(err, err_len, "stream steering produced no flow pipes");
      cleanup_local();
      return -1;
    }
  }

  g_session.active = true;
  g_session.iface = iface ? iface : "";
  g_session.device_name = device_name ? device_name : "";
  g_session.queue_ids = queue_ids;
  g_session.proto_mask = union_proto_mask;
  g_session.stream_rule_sig = rule_sig;
  g_session.streams_multi_pipe = streams_multi_pipe;
  g_session.flow_cfg = flow_cfg;
  g_session.port = port;
  g_session.pipes = std::move(pipe_states);
  return 0;
}

#endif  // SAMURAI_HAS_DOCA_FLOW_HEADERS

}  // namespace

extern "C" int samurai_doca_flow_program_steering_v1(
    const char* iface,
    const char* device_name,
    const int* rxq_ids,
    int rxq_count,
    uint32_t proto_mask,
    char* err,
    size_t err_len) {
  if (iface == nullptr || !*iface || device_name == nullptr || !*device_name || rxq_ids == nullptr || rxq_count <= 0 ||
      proto_mask == 0u) {
    write_err(err, err_len, "invalid flow steering inputs");
    return -1;
  }

  std::vector<uint16_t> queue_ids;
  queue_ids.reserve(static_cast<size_t>(rxq_count));
  for (int i = 0; i < rxq_count; ++i) {
    const int q = rxq_ids[static_cast<size_t>(i)];
    if (q < 0 || q > static_cast<int>(std::numeric_limits<uint16_t>::max())) {
      write_err(err, err_len, "invalid RX queue id");
      return -1;
    }
    queue_ids.push_back(static_cast<uint16_t>(q));
  }
  dedupe_queue_ids(queue_ids);
  if (queue_ids.size() < 2u) {
    write_err(err, err_len, "flow steering requires at least 2 unique RX queues");
    return -1;
  }

#if !SAMURAI_HAS_DOCA_FLOW_HEADERS
  write_err(
      err,
      err_len,
      "DOCA Flow headers are unavailable at build time; install DOCA SDK and rebuild flow shim.");
  return -1;
#else
  std::lock_guard<std::mutex> guard(g_flow_program_lock);
  return program_flow_rules(iface, device_name, queue_ids, proto_mask, std::string(), err, err_len);
#endif
}

extern "C" int samurai_doca_flow_program_steering_streams_v1(
    const char* iface,
    const char* device_name,
    const int* rxq_ids,
    int rxq_count,
    const samurai_doca_flow_stream_rule_v1* rules,
    int rule_count,
    char* err,
    size_t err_len) {
  if (iface == nullptr || !*iface || device_name == nullptr || !*device_name || rxq_ids == nullptr || rxq_count <= 0 ||
      rules == nullptr || rule_count <= 0) {
    write_err(err, err_len, "invalid flow stream steering inputs");
    return -1;
  }
  std::vector<uint16_t> queue_ids;
  queue_ids.reserve(static_cast<size_t>(rxq_count));
  for (int i = 0; i < rxq_count; ++i) {
    const int q = rxq_ids[static_cast<size_t>(i)];
    if (q < 0 || q > static_cast<int>(std::numeric_limits<uint16_t>::max())) {
      write_err(err, err_len, "invalid RX queue id in stream steering");
      return -1;
    }
    queue_ids.push_back(static_cast<uint16_t>(q));
  }
  dedupe_queue_ids(queue_ids);
  if (queue_ids.size() < 2u) {
    write_err(err, err_len, "stream steering requires at least 2 unique RX queues");
    return -1;
  }

#if !SAMURAI_HAS_DOCA_FLOW_HEADERS
  write_err(
      err,
      err_len,
      "DOCA Flow headers are unavailable at build time; install DOCA SDK and rebuild flow shim.");
  return -1;
#else
  std::lock_guard<std::mutex> guard(g_flow_program_lock);
  return program_flow_rules_streams(iface, device_name, queue_ids, rules, rule_count, err, err_len);
#endif
}
