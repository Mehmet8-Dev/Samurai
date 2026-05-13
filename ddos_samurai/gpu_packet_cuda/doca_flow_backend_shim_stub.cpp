#include "doca_flow_backend_api.h"

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
  bool active = false;
  std::string iface;
  std::string device_name;
  std::vector<uint16_t> queue_ids;
  uint32_t proto_mask = 0u;
  uint16_t pipe_queue = 0u;
  doca_flow_cfg* flow_cfg = nullptr;
  doca_flow_port* port = nullptr;
  doca_flow_pipe* pipe = nullptr;
  std::vector<doca_flow_pipe_entry*> entries;
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
    uint16_t pipe_queue) {
  return s.active && s.iface == (iface ? iface : "") && s.device_name == (device_name ? device_name : "") &&
      s.queue_ids == queue_ids && s.proto_mask == proto_mask && s.pipe_queue == pipe_queue;
}

inline void cleanup_session(ActiveFlowSession& s) {
  if (!s.active) {
    return;
  }
  for (doca_flow_pipe_entry* e : s.entries) {
    if (e) {
      (void)doca_flow_pipe_rm_entry(s.pipe_queue, nullptr, e);
    }
  }
  s.entries.clear();
  if (s.pipe) {
    (void)doca_flow_pipe_destroy(s.pipe);
    s.pipe = nullptr;
  }
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
  s.pipe_queue = 0u;
  s.active = false;
}

struct ProtoRule {
  uint32_t bit;
  doca_flow_l4_meta meta;
  uint32_t rss_flags;
};

inline int program_flow_rules(
    const char* iface,
    const char* device_name,
    const std::vector<uint16_t>& queue_ids,
    uint32_t proto_mask,
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

  if (session_matches(g_session, iface, device_name, queue_ids, proto_mask, pipe_queue)) {
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
  g_session.pipe_queue = pipe_queue;
  g_session.flow_cfg = flow_cfg;
  g_session.port = port;
  g_session.pipe = pipe;
  g_session.entries = std::move(entries);
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
  return program_flow_rules(iface, device_name, queue_ids, proto_mask, err, err_len);
#endif
}
