#include "tx_backend_doca_gpunetio.cuh"
#include "doca_flow_backend_api.h"

#include <arpa/inet.h>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <fcntl.h>
#include <cstdio>
#include <initializer_list>
#include <limits>
#include <sys/mman.h>
#include <sys/stat.h>
#include <mutex>
#include <memory>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <vector>

namespace {

using doca_error_t = int;
constexpr doca_error_t kDocaSuccess = 0;
constexpr uint32_t kDocaEthTxqTypeRegular = 0u;
constexpr uint32_t kDocaEthRxqTypeRegular = 0u;

union doca_data {
  void* ptr;
  uint64_t u64;
  int64_t i64;
};

struct doca_devinfo;
struct doca_dev;
struct doca_ctx;
struct doca_pe;
struct doca_buf;
struct doca_buf_inventory;
struct doca_mmap;
struct doca_gpu;
struct doca_eth_txq;
struct doca_gpu_eth_txq;
struct doca_eth_txq_task_send;
struct doca_eth_rxq;
struct doca_gpu_eth_rxq;
struct doca_eth_rxq_task_recv;
struct doca_task;

using TxqTaskSendCb = void (*)(doca_eth_txq_task_send* task, doca_data task_user_data, doca_data ctx_user_data);
using RxqTaskRecvCb = void (*)(doca_eth_rxq_task_recv* task, doca_data task_user_data, doca_data ctx_user_data);

struct DocaApi {
  void* lib_core = nullptr;
  void* lib_eth = nullptr;
  void* lib_eth_cpu = nullptr;
  void* lib_eth_gpu = nullptr;
  bool loaded = false;
  std::string load_error;

  const char* (*doca_error_get_descr)(doca_error_t) = nullptr;

  doca_error_t (*doca_devinfo_create_list)(doca_devinfo*** dev_list, uint32_t* nb_devs) = nullptr;
  doca_error_t (*doca_devinfo_destroy_list)(doca_devinfo** dev_list) = nullptr;
  doca_error_t (*doca_devinfo_get_ibdev_name)(const doca_devinfo* devinfo, char* ibdev_name, uint32_t size) =
      nullptr;
  doca_error_t (*doca_devinfo_get_iface_name)(const doca_devinfo* devinfo, char* iface_name, uint32_t size) =
      nullptr;
  doca_error_t (*doca_dev_open)(doca_devinfo* devinfo, doca_dev** dev) = nullptr;
  doca_error_t (*doca_dev_close)(doca_dev* dev) = nullptr;

  doca_error_t (*doca_pe_create)(doca_pe** pe) = nullptr;
  doca_error_t (*doca_pe_destroy)(doca_pe* pe) = nullptr;
  doca_error_t (*doca_pe_connect_ctx)(doca_pe* pe, doca_ctx* ctx) = nullptr;
  uint8_t (*doca_pe_progress)(doca_pe* pe) = nullptr;

  doca_error_t (*doca_ctx_set_user_data)(doca_ctx* ctx, doca_data user_data) = nullptr;
  doca_error_t (*doca_ctx_start)(doca_ctx* ctx) = nullptr;
  doca_error_t (*doca_ctx_stop)(doca_ctx* ctx) = nullptr;
  doca_error_t (*doca_ctx_set_datapath_on_gpu)(doca_ctx* ctx, doca_gpu* gpu_dev) = nullptr;

  doca_error_t (*doca_gpu_create)(const char* gpu_bus_id, doca_gpu** gpu_dev) = nullptr;
  doca_error_t (*doca_gpu_destroy)(doca_gpu* gpu_dev) = nullptr;

  doca_error_t (*doca_mmap_create)(doca_mmap** mmap) = nullptr;
  doca_error_t (*doca_mmap_destroy)(doca_mmap* mmap) = nullptr;
  doca_error_t (*doca_mmap_add_dev)(doca_mmap* mmap, doca_dev* dev) = nullptr;
  doca_error_t (*doca_mmap_set_memrange)(doca_mmap* mmap, void* addr, size_t len) = nullptr;
  doca_error_t (*doca_mmap_start)(doca_mmap* mmap) = nullptr;
  doca_error_t (*doca_mmap_stop)(doca_mmap* mmap) = nullptr;
  doca_error_t (*doca_mmap_get_mkey)(const doca_mmap* mmap, const doca_dev* dev, uint32_t* mkey) = nullptr;

  doca_error_t (*doca_buf_inventory_create)(size_t num_elements, doca_buf_inventory** inventory) = nullptr;
  doca_error_t (*doca_buf_inventory_destroy)(doca_buf_inventory* inventory) = nullptr;
  doca_error_t (*doca_buf_inventory_start)(doca_buf_inventory* inventory) = nullptr;
  doca_error_t (*doca_buf_inventory_stop)(doca_buf_inventory* inventory) = nullptr;
  doca_error_t (*doca_buf_inventory_buf_get_by_addr)(
      doca_buf_inventory* inventory,
      doca_mmap* mmap,
      void* addr,
      size_t len,
      doca_buf** buf) = nullptr;
  doca_error_t (*doca_buf_dec_refcount)(doca_buf* buf, uint16_t* refcount) = nullptr;
  doca_error_t (*doca_buf_get_data)(const doca_buf* buf, void** data) = nullptr;
  doca_error_t (*doca_buf_get_data_len)(const doca_buf* buf, size_t* data_len) = nullptr;
  doca_error_t (*doca_buf_get_head)(const doca_buf* buf, void** head) = nullptr;
  doca_error_t (*doca_buf_get_len)(const doca_buf* buf, size_t* len) = nullptr;

  doca_error_t (*doca_eth_txq_create)(doca_dev* dev, uint32_t max_burst_size, doca_eth_txq** eth_txq) = nullptr;
  doca_error_t (*doca_eth_txq_destroy)(doca_eth_txq* eth_txq) = nullptr;
  doca_error_t (*doca_eth_txq_set_type)(doca_eth_txq* eth_txq, uint32_t type) = nullptr;
  doca_error_t (*doca_eth_txq_set_l3_chksum_offload)(doca_eth_txq* eth_txq, uint8_t enable_l3_chksum) = nullptr;
  doca_error_t (*doca_eth_txq_set_l4_chksum_offload)(doca_eth_txq* eth_txq, uint8_t enable_l4_chksum) = nullptr;
  doca_error_t (*doca_eth_txq_apply_queue_id)(doca_eth_txq* eth_txq, uint16_t queue_id) = nullptr;
  doca_error_t (*doca_eth_txq_get_gpu_handle)(const doca_eth_txq* eth_txq, doca_gpu_eth_txq** eth_txq_ext) =
      nullptr;
  doca_ctx* (*doca_eth_txq_as_doca_ctx)(doca_eth_txq* eth_txq) = nullptr;
  doca_error_t (*doca_eth_txq_task_send_set_conf)(
      doca_eth_txq* eth_txq,
      TxqTaskSendCb task_completion_cb,
      TxqTaskSendCb task_error_cb,
      uint32_t task_send_num) = nullptr;
  doca_error_t (*doca_eth_txq_task_send_allocate_init)(
      doca_eth_txq* eth_txq,
      doca_buf* pkt,
      doca_data user_data,
      doca_eth_txq_task_send** task_send) = nullptr;
  doca_task* (*doca_eth_txq_task_send_as_doca_task)(doca_eth_txq_task_send* task) = nullptr;
  doca_error_t (*doca_eth_txq_task_send_get_pkt)(doca_eth_txq_task_send* task, doca_buf** pkt) = nullptr;

  doca_error_t (*doca_eth_rxq_create)(
      doca_dev* dev,
      uint32_t max_burst_size,
      uint32_t max_packet_size,
      doca_eth_rxq** eth_rxq) = nullptr;
  doca_error_t (*doca_eth_rxq_destroy)(doca_eth_rxq* eth_rxq) = nullptr;
  doca_error_t (*doca_eth_rxq_set_type)(doca_eth_rxq* eth_rxq, uint32_t type) = nullptr;
  doca_error_t (*doca_eth_rxq_apply_queue_id)(doca_eth_rxq* eth_rxq, uint16_t queue_id) = nullptr;
  doca_ctx* (*doca_eth_rxq_as_doca_ctx)(doca_eth_rxq* eth_rxq) = nullptr;
  doca_error_t (*doca_eth_rxq_get_gpu_handle)(const doca_eth_rxq* eth_rxq, doca_gpu_eth_rxq** eth_rxq_ext) =
      nullptr;
  doca_error_t (*doca_eth_rxq_task_recv_set_conf)(
      doca_eth_rxq* eth_rxq,
      RxqTaskRecvCb task_completion_cb,
      RxqTaskRecvCb task_error_cb,
      uint32_t task_recv_num) = nullptr;
  doca_error_t (*doca_eth_rxq_task_recv_allocate_init)(
      doca_eth_rxq* eth_rxq,
      doca_buf* pkt,
      doca_data user_data,
      doca_eth_rxq_task_recv** task_recv) = nullptr;
  doca_task* (*doca_eth_rxq_task_recv_as_doca_task)(doca_eth_rxq_task_recv* task_recv) = nullptr;
  doca_error_t (*doca_eth_rxq_task_recv_get_pkt)(doca_eth_rxq_task_recv* task_recv, doca_buf** pkt) = nullptr;

  doca_error_t (*doca_task_submit)(doca_task* task) = nullptr;
  doca_error_t (*doca_task_get_status)(const doca_task* task) = nullptr;
  void (*doca_task_free)(doca_task* task) = nullptr;
};

struct BackendTxqHandle {
  int handle = -1;
  std::string iface;
  std::string device_name;
  int gpu_id = 0;
  int queue_id = 0;

  doca_dev* dev = nullptr;
  doca_pe* pe = nullptr;
  doca_eth_txq* txq = nullptr;
  doca_ctx* ctx = nullptr;
  doca_gpu_eth_txq* gpu_txq = nullptr;
  doca_mmap* mmap = nullptr;
  doca_buf_inventory* buf_inv = nullptr;
  uint32_t txq_mkey_be = 0u;

  uint32_t inflight = 0u;
  uint32_t task_slots = 1024u;
  uint32_t max_progress_loops = 200000u;

  uint64_t tx_packets = 0u;
  uint64_t tx_bytes = 0u;
  uint64_t tx_errors = 0u;
  uint64_t tx_drops = 0u;
  std::mutex op_lock{};
};

struct BackendRxqHandle {
  int handle = -1;
  std::string iface;
  std::string device_name;
  int gpu_id = 0;
  int queue_id = 0;

  doca_dev* dev = nullptr;
  doca_pe* pe = nullptr;
  doca_eth_rxq* rxq = nullptr;
  doca_gpu_eth_rxq* gpu_rxq = nullptr;
  doca_gpu* gpu_dev = nullptr;
  doca_ctx* ctx = nullptr;
  doca_mmap* mmap = nullptr;
  doca_buf_inventory* buf_inv = nullptr;
  bool gpu_datapath = false;

  uint32_t inflight = 0u;
  uint32_t task_slots = 1024u;
  uint32_t max_progress_loops = 200000u;
  uint32_t max_packet_size = 2048u;

  std::vector<uint8_t*> pkt_storage{};
  std::vector<doca_buf*> completed_pkts{};

  uint64_t rx_packets = 0u;
  uint64_t rx_bytes = 0u;
  uint64_t rx_errors = 0u;
  uint64_t rx_drops = 0u;
};

struct alignas(64) BackendContractFlowUpdateSlot {
  uint64_t version = 0u;
  uint64_t epoch = 0u;
  uint32_t flow_id = 0u;
  uint32_t tcp_seq = 0u;
  uint32_t tcp_ack = 0u;
  uint16_t src_port = 0u;
  uint16_t dst_port = 0u;
  uint8_t tcp_state = 0u;
  uint8_t proto = 0u;
  uint16_t flags = 0u;
  uint32_t rtt_us = 0u;
  uint64_t dpu_ts_ns = 0u;
};

static_assert(sizeof(BackendContractFlowUpdateSlot) == 64, "contract update slot must be 64 bytes");

struct BackendContractWriterHandle {
  int handle = -1;
  void* region = nullptr;
  size_t region_len = 0u;
  std::string region_kind{"addr"};
  bool owns_mapping = false;
  int fd = -1;
  doca_dev* dev = nullptr;
  doca_mmap* mmap = nullptr;
  uint32_t mmap_mkey = 0u;
  void* rdma_importer_so = nullptr;
  uint64_t rdma_import_cookie = 0u;
  int (*rdma_release)(uint64_t cookie, char* err, size_t err_len) = nullptr;
  uint32_t shard_count = 0u;
  uint32_t ring_slots_per_shard = 0u;
  uint32_t hot_flow_capacity = 0u;
  uint64_t publish_count = 0u;
  uint64_t overflow_count = 0u;
  std::mutex op_lock{};
};

std::mutex g_lock;
std::unordered_map<int, std::shared_ptr<BackendTxqHandle>> g_handles;
std::unordered_map<int, BackendRxqHandle> g_rx_handles;
std::unordered_map<int, std::shared_ptr<BackendContractWriterHandle>> g_contract_writers;
int g_next_handle = 1;

std::mutex g_api_lock;
DocaApi g_doca{};

using DocaFlowProgramSteeringFn = int (*)(
    const char* iface,
    const char* device_name,
    const int* rxq_ids,
    int rxq_count,
    uint32_t proto_mask,
    char* err,
    size_t err_len);
using DocaFlowProgramSteeringStreamsFn = int (*)(
    const char* iface,
    const char* device_name,
    const int* rxq_ids,
    int rxq_count,
    const samurai_doca_flow_stream_rule_v1* rules,
    int rule_count,
    char* err,
    size_t err_len);

struct DocaFlowDispatch {
  void* handle = nullptr;
  bool load_attempted = false;
  std::string load_error;
  DocaFlowProgramSteeringFn program_steering = nullptr;
  DocaFlowProgramSteeringStreamsFn program_steering_streams = nullptr;
};

std::mutex g_flow_lock;
DocaFlowDispatch g_flow{};

inline void write_err(char* err, size_t err_len, const std::string& msg) {
  if (!err || err_len == 0u) {
    return;
  }
  const size_t n = std::min(err_len - 1u, msg.size());
  std::memcpy(err, msg.data(), n);
  err[n] = '\0';
}

inline std::string env_string(const char* name, const char* defv) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return std::string(defv ? defv : "");
  }
  return std::string(raw);
}

inline std::string join_int_csv(const int* values, int count) {
  std::string out;
  if (!values || count <= 0) {
    return out;
  }
  for (int i = 0; i < count; ++i) {
    if (i > 0) {
      out.push_back(',');
    }
    out += std::to_string(values[static_cast<size_t>(i)]);
  }
  return out;
}

inline std::string trim_copy(const std::string& s) {
  size_t b = 0u;
  while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b])) != 0) {
    ++b;
  }
  size_t e = s.size();
  while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1u])) != 0) {
    --e;
  }
  return s.substr(b, e - b);
}

inline std::vector<std::string> split_copy(const std::string& s, char delim) {
  std::vector<std::string> out;
  std::string cur;
  cur.reserve(s.size());
  for (char c : s) {
    if (c == delim) {
      out.push_back(cur);
      cur.clear();
      continue;
    }
    cur.push_back(c);
  }
  out.push_back(cur);
  return out;
}

inline bool parse_u64_text(const std::string& raw, uint64_t* out) {
  if (!out) {
    return false;
  }
  const std::string t = trim_copy(raw);
  if (t.empty()) {
    return false;
  }
  char* end = nullptr;
  errno = 0;
  const unsigned long long parsed = std::strtoull(t.c_str(), &end, 0);
  if (errno != 0 || end == t.c_str() || !end || *end != '\0') {
    return false;
  }
  *out = static_cast<uint64_t>(parsed);
  return true;
}

struct ContractRegionSpec {
  std::string kind{};
  uintptr_t addr = 0u;
  std::string file{};
  std::string importer_so{};
  size_t size = 0u;
  uint32_t layout_version = 0u;
  uint32_t shard_count = 0u;
  uint32_t ring_slots_per_shard = 0u;
  uint32_t hot_flow_capacity = 0u;
  size_t event_size = 0u;
};

inline bool parse_contract_region_spec(
    const std::string& raw,
    ContractRegionSpec* out,
    std::string* why) {
  if (!out) {
    if (why) *why = "contract region output spec is null";
    return false;
  }
  *out = ContractRegionSpec{};
  const std::string spec = trim_copy(raw);
  if (spec.empty()) {
    if (why) *why = "contract region spec is empty";
    return false;
  }

  if (spec.rfind("0x", 0) == 0 || spec.rfind("addr:", 0) == 0) {
    out->kind = "addr";
    const size_t sep = spec.find(':', spec.rfind("addr:", 0) == 0 ? 5u : 2u);
    const std::string addr_s = spec.rfind("addr:", 0) == 0
        ? (sep == std::string::npos ? spec.substr(5u) : spec.substr(5u, sep - 5u))
        : (sep == std::string::npos ? spec : spec.substr(0u, sep));
    uint64_t addr = 0u;
    if (!parse_u64_text(addr_s, &addr) || addr == 0u) {
      if (why) *why = "invalid contract addr region spec";
      return false;
    }
    out->addr = static_cast<uintptr_t>(addr);
    if (sep != std::string::npos) {
      uint64_t parsed_size = 0u;
      if (!parse_u64_text(spec.substr(sep + 1u), &parsed_size) || parsed_size == 0u) {
        if (why) *why = "invalid contract addr size";
        return false;
      }
      out->size = static_cast<size_t>(parsed_size);
    }
    return true;
  }

  for (const std::string& token_raw : split_copy(spec, ',')) {
    const std::string token = trim_copy(token_raw);
    const size_t eq = token.find('=');
    if (eq == std::string::npos) {
      if (token.rfind("file:", 0) == 0) {
        out->kind = "file";
        out->file = token.substr(5u);
        continue;
      }
      if (why) *why = "invalid contract region token: " + token;
      return false;
    }
    std::string key = trim_copy(token.substr(0u, eq));
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    const std::string value = trim_copy(token.substr(eq + 1u));
    if (key == "kind" || key == "type") {
      std::string k = value;
      std::transform(k.begin(), k.end(), k.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      if (k != "file" && k != "addr" && k != "rdma" && k != "doca_mmap" && k != "doca-mmap" &&
          k != "bar1_p2p" && k != "bar1-p2p") {
        if (why) *why = "unknown contract region kind: " + value;
        return false;
      }
      if (k == "doca-mmap") {
        out->kind = "doca_mmap";
      } else if (k == "bar1-p2p") {
        out->kind = "bar1_p2p";
      } else {
        out->kind = k;
      }
    } else if (key == "addr") {
      uint64_t addr = 0u;
      if (!parse_u64_text(value, &addr) || addr == 0u) {
        if (why) *why = "invalid contract addr value";
        return false;
      }
      out->addr = static_cast<uintptr_t>(addr);
    } else if (key == "file" || key == "path") {
      out->file = value;
    } else if (key == "importer" || key == "importer_so" || key == "so") {
      out->importer_so = value;
    } else if (key == "size" || key == "len") {
      uint64_t parsed_size = 0u;
      if (!parse_u64_text(value, &parsed_size) || parsed_size == 0u) {
        if (why) *why = "invalid contract region size";
        return false;
      }
      out->size = static_cast<size_t>(parsed_size);
    } else if (key == "layout" || key == "layout_version") {
      uint64_t v = 0u;
      if (!parse_u64_text(value, &v) || v == 0u || v > UINT32_MAX) {
        if (why) *why = "invalid contract layout version";
        return false;
      }
      out->layout_version = static_cast<uint32_t>(v);
    } else if (key == "shards" || key == "shard_count") {
      uint64_t v = 0u;
      if (!parse_u64_text(value, &v) || v == 0u || v > UINT32_MAX) {
        if (why) *why = "invalid contract shard count";
        return false;
      }
      out->shard_count = static_cast<uint32_t>(v);
    } else if (key == "slots" || key == "ring_slots" || key == "ring_slots_per_shard") {
      uint64_t v = 0u;
      if (!parse_u64_text(value, &v) || v == 0u || v > UINT32_MAX) {
        if (why) *why = "invalid contract ring slot count";
        return false;
      }
      out->ring_slots_per_shard = static_cast<uint32_t>(v);
    } else if (key == "hot" || key == "hot_flows" || key == "hot_flow_capacity") {
      uint64_t v = 0u;
      if (!parse_u64_text(value, &v) || v == 0u || v > UINT32_MAX) {
        if (why) *why = "invalid contract hot-flow capacity";
        return false;
      }
      out->hot_flow_capacity = static_cast<uint32_t>(v);
    } else if (key == "event" || key == "event_size") {
      uint64_t v = 0u;
      if (!parse_u64_text(value, &v) || v == 0u) {
        if (why) *why = "invalid contract event size";
        return false;
      }
      out->event_size = static_cast<size_t>(v);
    } else if (key == "bar1_phys") {
      uint64_t v = 0u;
      if (!parse_u64_text(value, &v)) {
        if (why) *why = "invalid contract bar1_phys value";
        return false;
      }
    } else {
      if (why) *why = "unknown contract region key: " + key;
      return false;
    }
  }
  if (out->kind.empty()) {
    out->kind = !out->file.empty() ? "file" : "addr";
  }
  if (out->kind == "file" && out->file.empty()) {
    if (why) *why = "contract region kind=file requires file=";
    return false;
  }
  if ((out->kind == "addr" || out->kind == "doca_mmap") && out->addr == 0u && out->file.empty()) {
    if (why) *why = "contract region kind requires addr= or file=";
    return false;
  }
  return true;
}

inline uint32_t parse_proto_mask_text(const std::string& raw, bool* ok) {
  if (ok) {
    *ok = false;
  }
  const std::string t = trim_copy(raw);
  if (t.empty()) {
    return 0u;
  }
  char* end = nullptr;
  const unsigned long parsed = std::strtoul(t.c_str(), &end, 0);
  if (end != t.c_str() && end != nullptr && *end == '\0') {
    if (ok) {
      *ok = true;
    }
    return static_cast<uint32_t>(parsed);
  }
  uint32_t mask = 0u;
  for (const std::string& token_raw : split_copy(t, '|')) {
    std::string token = trim_copy(token_raw);
    std::transform(token.begin(), token.end(), token.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    if (token.empty()) {
      continue;
    }
    if (token == "tcp") {
      mask |= (1u << 0);
      continue;
    }
    if (token == "udp") {
      mask |= (1u << 1);
      continue;
    }
    if (token == "icmp") {
      mask |= (1u << 2);
      continue;
    }
    return 0u;
  }
  if (ok) {
    *ok = (mask != 0u);
  }
  return mask;
}

struct ContractRegionLayout {
  size_t ring_head_off = 0u;
  size_t ring_tail_off = 0u;
  size_t update_ring_off = 0u;
  size_t hot_flow_table_off = 0u;
  size_t hot_flow_versions_off = 0u;
  size_t hot_flow_epochs_off = 0u;
  size_t total_bytes = 0u;
};

inline bool checked_add_size(size_t a, size_t b, size_t* out) {
  if (!out || a > std::numeric_limits<size_t>::max() - b) {
    return false;
  }
  *out = a + b;
  return true;
}

inline bool checked_mul_size(size_t a, size_t b, size_t* out) {
  if (!out || (a != 0u && b > std::numeric_limits<size_t>::max() / a)) {
    return false;
  }
  *out = a * b;
  return true;
}

inline bool contract_region_layout(
    uint32_t shard_count,
    uint32_t ring_slots_per_shard,
    uint32_t hot_flow_capacity,
    ContractRegionLayout* out,
    std::string* why) {
  if (!out || shard_count == 0u || ring_slots_per_shard == 0u || hot_flow_capacity == 0u) {
    if (why) *why = "invalid contract region dimensions";
    return false;
  }
  size_t shard_bytes = 0u;
  size_t ring_slots = 0u;
  size_t ring_bytes = 0u;
  size_t hot_bytes = 0u;
  size_t hot_versions_bytes = 0u;
  if (!checked_mul_size(static_cast<size_t>(shard_count), sizeof(uint64_t), &shard_bytes) ||
      !checked_mul_size(static_cast<size_t>(shard_count), static_cast<size_t>(ring_slots_per_shard), &ring_slots) ||
      !checked_mul_size(ring_slots, sizeof(BackendContractFlowUpdateSlot), &ring_bytes) ||
      !checked_mul_size(static_cast<size_t>(hot_flow_capacity), sizeof(BackendContractFlowUpdateSlot), &hot_bytes) ||
      !checked_mul_size(static_cast<size_t>(hot_flow_capacity), sizeof(uint64_t), &hot_versions_bytes)) {
    if (why) *why = "contract region layout overflow";
    return false;
  }
  ContractRegionLayout layout{};
  size_t cur = 0u;
  layout.ring_head_off = cur;
  if (!checked_add_size(cur, shard_bytes, &cur)) return false;
  layout.ring_tail_off = cur;
  if (!checked_add_size(cur, shard_bytes, &cur)) return false;
  layout.update_ring_off = cur;
  if (!checked_add_size(cur, ring_bytes, &cur)) return false;
  layout.hot_flow_table_off = cur;
  if (!checked_add_size(cur, hot_bytes, &cur)) return false;
  layout.hot_flow_versions_off = cur;
  if (!checked_add_size(cur, hot_versions_bytes, &cur)) return false;
  layout.hot_flow_epochs_off = cur;
  if (!checked_add_size(cur, hot_versions_bytes, &cur)) return false;
  layout.total_bytes = cur;
  *out = layout;
  return true;
}

inline uint8_t* contract_base(BackendContractWriterHandle& h) {
  return static_cast<uint8_t*>(h.region);
}

inline volatile uint64_t* contract_ring_head(BackendContractWriterHandle& h, const ContractRegionLayout& layout) {
  return reinterpret_cast<volatile uint64_t*>(contract_base(h) + layout.ring_head_off);
}

inline volatile uint64_t* contract_ring_tail(BackendContractWriterHandle& h, const ContractRegionLayout& layout) {
  return reinterpret_cast<volatile uint64_t*>(contract_base(h) + layout.ring_tail_off);
}

inline volatile BackendContractFlowUpdateSlot* contract_update_ring(
    BackendContractWriterHandle& h,
    const ContractRegionLayout& layout) {
  return reinterpret_cast<volatile BackendContractFlowUpdateSlot*>(contract_base(h) + layout.update_ring_off);
}

inline volatile BackendContractFlowUpdateSlot* contract_hot_flow_table(
    BackendContractWriterHandle& h,
    const ContractRegionLayout& layout) {
  return reinterpret_cast<volatile BackendContractFlowUpdateSlot*>(contract_base(h) + layout.hot_flow_table_off);
}

inline volatile uint64_t* contract_hot_versions(BackendContractWriterHandle& h, const ContractRegionLayout& layout) {
  return reinterpret_cast<volatile uint64_t*>(contract_base(h) + layout.hot_flow_versions_off);
}

inline volatile uint64_t* contract_hot_epochs(BackendContractWriterHandle& h, const ContractRegionLayout& layout) {
  return reinterpret_cast<volatile uint64_t*>(contract_base(h) + layout.hot_flow_epochs_off);
}

inline void contract_store_event_slot(
    volatile BackendContractFlowUpdateSlot* dst,
    const DocaFlowUpdateEventV1& ev) {
  const uint64_t commit_version = ev.version;
  const uint64_t begin_version = (commit_version > 0u && (commit_version & 1ull) == 0ull)
      ? (commit_version - 1ull)
      : (commit_version | 1ull);
  __atomic_store_n(&dst->version, begin_version, __ATOMIC_RELEASE);
  __atomic_thread_fence(__ATOMIC_RELEASE);
  dst->epoch = ev.epoch;
  dst->flow_id = ev.flow_id;
  dst->tcp_seq = ev.tcp_seq;
  dst->tcp_ack = ev.tcp_ack;
  dst->src_port = ev.src_port;
  dst->dst_port = ev.dst_port;
  dst->tcp_state = ev.tcp_state;
  dst->proto = ev.proto;
  dst->flags = ev.flags;
  dst->rtt_us = ev.rtt_us;
  dst->dpu_ts_ns = ev.dpu_ts_ns;
  __atomic_thread_fence(__ATOMIC_RELEASE);
  __atomic_store_n(&dst->version, commit_version, __ATOMIC_RELEASE);
}

inline bool queue_id_allowed(const std::vector<int>& allowed, int qid) {
  return std::find(allowed.begin(), allowed.end(), qid) != allowed.end();
}

inline bool parse_stream_rules_env(
    const std::string& env_value,
    const std::vector<int>& allowed_qids,
    std::vector<samurai_doca_flow_stream_rule_v1>& out_rules,
    std::string& why) {
  out_rules.clear();
  if (env_value.empty()) {
    return true;
  }
  uint32_t default_stream_id = 1u;
  for (const std::string& rule_raw : split_copy(env_value, ';')) {
    const std::string rule_text = trim_copy(rule_raw);
    if (rule_text.empty()) {
      continue;
    }
    samurai_doca_flow_stream_rule_v1 rule{};
    rule.stream_id = default_stream_id++;
    rule.proto_mask = 0u;
    rule.ipv4_dst_be = 0u;
    rule.l4_dst_port_be = 0u;
    rule.rxq_id = 0u;
    bool has_queue = false;
    bool has_proto = false;
    for (const std::string& field_raw : split_copy(rule_text, ',')) {
      const std::string field = trim_copy(field_raw);
      if (field.empty()) {
        continue;
      }
      const size_t eq = field.find('=');
      if (eq == std::string::npos) {
        why = "invalid stream rule field (expected key=value)";
        return false;
      }
      std::string key = trim_copy(field.substr(0, eq));
      std::string value = trim_copy(field.substr(eq + 1u));
      std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      if (key == "stream" || key == "stream_id") {
        char* end = nullptr;
        const unsigned long v = std::strtoul(value.c_str(), &end, 10);
        if (end == value.c_str() || (end != nullptr && *end != '\0')) {
          why = "invalid stream_id in flow stream rule";
          return false;
        }
        rule.stream_id = static_cast<uint32_t>(v);
        continue;
      }
      if (key == "queue" || key == "rxq" || key == "queue_id") {
        char* end = nullptr;
        const long q = std::strtol(value.c_str(), &end, 10);
        if (end == value.c_str() || (end != nullptr && *end != '\0') || q < 0 || q > 65535) {
          why = "invalid queue id in flow stream rule";
          return false;
        }
        if (!queue_id_allowed(allowed_qids, static_cast<int>(q))) {
          why = "flow stream rule queue id is not in configured RX queues";
          return false;
        }
        rule.rxq_id = static_cast<uint16_t>(q);
        has_queue = true;
        continue;
      }
      if (key == "proto" || key == "proto_mask") {
        bool ok = false;
        const uint32_t mask = parse_proto_mask_text(value, &ok);
        if (!ok || mask == 0u) {
          why = "invalid proto mask in flow stream rule";
          return false;
        }
        rule.proto_mask = mask;
        has_proto = true;
        continue;
      }
      if (key == "dstip" || key == "dst_ip" || key == "ipv4_dst") {
        struct in_addr addr {};
        if (inet_pton(AF_INET, value.c_str(), &addr) != 1) {
          why = "invalid IPv4 destination in flow stream rule";
          return false;
        }
        rule.ipv4_dst_be = static_cast<uint32_t>(addr.s_addr);
        continue;
      }
      if (key == "dstport" || key == "dst_port" || key == "l4_dst_port") {
        char* end = nullptr;
        const long port = std::strtol(value.c_str(), &end, 10);
        if (end == value.c_str() || (end != nullptr && *end != '\0') || port < 0 || port > 65535) {
          why = "invalid L4 destination port in flow stream rule";
          return false;
        }
        rule.l4_dst_port_be = htons(static_cast<uint16_t>(port));
        continue;
      }
      why = "unknown key in flow stream rule: " + key;
      return false;
    }
    if (!has_queue) {
      why = "missing queue in flow stream rule";
      return false;
    }
    if (!has_proto) {
      why = "missing proto in flow stream rule";
      return false;
    }
    out_rules.push_back(rule);
  }
  if (out_rules.empty()) {
    why = "empty flow stream rules";
    return false;
  }
  return true;
}

inline int env_int(const char* name, int defv, int minv, int maxv) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return defv;
  }
  char* end = nullptr;
  const long v = std::strtol(raw, &end, 10);
  if (end == raw || (end && *end != '\0')) {
    return defv;
  }
  const long lo = static_cast<long>(minv);
  const long hi = static_cast<long>(maxv);
  if (v < lo) {
    return minv;
  }
  if (v > hi) {
    return maxv;
  }
  return static_cast<int>(v);
}

inline std::string doca_err(const DocaApi& api, doca_error_t rc) {
  if (api.doca_error_get_descr) {
    const char* d = api.doca_error_get_descr(rc);
    if (d && *d) {
      return std::string(d);
    }
  }
  return std::string("doca_error=") + std::to_string(static_cast<int>(rc));
}

inline int run_flow_ctl_command(
    const char* iface,
    const char* device_name,
    const int* rxq_ids,
    int rxq_count,
    uint32_t proto_mask,
    char* err,
    size_t err_len) {
  const std::string flow_ctl = env_string("SAMURAI_GPU_DOCA_FLOW_CTL", "");
  if (flow_ctl.empty()) {
    return 1;
  }
  const std::string qcsv = join_int_csv(rxq_ids, rxq_count);
  std::string cmd;
  cmd.reserve(512);
  cmd.append(flow_ctl);
  cmd.append(" --iface ");
  cmd.append(iface ? iface : "");
  cmd.append(" --device ");
  cmd.append(device_name ? device_name : "");
  cmd.append(" --proto-mask ");
  cmd.append(std::to_string(proto_mask));
  cmd.append(" --queues ");
  cmd.append(qcsv);
  const int rc = std::system(cmd.c_str());
  if (rc == 0) {
    return 0;
  }
  write_err(err, err_len, "flow steering control command failed");
  return -1;
}

inline bool ensure_flow_dispatch(std::string& why) {
  std::lock_guard<std::mutex> guard(g_flow_lock);
  if (g_flow.program_steering != nullptr) {
    return true;
  }
  if (g_flow.load_attempted) {
    why = g_flow.load_error.empty() ? "flow dispatch unavailable" : g_flow.load_error;
    return false;
  }
  g_flow.load_attempted = true;

  const std::string so_path =
      env_string("SAMURAI_GPU_DOCA_FLOW_SHIM_SO", "libsamurai_doca_flow_backend.so");
  dlerror();
  g_flow.handle = dlopen(so_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (g_flow.handle == nullptr) {
    const char* dl_err = dlerror();
    g_flow.load_error = std::string("dlopen failed for flow steering backend: ") +
        (dl_err ? dl_err : "unknown");
    why = g_flow.load_error;
    return false;
  }
  dlerror();
  void* sym = dlsym(g_flow.handle, "samurai_doca_flow_program_steering_v1");
  const char* sym_err = dlerror();
  if (!sym || sym_err) {
    g_flow.load_error = std::string("dlsym(samurai_doca_flow_program_steering_v1) failed: ") +
        (sym_err ? sym_err : "unknown");
    dlclose(g_flow.handle);
    g_flow.handle = nullptr;
    why = g_flow.load_error;
    return false;
  }
  g_flow.program_steering = reinterpret_cast<DocaFlowProgramSteeringFn>(sym);
  dlerror();
  void* sym_streams = dlsym(g_flow.handle, "samurai_doca_flow_program_steering_streams_v1");
  const char* sym_streams_err = dlerror();
  if (sym_streams && !sym_streams_err) {
    g_flow.program_steering_streams = reinterpret_cast<DocaFlowProgramSteeringStreamsFn>(sym_streams);
  } else {
    g_flow.program_steering_streams = nullptr;
  }
  return true;
}

inline bool try_dlopen(std::vector<void*>& libs, const char* soname) {
  if (!soname || !*soname) {
    return false;
  }
  void* h = dlopen(soname, RTLD_NOW | RTLD_LOCAL);
  if (!h) {
    return false;
  }
  libs.push_back(h);
  return true;
}

inline void* find_symbol(const std::vector<void*>& libs, const char* name) {
  for (void* lib : libs) {
    if (!lib) {
      continue;
    }
    dlerror();
    void* sym = dlsym(lib, name);
    if (sym && !dlerror()) {
      return sym;
    }
  }
  dlerror();
  void* sym = dlsym(RTLD_DEFAULT, name);
  if (sym && !dlerror()) {
    return sym;
  }
  return nullptr;
}

template <typename Fn>
inline bool resolve_symbol(const std::vector<void*>& libs, const char* name, Fn& out, std::string& why) {
  void* sym = find_symbol(libs, name);
  if (!sym) {
    why = std::string("missing DOCA symbol: ") + name;
    return false;
  }
  out = reinterpret_cast<Fn>(sym);
  return true;
}

template <typename Fn>
inline bool resolve_symbol_any(const std::vector<void*>& libs, std::initializer_list<const char*> names, Fn& out) {
  std::string why;
  for (const char* name : names) {
    if (!name || !*name) {
      continue;
    }
    Fn fn = nullptr;
    if (resolve_symbol(libs, name, fn, why)) {
      out = fn;
      return true;
    }
  }
  return false;
}

inline void close_lib(void*& lib) {
  if (!lib) {
    return;
  }
  dlclose(lib);
  lib = nullptr;
}

inline bool ensure_doca_api(std::string& why) {
  std::lock_guard<std::mutex> guard(g_api_lock);
  if (g_doca.loaded) {
    return true;
  }
  if (!g_doca.load_error.empty()) {
    why = g_doca.load_error;
    return false;
  }

  std::vector<void*> libs;
  const bool core_ok = try_dlopen(libs, "libdoca_common.so") || try_dlopen(libs, "libdoca_core.so");
  const bool eth_ok = try_dlopen(libs, "libdoca_eth.so");
  const bool eth_cpu_ok = try_dlopen(libs, "libdoca_eth_cpu_data_path.so");
  const bool eth_gpu_ok = try_dlopen(libs, "libdoca_eth_txq_gpu_data_path.so") || try_dlopen(libs, "libdoca_gpunetio.so");
  if (!core_ok || !eth_ok || !eth_cpu_ok) {
    g_doca.load_error =
        "failed to load required DOCA shared libraries (need libdoca_common/core, libdoca_eth, libdoca_eth_cpu_data_path)";
    why = g_doca.load_error;
    for (void* lib : libs) {
      if (lib) {
        dlclose(lib);
      }
    }
    return false;
  }
  (void)eth_gpu_ok;

  std::string sym_why;
  if (!resolve_symbol(libs, "doca_error_get_descr", g_doca.doca_error_get_descr, sym_why) ||
      !resolve_symbol(libs, "doca_devinfo_create_list", g_doca.doca_devinfo_create_list, sym_why) ||
      !resolve_symbol(libs, "doca_devinfo_destroy_list", g_doca.doca_devinfo_destroy_list, sym_why) ||
      !resolve_symbol(libs, "doca_devinfo_get_ibdev_name", g_doca.doca_devinfo_get_ibdev_name, sym_why) ||
      !resolve_symbol(libs, "doca_devinfo_get_iface_name", g_doca.doca_devinfo_get_iface_name, sym_why) ||
      !resolve_symbol(libs, "doca_dev_open", g_doca.doca_dev_open, sym_why) ||
      !resolve_symbol(libs, "doca_dev_close", g_doca.doca_dev_close, sym_why) ||
      !resolve_symbol(libs, "doca_pe_create", g_doca.doca_pe_create, sym_why) ||
      !resolve_symbol(libs, "doca_pe_destroy", g_doca.doca_pe_destroy, sym_why) ||
      !resolve_symbol(libs, "doca_pe_connect_ctx", g_doca.doca_pe_connect_ctx, sym_why) ||
      !resolve_symbol(libs, "doca_pe_progress", g_doca.doca_pe_progress, sym_why) ||
      !resolve_symbol(libs, "doca_ctx_set_user_data", g_doca.doca_ctx_set_user_data, sym_why) ||
      !resolve_symbol(libs, "doca_ctx_start", g_doca.doca_ctx_start, sym_why) ||
      !resolve_symbol(libs, "doca_ctx_stop", g_doca.doca_ctx_stop, sym_why) ||
      !resolve_symbol(libs, "doca_mmap_create", g_doca.doca_mmap_create, sym_why) ||
      !resolve_symbol(libs, "doca_mmap_destroy", g_doca.doca_mmap_destroy, sym_why) ||
      !resolve_symbol(libs, "doca_mmap_add_dev", g_doca.doca_mmap_add_dev, sym_why) ||
      !resolve_symbol(libs, "doca_mmap_set_memrange", g_doca.doca_mmap_set_memrange, sym_why) ||
      !resolve_symbol(libs, "doca_mmap_start", g_doca.doca_mmap_start, sym_why) ||
      !resolve_symbol(libs, "doca_mmap_get_mkey", g_doca.doca_mmap_get_mkey, sym_why) ||
      !resolve_symbol(libs, "doca_buf_inventory_create", g_doca.doca_buf_inventory_create, sym_why) ||
      !resolve_symbol(libs, "doca_buf_inventory_destroy", g_doca.doca_buf_inventory_destroy, sym_why) ||
      !resolve_symbol(libs, "doca_buf_inventory_start", g_doca.doca_buf_inventory_start, sym_why) ||
      !resolve_symbol(libs, "doca_buf_inventory_buf_get_by_addr", g_doca.doca_buf_inventory_buf_get_by_addr, sym_why) ||
      !resolve_symbol(libs, "doca_buf_dec_refcount", g_doca.doca_buf_dec_refcount, sym_why) ||
      !resolve_symbol(libs, "doca_buf_get_data", g_doca.doca_buf_get_data, sym_why) ||
      !resolve_symbol(libs, "doca_buf_get_data_len", g_doca.doca_buf_get_data_len, sym_why) ||
      !resolve_symbol(libs, "doca_buf_get_head", g_doca.doca_buf_get_head, sym_why) ||
      !resolve_symbol(libs, "doca_buf_get_len", g_doca.doca_buf_get_len, sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_create", g_doca.doca_eth_txq_create, sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_destroy", g_doca.doca_eth_txq_destroy, sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_set_type", g_doca.doca_eth_txq_set_type, sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_set_l3_chksum_offload", g_doca.doca_eth_txq_set_l3_chksum_offload, sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_set_l4_chksum_offload", g_doca.doca_eth_txq_set_l4_chksum_offload, sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_apply_queue_id", g_doca.doca_eth_txq_apply_queue_id, sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_get_gpu_handle", g_doca.doca_eth_txq_get_gpu_handle, sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_as_doca_ctx", g_doca.doca_eth_txq_as_doca_ctx, sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_task_send_set_conf", g_doca.doca_eth_txq_task_send_set_conf, sym_why) ||
      !resolve_symbol(
          libs,
          "doca_eth_txq_task_send_allocate_init",
          g_doca.doca_eth_txq_task_send_allocate_init,
          sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_task_send_as_doca_task", g_doca.doca_eth_txq_task_send_as_doca_task, sym_why) ||
      !resolve_symbol(libs, "doca_eth_txq_task_send_get_pkt", g_doca.doca_eth_txq_task_send_get_pkt, sym_why) ||
      !resolve_symbol(libs, "doca_eth_rxq_create", g_doca.doca_eth_rxq_create, sym_why) ||
      !resolve_symbol(libs, "doca_eth_rxq_destroy", g_doca.doca_eth_rxq_destroy, sym_why) ||
      !resolve_symbol(libs, "doca_eth_rxq_set_type", g_doca.doca_eth_rxq_set_type, sym_why) ||
      !resolve_symbol(libs, "doca_eth_rxq_as_doca_ctx", g_doca.doca_eth_rxq_as_doca_ctx, sym_why) ||
      !resolve_symbol(libs, "doca_eth_rxq_task_recv_set_conf", g_doca.doca_eth_rxq_task_recv_set_conf, sym_why) ||
      !resolve_symbol(
          libs,
          "doca_eth_rxq_task_recv_allocate_init",
          g_doca.doca_eth_rxq_task_recv_allocate_init,
          sym_why) ||
      !resolve_symbol(libs, "doca_eth_rxq_task_recv_as_doca_task", g_doca.doca_eth_rxq_task_recv_as_doca_task, sym_why) ||
      !resolve_symbol(libs, "doca_eth_rxq_task_recv_get_pkt", g_doca.doca_eth_rxq_task_recv_get_pkt, sym_why) ||
      !resolve_symbol(libs, "doca_task_submit", g_doca.doca_task_submit, sym_why) ||
      !resolve_symbol(libs, "doca_task_get_status", g_doca.doca_task_get_status, sym_why) ||
      !resolve_symbol(libs, "doca_task_free", g_doca.doca_task_free, sym_why)) {
    g_doca.load_error = sym_why;
    why = g_doca.load_error;
    for (void* lib : libs) {
      if (lib) {
        dlclose(lib);
      }
    }
    return false;
  }

  g_doca.lib_core = libs.size() > 0u ? libs[0] : nullptr;
  g_doca.lib_eth = libs.size() > 1u ? libs[1] : nullptr;
  g_doca.lib_eth_cpu = libs.size() > 2u ? libs[2] : nullptr;
  g_doca.lib_eth_gpu = libs.size() > 3u ? libs[3] : nullptr;
  (void)resolve_symbol_any(
      libs,
      {"doca_ctx_set_datapath_on_gpu", "doca_ctx_set_data_path_on_gpu"},
      g_doca.doca_ctx_set_datapath_on_gpu);
  (void)resolve_symbol_any(libs, {"doca_gpu_create"}, g_doca.doca_gpu_create);
  (void)resolve_symbol_any(libs, {"doca_gpu_destroy"}, g_doca.doca_gpu_destroy);
  (void)resolve_symbol_any(libs, {"doca_eth_rxq_get_gpu_handle"}, g_doca.doca_eth_rxq_get_gpu_handle);
  g_doca.loaded = true;
  return true;
}

inline void destroy_backend_txq_unlocked(BackendTxqHandle& h) {
  if (!g_doca.loaded) {
    return;
  }
  if (h.ctx && g_doca.doca_ctx_stop) {
    (void)g_doca.doca_ctx_stop(h.ctx);
  }
  if (h.buf_inv) {
    if (g_doca.doca_buf_inventory_stop) {
      (void)g_doca.doca_buf_inventory_stop(h.buf_inv);
    }
    (void)g_doca.doca_buf_inventory_destroy(h.buf_inv);
    h.buf_inv = nullptr;
  }
  if (h.mmap) {
    if (g_doca.doca_mmap_stop) {
      (void)g_doca.doca_mmap_stop(h.mmap);
    }
    (void)g_doca.doca_mmap_destroy(h.mmap);
    h.mmap = nullptr;
  }
  if (h.txq) {
    (void)g_doca.doca_eth_txq_destroy(h.txq);
    h.txq = nullptr;
    h.ctx = nullptr;
    h.gpu_txq = nullptr;
  }
  if (h.pe) {
    (void)g_doca.doca_pe_destroy(h.pe);
    h.pe = nullptr;
  }
  if (h.dev) {
    (void)g_doca.doca_dev_close(h.dev);
    h.dev = nullptr;
  }
}

inline void destroy_backend_rxq_unlocked(BackendRxqHandle& h) {
  if (!g_doca.loaded) {
    return;
  }
  if (h.ctx && g_doca.doca_ctx_stop) {
    (void)g_doca.doca_ctx_stop(h.ctx);
  }
  h.completed_pkts.clear();
  if (h.buf_inv) {
    if (g_doca.doca_buf_inventory_stop) {
      (void)g_doca.doca_buf_inventory_stop(h.buf_inv);
    }
    (void)g_doca.doca_buf_inventory_destroy(h.buf_inv);
    h.buf_inv = nullptr;
  }
  if (h.mmap) {
    if (g_doca.doca_mmap_stop) {
      (void)g_doca.doca_mmap_stop(h.mmap);
    }
    (void)g_doca.doca_mmap_destroy(h.mmap);
    h.mmap = nullptr;
  }
  if (h.rxq) {
    (void)g_doca.doca_eth_rxq_destroy(h.rxq);
    h.rxq = nullptr;
    h.gpu_rxq = nullptr;
    h.ctx = nullptr;
  }
  if (h.gpu_dev && g_doca.doca_gpu_destroy) {
    (void)g_doca.doca_gpu_destroy(h.gpu_dev);
    h.gpu_dev = nullptr;
  }
  h.gpu_datapath = false;
  if (h.pe) {
    (void)g_doca.doca_pe_destroy(h.pe);
    h.pe = nullptr;
  }
  if (h.dev) {
    (void)g_doca.doca_dev_close(h.dev);
    h.dev = nullptr;
  }
  for (uint8_t* p : h.pkt_storage) {
    if (p) {
      std::free(p);
    }
  }
  h.pkt_storage.clear();
}

static void task_send_common_cb(
    doca_eth_txq_task_send* task_send,
    doca_data task_user_data,
    doca_data ctx_user_data) {
  (void)task_user_data;
  if (!task_send || !ctx_user_data.ptr) {
    return;
  }
  auto* h = reinterpret_cast<BackendTxqHandle*>(ctx_user_data.ptr);
  doca_task* task = g_doca.doca_eth_txq_task_send_as_doca_task(task_send);
  doca_error_t task_status = kDocaSuccess;
  if (task && g_doca.doca_task_get_status) {
    task_status = g_doca.doca_task_get_status(task);
  }
  if (task_status != kDocaSuccess) {
    h->tx_errors += 1u;
    h->tx_drops += 1u;
  }
  doca_buf* pkt = nullptr;
  if (g_doca.doca_eth_txq_task_send_get_pkt &&
      g_doca.doca_eth_txq_task_send_get_pkt(task_send, &pkt) == kDocaSuccess &&
      pkt && g_doca.doca_buf_dec_refcount) {
    (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
  }
  if (task && g_doca.doca_task_free) {
    g_doca.doca_task_free(task);
  }
  if (h->inflight > 0u) {
    h->inflight -= 1u;
  }
}

static void task_recv_common_cb(
    doca_eth_rxq_task_recv* task_recv,
    doca_data task_user_data,
    doca_data ctx_user_data) {
  (void)task_user_data;
  if (!task_recv || !ctx_user_data.ptr) {
    return;
  }
  auto* h = reinterpret_cast<BackendRxqHandle*>(ctx_user_data.ptr);
  doca_task* task = g_doca.doca_eth_rxq_task_recv_as_doca_task(task_recv);
  doca_error_t task_status = kDocaSuccess;
  if (task && g_doca.doca_task_get_status) {
    task_status = g_doca.doca_task_get_status(task);
  }
  doca_buf* pkt = nullptr;
  if (g_doca.doca_eth_rxq_task_recv_get_pkt) {
    (void)g_doca.doca_eth_rxq_task_recv_get_pkt(task_recv, &pkt);
  }
  if (task_status == kDocaSuccess && pkt) {
    h->completed_pkts.push_back(pkt);
  } else {
    h->rx_errors += 1u;
    h->rx_drops += 1u;
    if (pkt && g_doca.doca_buf_dec_refcount) {
      (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
    }
  }
  if (task && g_doca.doca_task_free) {
    g_doca.doca_task_free(task);
  }
  if (h->inflight > 0u) {
    h->inflight -= 1u;
  }
}

inline void progress_rxq_until_packet_or_budget_unlocked(BackendRxqHandle& h) {
  uint32_t loops = 0u;
  while (h.completed_pkts.empty() && loops < h.max_progress_loops) {
    (void)g_doca.doca_pe_progress(h.pe);
    loops += 1u;
  }
}

inline bool rearm_rx_packet_unlocked(BackendRxqHandle& h, doca_buf* pkt) {
  if (!pkt || !h.rxq || !h.buf_inv || !h.mmap) {
    return false;
  }
  void* head_ptr = nullptr;
  size_t head_len = 0u;
  if (g_doca.doca_buf_get_head(pkt, &head_ptr) != kDocaSuccess || !head_ptr ||
      g_doca.doca_buf_get_len(pkt, &head_len) != kDocaSuccess || head_len == 0u) {
    (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
    return false;
  }
  (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);

  doca_buf* next_pkt = nullptr;
  doca_error_t rc = g_doca.doca_buf_inventory_buf_get_by_addr(h.buf_inv, h.mmap, head_ptr, head_len, &next_pkt);
  if (rc != kDocaSuccess || !next_pkt) {
    return false;
  }
  doca_data user_data{};
  user_data.u64 = 0u;
  doca_eth_rxq_task_recv* next_task_recv = nullptr;
  rc = g_doca.doca_eth_rxq_task_recv_allocate_init(h.rxq, next_pkt, user_data, &next_task_recv);
  if (rc != kDocaSuccess || !next_task_recv) {
    (void)g_doca.doca_buf_dec_refcount(next_pkt, nullptr);
    return false;
  }
  doca_task* next_task = g_doca.doca_eth_rxq_task_recv_as_doca_task(next_task_recv);
  if (!next_task) {
    (void)g_doca.doca_buf_dec_refcount(next_pkt, nullptr);
    return false;
  }
  rc = g_doca.doca_task_submit(next_task);
  if (rc != kDocaSuccess) {
    (void)g_doca.doca_task_free(next_task);
    (void)g_doca.doca_buf_dec_refcount(next_pkt, nullptr);
    return false;
  }
  h.inflight += 1u;
  return true;
}

inline int receive_burst_view_unlocked(
    BackendRxqHandle& h,
    uint64_t* out_packet_ptrs,
    uint16_t* out_lengths,
    uint64_t* out_packet_handles,
    int max_packets) {
  if (!out_packet_ptrs || !out_lengths || !out_packet_handles || max_packets <= 0) {
    return -1;
  }
  progress_rxq_until_packet_or_budget_unlocked(h);

  int copied = 0;
  while (!h.completed_pkts.empty() && copied < max_packets) {
    doca_buf* pkt = h.completed_pkts.back();
    h.completed_pkts.pop_back();
    if (!pkt) {
      continue;
    }
    void* data_ptr = nullptr;
    size_t data_len = 0u;
    if (g_doca.doca_buf_get_data(pkt, &data_ptr) != kDocaSuccess || !data_ptr ||
        g_doca.doca_buf_get_data_len(pkt, &data_len) != kDocaSuccess || data_len == 0u) {
      h.rx_errors += 1u;
      h.rx_drops += 1u;
      if (!rearm_rx_packet_unlocked(h, pkt)) {
        h.rx_errors += 1u;
        h.rx_drops += 1u;
      }
      continue;
    }
    if (data_len > static_cast<size_t>(std::numeric_limits<uint16_t>::max())) {
      data_len = static_cast<size_t>(std::numeric_limits<uint16_t>::max());
    }
    out_packet_ptrs[copied] = reinterpret_cast<uint64_t>(data_ptr);
    out_lengths[copied] = static_cast<uint16_t>(data_len);
    out_packet_handles[copied] = reinterpret_cast<uint64_t>(pkt);
    copied += 1;
    h.rx_packets += 1u;
    h.rx_bytes += static_cast<uint64_t>(data_len);
  }
  return copied;
}

inline int release_burst_view_unlocked(BackendRxqHandle& h, const uint64_t* packet_handles, int packet_count) {
  if (!packet_handles || packet_count <= 0) {
    return -1;
  }
  int rearmed = 0;
  for (int i = 0; i < packet_count; ++i) {
    doca_buf* pkt = reinterpret_cast<doca_buf*>(packet_handles[i]);
    if (!pkt) {
      continue;
    }
    if (rearm_rx_packet_unlocked(h, pkt)) {
      rearmed += 1;
    } else {
      h.rx_errors += 1u;
      h.rx_drops += 1u;
    }
  }
  return rearmed;
}

inline bool any_invalid_len(const uint16_t* lengths, int count) {
  if (!lengths || count <= 0) {
    return true;
  }
  for (int i = 0; i < count; ++i) {
    if (lengths[i] == 0u) {
      return true;
    }
  }
  return false;
}

enum class TimedClockDomain : int {
  kMonotonic = 0,
  kRealtime = 1,
  kTai = 2,
  kAuto = 3,
};

inline bool read_now_ns(clockid_t cid, uint64_t* out_ns) {
  if (!out_ns) {
    return false;
  }
  struct timespec ts;
  ts.tv_sec = 0;
  ts.tv_nsec = 0;
  if (clock_gettime(cid, &ts) != 0) {
    return false;
  }
  *out_ns = (static_cast<uint64_t>(ts.tv_sec) * 1000000000ull) + static_cast<uint64_t>(ts.tv_nsec);
  return true;
}

inline uint64_t now_ns_monotonic() {
  uint64_t out = 0ull;
  if (!read_now_ns(CLOCK_MONOTONIC, &out)) {
    return 0ull;
  }
  return out;
}

inline void wait_until_ns_monotonic(uint64_t target_ns) {
  if (target_ns == 0ull) {
    return;
  }
  while (true) {
    const uint64_t now = now_ns_monotonic();
    if (now >= target_ns) {
      return;
    }
    const uint64_t remain = target_ns - now;
    if (remain > 50000ull) {
      struct timespec req;
      req.tv_sec = static_cast<time_t>(remain / 1000000000ull);
      req.tv_nsec = static_cast<long>(remain % 1000000000ull);
      while (clock_nanosleep(CLOCK_MONOTONIC, 0, &req, &req) == EINTR) {
      }
    } else {
      // fine-grained tail spin for sub-50us windows
#if defined(__x86_64__) || defined(__i386__)
      __asm__ volatile("pause");
#endif
    }
  }
}

inline TimedClockDomain timed_clock_domain_from_env() {
  std::string mode = env_string("SAMURAI_GPU_DOCA_TIMED_TX_CLOCK", "monotonic");
  std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  if (mode == "realtime" || mode == "real" || mode == "clock_realtime") {
    return TimedClockDomain::kRealtime;
  }
  if (mode == "tai" || mode == "clock_tai") {
    return TimedClockDomain::kTai;
  }
  if (mode == "auto") {
    return TimedClockDomain::kAuto;
  }
  return TimedClockDomain::kMonotonic;
}

inline bool resolve_clockid_for_domain(TimedClockDomain domain, clockid_t* out_cid) {
  if (!out_cid) {
    return false;
  }
  switch (domain) {
    case TimedClockDomain::kMonotonic:
      *out_cid = CLOCK_MONOTONIC;
      return true;
    case TimedClockDomain::kRealtime:
      *out_cid = CLOCK_REALTIME;
      return true;
    case TimedClockDomain::kTai:
#ifdef CLOCK_TAI
      *out_cid = CLOCK_TAI;
      return true;
#else
      return false;
#endif
    case TimedClockDomain::kAuto:
      break;
  }
  return false;
}

inline TimedClockDomain infer_auto_domain_from_samples(const uint64_t* ts, int count) {
  if (!ts || count <= 0) {
    return TimedClockDomain::kMonotonic;
  }
  // Monotonic boot clocks are typically far smaller than epoch nanoseconds.
  constexpr uint64_t kEpochThresholdNs = 1000000000000000ull;  // ~11.5 days in ns scale from epoch discriminant
  int epoch_like = 0;
  int monotonic_like = 0;
  const int sample_n = std::min(count, 32);
  for (int i = 0; i < sample_n; ++i) {
    if (ts[i] >= kEpochThresholdNs) {
      epoch_like += 1;
    } else {
      monotonic_like += 1;
    }
  }
  return (epoch_like > monotonic_like) ? TimedClockDomain::kRealtime : TimedClockDomain::kMonotonic;
}

inline bool convert_timestamps_to_monotonic(
    const uint64_t* ts_in,
    int count,
    TimedClockDomain requested_domain,
    std::vector<uint64_t>* ts_out,
    char* err,
    size_t err_len) {
  if (!ts_out || !ts_in || count <= 0) {
    write_err(err, err_len, "invalid timestamp conversion arguments");
    return false;
  }
  ts_out->assign(static_cast<size_t>(count), 0ull);
  if (requested_domain == TimedClockDomain::kMonotonic) {
    for (int i = 0; i < count; ++i) {
      (*ts_out)[static_cast<size_t>(i)] = ts_in[static_cast<size_t>(i)];
    }
    return true;
  }

  TimedClockDomain domain = requested_domain;
  if (domain == TimedClockDomain::kAuto) {
    domain = infer_auto_domain_from_samples(ts_in, count);
  }
  clockid_t src_cid = CLOCK_MONOTONIC;
  if (!resolve_clockid_for_domain(domain, &src_cid)) {
    write_err(err, err_len, "requested timed clock domain is unsupported on this platform");
    return false;
  }
  uint64_t mono_now = 0ull;
  uint64_t src_now = 0ull;
  if (!read_now_ns(CLOCK_MONOTONIC, &mono_now) || !read_now_ns(src_cid, &src_now)) {
    write_err(err, err_len, "clock_gettime failed while resolving timed clock domain");
    return false;
  }
  const int64_t delta = static_cast<int64_t>(mono_now) - static_cast<int64_t>(src_now);
  for (int i = 0; i < count; ++i) {
    const int64_t raw = static_cast<int64_t>(ts_in[static_cast<size_t>(i)]);
    int64_t mono_ts = raw + delta;
    if (mono_ts < 0) {
      mono_ts = 0;
    }
    (*ts_out)[static_cast<size_t>(i)] = static_cast<uint64_t>(mono_ts);
  }
  return true;
}

inline int send_vector_unlocked(
    BackendTxqHandle& h,
    const uint8_t** packets,
    const uint16_t* lengths,
    const uint64_t* tx_timestamps_ns,
    bool use_host_wait_timing,
    int count,
    int* out_sent,
    int* out_errors,
    char* err,
    size_t err_len,
    const char* op_name) {
  int submitted = 0;
  int failures = 0;
  uint64_t bytes_submitted = 0u;
  for (int i = 0; i < count; ++i) {
    if (!packets[i] || lengths[i] == 0u) {
      failures += 1;
      continue;
    }
    if (use_host_wait_timing && tx_timestamps_ns != nullptr) {
      const uint64_t target_ns = tx_timestamps_ns[static_cast<size_t>(i)];
      if (target_ns > 0ull) {
        wait_until_ns_monotonic(target_ns);
      }
    }
    doca_buf* pkt = nullptr;
    doca_error_t rc = g_doca.doca_buf_inventory_buf_get_by_addr(
        h.buf_inv,
        h.mmap,
        const_cast<uint8_t*>(packets[i]),
        static_cast<size_t>(lengths[i]),
        &pkt);
    if (rc != kDocaSuccess || !pkt) {
      failures += 1;
      continue;
    }
    doca_data user_data{};
    user_data.u64 = static_cast<uint64_t>(i);
    doca_eth_txq_task_send* task_send = nullptr;
    rc = g_doca.doca_eth_txq_task_send_allocate_init(h.txq, pkt, user_data, &task_send);
    if (rc != kDocaSuccess || !task_send) {
      (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
      failures += 1;
      continue;
    }
    doca_task* task = g_doca.doca_eth_txq_task_send_as_doca_task(task_send);
    if (!task) {
      (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
      failures += 1;
      continue;
    }
    rc = g_doca.doca_task_submit(task);
    if (rc != kDocaSuccess) {
      (void)g_doca.doca_task_free(task);
      (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
      failures += 1;
      continue;
    }
    h.inflight += 1u;
    submitted += 1;
    bytes_submitted += static_cast<uint64_t>(lengths[i]);
  }

  uint32_t loops = 0u;
  while (h.inflight > 0u && loops < h.max_progress_loops) {
    (void)g_doca.doca_pe_progress(h.pe);
    loops += 1u;
  }
  if (h.inflight > 0u) {
    failures += static_cast<int>(h.inflight);
    h.tx_errors += static_cast<uint64_t>(failures);
    h.tx_drops += static_cast<uint64_t>(failures);
    *out_sent = submitted;
    *out_errors = failures;
    write_err(err, err_len, std::string("DOCA ") + op_name + " timed out waiting for task completions");
    return -1;
  }

  h.tx_packets += static_cast<uint64_t>(submitted);
  h.tx_bytes += bytes_submitted;
  h.tx_errors += static_cast<uint64_t>(failures);
  h.tx_drops += static_cast<uint64_t>(failures);
  *out_sent = submitted;
  *out_errors = failures;
  if (submitted <= 0) {
    write_err(err, err_len, std::string("DOCA ") + op_name + " submitted zero packets");
    return -1;
  }
  return 0;
}

inline bool is_matching_dev(
    DocaApi& api,
    doca_devinfo* devinfo,
    const char* iface,
    const char* device_name,
    std::string& ibdev_out,
    std::string& iface_out) {
  char ibdev[128];
  char ifname[128];
  ibdev[0] = '\0';
  ifname[0] = '\0';
  (void)api.doca_devinfo_get_ibdev_name(devinfo, ibdev, static_cast<uint32_t>(sizeof(ibdev)));
  (void)api.doca_devinfo_get_iface_name(devinfo, ifname, static_cast<uint32_t>(sizeof(ifname)));
  ibdev_out = std::string(ibdev);
  iface_out = std::string(ifname);
  const bool dev_match = (device_name && *device_name) ? (ibdev_out == device_name) : false;
  const bool iface_match = (iface && *iface) ? (iface_out == iface) : false;
  return dev_match || iface_match;
}

inline bool open_doca_dev_by_name(const char* device_name, doca_dev** out_dev, char* err, size_t err_len) {
  if (!device_name || !*device_name || !out_dev) {
    write_err(err, err_len, "contract DOCA mmap requires device_name");
    return false;
  }
  *out_dev = nullptr;
  doca_devinfo** dev_list = nullptr;
  uint32_t nb_devs = 0u;
  doca_error_t rc = g_doca.doca_devinfo_create_list(&dev_list, &nb_devs);
  if (rc != kDocaSuccess || !dev_list || nb_devs == 0u) {
    write_err(err, err_len, std::string("doca_devinfo_create_list failed: ") + doca_err(g_doca, rc));
    return false;
  }
  doca_devinfo* selected = nullptr;
  for (uint32_t i = 0; i < nb_devs; ++i) {
    doca_devinfo* cand = dev_list[i];
    if (!cand) {
      continue;
    }
    std::string cand_ibdev;
    std::string cand_iface;
    if (is_matching_dev(g_doca, cand, nullptr, device_name, cand_ibdev, cand_iface)) {
      selected = cand;
      break;
    }
  }
  if (!selected) {
    (void)g_doca.doca_devinfo_destroy_list(dev_list);
    write_err(err, err_len, std::string("no matching DOCA device found for ibdev=") + device_name);
    return false;
  }
  rc = g_doca.doca_dev_open(selected, out_dev);
  (void)g_doca.doca_devinfo_destroy_list(dev_list);
  if (rc != kDocaSuccess || !*out_dev) {
    write_err(err, err_len, std::string("doca_dev_open failed: ") + doca_err(g_doca, rc));
    return false;
  }
  return true;
}

inline void close_contract_writer_resources(BackendContractWriterHandle& h) {
  if (h.rdma_release && h.region_kind == "rdma") {
    char rdma_err[160];
    rdma_err[0] = '\0';
    (void)h.rdma_release(h.rdma_import_cookie, rdma_err, sizeof(rdma_err));
    h.rdma_import_cookie = 0u;
  }
  h.rdma_release = nullptr;
  if (h.rdma_importer_so) {
    dlclose(h.rdma_importer_so);
    h.rdma_importer_so = nullptr;
  }
  if (h.mmap) {
    if (g_doca.loaded && g_doca.doca_mmap_stop) {
      (void)g_doca.doca_mmap_stop(h.mmap);
    }
    if (g_doca.loaded && g_doca.doca_mmap_destroy) {
      (void)g_doca.doca_mmap_destroy(h.mmap);
    }
    h.mmap = nullptr;
  }
  if (h.dev) {
    if (g_doca.loaded && g_doca.doca_dev_close) {
      (void)g_doca.doca_dev_close(h.dev);
    }
    h.dev = nullptr;
  }
  if (h.owns_mapping && h.region && h.region_len > 0u) {
    (void)::msync(h.region, h.region_len, MS_SYNC);
    (void)::munmap(h.region, h.region_len);
  }
  if (h.fd >= 0) {
    (void)::close(h.fd);
  }
  h.region = nullptr;
  h.region_len = 0u;
  h.fd = -1;
  h.mmap_mkey = 0u;
}

inline std::string contract_rdma_importer_path(const ContractRegionSpec& spec) {
  if (!spec.importer_so.empty()) {
    return spec.importer_so;
  }
  const char* env = std::getenv("SAMURAI_DOCA_CONTRACT_RDMA_IMPORTER_SO");
  if (env && *env) {
    return std::string(env);
  }
  return "";
}

inline bool import_contract_writer_rdma_region(
    BackendContractWriterHandle& h,
    const ContractRegionSpec& spec,
    const DocaContractWriterConfigV1& cfg,
    const ContractRegionLayout& layout,
    char* err,
    size_t err_len) {
  const std::string importer_path = contract_rdma_importer_path(spec);
  if (importer_path.empty()) {
    write_err(
        err,
        err_len,
        "contract region kind=rdma requires SAMURAI_DOCA_CONTRACT_RDMA_IMPORTER_SO or importer= in region spec");
    return false;
  }
  void* so = dlopen(importer_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (!so) {
    const char* dl_reason = dlerror();
    write_err(err, err_len, std::string("contract RDMA importer dlopen failed: ") + (dl_reason ? dl_reason : "unknown"));
    return false;
  }
  auto import_fn = reinterpret_cast<DocaContractRdmaImportFnV1>(dlsym(so, "samurai_doca_contract_rdma_import_v1"));
  auto release_fn = reinterpret_cast<DocaContractRdmaReleaseFnV1>(dlsym(so, "samurai_doca_contract_rdma_release_v1"));
  if (!import_fn || !release_fn) {
    dlclose(so);
    write_err(err, err_len, "contract RDMA importer symbols missing");
    return false;
  }
  void* addr = nullptr;
  size_t len = 0u;
  uint64_t cookie = 0u;
  if (import_fn(cfg.region_spec, &cfg, &addr, &len, &cookie, err, err_len) != 0 || !addr || len < layout.total_bytes) {
    dlclose(so);
    if (err && err_len > 0u && err[0] == '\0') {
      write_err(err, err_len, "contract RDMA import failed");
    }
    return false;
  }
  h.region = addr;
  h.region_len = len;
  h.rdma_import_cookie = cookie;
  h.rdma_release = release_fn;
  h.rdma_importer_so = so;
  return true;
}

inline bool register_contract_writer_doca_mmap(
    BackendContractWriterHandle& h,
    const char* device_name,
    char* err,
    size_t err_len) {
  if (!h.region || h.region_len == 0u) {
    write_err(err, err_len, "contract DOCA mmap requires a resolved region");
    return false;
  }
  std::string why;
  if (!ensure_doca_api(why)) {
    write_err(err, err_len, std::string("DOCA runtime unavailable for contract mmap: ") + why);
    return false;
  }
  if (!open_doca_dev_by_name(device_name, &h.dev, err, err_len)) {
    return false;
  }
  doca_error_t rc = g_doca.doca_mmap_create(&h.mmap);
  if (rc != kDocaSuccess || !h.mmap) {
    write_err(err, err_len, std::string("contract doca_mmap_create failed: ") + doca_err(g_doca, rc));
    close_contract_writer_resources(h);
    return false;
  }
  rc = g_doca.doca_mmap_add_dev(h.mmap, h.dev);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("contract doca_mmap_add_dev failed: ") + doca_err(g_doca, rc));
    close_contract_writer_resources(h);
    return false;
  }
  rc = g_doca.doca_mmap_set_memrange(h.mmap, h.region, h.region_len);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("contract doca_mmap_set_memrange failed: ") + doca_err(g_doca, rc));
    close_contract_writer_resources(h);
    return false;
  }
  rc = g_doca.doca_mmap_start(h.mmap);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("contract doca_mmap_start failed: ") + doca_err(g_doca, rc));
    close_contract_writer_resources(h);
    return false;
  }
  rc = g_doca.doca_mmap_get_mkey(h.mmap, h.dev, &h.mmap_mkey);
  if (rc != kDocaSuccess || h.mmap_mkey == 0u) {
    write_err(err, err_len, std::string("contract doca_mmap_get_mkey failed: ") + doca_err(g_doca, rc));
    close_contract_writer_resources(h);
    return false;
  }
  return true;
}

}  // namespace

extern "C" int samurai_doca_backend_create_txq(
    const char* iface,
    const char* device_name,
    int gpu_id,
    int queue_id,
    int* out_handle,
    char* err,
    size_t err_len) {
  if (!iface || !*iface || !device_name || !*device_name || !out_handle || queue_id < 0 || gpu_id < 0) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_create_txq");
    return -1;
  }

  std::string why;
  if (!ensure_doca_api(why)) {
    write_err(err, err_len, std::string("DOCA runtime unavailable: ") + why);
    return -1;
  }

  BackendTxqHandle tmp{};
  tmp.iface = iface;
  tmp.device_name = device_name;
  tmp.gpu_id = gpu_id;
  tmp.queue_id = queue_id;
  tmp.task_slots = static_cast<uint32_t>(env_int("SAMURAI_GPU_DOCA_TASK_SLOTS", 1024, 64, 65536));
  tmp.max_progress_loops = static_cast<uint32_t>(env_int("SAMURAI_GPU_DOCA_PROGRESS_LOOPS", 200000, 1000, 2000000));

  doca_devinfo** dev_list = nullptr;
  uint32_t nb_devs = 0u;
  doca_error_t rc = g_doca.doca_devinfo_create_list(&dev_list, &nb_devs);
  if (rc != kDocaSuccess || !dev_list || nb_devs == 0u) {
    write_err(err, err_len, std::string("doca_devinfo_create_list failed: ") + doca_err(g_doca, rc));
    return -1;
  }
  doca_devinfo* selected = nullptr;
  std::string selected_ibdev;
  std::string selected_iface;
  for (uint32_t i = 0; i < nb_devs; ++i) {
    doca_devinfo* cand = dev_list[i];
    if (!cand) {
      continue;
    }
    std::string cand_ibdev;
    std::string cand_iface;
    if (is_matching_dev(g_doca, cand, iface, device_name, cand_ibdev, cand_iface)) {
      selected = cand;
      selected_ibdev = cand_ibdev;
      selected_iface = cand_iface;
      break;
    }
  }
  if (!selected) {
    (void)g_doca.doca_devinfo_destroy_list(dev_list);
    write_err(
        err,
        err_len,
        std::string("no matching DOCA device found for iface=") + iface + " / ibdev=" + device_name);
    return -1;
  }

  rc = g_doca.doca_dev_open(selected, &tmp.dev);
  (void)g_doca.doca_devinfo_destroy_list(dev_list);
  if (rc != kDocaSuccess || !tmp.dev) {
    write_err(err, err_len, std::string("doca_dev_open failed: ") + doca_err(g_doca, rc));
    return -1;
  }

  rc = g_doca.doca_eth_txq_create(tmp.dev, tmp.task_slots, &tmp.txq);
  if (rc != kDocaSuccess || !tmp.txq) {
    write_err(err, err_len, std::string("doca_eth_txq_create failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }

  rc = g_doca.doca_eth_txq_set_type(tmp.txq, kDocaEthTxqTypeRegular);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_eth_txq_set_type failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_eth_txq_set_l3_chksum_offload(tmp.txq, 1u);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_eth_txq_set_l3_chksum_offload failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_eth_txq_set_l4_chksum_offload(tmp.txq, 1u);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_eth_txq_set_l4_chksum_offload failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }

  rc = g_doca.doca_eth_txq_task_send_set_conf(tmp.txq, task_send_common_cb, task_send_common_cb, tmp.task_slots);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_eth_txq_task_send_set_conf failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }

  tmp.ctx = g_doca.doca_eth_txq_as_doca_ctx(tmp.txq);
  if (!tmp.ctx) {
    write_err(err, err_len, "doca_eth_txq_as_doca_ctx returned NULL");
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }

  rc = g_doca.doca_pe_create(&tmp.pe);
  if (rc != kDocaSuccess || !tmp.pe) {
    write_err(err, err_len, std::string("doca_pe_create failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_pe_connect_ctx(tmp.pe, tmp.ctx);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_pe_connect_ctx failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  doca_data ctx_ud{};
  ctx_ud.ptr = &tmp;
  rc = g_doca.doca_ctx_set_user_data(tmp.ctx, ctx_ud);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_ctx_set_user_data failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_ctx_start(tmp.ctx);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_ctx_start failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_eth_txq_apply_queue_id(tmp.txq, static_cast<uint16_t>(queue_id));
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_eth_txq_apply_queue_id failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }

  rc = g_doca.doca_eth_txq_get_gpu_handle(tmp.txq, &tmp.gpu_txq);
  if (rc != kDocaSuccess || !tmp.gpu_txq) {
    write_err(
        err,
        err_len,
        std::string("doca_eth_txq_get_gpu_handle failed (GPUNetIO export required): ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }

  rc = g_doca.doca_mmap_create(&tmp.mmap);
  if (rc != kDocaSuccess || !tmp.mmap) {
    write_err(err, err_len, std::string("doca_mmap_create failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_mmap_add_dev(tmp.mmap, tmp.dev);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_mmap_add_dev failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_mmap_set_memrange(tmp.mmap, nullptr, std::numeric_limits<size_t>::max());
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_mmap_set_memrange failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_mmap_start(tmp.mmap);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_mmap_start failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  uint32_t txq_mkey_host = 0u;
  rc = g_doca.doca_mmap_get_mkey(tmp.mmap, tmp.dev, &txq_mkey_host);
  if (rc != kDocaSuccess || txq_mkey_host == 0u) {
    write_err(err, err_len, std::string("doca_mmap_get_mkey failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  tmp.txq_mkey_be = htonl(txq_mkey_host);

  rc = g_doca.doca_buf_inventory_create(static_cast<size_t>(tmp.task_slots) * 4u, &tmp.buf_inv);
  if (rc != kDocaSuccess || !tmp.buf_inv) {
    write_err(err, err_len, std::string("doca_buf_inventory_create failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_buf_inventory_start(tmp.buf_inv);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_buf_inventory_start failed: ") + doca_err(g_doca, rc));
    destroy_backend_txq_unlocked(tmp);
    return -1;
  }

  std::lock_guard<std::mutex> guard(g_lock);
  const int hnd = g_next_handle++;
  auto sp = std::make_shared<BackendTxqHandle>();
  sp->handle = hnd;
  sp->iface = std::move(tmp.iface);
  sp->device_name = std::move(tmp.device_name);
  sp->gpu_id = tmp.gpu_id;
  sp->queue_id = tmp.queue_id;
  sp->dev = tmp.dev;
  sp->pe = tmp.pe;
  sp->txq = tmp.txq;
  sp->ctx = tmp.ctx;
  sp->gpu_txq = tmp.gpu_txq;
  sp->mmap = tmp.mmap;
  sp->buf_inv = tmp.buf_inv;
  sp->txq_mkey_be = tmp.txq_mkey_be;
  sp->inflight = tmp.inflight;
  sp->task_slots = tmp.task_slots;
  sp->max_progress_loops = tmp.max_progress_loops;
  sp->tx_packets = tmp.tx_packets;
  sp->tx_bytes = tmp.tx_bytes;
  sp->tx_errors = tmp.tx_errors;
  sp->tx_drops = tmp.tx_drops;
  tmp.dev = nullptr;
  tmp.pe = nullptr;
  tmp.txq = nullptr;
  tmp.ctx = nullptr;
  tmp.gpu_txq = nullptr;
  tmp.mmap = nullptr;
  tmp.buf_inv = nullptr;
  g_handles.emplace(hnd, sp);
  if (sp && sp->ctx) {
    doca_data ctx_data{};
    ctx_data.ptr = sp.get();
    (void)g_doca.doca_ctx_set_user_data(sp->ctx, ctx_data);
  }
  *out_handle = hnd;
  return 0;
}

extern "C" int samurai_doca_backend_destroy_txq(int handle, char* err, size_t err_len) {
  if (handle < 0) {
    write_err(err, err_len, "invalid handle in samurai_doca_backend_destroy_txq");
    return -1;
  }
  std::shared_ptr<BackendTxqHandle> h{};
  {
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_handles.find(handle);
    if (it == g_handles.end()) {
      return 0;
    }
    h = it->second;
    g_handles.erase(it);
  }
  if (!h) {
    return 0;
  }
  std::lock_guard<std::mutex> op_guard(h->op_lock);
  destroy_backend_txq_unlocked(*h);
  return 0;
}

extern "C" int samurai_doca_backend_send_vector(
    int handle,
    const uint8_t** packets,
    const uint16_t* lengths,
    const int32_t* stream_slots,
    int count,
    int* out_sent,
    int* out_errors,
    char* err,
    size_t err_len) {
  (void)stream_slots;
  if (out_sent) {
    *out_sent = 0;
  }
  if (out_errors) {
    *out_errors = 0;
  }
  if (handle < 0 || !packets || !lengths || count <= 0 || !out_sent || !out_errors || any_invalid_len(lengths, count)) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_send_vector");
    return -1;
  }

  std::shared_ptr<BackendTxqHandle> h{};
  {
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_handles.find(handle);
    if (it == g_handles.end()) {
      write_err(err, err_len, "txq handle not found");
      return -1;
    }
    h = it->second;
  }
  if (!h) {
    write_err(err, err_len, "txq handle not found");
    return -1;
  }
  std::lock_guard<std::mutex> op_guard(h->op_lock);
  if (!h->txq || !h->pe || !h->mmap || !h->buf_inv) {
    write_err(err, err_len, "DOCA txq handle is not fully initialized");
    return -1;
  }

  return send_vector_unlocked(
      *h,
      packets,
      lengths,
      nullptr,
      false,
      count,
      out_sent,
      out_errors,
      err,
      err_len,
      "send_vector");
}

extern "C" int samurai_doca_backend_send_vector_timed(
    int handle,
    const uint8_t** packets,
    const uint16_t* lengths,
    const int32_t* stream_slots,
    const uint64_t* tx_timestamps_ns,
    int count,
    int* out_sent,
    int* out_errors,
    char* err,
    size_t err_len) {
  (void)stream_slots;
  if (out_sent) {
    *out_sent = 0;
  }
  if (out_errors) {
    *out_errors = 0;
  }
  if (handle < 0 || !packets || !lengths || !tx_timestamps_ns || count <= 0 || !out_sent || !out_errors ||
      any_invalid_len(lengths, count)) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_send_vector_timed");
    return -1;
  }

  std::string mode = env_string("SAMURAI_GPU_DOCA_TIMED_TX_MODE", "host_wait");
  std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  const bool strict_mode =
      (mode == "strict" || mode == "hardware" || mode == "hw" || mode == "require_hardware");
  const bool host_wait_mode = (mode.empty() || mode == "auto" || mode == "host_wait" || mode == "host");
  const bool immediate_mode = (mode == "off" || mode == "none" || mode == "immediate");
  if (strict_mode) {
    write_err(
        err,
        err_len,
        "DOCA timed TX strict mode requested but hardware-scheduled timed send is unavailable in CPU-task backend");
    return -1;
  }

  std::shared_ptr<BackendTxqHandle> h{};
  {
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_handles.find(handle);
    if (it == g_handles.end()) {
      write_err(err, err_len, "txq handle not found");
      return -1;
    }
    h = it->second;
  }
  if (!h) {
    write_err(err, err_len, "txq handle not found");
    return -1;
  }
  std::lock_guard<std::mutex> op_guard(h->op_lock);
  if (!h->txq || !h->pe || !h->mmap || !h->buf_inv) {
    write_err(err, err_len, "DOCA txq handle is not fully initialized");
    return -1;
  }
  const bool use_host_wait = host_wait_mode && !immediate_mode;
  const TimedClockDomain requested_domain = timed_clock_domain_from_env();
  std::vector<uint64_t> mono_ts{};
  const uint64_t* wait_ts = tx_timestamps_ns;
  if (use_host_wait) {
    if (!convert_timestamps_to_monotonic(tx_timestamps_ns, count, requested_domain, &mono_ts, err, err_len)) {
      return -1;
    }
    wait_ts = mono_ts.data();
  }
  return send_vector_unlocked(
      *h,
      packets,
      lengths,
      wait_ts,
      use_host_wait,
      count,
      out_sent,
      out_errors,
      err,
      err_len,
      "send_vector_timed");
}

extern "C" int samurai_doca_backend_get_stats(int handle, DocaGpuNetioStats* out, char* err, size_t err_len) {
  if (handle < 0 || !out) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_get_stats");
    return -1;
  }
  std::shared_ptr<BackendTxqHandle> h{};
  {
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_handles.find(handle);
    if (it == g_handles.end()) {
      write_err(err, err_len, "txq handle not found");
      return -1;
    }
    h = it->second;
  }
  if (!h) {
    write_err(err, err_len, "txq handle not found");
    return -1;
  }
  std::lock_guard<std::mutex> op_guard(h->op_lock);
  out->tx_packets = h->tx_packets;
  out->tx_bytes = h->tx_bytes;
  out->tx_errors = h->tx_errors;
  out->tx_drops = h->tx_drops;
  out->queue_id = h->queue_id;
  return 0;
}

extern "C" int samurai_doca_backend_get_gpu_txq_handle(
    int handle,
    uint64_t* out_gpu_txq_handle,
    char* err,
    size_t err_len) {
  if (handle < 0 || !out_gpu_txq_handle) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_get_gpu_txq_handle");
    return -1;
  }
  std::shared_ptr<BackendTxqHandle> h{};
  {
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_handles.find(handle);
    if (it == g_handles.end()) {
      write_err(err, err_len, "txq handle not found or gpu handle unavailable");
      return -1;
    }
    h = it->second;
  }
  if (!h) {
    write_err(err, err_len, "txq handle not found or gpu handle unavailable");
    return -1;
  }
  std::lock_guard<std::mutex> op_guard(h->op_lock);
  if (!h->gpu_txq) {
    write_err(err, err_len, "txq handle not found or gpu handle unavailable");
    return -1;
  }
  *out_gpu_txq_handle = reinterpret_cast<uint64_t>(h->gpu_txq);
  return 0;
}

extern "C" int samurai_doca_backend_get_txq_mkey_be(int handle, uint32_t* out_mkey_be, char* err, size_t err_len) {
  if (handle < 0 || !out_mkey_be) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_get_txq_mkey_be");
    return -1;
  }
  std::shared_ptr<BackendTxqHandle> h{};
  {
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_handles.find(handle);
    if (it == g_handles.end()) {
      write_err(err, err_len, "txq handle not found or txq mkey unavailable");
      return -1;
    }
    h = it->second;
  }
  if (!h) {
    write_err(err, err_len, "txq handle not found or txq mkey unavailable");
    return -1;
  }
  std::lock_guard<std::mutex> op_guard(h->op_lock);
  if (h->txq_mkey_be == 0u) {
    write_err(err, err_len, "txq handle not found or txq mkey unavailable");
    return -1;
  }
  *out_mkey_be = h->txq_mkey_be;
  return 0;
}

extern "C" int samurai_doca_backend_contract_writer_open(
    const DocaContractWriterConfigV1* cfg,
    int* out_handle,
    char* err,
    size_t err_len) {
  if (!cfg || !out_handle || cfg->region_spec[0] == '\0' || cfg->shard_count == 0u ||
      cfg->ring_slots_per_shard == 0u || cfg->hot_flow_capacity == 0u) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_contract_writer_open");
    return -1;
  }
  *out_handle = -1;

  ContractRegionLayout layout{};
  std::string why;
  if (!contract_region_layout(cfg->shard_count, cfg->ring_slots_per_shard, cfg->hot_flow_capacity, &layout, &why)) {
    write_err(err, err_len, why.empty() ? "invalid contract region layout" : why);
    return -1;
  }

  ContractRegionSpec spec{};
  if (!parse_contract_region_spec(cfg->region_spec, &spec, &why)) {
    write_err(err, err_len, why.empty() ? "invalid contract region spec" : why);
    return -1;
  }
  if (spec.layout_version != 0u && spec.layout_version != 1u) {
    write_err(err, err_len, "contract region layout version mismatch");
    return -1;
  }
  if (spec.shard_count != 0u && spec.shard_count != cfg->shard_count) {
    write_err(err, err_len, "contract region shard count mismatch");
    return -1;
  }
  if (spec.ring_slots_per_shard != 0u && spec.ring_slots_per_shard != cfg->ring_slots_per_shard) {
    write_err(err, err_len, "contract region ring slot count mismatch");
    return -1;
  }
  if (spec.hot_flow_capacity != 0u && spec.hot_flow_capacity != cfg->hot_flow_capacity) {
    write_err(err, err_len, "contract region hot-flow capacity mismatch");
    return -1;
  }
  if (spec.event_size != 0u && spec.event_size != sizeof(BackendContractFlowUpdateSlot)) {
    write_err(err, err_len, "contract region event size mismatch");
    return -1;
  }
  if (spec.size != 0u && spec.size < layout.total_bytes) {
    write_err(err, err_len, "contract region spec size is smaller than required layout");
    return -1;
  }

  auto writer = std::make_shared<BackendContractWriterHandle>();
  writer->shard_count = cfg->shard_count;
  writer->ring_slots_per_shard = cfg->ring_slots_per_shard;
  writer->hot_flow_capacity = cfg->hot_flow_capacity;
  writer->region_kind = spec.kind;
  writer->region_len = spec.size != 0u ? spec.size : layout.total_bytes;

  if (writer->region_kind == "rdma") {
    if (!import_contract_writer_rdma_region(*writer, spec, *cfg, layout, err, err_len)) {
      return -1;
    }
  } else if (!spec.file.empty()) {
    const int fd = ::open(spec.file.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
      write_err(err, err_len, std::string("contract region file open failed: ") + std::strerror(errno));
      return -1;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0) {
      const std::string msg = std::string("contract region file stat failed: ") + std::strerror(errno);
      ::close(fd);
      write_err(err, err_len, msg);
      return -1;
    }
    if (st.st_size < 0 || static_cast<uint64_t>(st.st_size) < static_cast<uint64_t>(layout.total_bytes)) {
      ::close(fd);
      write_err(err, err_len, "contract region file is smaller than required layout");
      return -1;
    }
    writer->region_len = spec.size != 0u ? spec.size : static_cast<size_t>(st.st_size);
    void* mapped = ::mmap(nullptr, writer->region_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
      const std::string msg = std::string("contract region mmap failed: ") + std::strerror(errno);
      ::close(fd);
      write_err(err, err_len, msg);
      return -1;
    }
    writer->region = mapped;
    writer->owns_mapping = true;
    writer->fd = fd;
  } else {
    writer->region = reinterpret_cast<void*>(spec.addr);
    writer->owns_mapping = false;
    writer->fd = -1;
  }
  if (!writer->region) {
    write_err(err, err_len, "contract region resolved to null");
    close_contract_writer_resources(*writer);
    return -1;
  }
  if (writer->region_kind == "doca_mmap") {
    if (!register_contract_writer_doca_mmap(*writer, cfg->device_name, err, err_len)) {
      return -1;
    }
  } else if (writer->region_kind != "file" && writer->region_kind != "addr" &&
             writer->region_kind != "rdma" && writer->region_kind != "bar1_p2p") {
    write_err(err, err_len, "unsupported contract region kind");
    close_contract_writer_resources(*writer);
    return -1;
  }

  std::lock_guard<std::mutex> guard(g_lock);
  const int hnd = g_next_handle++;
  writer->handle = hnd;
  g_contract_writers.emplace(hnd, writer);
  *out_handle = hnd;
  return 0;
}

extern "C" int samurai_doca_backend_contract_writer_close(int handle, char* err, size_t err_len) {
  if (handle < 0) {
    write_err(err, err_len, "invalid handle in samurai_doca_backend_contract_writer_close");
    return -1;
  }
  std::shared_ptr<BackendContractWriterHandle> h{};
  {
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_contract_writers.find(handle);
    if (it == g_contract_writers.end()) {
      return 0;
    }
    h = it->second;
    g_contract_writers.erase(it);
  }
  if (!h) {
    return 0;
  }
  std::lock_guard<std::mutex> op_guard(h->op_lock);
  close_contract_writer_resources(*h);
  return 0;
}

extern "C" int samurai_doca_backend_contract_writer_publish_flow_update_v1(
    int handle,
    const DocaFlowUpdateEventV1* event,
    char* err,
    size_t err_len) {
  if (handle < 0 || !event || event->version == 0u || (event->version & 1ull) != 0ull) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_contract_writer_publish_flow_update_v1");
    return -1;
  }

  std::shared_ptr<BackendContractWriterHandle> h{};
  {
    std::lock_guard<std::mutex> guard(g_lock);
    auto it = g_contract_writers.find(handle);
    if (it == g_contract_writers.end()) {
      write_err(err, err_len, "contract writer handle not found");
      return -1;
    }
    h = it->second;
  }
  if (!h || !h->region) {
    write_err(err, err_len, "contract writer handle is not initialized");
    return -1;
  }

  ContractRegionLayout layout{};
  std::string why;
  if (!contract_region_layout(h->shard_count, h->ring_slots_per_shard, h->hot_flow_capacity, &layout, &why)) {
    write_err(err, err_len, why.empty() ? "invalid contract writer layout" : why);
    return -1;
  }
  if (h->region_len < layout.total_bytes || event->flow_id >= h->hot_flow_capacity) {
    write_err(err, err_len, "contract writer event exceeds mapped region");
    return -1;
  }

  std::lock_guard<std::mutex> op_guard(h->op_lock);
  const uint32_t shard = event->flow_id % h->shard_count;
  volatile uint64_t* heads = contract_ring_head(*h, layout);
  volatile uint64_t* tails = contract_ring_tail(*h, layout);
  volatile BackendContractFlowUpdateSlot* ring = contract_update_ring(*h, layout);
  volatile BackendContractFlowUpdateSlot* hot = contract_hot_flow_table(*h, layout);
  volatile uint64_t* hot_versions = contract_hot_versions(*h, layout);
  volatile uint64_t* hot_epochs = contract_hot_epochs(*h, layout);

  const uint64_t head = __atomic_load_n(&heads[shard], __ATOMIC_ACQUIRE);
  const uint64_t tail = __atomic_load_n(&tails[shard], __ATOMIC_ACQUIRE);
  const uint64_t used = (head >= tail) ? (head - tail) : 0u;
  if (used >= static_cast<uint64_t>(h->ring_slots_per_shard)) {
    h->overflow_count += 1u;
    write_err(err, err_len, "contract writer ring overflow");
    return -1;
  }

  const size_t ring_index =
      (static_cast<size_t>(shard) * static_cast<size_t>(h->ring_slots_per_shard)) +
      static_cast<size_t>(head % static_cast<uint64_t>(h->ring_slots_per_shard));
  contract_store_event_slot(ring + ring_index, *event);
  contract_store_event_slot(hot + event->flow_id, *event);
  __atomic_store_n(&hot_versions[event->flow_id], event->version, __ATOMIC_RELEASE);
  __atomic_store_n(&hot_epochs[event->flow_id], event->epoch, __ATOMIC_RELEASE);
  __atomic_thread_fence(__ATOMIC_RELEASE);
  __atomic_store_n(&heads[shard], head + 1u, __ATOMIC_RELEASE);
  h->publish_count += 1u;
  return 0;
}

extern "C" int samurai_doca_backend_get_gpu_rxq_handle(
    int handle,
    uint64_t* out_gpu_rxq_handle,
    char* err,
    size_t err_len) {
  if (handle < 0 || !out_gpu_rxq_handle) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_get_gpu_rxq_handle");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_rx_handles.find(handle);
  if (it == g_rx_handles.end() || !it->second.gpu_rxq || !it->second.gpu_datapath) {
    write_err(err, err_len, "rxq handle not found or gpu rxq handle unavailable");
    return -1;
  }
  *out_gpu_rxq_handle = reinterpret_cast<uint64_t>(it->second.gpu_rxq);
  return 0;
}

extern "C" int samurai_doca_backend_create_rxq(
    const char* iface,
    const char* device_name,
    int gpu_id,
    int queue_id,
    int* out_handle,
    char* err,
    size_t err_len) {
  if (!iface || !*iface || !device_name || !*device_name || !out_handle || queue_id < 0 || gpu_id < 0) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_create_rxq");
    return -1;
  }
  std::string why;
  if (!ensure_doca_api(why)) {
    write_err(err, err_len, std::string("DOCA runtime unavailable: ") + why);
    return -1;
  }

  BackendRxqHandle tmp{};
  tmp.iface = iface;
  tmp.device_name = device_name;
  tmp.gpu_id = gpu_id;
  tmp.queue_id = queue_id;
  tmp.task_slots = static_cast<uint32_t>(env_int("SAMURAI_GPU_DOCA_RX_TASK_SLOTS", 1024, 64, 65536));
  tmp.max_progress_loops = static_cast<uint32_t>(env_int("SAMURAI_GPU_DOCA_RX_PROGRESS_LOOPS", 200000, 1000, 2000000));
  tmp.max_packet_size = static_cast<uint32_t>(env_int("SAMURAI_GPU_DOCA_RX_MAX_PACKET_SIZE", 2048, 64, 9600));
  tmp.completed_pkts.reserve(static_cast<size_t>(tmp.task_slots) * 2u);
  const bool rx_gpu_datapath_requested =
      env_int("SAMURAI_GPU_DOCA_RX_GPU_DATAPATH", 1, 0, 1) != 0;
  const bool rx_gpu_datapath_strict =
      env_int("SAMURAI_GPU_DOCA_RX_GPU_DATAPATH_STRICT", 1, 0, 1) != 0;
  const std::string gpu_bus_id = env_string("SAMURAI_GPU_DOCA_GPU_BUS_ID", "");

  doca_devinfo** dev_list = nullptr;
  uint32_t nb_devs = 0u;
  doca_error_t rc = g_doca.doca_devinfo_create_list(&dev_list, &nb_devs);
  if (rc != kDocaSuccess || !dev_list || nb_devs == 0u) {
    write_err(err, err_len, std::string("doca_devinfo_create_list failed: ") + doca_err(g_doca, rc));
    return -1;
  }
  doca_devinfo* selected = nullptr;
  for (uint32_t i = 0; i < nb_devs; ++i) {
    doca_devinfo* cand = dev_list[i];
    if (!cand) {
      continue;
    }
    std::string cand_ibdev;
    std::string cand_iface;
    if (is_matching_dev(g_doca, cand, iface, device_name, cand_ibdev, cand_iface)) {
      selected = cand;
      break;
    }
  }
  if (!selected) {
    (void)g_doca.doca_devinfo_destroy_list(dev_list);
    write_err(
        err,
        err_len,
        std::string("no matching DOCA device found for iface=") + iface + " / ibdev=" + device_name);
    return -1;
  }
  rc = g_doca.doca_dev_open(selected, &tmp.dev);
  (void)g_doca.doca_devinfo_destroy_list(dev_list);
  if (rc != kDocaSuccess || !tmp.dev) {
    write_err(err, err_len, std::string("doca_dev_open failed: ") + doca_err(g_doca, rc));
    return -1;
  }

  rc = g_doca.doca_eth_rxq_create(tmp.dev, tmp.task_slots, tmp.max_packet_size, &tmp.rxq);
  if (rc != kDocaSuccess || !tmp.rxq) {
    write_err(err, err_len, std::string("doca_eth_rxq_create failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_eth_rxq_set_type(tmp.rxq, kDocaEthRxqTypeRegular);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_eth_rxq_set_type failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_eth_rxq_task_recv_set_conf(tmp.rxq, task_recv_common_cb, task_recv_common_cb, tmp.task_slots);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_eth_rxq_task_recv_set_conf failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  tmp.ctx = g_doca.doca_eth_rxq_as_doca_ctx(tmp.rxq);
  if (!tmp.ctx) {
    write_err(err, err_len, "doca_eth_rxq_as_doca_ctx returned NULL");
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  if (rx_gpu_datapath_requested) {
    if (!g_doca.doca_gpu_create || !g_doca.doca_ctx_set_datapath_on_gpu || !g_doca.doca_eth_rxq_get_gpu_handle) {
      if (rx_gpu_datapath_strict) {
        write_err(err, err_len, "DOCA RX GPU datapath requested but required symbols are unavailable");
        destroy_backend_rxq_unlocked(tmp);
        return -1;
      }
    } else if (gpu_bus_id.empty()) {
      if (rx_gpu_datapath_strict) {
        write_err(err, err_len, "DOCA RX GPU datapath requested but SAMURAI_GPU_DOCA_GPU_BUS_ID is empty");
        destroy_backend_rxq_unlocked(tmp);
        return -1;
      }
    } else {
      rc = g_doca.doca_gpu_create(gpu_bus_id.c_str(), &tmp.gpu_dev);
      if (rc != kDocaSuccess || !tmp.gpu_dev) {
        if (rx_gpu_datapath_strict) {
          write_err(err, err_len, std::string("doca_gpu_create failed: ") + doca_err(g_doca, rc));
          destroy_backend_rxq_unlocked(tmp);
          return -1;
        }
      } else {
        rc = g_doca.doca_ctx_set_datapath_on_gpu(tmp.ctx, tmp.gpu_dev);
        if (rc != kDocaSuccess) {
          if (rx_gpu_datapath_strict) {
            write_err(err, err_len, std::string("doca_ctx_set_datapath_on_gpu failed: ") + doca_err(g_doca, rc));
            destroy_backend_rxq_unlocked(tmp);
            return -1;
          }
          if (g_doca.doca_gpu_destroy) {
            (void)g_doca.doca_gpu_destroy(tmp.gpu_dev);
          }
          tmp.gpu_dev = nullptr;
        } else {
          tmp.gpu_datapath = true;
        }
      }
    }
  }
  rc = g_doca.doca_pe_create(&tmp.pe);
  if (rc != kDocaSuccess || !tmp.pe) {
    write_err(err, err_len, std::string("doca_pe_create failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_pe_connect_ctx(tmp.pe, tmp.ctx);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_pe_connect_ctx failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  doca_data ctx_ud{};
  ctx_ud.ptr = &tmp;
  rc = g_doca.doca_ctx_set_user_data(tmp.ctx, ctx_ud);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_ctx_set_user_data failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_ctx_start(tmp.ctx);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_ctx_start failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  if (tmp.gpu_datapath) {
    rc = g_doca.doca_eth_rxq_get_gpu_handle(tmp.rxq, &tmp.gpu_rxq);
    if (rc != kDocaSuccess || !tmp.gpu_rxq) {
      if (rx_gpu_datapath_strict) {
        write_err(err, err_len, std::string("doca_eth_rxq_get_gpu_handle failed: ") + doca_err(g_doca, rc));
        destroy_backend_rxq_unlocked(tmp);
        return -1;
      }
      tmp.gpu_datapath = false;
      if (g_doca.doca_gpu_destroy && tmp.gpu_dev) {
        (void)g_doca.doca_gpu_destroy(tmp.gpu_dev);
      }
      tmp.gpu_dev = nullptr;
      tmp.gpu_rxq = nullptr;
    }
  }
  if (g_doca.doca_eth_rxq_apply_queue_id) {
    rc = g_doca.doca_eth_rxq_apply_queue_id(tmp.rxq, static_cast<uint16_t>(queue_id));
    if (rc != kDocaSuccess) {
      write_err(err, err_len, std::string("doca_eth_rxq_apply_queue_id failed: ") + doca_err(g_doca, rc));
      destroy_backend_rxq_unlocked(tmp);
      return -1;
    }
  }

  rc = g_doca.doca_mmap_create(&tmp.mmap);
  if (rc != kDocaSuccess || !tmp.mmap) {
    write_err(err, err_len, std::string("doca_mmap_create failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_mmap_add_dev(tmp.mmap, tmp.dev);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_mmap_add_dev failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_mmap_set_memrange(tmp.mmap, nullptr, std::numeric_limits<size_t>::max());
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_mmap_set_memrange failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_mmap_start(tmp.mmap);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_mmap_start failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }

  rc = g_doca.doca_buf_inventory_create(static_cast<size_t>(tmp.task_slots) * 4u, &tmp.buf_inv);
  if (rc != kDocaSuccess || !tmp.buf_inv) {
    write_err(err, err_len, std::string("doca_buf_inventory_create failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }
  rc = g_doca.doca_buf_inventory_start(tmp.buf_inv);
  if (rc != kDocaSuccess) {
    write_err(err, err_len, std::string("doca_buf_inventory_start failed: ") + doca_err(g_doca, rc));
    destroy_backend_rxq_unlocked(tmp);
    return -1;
  }

  tmp.pkt_storage.reserve(static_cast<size_t>(tmp.task_slots));
  for (uint32_t i = 0; i < tmp.task_slots; ++i) {
    uint8_t* pkt_mem = static_cast<uint8_t*>(std::malloc(static_cast<size_t>(tmp.max_packet_size)));
    if (!pkt_mem) {
      write_err(err, err_len, "malloc failed for rx packet buffer");
      destroy_backend_rxq_unlocked(tmp);
      return -1;
    }
    tmp.pkt_storage.push_back(pkt_mem);
    doca_buf* pkt = nullptr;
    rc = g_doca.doca_buf_inventory_buf_get_by_addr(
        tmp.buf_inv,
        tmp.mmap,
        pkt_mem,
        static_cast<size_t>(tmp.max_packet_size),
        &pkt);
    if (rc != kDocaSuccess || !pkt) {
      write_err(err, err_len, std::string("doca_buf_inventory_buf_get_by_addr failed: ") + doca_err(g_doca, rc));
      destroy_backend_rxq_unlocked(tmp);
      return -1;
    }
    doca_data user_data{};
    user_data.u64 = static_cast<uint64_t>(i);
    doca_eth_rxq_task_recv* task_recv = nullptr;
    rc = g_doca.doca_eth_rxq_task_recv_allocate_init(tmp.rxq, pkt, user_data, &task_recv);
    if (rc != kDocaSuccess || !task_recv) {
      (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
      write_err(err, err_len, std::string("doca_eth_rxq_task_recv_allocate_init failed: ") + doca_err(g_doca, rc));
      destroy_backend_rxq_unlocked(tmp);
      return -1;
    }
    doca_task* task = g_doca.doca_eth_rxq_task_recv_as_doca_task(task_recv);
    if (!task) {
      (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
      write_err(err, err_len, "doca_eth_rxq_task_recv_as_doca_task returned NULL");
      destroy_backend_rxq_unlocked(tmp);
      return -1;
    }
    rc = g_doca.doca_task_submit(task);
    if (rc != kDocaSuccess) {
      (void)g_doca.doca_task_free(task);
      (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
      write_err(err, err_len, std::string("doca_task_submit(recv) failed: ") + doca_err(g_doca, rc));
      destroy_backend_rxq_unlocked(tmp);
      return -1;
    }
    tmp.inflight += 1u;
  }

  std::lock_guard<std::mutex> guard(g_lock);
  const int hnd = g_next_handle++;
  tmp.handle = hnd;
  g_rx_handles.emplace(hnd, std::move(tmp));
  auto it = g_rx_handles.find(hnd);
  if (it != g_rx_handles.end() && it->second.ctx) {
    doca_data ctx_data{};
    ctx_data.ptr = &(it->second);
    (void)g_doca.doca_ctx_set_user_data(it->second.ctx, ctx_data);
  }
  *out_handle = hnd;
  return 0;
}

extern "C" int samurai_doca_backend_destroy_rxq(int handle, char* err, size_t err_len) {
  if (handle < 0) {
    write_err(err, err_len, "invalid handle in samurai_doca_backend_destroy_rxq");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_rx_handles.find(handle);
  if (it == g_rx_handles.end()) {
    return 0;
  }
  destroy_backend_rxq_unlocked(it->second);
  g_rx_handles.erase(it);
  return 0;
}

extern "C" int samurai_doca_backend_configure_flow_steering(
    const char* iface,
    const char* device_name,
    const int* rxq_handles,
    const int* rxq_ids,
    int rxq_count,
    uint32_t proto_mask,
    int strict,
    char* err,
    size_t err_len) {
  if (!iface || !*iface || !device_name || !*device_name || !rxq_handles || !rxq_ids || rxq_count <= 0) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_configure_flow_steering");
    return -1;
  }
  if (rxq_count < 2 || proto_mask == 0u) {
    // Not an error: no meaningful multi-queue flow steering to apply.
    return 1;
  }
  std::string why;
  if (!ensure_doca_api(why)) {
    if (strict != 0) {
      write_err(err, err_len, std::string("DOCA runtime unavailable for flow steering: ") + why);
      return -1;
    }
    return 1;
  }

  std::vector<int> seen_queue_ids;
  seen_queue_ids.reserve(static_cast<size_t>(rxq_count));
  {
    std::lock_guard<std::mutex> guard(g_lock);
    for (int i = 0; i < rxq_count; ++i) {
      const int handle = rxq_handles[static_cast<size_t>(i)];
      const int queue_id = rxq_ids[static_cast<size_t>(i)];
      if (handle < 0 || queue_id < 0) {
        write_err(err, err_len, "invalid queue handle or queue id for flow steering");
        return -1;
      }
      auto it = g_rx_handles.find(handle);
      if (it == g_rx_handles.end()) {
        write_err(err, err_len, "flow steering rxq handle not found");
        return -1;
      }
      const BackendRxqHandle& h = it->second;
      if (h.iface != iface || h.device_name != device_name) {
        write_err(err, err_len, "flow steering queue/device mismatch");
        return -1;
      }
      if (h.queue_id != queue_id) {
        write_err(err, err_len, "flow steering queue id mismatch");
        return -1;
      }
      if (std::find(seen_queue_ids.begin(), seen_queue_ids.end(), queue_id) != seen_queue_ids.end()) {
        write_err(err, err_len, "flow steering duplicate queue id");
        return -1;
      }
      seen_queue_ids.push_back(queue_id);
    }
  }

  const std::string stream_rules_env = env_string("SAMURAI_GPU_DOCA_FLOW_STREAM_RULES", "");
  if (!stream_rules_env.empty()) {
    std::vector<samurai_doca_flow_stream_rule_v1> stream_rules;
    std::string parse_why;
    if (!parse_stream_rules_env(stream_rules_env, seen_queue_ids, stream_rules, parse_why)) {
      if (strict != 0) {
        write_err(err, err_len, parse_why.empty() ? "invalid flow stream rules" : parse_why);
        return -1;
      }
      return 1;
    }
    std::string flow_why;
    if (!ensure_flow_dispatch(flow_why) || g_flow.program_steering_streams == nullptr) {
      if (strict != 0) {
        const std::string msg = flow_why.empty()
            ? "flow steering streams backend unavailable"
            : (flow_why + " (stream steering unavailable)");
        write_err(err, err_len, msg);
        return -1;
      }
      return 1;
    }
    const int rc = g_flow.program_steering_streams(
        iface,
        device_name,
        seen_queue_ids.data(),
        static_cast<int>(seen_queue_ids.size()),
        stream_rules.data(),
        static_cast<int>(stream_rules.size()),
        err,
        err_len);
    if (rc == 0) {
      return 0;
    }
    if (strict != 0) {
      if (err == nullptr || err_len == 0u || err[0] == '\0') {
        write_err(err, err_len, "flow stream steering shim returned failure");
      }
      return -1;
    }
    return 1;
  }

  // Try steering programmer #1: explicit external control command.
  {
    const int ctl_rc = run_flow_ctl_command(
        iface,
        device_name,
        seen_queue_ids.data(),
        static_cast<int>(seen_queue_ids.size()),
        proto_mask,
        err,
        err_len);
    if (ctl_rc == 0) {
      return 0;
    }
    if (ctl_rc < 0 && strict != 0) {
      return -1;
    }
  }

  // Try steering programmer #2: pluggable native DOCA Flow shim backend.
  {
    std::string flow_why;
    if (ensure_flow_dispatch(flow_why) && g_flow.program_steering != nullptr) {
      const int rc = g_flow.program_steering(
          iface,
          device_name,
          seen_queue_ids.data(),
          static_cast<int>(seen_queue_ids.size()),
          proto_mask,
          err,
          err_len);
      if (rc == 0) {
        return 0;
      }
      if (strict != 0) {
        if (err == nullptr || err_len == 0u || err[0] == '\0') {
          write_err(err, err_len, "flow steering shim returned failure");
        }
        return -1;
      }
      return 1;
    }
    if (strict != 0) {
      const std::string msg = flow_why.empty() ? "flow steering backend unavailable" : flow_why;
      write_err(err, err_len, msg);
      return -1;
    }
  }

  // No steering programmer configured. In non-strict mode mark as not applied.
  write_err(err, err_len, "flow steering not applied (no backend configured)");
  return 1;
}

extern "C" int samurai_doca_backend_receive_burst(
    int handle,
    uint8_t* out_packets_flat,
    uint32_t out_packets_flat_len,
    uint16_t* out_lengths,
    int max_packets,
    int* out_received,
    char* err,
    size_t err_len) {
  if (out_received) {
    *out_received = 0;
  }
  if (handle < 0 || !out_packets_flat || out_packets_flat_len == 0u || !out_lengths || max_packets <= 0 ||
      !out_received) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_receive_burst");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_rx_handles.find(handle);
  if (it == g_rx_handles.end()) {
    write_err(err, err_len, "rxq handle not found");
    return -1;
  }
  BackendRxqHandle& h = it->second;
  if (!h.rxq || !h.pe || !h.buf_inv || !h.mmap) {
    write_err(err, err_len, "DOCA rxq handle is not fully initialized");
    return -1;
  }

  std::vector<uint64_t> packet_ptrs(static_cast<size_t>(max_packets), 0u);
  std::vector<uint64_t> packet_handles(static_cast<size_t>(max_packets), 0u);
  const int received = receive_burst_view_unlocked(h, packet_ptrs.data(), out_lengths, packet_handles.data(), max_packets);
  if (received < 0) {
    write_err(err, err_len, "DOCA receive_burst internal view receive failed");
    return -1;
  }
  size_t out_offset = 0u;
  int copied = 0;
  for (int i = 0; i < received; ++i) {
    const uint64_t ptr_raw = packet_ptrs[static_cast<size_t>(i)];
    const uint16_t len = out_lengths[static_cast<size_t>(i)];
    if (ptr_raw == 0u || len == 0u) {
      h.rx_drops += 1u;
      continue;
    }
    const size_t data_len = static_cast<size_t>(len);
    if (out_offset + data_len > static_cast<size_t>(out_packets_flat_len)) {
      h.rx_drops += 1u;
      break;
    }
    const uint8_t* src = reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(ptr_raw));
    std::memcpy(out_packets_flat + out_offset, src, data_len);
    out_lengths[copied] = len;
    out_offset += data_len;
    copied += 1;
  }
  const int rearmed = release_burst_view_unlocked(h, packet_handles.data(), received);
  if (rearmed < received) {
    write_err(err, err_len, "DOCA receive_burst internal view release failed");
    return -1;
  }
  *out_received = copied;
  return 0;
}

extern "C" int samurai_doca_backend_receive_burst_view(
    int handle,
    uint64_t* out_packet_ptrs,
    uint16_t* out_lengths,
    uint64_t* out_packet_handles,
    int max_packets,
    int* out_received,
    char* err,
    size_t err_len) {
  if (out_received) {
    *out_received = 0;
  }
  if (handle < 0 || !out_packet_ptrs || !out_lengths || !out_packet_handles || max_packets <= 0 || !out_received) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_receive_burst_view");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_rx_handles.find(handle);
  if (it == g_rx_handles.end()) {
    write_err(err, err_len, "rxq handle not found");
    return -1;
  }
  BackendRxqHandle& h = it->second;
  if (!h.rxq || !h.pe || !h.buf_inv || !h.mmap) {
    write_err(err, err_len, "DOCA rxq handle is not fully initialized");
    return -1;
  }

  const int copied = receive_burst_view_unlocked(h, out_packet_ptrs, out_lengths, out_packet_handles, max_packets);
  if (copied < 0) {
    write_err(err, err_len, "DOCA receive_burst_view internal failure");
    return -1;
  }
  *out_received = copied;
  return 0;
}

extern "C" int samurai_doca_backend_release_burst_view(
    int handle,
    const uint64_t* packet_handles,
    int packet_count,
    int* out_rearmed,
    char* err,
    size_t err_len) {
  if (out_rearmed) {
    *out_rearmed = 0;
  }
  if (handle < 0 || !packet_handles || packet_count <= 0 || !out_rearmed) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_release_burst_view");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_rx_handles.find(handle);
  if (it == g_rx_handles.end()) {
    write_err(err, err_len, "rxq handle not found");
    return -1;
  }
  BackendRxqHandle& h = it->second;
  if (!h.rxq || !h.pe || !h.buf_inv || !h.mmap) {
    write_err(err, err_len, "DOCA rxq handle is not fully initialized");
    return -1;
  }

  const int rearmed = release_burst_view_unlocked(h, packet_handles, packet_count);
  if (rearmed < 0) {
    write_err(err, err_len, "DOCA release_burst_view internal failure");
    return -1;
  }
  *out_rearmed = rearmed;
  if (rearmed < packet_count) {
    write_err(err, err_len, "DOCA release_burst_view had rearm failures");
    return -1;
  }
  return 0;
}
