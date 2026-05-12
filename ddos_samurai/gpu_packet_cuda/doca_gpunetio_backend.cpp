#include "tx_backend_doca_gpunetio.cuh"

#include <arpa/inet.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
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
struct doca_eth_txq;
struct doca_gpu_eth_txq;
struct doca_eth_txq_task_send;
struct doca_eth_rxq;
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
  doca_ctx* ctx = nullptr;
  doca_mmap* mmap = nullptr;
  doca_buf_inventory* buf_inv = nullptr;

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

std::mutex g_lock;
std::unordered_map<int, BackendTxqHandle> g_handles;
std::unordered_map<int, BackendRxqHandle> g_rx_handles;
int g_next_handle = 1;

std::mutex g_api_lock;
DocaApi g_doca{};

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
    h.ctx = nullptr;
  }
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
  tmp.handle = hnd;
  doca_data ud{};
  ud.ptr = nullptr;
  if (tmp.ctx) {
    ud.ptr = &tmp;
  }
  g_handles.emplace(hnd, std::move(tmp));
  auto it = g_handles.find(hnd);
  if (it != g_handles.end() && it->second.ctx) {
    doca_data ctx_data{};
    ctx_data.ptr = &(it->second);
    (void)g_doca.doca_ctx_set_user_data(it->second.ctx, ctx_data);
  }
  *out_handle = hnd;
  return 0;
}

extern "C" int samurai_doca_backend_destroy_txq(int handle, char* err, size_t err_len) {
  if (handle < 0) {
    write_err(err, err_len, "invalid handle in samurai_doca_backend_destroy_txq");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_handles.find(handle);
  if (it == g_handles.end()) {
    return 0;
  }
  destroy_backend_txq_unlocked(it->second);
  g_handles.erase(it);
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

  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_handles.find(handle);
  if (it == g_handles.end()) {
    write_err(err, err_len, "txq handle not found");
    return -1;
  }
  BackendTxqHandle& h = it->second;
  if (!h.txq || !h.pe || !h.mmap || !h.buf_inv) {
    write_err(err, err_len, "DOCA txq handle is not fully initialized");
    return -1;
  }

  int submitted = 0;
  int failures = 0;
  uint64_t bytes_submitted = 0u;
  for (int i = 0; i < count; ++i) {
    if (!packets[i] || lengths[i] == 0u) {
      failures += 1;
      continue;
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
    write_err(err, err_len, "DOCA send_vector timed out waiting for task completions");
    return -1;
  }

  h.tx_packets += static_cast<uint64_t>(submitted);
  h.tx_bytes += bytes_submitted;
  h.tx_errors += static_cast<uint64_t>(failures);
  h.tx_drops += static_cast<uint64_t>(failures);
  *out_sent = submitted;
  *out_errors = failures;
  if (submitted <= 0) {
    write_err(err, err_len, "DOCA send_vector submitted zero packets");
    return -1;
  }
  return 0;
}

extern "C" int samurai_doca_backend_get_stats(int handle, DocaGpuNetioStats* out, char* err, size_t err_len) {
  if (handle < 0 || !out) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_get_stats");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_handles.find(handle);
  if (it == g_handles.end()) {
    write_err(err, err_len, "txq handle not found");
    return -1;
  }
  out->tx_packets = it->second.tx_packets;
  out->tx_bytes = it->second.tx_bytes;
  out->tx_errors = it->second.tx_errors;
  out->tx_drops = it->second.tx_drops;
  out->queue_id = it->second.queue_id;
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
  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_handles.find(handle);
  if (it == g_handles.end() || !it->second.gpu_txq) {
    write_err(err, err_len, "txq handle not found or gpu handle unavailable");
    return -1;
  }
  *out_gpu_txq_handle = reinterpret_cast<uint64_t>(it->second.gpu_txq);
  return 0;
}

extern "C" int samurai_doca_backend_get_txq_mkey_be(int handle, uint32_t* out_mkey_be, char* err, size_t err_len) {
  if (handle < 0 || !out_mkey_be) {
    write_err(err, err_len, "invalid arguments for samurai_doca_backend_get_txq_mkey_be");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_lock);
  auto it = g_handles.find(handle);
  if (it == g_handles.end() || it->second.txq_mkey_be == 0u) {
    write_err(err, err_len, "txq handle not found or txq mkey unavailable");
    return -1;
  }
  *out_mkey_be = it->second.txq_mkey_be;
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

  uint32_t loops = 0u;
  while (h.completed_pkts.empty() && loops < h.max_progress_loops) {
    (void)g_doca.doca_pe_progress(h.pe);
    loops += 1u;
  }

  size_t out_offset = 0u;
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
      (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
      continue;
    }
    if (data_len > static_cast<size_t>(std::numeric_limits<uint16_t>::max())) {
      data_len = static_cast<size_t>(std::numeric_limits<uint16_t>::max());
    }
    if (out_offset + data_len > static_cast<size_t>(out_packets_flat_len)) {
      h.rx_drops += 1u;
      (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
      break;
    }
    std::memcpy(out_packets_flat + out_offset, data_ptr, data_len);
    out_lengths[copied] = static_cast<uint16_t>(data_len);
    out_offset += data_len;
    copied += 1;
    h.rx_packets += 1u;
    h.rx_bytes += static_cast<uint64_t>(data_len);

    void* head_ptr = nullptr;
    size_t head_len = 0u;
    if (g_doca.doca_buf_get_head(pkt, &head_ptr) != kDocaSuccess || !head_ptr ||
        g_doca.doca_buf_get_len(pkt, &head_len) != kDocaSuccess || head_len == 0u) {
      (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);
      h.rx_errors += 1u;
      continue;
    }
    (void)g_doca.doca_buf_dec_refcount(pkt, nullptr);

    doca_buf* next_pkt = nullptr;
    doca_error_t rc = g_doca.doca_buf_inventory_buf_get_by_addr(h.buf_inv, h.mmap, head_ptr, head_len, &next_pkt);
    if (rc != kDocaSuccess || !next_pkt) {
      h.rx_errors += 1u;
      h.rx_drops += 1u;
      continue;
    }
    doca_data user_data{};
    user_data.u64 = 0u;
    doca_eth_rxq_task_recv* next_task_recv = nullptr;
    rc = g_doca.doca_eth_rxq_task_recv_allocate_init(h.rxq, next_pkt, user_data, &next_task_recv);
    if (rc != kDocaSuccess || !next_task_recv) {
      (void)g_doca.doca_buf_dec_refcount(next_pkt, nullptr);
      h.rx_errors += 1u;
      h.rx_drops += 1u;
      continue;
    }
    doca_task* next_task = g_doca.doca_eth_rxq_task_recv_as_doca_task(next_task_recv);
    if (!next_task) {
      (void)g_doca.doca_buf_dec_refcount(next_pkt, nullptr);
      h.rx_errors += 1u;
      h.rx_drops += 1u;
      continue;
    }
    rc = g_doca.doca_task_submit(next_task);
    if (rc != kDocaSuccess) {
      (void)g_doca.doca_task_free(next_task);
      (void)g_doca.doca_buf_dec_refcount(next_pkt, nullptr);
      h.rx_errors += 1u;
      h.rx_drops += 1u;
      continue;
    }
    h.inflight += 1u;
  }

  *out_received = copied;
  return 0;
}
