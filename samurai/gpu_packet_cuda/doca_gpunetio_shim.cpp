#include "tx_backend_doca_gpunetio.cuh"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <mutex>
#include <string>
#include <vector>

namespace {

using BackendCreateTxqFn = int (*)(
    const char* iface,
    const char* device_name,
    int gpu_id,
    int queue_id,
    int* out_handle,
    char* err,
    size_t err_len);
using BackendDestroyTxqFn = int (*)(int handle, char* err, size_t err_len);
using BackendSendVectorFn = int (*)(
    int handle,
    const uint8_t** packets,
    const uint16_t* lengths,
    const int32_t* stream_slots,
    int count,
    int* out_sent,
    int* out_errors,
    char* err,
    size_t err_len);
using BackendSendVectorTimedFn = int (*)(
    int handle,
    const uint8_t** packets,
    const uint16_t* lengths,
    const int32_t* stream_slots,
    const uint64_t* tx_timestamps_ns,
    int count,
    int* out_sent,
    int* out_errors,
    char* err,
    size_t err_len);
using BackendGetStatsFn = int (*)(int handle, DocaGpuNetioStats* out, char* err, size_t err_len);
using BackendGetGpuTxqHandleFn =
    int (*)(int handle, uint64_t* out_gpu_txq_handle, char* err, size_t err_len);
using BackendGetTxqMkeyBeFn = int (*)(int handle, uint32_t* out_mkey_be, char* err, size_t err_len);
using BackendContractWriterOpenFn =
    int (*)(const DocaContractWriterConfigV1* cfg, int* out_handle, char* err, size_t err_len);
using BackendContractWriterCloseFn = int (*)(int handle, char* err, size_t err_len);
using BackendContractWriterPublishFlowUpdateFn =
    int (*)(int handle, const DocaFlowUpdateEventV1* event, char* err, size_t err_len);

struct BackendDispatch {
  BackendCreateTxqFn create_txq = nullptr;
  BackendDestroyTxqFn destroy_txq = nullptr;
  BackendSendVectorFn send_vector = nullptr;
  BackendSendVectorTimedFn send_vector_timed = nullptr;
  BackendGetStatsFn get_stats = nullptr;
  BackendGetGpuTxqHandleFn get_gpu_txq_handle = nullptr;
  BackendGetTxqMkeyBeFn get_txq_mkey_be = nullptr;
  BackendContractWriterOpenFn contract_writer_open = nullptr;
  BackendContractWriterCloseFn contract_writer_close = nullptr;
  BackendContractWriterPublishFlowUpdateFn contract_writer_publish_flow_update = nullptr;
};

std::mutex g_backend_lock;
void* g_backend_so = nullptr;
BackendDispatch g_backend{};
bool g_backend_load_attempted = false;
std::string g_backend_load_error;

inline void write_err(char* err, size_t err_len, const std::string& msg) {
  if (!err || err_len == 0u) {
    return;
  }
  if (msg.empty()) {
    err[0] = '\0';
    return;
  }
  const size_t n = std::min(err_len - 1u, msg.size());
  std::memcpy(err, msg.data(), n);
  err[n] = '\0';
}

inline bool env_flag(const char* name, bool defv) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return defv;
  }
  std::string v(raw);
  std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return v == "1" || v == "true" || v == "yes" || v == "on";
}

inline std::string env_string_or(const char* name, const char* defv) {
  const char* raw = std::getenv(name);
  if (!raw || !*raw) {
    return std::string(defv ? defv : "");
  }
  return std::string(raw);
}

inline bool resolve_backend_symbol(void* handle, const char* name, void** out, std::string& why) {
  if (!handle || !name || !out) {
    why = "invalid resolve inputs";
    return false;
  }
  dlerror();
  void* fn = dlsym(handle, name);
  const char* sym_err = dlerror();
  if (!fn || sym_err) {
    why = std::string("dlsym(") + name + ") failed: " + (sym_err ? sym_err : "unknown");
    return false;
  }
  *out = fn;
  return true;
}

inline bool ensure_backend_loaded_unlocked(std::string& why) {
  if (g_backend_so && g_backend.create_txq && g_backend.destroy_txq && g_backend.send_vector &&
      g_backend.get_stats && g_backend.get_gpu_txq_handle && g_backend.get_txq_mkey_be) {
    return true;
  }
  if (g_backend_load_attempted) {
    why = g_backend_load_error.empty() ? "backend load failed earlier" : g_backend_load_error;
    return false;
  }
  g_backend_load_attempted = true;

  const std::string so_path = env_string_or("SAMURAI_GPU_DOCA_SHIM_SO", "libsamurai_doca_gpunetio_backend.so");
  std::vector<std::string> candidates;
  candidates.push_back(so_path);
  if (so_path.find('/') == std::string::npos) {
    Dl_info info{};
    if (dladdr(reinterpret_cast<void*>(samurai_doca_gpunetio_get_api_v1), &info) != 0 && info.dli_fname &&
        *info.dli_fname) {
      std::string base(info.dli_fname);
      const size_t slash = base.find_last_of('/');
      if (slash != std::string::npos) {
        base.resize(slash + 1u);
        candidates.push_back(base + so_path);
      }
    }
  }
  for (const std::string& cand : candidates) {
    dlerror();
    g_backend_so = dlopen(cand.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (g_backend_so) {
      break;
    }
  }
  if (!g_backend_so) {
    const char* dlerr = dlerror();
    g_backend_load_error = std::string("dlopen failed for DOCA backend candidates (primary=") + so_path +
                           "): " + (dlerr ? dlerr : "unknown");
    why = g_backend_load_error;
    return false;
  }

  void* p_create = nullptr;
  void* p_destroy = nullptr;
  void* p_send = nullptr;
  void* p_send_timed = nullptr;
  void* p_stats = nullptr;
  void* p_gpu_txq = nullptr;
  void* p_mkey = nullptr;
  std::string sym_why;
  if (!resolve_backend_symbol(g_backend_so, "samurai_doca_backend_create_txq", &p_create, sym_why) ||
      !resolve_backend_symbol(g_backend_so, "samurai_doca_backend_destroy_txq", &p_destroy, sym_why) ||
      !resolve_backend_symbol(g_backend_so, "samurai_doca_backend_send_vector", &p_send, sym_why) ||
      !resolve_backend_symbol(g_backend_so, "samurai_doca_backend_get_stats", &p_stats, sym_why) ||
      !resolve_backend_symbol(g_backend_so, "samurai_doca_backend_get_gpu_txq_handle", &p_gpu_txq, sym_why) ||
      !resolve_backend_symbol(g_backend_so, "samurai_doca_backend_get_txq_mkey_be", &p_mkey, sym_why)) {
    g_backend_load_error = sym_why;
    dlclose(g_backend_so);
    g_backend_so = nullptr;
    why = g_backend_load_error;
    return false;
  }

  g_backend.create_txq = reinterpret_cast<BackendCreateTxqFn>(p_create);
  g_backend.destroy_txq = reinterpret_cast<BackendDestroyTxqFn>(p_destroy);
  g_backend.send_vector = reinterpret_cast<BackendSendVectorFn>(p_send);
  dlerror();
  p_send_timed = dlsym(g_backend_so, "samurai_doca_backend_send_vector_timed");
  if (dlerror() == nullptr && p_send_timed != nullptr) {
    g_backend.send_vector_timed = reinterpret_cast<BackendSendVectorTimedFn>(p_send_timed);
  } else {
    g_backend.send_vector_timed = nullptr;
  }
  g_backend.get_stats = reinterpret_cast<BackendGetStatsFn>(p_stats);
  g_backend.get_gpu_txq_handle = reinterpret_cast<BackendGetGpuTxqHandleFn>(p_gpu_txq);
  g_backend.get_txq_mkey_be = reinterpret_cast<BackendGetTxqMkeyBeFn>(p_mkey);
  void* p_contract_open = nullptr;
  void* p_contract_close = nullptr;
  void* p_contract_publish = nullptr;
  dlerror();
  p_contract_open = dlsym(g_backend_so, "samurai_doca_backend_contract_writer_open");
  if (dlerror() == nullptr && p_contract_open != nullptr) {
    g_backend.contract_writer_open = reinterpret_cast<BackendContractWriterOpenFn>(p_contract_open);
  }
  dlerror();
  p_contract_close = dlsym(g_backend_so, "samurai_doca_backend_contract_writer_close");
  if (dlerror() == nullptr && p_contract_close != nullptr) {
    g_backend.contract_writer_close = reinterpret_cast<BackendContractWriterCloseFn>(p_contract_close);
  }
  dlerror();
  p_contract_publish = dlsym(g_backend_so, "samurai_doca_backend_contract_writer_publish_flow_update_v1");
  if (dlerror() == nullptr && p_contract_publish != nullptr) {
    g_backend.contract_writer_publish_flow_update =
        reinterpret_cast<BackendContractWriterPublishFlowUpdateFn>(p_contract_publish);
  }
  return true;
}

inline int shim_create_txq(
    const char* iface,
    const char* device_name,
    int gpu_id,
    int queue_id,
    int* out_handle,
    char* err,
    size_t err_len) {
  if (!env_flag("SAMURAI_GPU_DOCA_ENABLE", false)) {
    write_err(
        err,
        err_len,
        "doca_gpunetio disabled: set SAMURAI_GPU_DOCA_ENABLE=1 and provide SAMURAI_GPU_DOCA_SHIM_SO backend.");
    return -1;
  }
  if (!iface || !*iface || !device_name || !*device_name || !out_handle) {
    write_err(err, err_len, "invalid DOCA TXQ create arguments");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_backend_lock);
  std::string why;
  if (!ensure_backend_loaded_unlocked(why)) {
    write_err(err, err_len, why);
    return -1;
  }
  return g_backend.create_txq(iface, device_name, gpu_id, queue_id, out_handle, err, err_len);
}

inline int shim_destroy_txq(int handle, char* err, size_t err_len) {
  std::lock_guard<std::mutex> guard(g_backend_lock);
  std::string why;
  if (!ensure_backend_loaded_unlocked(why)) {
    write_err(err, err_len, why);
    return -1;
  }
  return g_backend.destroy_txq(handle, err, err_len);
}

inline int shim_send_vector(
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
  if (count <= 0 || !packets || !lengths || !out_sent || !out_errors) {
    write_err(err, err_len, "invalid DOCA send_vector arguments");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_backend_lock);
  std::string why;
  if (!ensure_backend_loaded_unlocked(why)) {
    write_err(err, err_len, why);
    return -1;
  }
  return g_backend.send_vector(handle, packets, lengths, stream_slots, count, out_sent, out_errors, err, err_len);
}

inline int shim_send_vector_timed(
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
  if (count <= 0 || !packets || !lengths || !tx_timestamps_ns || !out_sent || !out_errors) {
    write_err(err, err_len, "invalid DOCA send_vector_timed arguments");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_backend_lock);
  std::string why;
  if (!ensure_backend_loaded_unlocked(why)) {
    write_err(err, err_len, why);
    return -1;
  }
  if (!g_backend.send_vector_timed) {
    write_err(err, err_len, "DOCA backend does not expose send_vector_timed");
    return -1;
  }
  return g_backend.send_vector_timed(
      handle,
      packets,
      lengths,
      stream_slots,
      tx_timestamps_ns,
      count,
      out_sent,
      out_errors,
      err,
      err_len);
}

inline int shim_get_stats(int handle, DocaGpuNetioStats* out, char* err, size_t err_len) {
  if (!out) {
    write_err(err, err_len, "invalid DOCA get_stats output pointer");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_backend_lock);
  std::string why;
  if (!ensure_backend_loaded_unlocked(why)) {
    write_err(err, err_len, why);
    return -1;
  }
  return g_backend.get_stats(handle, out, err, err_len);
}

inline int shim_get_gpu_txq_handle(int handle, uint64_t* out_gpu_txq_handle, char* err, size_t err_len) {
  if (!out_gpu_txq_handle) {
    write_err(err, err_len, "invalid DOCA get_gpu_txq_handle output pointer");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_backend_lock);
  std::string why;
  if (!ensure_backend_loaded_unlocked(why)) {
    write_err(err, err_len, why);
    return -1;
  }
  return g_backend.get_gpu_txq_handle(handle, out_gpu_txq_handle, err, err_len);
}

inline int shim_get_txq_mkey_be(int handle, uint32_t* out_mkey_be, char* err, size_t err_len) {
  if (!out_mkey_be) {
    write_err(err, err_len, "invalid DOCA get_txq_mkey_be output pointer");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_backend_lock);
  std::string why;
  if (!ensure_backend_loaded_unlocked(why)) {
    write_err(err, err_len, why);
    return -1;
  }
  return g_backend.get_txq_mkey_be(handle, out_mkey_be, err, err_len);
}

inline int shim_contract_writer_open(
    const DocaContractWriterConfigV1* cfg,
    int* out_handle,
    char* err,
    size_t err_len) {
  if (!env_flag("SAMURAI_GPU_DOCA_ENABLE", false)) {
    write_err(err, err_len, "doca_gpunetio disabled for contract writer");
    return -1;
  }
  if (!cfg || !out_handle || cfg->region_spec[0] == '\0') {
    write_err(err, err_len, "invalid DOCA contract writer open arguments");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_backend_lock);
  std::string why;
  if (!ensure_backend_loaded_unlocked(why)) {
    write_err(err, err_len, why);
    return -1;
  }
  if (!g_backend.contract_writer_open) {
    write_err(err, err_len, "doca_contract_writer_unavailable");
    return -1;
  }
  return g_backend.contract_writer_open(cfg, out_handle, err, err_len);
}

inline int shim_contract_writer_close(int handle, char* err, size_t err_len) {
  std::lock_guard<std::mutex> guard(g_backend_lock);
  std::string why;
  if (!ensure_backend_loaded_unlocked(why)) {
    write_err(err, err_len, why);
    return -1;
  }
  if (!g_backend.contract_writer_close) {
    write_err(err, err_len, "doca_contract_writer_unavailable");
    return -1;
  }
  return g_backend.contract_writer_close(handle, err, err_len);
}

inline int shim_contract_writer_publish_flow_update(
    int handle,
    const DocaFlowUpdateEventV1* event,
    char* err,
    size_t err_len) {
  if (!event) {
    write_err(err, err_len, "invalid DOCA contract writer event");
    return -1;
  }
  std::lock_guard<std::mutex> guard(g_backend_lock);
  std::string why;
  if (!ensure_backend_loaded_unlocked(why)) {
    write_err(err, err_len, why);
    return -1;
  }
  if (!g_backend.contract_writer_publish_flow_update) {
    write_err(err, err_len, "doca_contract_writer_unavailable");
    return -1;
  }
  return g_backend.contract_writer_publish_flow_update(handle, event, err, err_len);
}

}  // namespace

extern "C" DocaGpuNetioApiV1* samurai_doca_gpunetio_get_api_v1(void) {
  static DocaGpuNetioApiV1 api{};
  static std::once_flag once;
  std::call_once(once, []() {
    api.version = kDocaGpuNetioApiVersion;
    api.create_txq = shim_create_txq;
    api.destroy_txq = shim_destroy_txq;
    api.send_vector = shim_send_vector;
    api.send_vector_timed = shim_send_vector_timed;
    api.get_stats = shim_get_stats;
    api.get_gpu_txq_handle = shim_get_gpu_txq_handle;
    api.get_txq_mkey_be = shim_get_txq_mkey_be;
    api.contract_writer_open = shim_contract_writer_open;
    api.contract_writer_close = shim_contract_writer_close;
    api.contract_writer_publish_flow_update_v1 = shim_contract_writer_publish_flow_update;
  });
  return &api;
}
