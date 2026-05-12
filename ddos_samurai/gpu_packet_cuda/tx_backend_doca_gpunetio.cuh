#pragma once

#include <cstddef>
#include <cstdint>

#define SAMURAI_DOCA_GPUNETIO_API_DECLS 1

constexpr int kDocaGpuNetioApiVersion = 2;

struct DocaGpuNetioStats {
  uint64_t tx_packets = 0u;
  uint64_t tx_bytes = 0u;
  uint64_t tx_errors = 0u;
  uint64_t tx_drops = 0u;
  int queue_id = 0;
};

struct DocaGpuNetioApiV1 {
  int version = 0;
  int (*create_txq)(
      const char* iface,
      const char* device_name,
      int gpu_id,
      int queue_id,
      int* out_handle,
      char* err,
      size_t err_len) = nullptr;
  int (*destroy_txq)(int handle, char* err, size_t err_len) = nullptr;
  int (*send_vector)(
      int handle,
      const uint8_t** packets,
      const uint16_t* lengths,
      const int32_t* stream_slots,
      int count,
      int* out_sent,
      int* out_errors,
      char* err,
      size_t err_len) = nullptr;
  int (*get_stats)(int handle, DocaGpuNetioStats* out, char* err, size_t err_len) = nullptr;
  int (*get_gpu_txq_handle)(int handle, uint64_t* out_gpu_txq_handle, char* err, size_t err_len) = nullptr;
  int (*get_txq_mkey_be)(int handle, uint32_t* out_mkey_be, char* err, size_t err_len) = nullptr;
};

extern "C" __attribute__((weak)) DocaGpuNetioApiV1* samurai_doca_gpunetio_get_api_v1(void);
