#pragma once

#include <cstddef>
#include <cstdint>

#define SAMURAI_DOCA_GPUNETIO_API_DECLS 1

constexpr int kDocaGpuNetioApiVersion = 4;

struct DocaGpuNetioStats {
  uint64_t tx_packets = 0u;
  uint64_t tx_bytes = 0u;
  uint64_t tx_errors = 0u;
  uint64_t tx_drops = 0u;
  int queue_id = 0;
};

struct DocaFlowUpdateEventV1 {
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

struct DocaContractWriterConfigV1 {
  char region_spec[512]{};
  char device_name[64]{};
  uint32_t shard_count = 0u;
  uint32_t ring_slots_per_shard = 0u;
  uint32_t hot_flow_capacity = 0u;
  uint32_t flags = 0u;
};

// Optional plugin ABI for kind=rdma contract regions. The importer owns any
// provider-specific RDMA/DOCA import objects and returns a CPU-visible writer
// mapping plus an opaque cookie that is released by the matching release hook.
using DocaContractRdmaImportFnV1 = int (*)(
    const char* region_spec,
    const DocaContractWriterConfigV1* cfg,
    void** out_addr,
    size_t* out_len,
    uint64_t* out_cookie,
    char* err,
    size_t err_len);
using DocaContractRdmaReleaseFnV1 = int (*)(uint64_t cookie, char* err, size_t err_len);

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
  int (*send_vector_timed)(
      int handle,
      const uint8_t** packets,
      const uint16_t* lengths,
      const int32_t* stream_slots,
      const uint64_t* tx_timestamps_ns,
      int count,
      int* out_sent,
      int* out_errors,
      char* err,
      size_t err_len) = nullptr;
  int (*get_stats)(int handle, DocaGpuNetioStats* out, char* err, size_t err_len) = nullptr;
  int (*get_gpu_txq_handle)(int handle, uint64_t* out_gpu_txq_handle, char* err, size_t err_len) = nullptr;
  int (*get_txq_mkey_be)(int handle, uint32_t* out_mkey_be, char* err, size_t err_len) = nullptr;
  int (*contract_writer_open)(
      const DocaContractWriterConfigV1* cfg,
      int* out_handle,
      char* err,
      size_t err_len) = nullptr;
  int (*contract_writer_close)(int handle, char* err, size_t err_len) = nullptr;
  int (*contract_writer_publish_flow_update_v1)(
      int handle,
      const DocaFlowUpdateEventV1* event,
      char* err,
      size_t err_len) = nullptr;
};

extern "C" __attribute__((weak)) DocaGpuNetioApiV1* samurai_doca_gpunetio_get_api_v1(void);
