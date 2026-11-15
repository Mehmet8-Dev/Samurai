#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

#include "wire_protocol.h"

namespace samurai::daemon {

inline samurai::wire::SamuraiWireHeaderV1 MakeHeaderV(
    std::uint8_t version,
    std::uint8_t msg_type,
    std::uint32_t payload_len,
    std::uint64_t correlation_id,
    samurai::wire::WorkerKind worker_kind,
    const std::string& job_id) {
  samurai::wire::SamuraiWireHeaderV1 header{};
  header.magic = samurai::wire::kMagic;
  header.version = version;
  header.msg_type = msg_type;
  header.payload_len = payload_len;
  header.flags = 0;
  header.correlation_id = correlation_id;
  header.worker_kind = static_cast<std::uint8_t>(worker_kind);
  std::memset(header.job_id, 0, sizeof(header.job_id));
  std::memcpy(header.job_id, job_id.data(), std::min(job_id.size(), sizeof(header.job_id) - 1));
  std::memset(header.pad, 0, sizeof(header.pad));
  return header;
}

inline samurai::wire::SamuraiWireHeaderV1 MakeHeader(
    std::uint8_t msg_type,
    std::uint32_t payload_len,
    std::uint64_t correlation_id,
    samurai::wire::WorkerKind worker_kind,
    const std::string& job_id) {
  return MakeHeaderV(
      samurai::wire::kVersionV1, msg_type, payload_len, correlation_id, worker_kind, job_id);
}

inline samurai::wire::SamuraiWireHeaderV3 MakeHeaderV3(
    std::uint8_t msg_type,
    std::uint32_t payload_len,
    std::uint64_t correlation_id,
    samurai::wire::WorkerKind worker_kind,
    const std::string& job_id,
    std::uint8_t ext_count = 0,
    std::uint32_t flags = 0,
    std::uint16_t schema_minor = samurai::wire::kSchemaMinorV3) {
  samurai::wire::SamuraiWireHeaderV3 header{};
  header.magic = samurai::wire::kMagic;
  header.version = samurai::wire::kVersionV3;
  header.msg_type = msg_type;
  header.header_bytes = static_cast<std::uint16_t>(sizeof(samurai::wire::SamuraiWireHeaderV3));
  header.payload_len = payload_len;
  header.schema_major = samurai::wire::kSchemaMajorV3;
  header.schema_minor = schema_minor;
  header.correlation_id = correlation_id;
  header.flags = flags;
  header.worker_kind = static_cast<std::uint8_t>(worker_kind);
  header.ext_count = ext_count;
  header.reserved = 0;
  std::memset(header.job_id, 0, sizeof(header.job_id));
  std::memcpy(header.job_id, job_id.data(), std::min(job_id.size(), sizeof(header.job_id) - 1));
  return header;
}

inline std::string ReadJobId(const samurai::wire::SamuraiWireHeaderV1& header) {
  return std::string(header.job_id, strnlen(header.job_id, sizeof(header.job_id)));
}

}  // namespace samurai::daemon
