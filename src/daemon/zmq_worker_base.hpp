#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

#include "wire_protocol.h"

namespace samurai::daemon {

inline samurai::wire::SamuraiWireHeaderV1 MakeHeader(
    std::uint8_t msg_type,
    std::uint32_t payload_len,
    std::uint64_t correlation_id,
    samurai::wire::WorkerKind worker_kind,
    const std::string& job_id) {
  samurai::wire::SamuraiWireHeaderV1 header{};
  header.magic = samurai::wire::kMagic;
  header.version = samurai::wire::kVersionV1;
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

inline std::string ReadJobId(const samurai::wire::SamuraiWireHeaderV1& header) {
  return std::string(header.job_id, strnlen(header.job_id, sizeof(header.job_id)));
}

}  // namespace samurai::daemon
