#pragma once

// Maps a logical worker kind to the native worker binary that implements it.
//
// This is the native replacement for the worker-selection logic that used to
// live in the Python orchestrator: instead of importing a Python module per
// backend, the orchestrator spawns the corresponding compiled worker daemon.

#include <optional>
#include <string>

#include "wire_protocol.h"

// Some Linux socket headers (<sys/socket.h>, pulled in by e.g. <arpa/inet.h>)
// define AF_XDP as a numeric macro. If such a header is included after
// wire_protocol.h, its #pragma once prevents wire_protocol.h from re-running its
// own undef, and the macro then clobbers WorkerKind::AF_XDP below. Undef it here
// so this header is robust to include order.
#ifdef AF_XDP
#undef AF_XDP
#endif

namespace samurai::orchestrator {

struct WorkerEntry {
  samurai::wire::WorkerKind kind;
  const char* name;     // stable CLI name, e.g. "cpu"
  const char* binary;   // executable produced by zmq/CMakeLists.txt
};

inline constexpr WorkerEntry kWorkerTable[] = {
    {samurai::wire::WorkerKind::CPU, "cpu", "samurai_cpu_worker"},
    {samurai::wire::WorkerKind::GPU, "gpu", "samurai_gpu_worker"},
    {samurai::wire::WorkerKind::DPDK, "dpdk", "samurai_dpdk_worker"},
    {samurai::wire::WorkerKind::AF_XDP, "afxdp", "samurai_afxdp_worker"},
    {samurai::wire::WorkerKind::DOCA, "doca", "samurai_doca_worker"},
    {samurai::wire::WorkerKind::L7, "l7", "samurai_l7_worker"},
    {samurai::wire::WorkerKind::DEFENSE, "defense", "samurai_defense_worker"},
    {samurai::wire::WorkerKind::SCENARIO, "scenario", "samurai_scenario_worker"},
};

inline std::optional<WorkerEntry> LookupWorker(const std::string& name) {
  for (const auto& e : kWorkerTable) {
    if (name == e.name) {
      return e;
    }
  }
  return std::nullopt;
}

inline const char* WorkerName(samurai::wire::WorkerKind kind) {
  for (const auto& e : kWorkerTable) {
    if (e.kind == kind) {
      return e.name;
    }
  }
  return "unknown";
}

}  // namespace samurai::orchestrator
