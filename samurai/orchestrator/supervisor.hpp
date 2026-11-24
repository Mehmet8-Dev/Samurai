#pragma once

// Native worker supervisor: spawns a compiled worker daemon and drives a single
// job over the shared ZMQ wire protocol, then shuts the worker down cleanly.
//
// This is the native-C++ core of what the Python orchestrator used to do in
// `start_worker_zmq`: pick a worker, hand it a job envelope, collect its metric
// snapshots, and tear it down. It links only libzmq + the shared wire headers.

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "job_builder.hpp"
#include "run_summary.hpp"
#include "wire_protocol.h"
#include "worker_registry.hpp"

namespace samurai::orchestrator {

enum class OutputMode {
  kAuto,
  kPretty,
  kNdjson,
  kQuiet,
};

inline bool EnvWireV3Enabled() noexcept {
  const char* raw = std::getenv("SAMURAI_WIRE_ABI");
  if (!raw || raw[0] == '\0') return false;
  return std::strcmp(raw, "3") == 0 || std::strcmp(raw, "v3") == 0 ||
         std::strcmp(raw, "V3") == 0;
}

struct SupervisorConfig {
  WorkerEntry worker;                 // which worker binary to spawn
  std::string worker_dir = ".";       // directory containing the worker binary
  std::string jobs_endpoint;          // ipc/tcp endpoint for the jobs channel
  std::string events_endpoint;        // ipc/tcp endpoint for the events channel
  int recv_timeout_ms = 5000;         // per-recv timeout on the events socket
  int max_idle_recvs = 24;            // give up after this many empty recvs
  bool use_wire_v3 = EnvWireV3Enabled();  // SAMURAI_WIRE_ABI=v3 uses aligned V3 frames
  OutputMode output_mode = OutputMode::kAuto;
  std::string iface;                  // CLI --iface override
  std::string transport;              // CLI --transport override
  int dpdk_port = -1;                 // CLI --dpdk-port override
  int dpdk_queue = -1;                // CLI --dpdk-queue override
};

// Maintains warm persistent worker processes across sequential jobs/windows so
// closed-loop windows and repeated shard runs avoid fork/exec + cold init cost.
// Enabled by default unless SAMURAI_WARM_WORKERS=0.
class WarmWorkerPool {
 public:
  struct Slot;

  WarmWorkerPool();
  ~WarmWorkerPool();

  WarmWorkerPool(const WarmWorkerPool&) = delete;
  WarmWorkerPool& operator=(const WarmWorkerPool&) = delete;

  bool Enabled() const noexcept { return enabled_.load(); }
  void SetEnabled(bool enabled) noexcept { enabled_.store(enabled); }

  // Sends SHUTDOWN to all cached idle workers (and marks busy ones to close on
  // release), waits for process exit, and cleans up ZMQ sockets and IPC paths.
  void ShutdownAll();

  // Queues a live RECONFIGURE_JOB frame for an active shard running on a warm
  // worker. Thread-safe; the active RunJob loop drains and transmits it.
  bool ReconfigureActiveShard(const std::string& shard_id,
                              const samurai::wire::ReconfigureWindowV1& window);

  std::size_t WarmSlotCount() const;
  std::size_t ActiveSlotCount() const;
  std::uint64_t SpawnCount() const noexcept { return spawn_count_.load(); }
  std::uint64_t ReuseCount() const noexcept { return reuse_count_.load(); }
  long LastWorkerPid(samurai::wire::WorkerKind kind) const;

 private:
  friend int RunJob(const SupervisorConfig& cfg,
                    const JobOptions& job,
                    RunStats& out_stats,
                    WarmWorkerPool* pool,
                    std::atomic<bool>* cancel_requested,
                    const std::string& shard_id);

  std::shared_ptr<Slot> AcquireSlot(const SupervisorConfig& cfg,
                                    const std::string& shard_id,
                                    bool& out_reused);
  void ReleaseSlot(const std::shared_ptr<Slot>& slot, bool keep_warm);
  void DestroySlot(const std::shared_ptr<Slot>& slot, bool send_shutdown, bool force_kill);

  mutable std::mutex mu_;
  std::vector<std::shared_ptr<Slot>> slots_;
  std::atomic<bool> enabled_{true};
  std::atomic<bool> shutting_down_{false};
  std::atomic<std::uint64_t> next_slot_seq_{1};
  std::atomic<std::uint64_t> spawn_count_{0};
  std::atomic<std::uint64_t> reuse_count_{0};
};

// Runs one job end-to-end. When `pool` is provided and enabled, reuses/retains
// a warm worker process across calls. When `cancel_requested` becomes true,
// interrupts the active worker cleanly via STOP_JOB (falling back to ABORT /
// SIGTERM if unresponsive). Returns 0 on clean JOB_DONE or non-zero on error.
int RunJob(const SupervisorConfig& cfg,
           const JobOptions& job,
           RunStats& out_stats,
           WarmWorkerPool* pool = nullptr,
           std::atomic<bool>* cancel_requested = nullptr,
           const std::string& shard_id = "");

}  // namespace samurai::orchestrator
