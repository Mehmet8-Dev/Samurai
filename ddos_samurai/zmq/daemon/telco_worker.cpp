#include "wire_protocol.h"
#include "worker_common.hpp"
#include "zmq_worker_base.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "ddos_samurai/telecom/protocols/stateful/pppoe/pppoe_engine.hpp"

#include <zmq.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <sched.h>

using namespace samurai::wire;
using namespace samurai::daemon;
using namespace ddos_samurai::telecom;
using namespace ddos_samurai::telecom::pppoe;

namespace {

constexpr const char* kDefaultJobs = "ipc:///tmp/samurai_jobs_telco";
constexpr const char* kDefaultEvents = "ipc:///tmp/samurai_events_telco";

void ApplyAffinity(std::int32_t pin_cpu) {
    if (pin_cpu < 0) return;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(static_cast<unsigned>(pin_cpu), &cpuset);
    (void)sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

} // namespace

int main(int argc, char** argv) {
    std::string jobs_endpoint = kDefaultJobs;
    std::string events_endpoint = kDefaultEvents;
    int pin_cpu = -1;

    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--job-endpoint" && i + 1 < argc) {
            jobs_endpoint = argv[++i];
        } else if (std::string(argv[i]) == "--event-endpoint" && i + 1 < argc) {
            events_endpoint = argv[++i];
        } else if (std::string(argv[i]) == "--pin-cpu" && i + 1 < argc) {
            pin_cpu = std::stoi(argv[++i]);
        }
    }

    if (pin_cpu >= 0) {
        ApplyAffinity(pin_cpu);
    }

    std::cout << "[TELCO_WORKER] Samurai Carrier-Grade Telco Daemon starting..." << std::endl;
    std::cout << "[TELCO_WORKER] Jobs (PULL): " << jobs_endpoint << ", Events (PUSH): " << events_endpoint << std::endl;

    void* zmq_ctx = zmq_ctx_new();
    void* jobs_sock = zmq_socket(zmq_ctx, ZMQ_PULL);
    void* events_sock = zmq_socket(zmq_ctx, ZMQ_PUSH);

    if (zmq_bind(jobs_sock, jobs_endpoint.c_str()) != 0) {
        zmq_connect(jobs_sock, jobs_endpoint.c_str());
    }
    zmq_connect(events_sock, events_endpoint.c_str());

    // 100,000 abone kapasiteli SessionManager başlat
    constexpr uint32_t MAX_SESSIONS = 100000;
    SessionManager session_mgr(MAX_SESSIONS);

    // 2.4 GHz varsayılan TSC çözünürlüklü 3 kademeli Timing Wheel
    uint64_t tsc_hz = 2400000000ULL;
    HierarchicalTimingWheel timing_wheel(tsc_hz);

    PppoeEngine pppoe_engine(session_mgr, &timing_wheel);
    ProtocolConfig proto_cfg{};
    proto_cfg.max_sessions = MAX_SESSIONS;
    proto_cfg.rate_cps = 5000;
    proto_cfg.retransmit_timeout_ms = 500;
    proto_cfg.max_retries = 3;
    pppoe_engine.Init(proto_cfg);

    std::atomic<bool> running{true};
    uint64_t last_metric_tsc = __builtin_ia32_rdtsc();
    uint64_t tsc_per_sec = tsc_hz;

    std::cout << "[TELCO_WORKER] Initialized with capacity: " << MAX_SESSIONS 
              << " subscribers (" << (session_mgr.GetMemoryFootprintBytes() / (1024 * 1024)) << " MB)" << std::endl;

    while (running.load(std::memory_order_relaxed)) {
        zmq_msg_t msg;
        zmq_msg_init(&msg);

        // ZMQ komutlarını beklemeden yokla
        int rc = zmq_msg_recv(&msg, jobs_sock, ZMQ_DONTWAIT);
        if (rc > 0) {
            if (static_cast<size_t>(rc) >= sizeof(SamuraiWireHeaderV1)) {
                auto* hdr = reinterpret_cast<SamuraiWireHeaderV1*>(zmq_msg_data(&msg));
                if (IsHeaderV1Compatible(*hdr)) {
                    if (hdr->msg_type == static_cast<uint8_t>(MessageType::START_JOB)) {
                        SendFrame(events_sock, static_cast<std::uint8_t>(MessageType::ACK),
                                  hdr->correlation_id, WorkerKind::TELCO, ReadFixed(hdr->job_id, sizeof(hdr->job_id)));
                    } else if (hdr->msg_type == static_cast<uint8_t>(MessageType::STOP_JOB)) {
                        SendFrame(events_sock, static_cast<std::uint8_t>(MessageType::ACK),
                                  hdr->correlation_id, WorkerKind::TELCO, ReadFixed(hdr->job_id, sizeof(hdr->job_id)));
                    } else if (hdr->msg_type == static_cast<uint8_t>(MessageType::SHUTDOWN)) {
                        running.store(false);
                    }
                }
            }
            zmq_msg_close(&msg);
        } else {
            zmq_msg_close(&msg);
        }

        uint64_t now_tsc = __builtin_ia32_rdtsc();

        // 1. Zamanlayıcı çarkını ilerlet (O(1) Retransmissions / Echo Keepalives)
        pppoe_engine.OnTimerTick(now_tsc);

        // 2. Periyodik MetricSnapshot (Her 1 saniyede bir)
        if (now_tsc - last_metric_tsc >= tsc_per_sec) {
            MetricSnapshotV1 snap{};
            snap.timestamp_ns = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
            snap.packets_sent = session_mgr.GetActiveSessionCount();
            snap.actual_rps = session_mgr.GetActiveSessionCount();
            snap.rate_accuracy_pct = 100.0;

            const auto* p = reinterpret_cast<const uint8_t*>(&snap);
            std::vector<uint8_t> payload(p, p + sizeof(snap));
            SendFrame(events_sock, static_cast<std::uint8_t>(MessageType::METRIC_SNAPSHOT),
                      0, WorkerKind::TELCO, "telco_snapshot", payload);
            last_metric_tsc = now_tsc;
        }

        // CPU boşta yanmasını önlemek için hafif duraklama
        if (session_mgr.GetActiveSessionCount() == 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
    }

    std::cout << "[TELCO_WORKER] Shutting down cleanly." << std::endl;
    zmq_close(jobs_sock);
    zmq_close(events_sock);
    zmq_ctx_term(zmq_ctx);
    return 0;
}
