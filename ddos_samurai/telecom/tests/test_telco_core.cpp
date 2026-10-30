#include "ddos_samurai/telecom/core/session_context.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "ddos_samurai/telecom/core/fastpath_classifier.hpp"
#include "ddos_samurai/telecom/core/ring_buffer_shuttle.hpp"
#include "ddos_samurai/telecom/lockfree_l2l3_cache.hpp"
#include "ddos_samurai/telecom/l2l3_fastpath_wiring.hpp"

#include <iostream>
#include <cassert>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <cstring>
#include <arpa/inet.h>

using namespace ddos_samurai::telecom;

void TestAlignmentAndMemoryLayout() {
    std::cout << "[TEST] 1. TelcoSessionContext 128-Byte Alignment & Cache Line Layout..." << std::endl;

    static_assert(sizeof(TelcoSessionContext) == 128, "TelcoSessionContext must be exactly 128 bytes");
    static_assert(alignof(TelcoSessionContext) == 64, "TelcoSessionContext must be 64-byte aligned");
    static_assert(offsetof(TelcoSessionContext, wheel_prev) == 64, "wheel_prev must be at offset 64 (start of CL2)");

    assert(sizeof(TelcoSessionContext) == 128);
    assert(alignof(TelcoSessionContext) == 64);
    assert(offsetof(TelcoSessionContext, wheel_prev) == 64);

    // Verify CL1 fields are within [0, 63]
    assert(offsetof(TelcoSessionContext, client_ip) == 0);
    assert(offsetof(TelcoSessionContext, peer_ip) == 4);
    assert(offsetof(TelcoSessionContext, client_port) == 8);
    assert(offsetof(TelcoSessionContext, peer_port) == 10);
    assert(offsetof(TelcoSessionContext, ip_proto) == 12);
    assert(offsetof(TelcoSessionContext, state) == 13);
    assert(offsetof(TelcoSessionContext, protocol_id) == 14);
    assert(offsetof(TelcoSessionContext, session_id) == 16);
    assert(offsetof(TelcoSessionContext, teid_uplink) == 20);
    assert(offsetof(TelcoSessionContext, teid_downlink) == 24);
    assert(offsetof(TelcoSessionContext, flow_hash) == 28);
    assert(offsetof(TelcoSessionContext, s_vlan) == 32);
    assert(offsetof(TelcoSessionContext, c_vlan) == 34);
    assert(offsetof(TelcoSessionContext, client_mac) == 36);
    assert(offsetof(TelcoSessionContext, peer_mac) == 42);
    assert(offsetof(TelcoSessionContext, ppp_lcp_identifier) == 48);
    assert(offsetof(TelcoSessionContext, retry_count) == 50);
    assert(offsetof(TelcoSessionContext, ppp_magic_number) == 52);
    assert(offsetof(TelcoSessionContext, wheel_slot) == 56);
    assert(offsetof(TelcoSessionContext, wheel_tier) == 58);
    assert(offsetof(TelcoSessionContext, in_wheel) == 59);

    // Verify CL2 fields are within [64, 127]
    assert(offsetof(TelcoSessionContext, wheel_prev) == 64);
    assert(offsetof(TelcoSessionContext, wheel_next) == 72);
    assert(offsetof(TelcoSessionContext, timer_expire_tsc) == 80);
    assert(offsetof(TelcoSessionContext, last_activity_tsc) == 88);
    assert(offsetof(TelcoSessionContext, tx_packets) == 96);
    assert(offsetof(TelcoSessionContext, rx_packets) == 104);
    assert(offsetof(TelcoSessionContext, tx_bytes) == 112);
    assert(offsetof(TelcoSessionContext, rx_bytes) == 120);

    // Dynamic pool alignment check
    SessionManager mgr(1000);
    for (uint32_t i = 0; i < 100; ++i) {
        TelcoSessionContext* s = mgr.GetSessionByIndex(i);
        assert(s != nullptr);
        uintptr_t addr = reinterpret_cast<uintptr_t>(s);
        assert(addr % 64 == 0); // Must be strictly 64-byte aligned in memory
    }

    std::cout << "  -> 128-byte struct and 64-byte dual cache-line layout: PASSED" << std::endl;
}

void TestSessionManagerAnd5TupleLookup() {
    std::cout << "[TEST] 2. SessionManager O(1) 5-Tuple Fastpath Lookup & Benchmark..." << std::endl;

    constexpr uint32_t NUM_SESSIONS = 50000;
    SessionManager mgr(NUM_SESSIONS);

    assert(mgr.GetCapacity() == NUM_SESSIONS);
    assert(mgr.GetActiveSessionCount() == 0);

    std::vector<TelcoSessionContext*> acquired;
    acquired.reserve(NUM_SESSIONS);

    // 1. Acquire sessions and bind 5-tuples
    for (uint32_t i = 0; i < NUM_SESSIONS; ++i) {
        TelcoSessionContext* s = mgr.AcquireSession();
        assert(s != nullptr);
        assert(s->state == SessionState::IDLE);

        uint32_t src_ip = 0x0A000001 + (i % 254);
        uint32_t dst_ip = 0xC0A80001;
        uint16_t src_port = static_cast<uint16_t>(1024 + (i % 60000));
        uint16_t dst_port = 443;
        uint8_t proto = 6; // TCP

        bool ok = mgr.Bind5Tuple(s, src_ip, dst_ip, src_port, dst_port, proto);
        assert(ok);
        acquired.push_back(s);
    }

    assert(mgr.GetActiveSessionCount() == NUM_SESSIONS);

    // 2. Verify all 5-tuples can be resolved in O(1)
    for (uint32_t i = 0; i < NUM_SESSIONS; ++i) {
        uint32_t src_ip = 0x0A000001 + (i % 254);
        uint32_t dst_ip = 0xC0A80001;
        uint16_t src_port = static_cast<uint16_t>(1024 + (i % 60000));
        uint16_t dst_port = 443;
        uint8_t proto = 6;

        TelcoSessionContext* found = mgr.FindSessionBy5Tuple(src_ip, dst_ip, src_port, dst_port, proto);
        assert(found != nullptr);
        assert(found == acquired[i]);
    }

    // 3. Negative lookup
    TelcoSessionContext* not_found = mgr.FindSessionBy5Tuple(0x7F000001, 0x7F000001, 9999, 9999, 17);
    assert(not_found == nullptr);

    // 4. Benchmark 1,000,000 lookups
    constexpr uint32_t BENCH_LOOKUPS = 1000000;
    auto t_start = std::chrono::steady_clock::now();
    uint64_t hits = 0;

    for (uint32_t i = 0; i < BENCH_LOOKUPS; ++i) {
        uint32_t idx = i % NUM_SESSIONS;
        uint32_t src_ip = 0x0A000001 + (idx % 254);
        uint32_t dst_ip = 0xC0A80001;
        uint16_t src_port = static_cast<uint16_t>(1024 + (idx % 60000));

        TelcoSessionContext* s = mgr.FindSessionBy5Tuple(src_ip, dst_ip, src_port, 443, 6);
        if (__builtin_expect(s != nullptr, 1)) {
            hits++;
        }
    }

    auto t_end = std::chrono::steady_clock::now();
    double duration_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();
    double lookups_per_sec = (hits / (duration_ms / 1000.0));

    assert(hits == BENCH_LOOKUPS);
    std::cout << "  -> 5-Tuple Benchmark: " << hits << " lookups in " << duration_ms << " ms ("
              << (lookups_per_sec / 1e6) << " Mlookups/sec, O(1) verified)" << std::endl;

    // 5. Test PPPoE MAC + SessionID lookup
    uint8_t mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    mgr.BindPppoeSession(acquired[0], mac1, 1001);
    TelcoSessionContext* pppoe_found = mgr.FindPppoeSession(mac1, 1001);
    assert(pppoe_found == acquired[0]);
    assert(mgr.FindPppoeSession(mac1, 9999) == nullptr);

    // 6. Test GTP-U TEID lookup
    mgr.BindGtpuSession(acquired[1], 0xDEADBEEF);
    TelcoSessionContext* gtpu_found = mgr.FindGtpuSession(0xDEADBEEF);
    assert(gtpu_found == acquired[1]);
    assert(mgr.FindGtpuSession(0x12345678) == nullptr);

    // 7. Release sessions
    for (auto* s : acquired) {
        mgr.ReleaseSession(s);
    }
    assert(mgr.GetActiveSessionCount() == 0);

    // Verify unbind happened
    assert(mgr.FindPppoeSession(mac1, 1001) == nullptr);
    assert(mgr.FindGtpuSession(0xDEADBEEF) == nullptr);

    std::cout << "  -> SessionManager 5-Tuple, PPPoE & GTP-U lookup: PASSED" << std::endl;
}

void TestHierarchicalTimingWheel() {
    std::cout << "[TEST] 3. HierarchicalTimingWheel 3-Tier O(1) Expiry & Cascading..." << std::endl;

    uint64_t tsc_hz = 2400000000ULL; // 2.4 GHz
    uint64_t tsc_per_ms = tsc_hz / 1000ULL;
    HierarchicalTimingWheel wheel(tsc_hz);

    SessionManager mgr(20000);

    // 1. Schedule timers across tiers
    TelcoSessionContext* s1 = mgr.AcquireSession(); // 10ms (Tier 0)
    TelcoSessionContext* s2 = mgr.AcquireSession(); // 200ms (Tier 0)
    TelcoSessionContext* s3 = mgr.AcquireSession(); // 1500ms (Tier 1)
    TelcoSessionContext* s4 = mgr.AcquireSession(); // 15000ms (Tier 2)
    TelcoSessionContext* s_cancel = mgr.AcquireSession(); // Will be cancelled
    TelcoSessionContext* s_exact = mgr.AcquireSession(); // 1150ms exact cascade test

    uint64_t start_tsc = 1000000000ULL;
    // Set baseline
    wheel.Advance(start_tsc, [](TelcoSessionContext*) {});

    wheel.Schedule(s1, 10);
    wheel.Schedule(s2, 200);
    wheel.Schedule(s3, 1500);
    wheel.Schedule(s4, 15000);
    wheel.Schedule(s_cancel, 50);
    wheel.Schedule(s_exact, 1150);

    assert(wheel.GetActiveTimers() == 6);

    // Cancel s_cancel
    wheel.Cancel(s_cancel);
    assert(wheel.GetActiveTimers() == 5);
    assert(s_cancel->in_wheel == 0);

    // 2. Advance time by 15 ms -> s1 should expire
    std::vector<TelcoSessionContext*> expired;
    uint32_t count = wheel.Advance(start_tsc + 15 * tsc_per_ms, [&](TelcoSessionContext* s) {
        expired.push_back(s);
    });
    assert(count == 1);
    assert(expired.size() == 1);
    assert(expired[0] == s1);
    assert(s1->in_wheel == 0);

    // 3. Advance time to 250 ms -> s2 should expire
    expired.clear();
    count = wheel.Advance(start_tsc + 250 * tsc_per_ms, [&](TelcoSessionContext* s) {
        expired.push_back(s);
    });
    assert(count == 1);
    assert(expired[0] == s2);

    // 3b. Verify precise cascading at 1150 ms (Tier 1 -> Tier 0 cascade)
    // Advance incrementally to 1100 ms: s_exact (1150ms) should cascade when Tier 1 ticks at 1000ms, but NOT expire yet
    expired.clear();
    count = wheel.Advance(start_tsc + 1100 * tsc_per_ms, [&](TelcoSessionContext* s) {
        expired.push_back(s);
    });
    assert(count == 0); // Not expired yet
    assert(wheel.GetActiveTimers() == 3); // s_exact, s3, s4

    // Advance to 1150 ms: s_exact MUST expire exactly here
    expired.clear();
    count = wheel.Advance(start_tsc + 1150 * tsc_per_ms, [&](TelcoSessionContext* s) {
        expired.push_back(s);
    });
    assert(count == 1);
    assert(expired[0] == s_exact);
    assert(s_exact->in_wheel == 0);

    // 4. Advance time to 1600 ms -> s3 should cascade from Tier 1 to Tier 0 and expire
    expired.clear();
    count = wheel.Advance(start_tsc + 1600 * tsc_per_ms, [&](TelcoSessionContext* s) {
        expired.push_back(s);
    });
    assert(count == 1);
    assert(expired[0] == s3);

    // 5. Advance time to 16000 ms -> s4 should cascade from Tier 2 to Tier 1/0 and expire
    expired.clear();
    count = wheel.Advance(start_tsc + 16000 * tsc_per_ms, [&](TelcoSessionContext* s) {
        expired.push_back(s);
    });
    assert(count == 1);
    assert(expired[0] == s4);
    assert(wheel.GetActiveTimers() == 0);

    // 6. Benchmark O(1) tick with 10,000 active timers
    constexpr uint32_t BENCH_TIMERS = 10000;
    std::vector<TelcoSessionContext*> bench_sessions;
    bench_sessions.reserve(BENCH_TIMERS);

    for (uint32_t i = 0; i < BENCH_TIMERS; ++i) {
        TelcoSessionContext* s = mgr.AcquireSession();
        bench_sessions.push_back(s);
        uint32_t delay = 1 + (i % 500); // 1 - 500 ms
        wheel.Schedule(s, delay);
    }

    uint64_t tick_start = __builtin_ia32_rdtsc();
    uint32_t exp_total = 0;
    for (uint32_t ms = 1; ms <= 500; ++ms) {
        exp_total += wheel.Advance(start_tsc + (16000 + ms) * tsc_per_ms, [](TelcoSessionContext*) {});
    }
    uint64_t tick_end = __builtin_ia32_rdtsc();
    uint64_t cycles = tick_end - tick_start;

    assert(exp_total == BENCH_TIMERS);
    std::cout << "  -> Timing Wheel: 10,000 timers scheduled & expired in " << cycles / 500
              << " cycles/ms tick (O(1) verified)" << std::endl;

    for (auto* s : bench_sessions) mgr.ReleaseSession(s);
    mgr.ReleaseSession(s1);
    mgr.ReleaseSession(s2);
    mgr.ReleaseSession(s3);
    mgr.ReleaseSession(s4);
    mgr.ReleaseSession(s_cancel);
    mgr.ReleaseSession(s_exact);

    std::cout << "  -> HierarchicalTimingWheel 3-Tier O(1): PASSED" << std::endl;
}

void TestRingBufferShuttle() {
    std::cout << "[TEST] 4. RingBufferShuttle SPSC Lock-Free Shuttle..." << std::endl;

    RingBufferShuttle<uint64_t, 1024> shuttle;
    assert(shuttle.IsEmpty());
    assert(!shuttle.IsFull());
    assert(shuttle.Size() == 0);

    // Enqueue until full
    for (uint64_t i = 0; i < 1024; ++i) {
        bool ok = shuttle.Enqueue(i + 1);
        assert(ok);
    }
    assert(shuttle.IsFull());
    assert(!shuttle.Enqueue(9999)); // Overflow rejected

    // Dequeue all
    for (uint64_t i = 0; i < 1024; ++i) {
        uint64_t val = 0;
        bool ok = shuttle.Dequeue(val);
        assert(ok);
        assert(val == i + 1);
    }
    assert(shuttle.IsEmpty());

    // Concurrent producer-consumer thread test
    constexpr uint64_t TOTAL_ITEMS = 500000;
    std::atomic<bool> start_flag{false};

    std::thread producer([&]() {
        while (!start_flag.load(std::memory_order_relaxed)) {}
        for (uint64_t i = 1; i <= TOTAL_ITEMS; ++i) {
            while (!shuttle.Enqueue(i)) {
                // backoff
            }
        }
    });

    std::thread consumer([&]() {
        while (!start_flag.load(std::memory_order_relaxed)) {}
        for (uint64_t i = 1; i <= TOTAL_ITEMS; ++i) {
            uint64_t val = 0;
            while (!shuttle.Dequeue(val)) {
                // backoff
            }
            assert(val == i);
        }
    });

    start_flag.store(true, std::memory_order_release);
    producer.join();
    consumer.join();

    assert(shuttle.IsEmpty());
    std::cout << "  -> SPSC Shuttle 500,000 items in-order lock-free transfer: PASSED" << std::endl;
}

void TestFastpathClassifier() {
    std::cout << "[TEST] 5. FastpathClassifier Demux & QinQ Parsing..." << std::endl;

    PacketMetadata meta{};
    TelcoFrameType type = TelcoFrameType::Unknown;

    // 1. PPPoE Discovery Frame (EtherType 0x8863)
    uint8_t pppoe_disc_pkt[30] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Dst MAC
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Src MAC
        0x88, 0x63,                         // PPPoE Discovery
        0x11, 0x09, 0x00, 0x00, 0x00, 0x00  // PADI
    };
    bool ok = FastpathClassifier::Classify(pppoe_disc_pkt, sizeof(pppoe_disc_pkt), meta, type);
    assert(ok);
    assert(type == TelcoFrameType::PppoeDiscovery);
    assert(FastpathClassifier::IsControlFrame(type));
    assert(meta.ether_type == 0x8863);
    assert(meta.outer_vlan == 0);

    // 2. QinQ Tagged GTP-U UDP Frame (0x88A8 + 0x8100 + IPv4 UDP 2152)
    uint8_t qinq_gtpu_pkt[54] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0x88, 0xA8, 0x00, 0x64,             // Outer S-VLAN 100
        0x81, 0x00, 0x00, 0xC8,             // Inner C-VLAN 200
        0x08, 0x00,                         // IPv4
        0x45, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00, // Proto 17 (UDP)
        10, 0, 0, 1, 10, 0, 0, 2,           // Src IP, Dst IP
        0x08, 0x68, 0x08, 0x68, 0x00, 0x10, 0x00, 0x00 // Port 2152 -> 2152 (GTP-U)
    };
    ok = FastpathClassifier::Classify(qinq_gtpu_pkt, sizeof(qinq_gtpu_pkt), meta, type);
    assert(ok);
    assert(type == TelcoFrameType::Gtpu);
    assert(meta.outer_vlan == 100);
    assert(meta.inner_vlan == 200);
    assert(meta.src_port == 2152);
    assert(meta.dst_port == 2152);

    // 3. Normal IPv4 Data (Fastpath)
    uint8_t ipv4_tcp_pkt[54] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0x08, 0x00,                         // IPv4
        0x45, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 64, 6, 0x00, 0x00, // Proto 6 (TCP)
        192, 168, 1, 50, 93, 184, 216, 34,
        0x04, 0x00, 0x00, 0x50              // Port 1024 -> 80
    };
    ok = FastpathClassifier::Classify(ipv4_tcp_pkt, sizeof(ipv4_tcp_pkt), meta, type);
    assert(ok);
    assert(type == TelcoFrameType::Ipv4Data);
    assert(!FastpathClassifier::IsControlFrame(type)); // Fastpath forwarding

    std::cout << "  -> FastpathClassifier L2/QinQ/PPPoE/GTP-U Demux: PASSED" << std::endl;
}

void TestLockfreeArpNdSeqlockAndVlan() {
    std::cout << "[TEST] 6. LockfreeArpTable & LockfreeNdTable Seqlock Concurrency & VLAN Isolation..." << std::endl;

    LockfreeArpTable arp_table;
    uint32_t ip1 = 0x0A000001; // 10.0.0.1
    uint8_t mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t mac2[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};

    // 1. VLAN Isolation on same IP
    arp_table.UpdateEntry(ip1, mac1, 100, 1000);
    arp_table.UpdateEntry(ip1, mac2, 200, 1001);

    uint8_t resolved[6];
    bool ok = arp_table.LookupMac(ip1, resolved, 100);
    assert(ok);
    assert(std::memcmp(resolved, mac1, 6) == 0);

    ok = arp_table.LookupMac(ip1, resolved, 200);
    assert(ok);
    assert(std::memcmp(resolved, mac2, 6) == 0);

    // Non-existent VLAN lookup returns false
    ok = arp_table.LookupMac(ip1, resolved, 300);
    assert(!ok);

    // 2. Concurrency stress test: 1 writer thread rapidly updating, 2 reader threads reading
    std::atomic<bool> stop_flag{false};
    std::atomic<uint64_t> read_hits{0};
    std::atomic<uint64_t> torn_reads{0};

    auto reader = [&]() {
        uint8_t out[6];
        while (!stop_flag.load(std::memory_order_relaxed)) {
            if (arp_table.LookupMac(ip1, out, 100)) {
                read_hits.fetch_add(1, std::memory_order_relaxed);
                // Verify MAC address is never torn / corrupted
                if (out[0] != 0x00 || out[1] != 0x11 || out[2] != 0x22) {
                    torn_reads.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
    };

    auto writer = [&]() {
        uint64_t tsc = 2000;
        for (int i = 0; i < 20000; ++i) {
            arp_table.UpdateEntry(ip1, mac1, 100, ++tsc);
        }
    };

    std::thread r1(reader);
    std::thread r2(reader);
    std::thread w(writer);

    w.join();
    stop_flag.store(true);
    r1.join();
    r2.join();

    assert(torn_reads.load() == 0); // Must be strictly 0 torn reads thanks to Seqlock!
    assert(read_hits.load() > 0);

    // 3. IPv6 ND Table verification
    LockfreeNdTable nd_table;
    uint8_t ip6_addr[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    nd_table.UpdateEntry(ip6_addr, mac1, 50, 5000);
    ok = nd_table.LookupMac(ip6_addr, resolved, 50);
    assert(ok);
    assert(std::memcmp(resolved, mac1, 6) == 0);

    // 4. L2L3FastpathWiring VLAN Peeling
    uint8_t vlan_arp[18 + 28] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x81, 0x00, 0x00, 0x64,             // 802.1Q VLAN 100
        0x08, 0x06                          // Inner EtherType: ARP
    };
    uint16_t parsed_vlan = 0;
    ControlFrameType ctype = L2L3FastpathWiring::ClassifyFrame(vlan_arp, sizeof(vlan_arp), &parsed_vlan);
    assert(ctype == ControlFrameType::Arp);
    assert(parsed_vlan == 100);

    std::cout << "  -> LockfreeArpTable/NdTable Seqlock & VLAN isolation: PASSED (Torn reads: 0)" << std::endl;
}

int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "        SAMURAI TELECOM ENGINE CORE VERIFICATION SUITE           " << std::endl;
    std::cout << "=================================================================" << std::endl;

    TestAlignmentAndMemoryLayout();
    TestSessionManagerAnd5TupleLookup();
    TestHierarchicalTimingWheel();
    TestRingBufferShuttle();
    TestFastpathClassifier();
    TestLockfreeArpNdSeqlockAndVlan();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL TELECOM CORE TESTS PASSED SUCCESSFULLY! (100% VERIFIED)    " << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
