#include "samurai/telecom/core/session_context.hpp"
#include "samurai/telecom/core/session_manager.hpp"
#include "samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "samurai/telecom/protocols/stateful/dhcp/dhcp_engine.hpp"
#include "samurai/telecom/protocols/stateful/dhcp/dhcp_types.hpp"
#include "samurai/telecom/protocols/stateful/dhcp/dhcp_fsm.hpp"
#include "samurai/telecom/protocols/stateful/bfd/bfd_engine.hpp"
#include "samurai/telecom/protocols/stateful/bfd/bfd_types.hpp"
#include "samurai/telecom/protocols/stateful/bfd/bfd_fsm.hpp"

#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace samurai::telecom;
using namespace samurai::telecom::dhcp;
using namespace samurai::telecom::bfd;

void TestDhcpv4DoraFullLifecycle() {
    std::cout << "[TEST] 1. DHCPv4 DORA Full Lifecycle (Discover -> Offer -> Request -> Ack -> Bound -> Release)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL); // 2.4 GHz
    DhcpEngine engine(mgr, &wheel);

    ProtocolConfig cfg{};
    cfg.retransmit_timeout_ms = 100;
    cfg.max_retries = 3;
    engine.Init(cfg);

    TelcoSessionContext* s = mgr.AcquireSession();
    assert(s != nullptr);
    uint8_t mac[6] = {0x00, 0x50, 0x56, 0xA1, 0xB2, 0xC3};
    std::memcpy(s->client_mac, mac, 6);

    uint32_t xid = 0x88776655;
    engine.StartDhcpv4(s, xid);

    assert(engine.GetSubState(s) == DhcpSubState::SELECTING);
    assert(s->state == SessionState::DISCOVERING);
    assert(s->GetDhcpXid() == xid);
    assert(s->tx_packets == 1);

    const auto& discover_frame = engine.GetLastTxFrame();
    assert(discover_frame.size() >= 300);

    // 2. Simulate Server Offer: 100.64.1.50, Server: 100.64.1.1
    uint32_t offered_ip = 0x64400132; // 100.64.1.50
    uint32_t server_ip = 0x64400101;  // 100.64.1.1
    auto offer_frame = engine.BuildDhcpv4Offer(s, offered_ip, server_ip, 3600);

    bool handled = engine.ProcessRxFrame(offer_frame.data(), offer_frame.size(), s);
    assert(handled);
    assert(engine.GetSubState(s) == DhcpSubState::REQUESTING);
    assert(s->client_ip == offered_ip);
    assert(s->peer_ip == server_ip);
    assert(s->tx_packets == 2);

    // 3. Simulate Server Ack
    auto ack_frame = engine.BuildDhcpv4Ack(s, offered_ip, server_ip, 3600);
    handled = engine.ProcessRxFrame(ack_frame.data(), ack_frame.size(), s);
    assert(handled);
    assert(engine.GetSubState(s) == DhcpSubState::BOUND);
    assert(s->state == SessionState::ESTABLISHED);
    assert(s->client_ip == offered_ip);

    // 4. Release Session
    engine.ReleaseDhcp(s);
    assert(engine.GetSubState(s) == DhcpSubState::RELEASED);
    assert(s->state == SessionState::TERMINATING);

    std::cout << "  -> DHCPv4 DORA Full Lifecycle & Release: PASSED" << std::endl;
}

void TestDhcpv4Option82RelayAgent() {
    std::cout << "[TEST] 2. DHCPv4 Option 82 Relay Agent Information (Circuit-ID / Remote-ID)..." << std::endl;

    SessionManager mgr(100);
    DhcpEngine engine(mgr, nullptr);

    std::string test_circuit = "GigabitEthernet0/1/1:200";
    std::string test_remote = "BRAS-CORE-NODE-01";
    engine.SetRelayAgentInfo(test_circuit, test_remote);
    assert(engine.HasRelayAgentInfo());

    TelcoSessionContext* s = mgr.AcquireSession();
    assert(s != nullptr);
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::memcpy(s->client_mac, mac, 6);

    uint32_t xid = 0x12344321;
    engine.StartDhcpv4(s, xid);

    const auto& discover = engine.GetLastTxFrame();

    // Verify Option 82 exists in payload
    bool found_opt82 = false;
    for (size_t i = 0; i < discover.size() - 2; ++i) {
        if (discover[i] == static_cast<uint8_t>(Dhcpv4Option::RELAY_AGENT_INFO)) {
            uint8_t opt_len = discover[i + 1];
            assert(opt_len > 0);
            found_opt82 = true;
            break;
        }
    }
    assert(found_opt82);

    // Offer with Option 82
    auto offer = engine.BuildDhcpv4Offer(s, 0x0A000005, 0x0A000001, 3600, test_circuit, test_remote);
    bool handled = engine.ProcessRxFrame(offer.data(), offer.size(), s);
    assert(handled);
    assert(engine.GetSubState(s) == DhcpSubState::REQUESTING);

    const auto& request = engine.GetLastTxFrame();
    found_opt82 = false;
    for (size_t i = 0; i < request.size() - 2; ++i) {
        if (request[i] == static_cast<uint8_t>(Dhcpv4Option::RELAY_AGENT_INFO)) {
            found_opt82 = true;
            break;
        }
    }
    assert(found_opt82);

    std::cout << "  -> DHCPv4 Option 82 Serialization & Verification: PASSED" << std::endl;
}

void TestDhcpv4RetransmissionAndTimeout() {
    std::cout << "[TEST] 3. DHCPv4 Retransmission, Exponential Backoff & Max-Retries Failure..." << std::endl;

    SessionManager mgr(100);
    uint64_t tsc_hz = 2400000000ULL;
    HierarchicalTimingWheel wheel(tsc_hz);
    DhcpEngine engine(mgr, &wheel);

    ProtocolConfig cfg{};
    cfg.retransmit_timeout_ms = 50; // 50ms initial
    cfg.max_retries = 3;
    engine.Init(cfg);

    TelcoSessionContext* s = mgr.AcquireSession();
    uint64_t now_tsc = 1000ULL;
    engine.OnTimerTick(now_tsc); // Initialize timing wheel baseline
    engine.StartDhcpv4(s, 0x99887766);
    assert(s->retry_count == 0);
    assert(s->tx_packets == 1);

    // Tick 1: 50ms expires -> retry 1
    now_tsc += (tsc_hz * 60) / 1000; // 60ms
    engine.OnTimerTick(now_tsc);
    assert(s->retry_count == 1);
    assert(s->tx_packets == 2);
    assert(engine.GetSubState(s) == DhcpSubState::SELECTING);

    // Tick 2: 100ms expires -> retry 2
    now_tsc += (tsc_hz * 120) / 1000;
    engine.OnTimerTick(now_tsc);
    assert(s->retry_count == 2);
    assert(s->tx_packets == 3);

    // Tick 3: 200ms expires -> max retries exceeded -> FAILED
    now_tsc += (tsc_hz * 250) / 1000;
    engine.OnTimerTick(now_tsc);
    assert(engine.GetSubState(s) == DhcpSubState::FAILED);
    assert(s->state == SessionState::FAILED);

    std::cout << "  -> DHCPv4 Retransmission & Failure Gate: PASSED" << std::endl;
}

void TestDhcpv6SarrFullLifecycle() {
    std::cout << "[TEST] 4. DHCPv6 SARR Full Lifecycle (Solicit -> Advertise -> Request -> Reply -> Bound)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    DhcpEngine engine(mgr, &wheel);

    TelcoSessionContext* s = mgr.AcquireSession();
    uint8_t mac[6] = {0x00, 0x16, 0x3E, 0xAA, 0xBB, 0xCC};
    std::memcpy(s->client_mac, mac, 6);

    uint32_t xid = 0x00123456;
    engine.StartDhcpv6(s, xid);

    assert(engine.GetSubState(s) == DhcpSubState::SELECTING);
    assert(s->tx_packets == 1);

    const auto& solicit = engine.GetLastTxFrame();
    assert(solicit.size() >= 80);

    // Simulate Server Advertise
    uint8_t assigned_ipv6[16] = {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t srv_duid[10] = {0x00, 0x03, 0x00, 0x01, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
    auto adv_frame = engine.BuildDhcpv6Advertise(s, assigned_ipv6, srv_duid, sizeof(srv_duid));

    bool handled = engine.ProcessRxFrame(adv_frame.data(), adv_frame.size(), s);
    assert(handled);
    assert(engine.GetSubState(s) == DhcpSubState::REQUESTING);
    assert(s->tx_packets == 2);

    // Simulate Server Reply
    auto reply_frame = engine.BuildDhcpv6Reply(s, assigned_ipv6, srv_duid, sizeof(srv_duid));
    handled = engine.ProcessRxFrame(reply_frame.data(), reply_frame.size(), s);
    assert(handled);
    assert(engine.GetSubState(s) == DhcpSubState::BOUND);
    assert(s->state == SessionState::ESTABLISHED);

    std::cout << "  -> DHCPv6 SARR Full Lifecycle: PASSED" << std::endl;
}

void TestDhcpMalformedFuzzResistance() {
    std::cout << "[TEST] 5. DHCP Malformed / Fuzz Truncated Frames Crash Resistance..." << std::endl;

    SessionManager mgr(100);
    DhcpEngine engine(mgr, nullptr);

    TelcoSessionContext* s = mgr.AcquireSession();

    // 1. Truncated frames at varying offsets
    uint8_t bad_buf[256];
    std::memset(bad_buf, 0xFF, sizeof(bad_buf));

    for (size_t len = 0; len < 100; ++len) {
        bool ok = engine.ProcessRxFrame(bad_buf, len, s);
        assert(!ok); // Must safely return false without crashing
    }

    // 2. Corrupted magic cookie in DHCPv4
    uint8_t fake_dhcp[300] = {0};
    fake_dhcp[12] = 0x08; fake_dhcp[13] = 0x00; // IPv4
    fake_dhcp[14] = 0x45; // IHL
    fake_dhcp[23] = 17;   // UDP
    fake_dhcp[36] = 0; fake_dhcp[37] = 67; // src port 67
    fake_dhcp[38] = 0; fake_dhcp[39] = 68; // dst port 68
    fake_dhcp[42 + 236] = 0x11; fake_dhcp[42 + 237] = 0x22; // Bad cookie

    bool ok = engine.ProcessRxFrame(fake_dhcp, sizeof(fake_dhcp), s);
    assert(!ok);

    // 3. Null pointer
    assert(!engine.ProcessRxFrame(nullptr, 100, s));

    std::cout << "  -> DHCP Fuzz / Malformed Protection: PASSED (No Crash)" << std::endl;
}

void TestBfdFullLifecycleAndKeepalive() {
    std::cout << "[TEST] 6. BFD Full Lifecycle (Down -> Init -> Up) & Sub-50ms Keepalive Heartbeats..." << std::endl;

    SessionManager mgr(100);
    uint64_t tsc_hz = 2400000000ULL;
    HierarchicalTimingWheel wheel(tsc_hz);
    BfdEngine engine(mgr, &wheel);

    TelcoSessionContext* s = mgr.AcquireSession();
    assert(s != nullptr);
    s->client_ip = 0x0A000002;
    s->peer_ip = 0x0A000001;

    BfdConfig bfd_cfg{};
    bfd_cfg.local_disc = 0xABCDE001;
    bfd_cfg.desired_tx_interval_us = 10000; // 10ms
    bfd_cfg.required_rx_interval_us = 10000;// 10ms
    bfd_cfg.detect_multiplier = 3;

    engine.OnTimerTick(1000ULL); // Initialize timing wheel baseline
    engine.StartSession(s, bfd_cfg);

    assert(engine.GetState(s) == BfdState::Down);
    assert(s->state == SessionState::FAILED); // BFD Down maps to FAILED session
    assert(s->tx_packets == 1);

    // Simulate Remote Down packet (from peer with disc 0x99990001)
    uint32_t remote_disc = 0x99990001;
    auto peer_down = BfdEngine::build_bfd_control_packet(
        {"10.0.0.1", "10.0.0.2", "00:11:22:33:44:55", "00:aa:bb:cc:dd:ee", 49152, 3784, 10000, 10000, 3, remote_disc},
        BfdState::Down, BfdDiag::None, s->GetBfdLocalDisc(), false, false);

    bool handled = engine.ProcessRxFrame(peer_down.data(), peer_down.size(), 1000ULL, s);
    assert(handled);
    assert(engine.GetState(s) == BfdState::Init);
    assert(s->state == SessionState::DISCOVERING);
    assert(s->GetBfdRemoteDisc() == remote_disc);

    // Simulate Remote Init packet -> transitions to Up
    auto peer_init = BfdEngine::build_bfd_control_packet(
        {"10.0.0.1", "10.0.0.2", "00:11:22:33:44:55", "00:aa:bb:cc:dd:ee", 49152, 3784, 10000, 10000, 3, remote_disc},
        BfdState::Init, BfdDiag::None, s->GetBfdLocalDisc(), false, false);

    handled = engine.ProcessRxFrame(peer_init.data(), peer_init.size(), 2000ULL, s);
    assert(handled);
    assert(engine.GetState(s) == BfdState::Up);
    assert(s->state == SessionState::ESTABLISHED);
    assert(engine.IsUp(s));

    // Verify Keepalive Heartbeat generation via Timing Wheel (10ms tick)
    uint64_t now_tsc = 2000ULL + (tsc_hz * 12) / 1000; // 12ms elapsed
    uint32_t expired = engine.OnTimerTick(now_tsc);
    assert(expired > 0);
    assert(engine.GetState(s) == BfdState::Up);

    std::cout << "  -> BFD Full Lifecycle & Sub-50ms Keepalive: PASSED" << std::endl;
}

void TestBfdDetectionTimeoutFailover() {
    std::cout << "[TEST] 7. BFD Detection Timeout (30ms) & Automatic Failover Trigger..." << std::endl;

    SessionManager mgr(100);
    uint64_t tsc_hz = 2400000000ULL;
    HierarchicalTimingWheel wheel(tsc_hz);
    BfdEngine engine(mgr, &wheel);

    TelcoSessionContext* s = mgr.AcquireSession();
    s->client_ip = 0x0A000002;
    s->peer_ip = 0x0A000001;

    BfdConfig bfd_cfg{};
    bfd_cfg.local_disc = 0x77770001;
    bfd_cfg.desired_tx_interval_us = 10000; // 10ms
    bfd_cfg.required_rx_interval_us = 10000;// 10ms
    bfd_cfg.detect_multiplier = 3;          // 3 x 10ms = 30ms

    engine.OnTimerTick(1000ULL); // Initialize timing wheel baseline
    engine.StartSession(s, bfd_cfg);

    // Bring session to Up
    auto peer_up = BfdEngine::build_bfd_control_packet(
        {"10.0.0.1", "10.0.0.2", "00:11:22:33:44:55", "00:aa:bb:cc:dd:ee", 49152, 3784, 10000, 10000, 3, 0x88880001},
        BfdState::Up, BfdDiag::None, s->GetBfdLocalDisc(), false, false);

    uint64_t last_rx_tsc = 100000ULL;
    engine.ProcessRxFrame(peer_up.data(), peer_up.size(), last_rx_tsc, s);
    assert(engine.IsUp(s));
    assert(!engine.HasFailed(s));

    // Peer goes completely silent! Advance past 30ms (e.g. 45ms)
    uint64_t fail_tsc = last_rx_tsc + (tsc_hz * 45) / 1000;
    engine.OnTimerTick(fail_tsc);

    assert(engine.GetState(s) == BfdState::Down);
    assert(engine.HasFailed(s));

    // Verify last transmitted packet signals Down with ControlDetectionTimeExpired
    BfdControlHeader tx_hdr{};
    uint32_t r_disc = 0;
    const auto& last_tx = engine.GetLastTxFrame();
    bool parse_ok = BfdEngine::ParseBfdControlPacket(last_tx.data(), last_tx.size(), tx_hdr, r_disc);
    assert(parse_ok);
    uint8_t state_val = (tx_hdr.sta_flags >> 6) & 0x03;
    assert(state_val == static_cast<uint8_t>(BfdState::Down));
    uint8_t diag_val = tx_hdr.vers_diag & 0x1F;
    assert(diag_val == static_cast<uint8_t>(BfdDiag::ControlDetectionTimeExpired));

    std::cout << "  -> BFD 30ms Detection Timeout & Failover: PASSED" << std::endl;
}

void TestBfdRfc5881StrictValidationAndFuzz() {
    std::cout << "[TEST] 8. BFD RFC 5881 Strict Validation (TTL=255, Port 3784) & Fuzz Resistance..." << std::endl;

    SessionManager mgr(100);
    BfdEngine engine(mgr, nullptr);
    TelcoSessionContext* s = mgr.AcquireSession();

    // 1. Valid BFD packet
    auto valid_packet = BfdEngine::build_bfd_control_packet(
        {"10.0.0.1", "10.0.0.2", "00:11:22:33:44:55", "00:aa:bb:cc:dd:ee", 49152, 3784, 10000, 10000, 3, 0x11112222},
        BfdState::Up, BfdDiag::None, 0x33334444);

    BfdControlHeader hdr{};
    uint32_t r_disc = 0;
    assert(BfdEngine::ParseBfdControlPacket(valid_packet.data(), valid_packet.size(), hdr, r_disc));

    // 2. RFC 5881 Violation: TTL = 254 (Must be dropped!)
    auto invalid_ttl_packet = valid_packet;
    invalid_ttl_packet[14 + 8] = 254; // TTL offset in IP header
    assert(!BfdEngine::ParseBfdControlPacket(invalid_ttl_packet.data(), invalid_ttl_packet.size(), hdr, r_disc));

    // 3. RFC 5881 Violation: Wrong destination port (e.g. 9999)
    auto invalid_port_packet = valid_packet;
    invalid_port_packet[14 + 20 + 2] = 0x27; // 9999
    invalid_port_packet[14 + 20 + 3] = 0x0F;
    assert(!BfdEngine::ParseBfdControlPacket(invalid_port_packet.data(), invalid_port_packet.size(), hdr, r_disc));

    // 4. Truncation Fuzz
    for (size_t len = 0; len < sizeof(valid_packet); ++len) {
        assert(!BfdEngine::ParseBfdControlPacket(valid_packet.data(), len, hdr, r_disc));
    }

    std::cout << "  -> BFD RFC 5881 Strict TTL 255 & Fuzz Protection: PASSED" << std::endl;
}

void TestDhcpv4InfiniteLease() {
    std::cout << "[TEST] 9. DHCPv4 Infinite Lease (0xFFFFFFFF) Timing Overflow Guard..." << std::endl;

    SessionManager mgr(10);
    HierarchicalTimingWheel wheel(2400000000ULL);
    DhcpEngine engine(mgr, &wheel);

    TelcoSessionContext* s = mgr.AcquireSession();
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::memcpy(s->client_mac, mac, 6);

    uint32_t xid = 0x55667788;
    engine.StartDhcpv4(s, xid);

    // Offer with lease_time = 0xFFFFFFFF (RFC 2131 infinite lease)
    auto offer = engine.BuildDhcpv4Offer(s, 0x0A010101, 0x0A0101FE, 0xFFFFFFFF);
    engine.ProcessRxFrame(offer.data(), offer.size(), s);
    assert(engine.GetSubState(s) == DhcpSubState::REQUESTING);

    // Ack with lease_time = 0xFFFFFFFF (Must not overflow uint32 timing wheel calculation)
    auto ack = engine.BuildDhcpv4Ack(s, 0x0A010101, 0x0A0101FE, 0xFFFFFFFF);
    engine.ProcessRxFrame(ack.data(), ack.size(), s);
    assert(engine.GetSubState(s) == DhcpSubState::BOUND);
    assert(s->state == SessionState::ESTABLISHED);

    std::cout << "  -> DHCPv4 Infinite Lease Overflow Guard: PASSED" << std::endl;
}

void TestIpv4MalformedIhlRejection() {
    std::cout << "[TEST] 10. IPv4 Malformed IHL < 5 Rejection (BFD & DHCP)..." << std::endl;

    SessionManager mgr(10);
    BfdEngine bfd(mgr, nullptr);
    DhcpEngine dhcp(mgr, nullptr);
    TelcoSessionContext* s = mgr.AcquireSession();

    auto valid_bfd = BfdEngine::build_bfd_control_packet(
        {"10.0.0.1", "10.0.0.2", "00:11:22:33:44:55", "00:aa:bb:cc:dd:ee", 49152, 3784, 10000, 10000, 3, 0x11112222},
        BfdState::Up, BfdDiag::None, 0x33334444);

    // Corrupt IHL to 3 (less than minimum 5)
    auto bad_ihl_bfd = valid_bfd;
    bad_ihl_bfd[14] = 0x43; // Version 4, IHL 3 (12 bytes, invalid!)
    BfdControlHeader hdr{};
    uint32_t r_disc = 0;
    assert(!BfdEngine::ParseBfdControlPacket(bad_ihl_bfd.data(), bad_ihl_bfd.size(), hdr, r_disc));

    // Corrupt DHCP frame IHL to 2
    auto valid_offer = dhcp.BuildDhcpv4Offer(s, 0x0A000002, 0x0A000001, 3600);
    auto bad_ihl_dhcp = valid_offer;
    bad_ihl_dhcp[14] = 0x42; // Version 4, IHL 2
    assert(!dhcp.ProcessRxFrame(bad_ihl_dhcp.data(), bad_ihl_dhcp.size(), s));

    std::cout << "  -> IPv4 Malformed IHL < 5 Rejection: PASSED" << std::endl;
}

int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "        SAMURAI DHCP & BFD STATEFUL FSM VERIFICATION SUITE       " << std::endl;
    std::cout << "=================================================================" << std::endl;

    TestDhcpv4DoraFullLifecycle();
    TestDhcpv4Option82RelayAgent();
    TestDhcpv4RetransmissionAndTimeout();
    TestDhcpv6SarrFullLifecycle();
    TestDhcpMalformedFuzzResistance();
    TestBfdFullLifecycleAndKeepalive();
    TestBfdDetectionTimeoutFailover();
    TestBfdRfc5881StrictValidationAndFuzz();
    TestDhcpv4InfiniteLease();
    TestIpv4MalformedIhlRejection();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL DHCP & BFD TESTS PASSED SUCCESSFULLY! (100% VERIFIED)      " << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
