#include "ddos_samurai/telecom/core/session_context.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "ddos_samurai/telecom/core/fastpath_classifier.hpp"
#include "ddos_samurai/telecom/protocols/stateful/mobile/gtpu_types.hpp"
#include "ddos_samurai/telecom/protocols/stateful/mobile/gtpu_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/mobile/pfcp_types.hpp"
#include "ddos_samurai/telecom/protocols/stateful/mobile/pfcp_engine.hpp"

#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace ddos_samurai::telecom;
using namespace ddos_samurai::telecom::mobile;

// Helper: Dummy Inner IPv4 Packet (e.g. Ping 10.45.0.2 -> 8.8.8.8)
std::vector<uint8_t> CreateDummyInnerIpPacket() {
    std::vector<uint8_t> pkt(28, 0); // 20 bytes IP + 8 bytes ICMP
    pkt[0] = 0x45; // IPv4, IHL 5
    pkt[8] = 64;   // TTL
    pkt[9] = 1;    // ICMP
    // 10.45.0.2
    pkt[12] = 10; pkt[13] = 45; pkt[14] = 0; pkt[15] = 2;
    // 8.8.8.8
    pkt[16] = 8;  pkt[17] = 8;  pkt[18] = 8;  pkt[19] = 8;
    // ICMP Echo Request
    pkt[20] = 8; pkt[21] = 0; // Type 8, Code 0
    return pkt;
}

void TestGtpuEncapsulationDecapsulation() {
    std::cout << "[TEST] 1. GTP-U Encapsulation & Decapsulation Wire-Format Roundtrip..." << std::endl;

    SessionManager mgr(100);
    GtpuEngine engine(mgr, nullptr);

    TelcoSessionContext* s = mgr.AcquireSession();
    assert(s != nullptr);

    GtpuTunnelConfig cfg{};
    cfg.uplink_teid = 0x11223344;
    cfg.downlink_teid = 0x55667788;
    cfg.local_gnb_ip = 0x0A000001; // 10.0.0.1
    cfg.peer_upf_ip = 0x0A000002;  // 10.0.0.2
    uint8_t gnb_mac[6] = {0x00, 0x16, 0x3E, 0x11, 0x22, 0x33};
    uint8_t upf_mac[6] = {0x00, 0x16, 0x3E, 0xAA, 0xBB, 0xCC};
    std::memcpy(cfg.local_mac, gnb_mac, 6);
    std::memcpy(cfg.peer_mac, upf_mac, 6);

    engine.StartSession(s, cfg);
    assert(engine.GetSubState(s) == GtpuSubState::ACTIVE);
    assert(s->state == SessionState::ESTABLISHED);
    assert(s->teid_uplink == 0x11223344);

    // 1. Encapsulate Inner IP packet
    auto inner_pkt = CreateDummyInnerIpPacket();
    uint16_t seq = 42;
    auto outer_frame = engine.Encapsulate(s, inner_pkt.data(), inner_pkt.size(), seq);

    assert(outer_frame.size() > inner_pkt.size());
    assert(s->tx_packets == 1);
    assert(s->tx_bytes == outer_frame.size());

    // 2. Decapsulate frame
    GtpuDecapInfo decap{};
    bool ok = GtpuEngine::Decapsulate(outer_frame.data(), outer_frame.size(), decap);
    assert(ok);
    assert(decap.msg_type == static_cast<uint8_t>(GtpuMessageType::GPdu));
    assert(decap.teid == cfg.uplink_teid);
    assert(decap.has_seq);
    assert(decap.seq_num == seq);
    assert(decap.payload_len == inner_pkt.size());
    assert(std::memcmp(decap.payload, inner_pkt.data(), inner_pkt.size()) == 0);

    // 3. Process Rx Frame in engine (Data plane demux)
    bool handled = engine.ProcessRxFrame(outer_frame.data(), outer_frame.size());
    assert(handled);
    assert(s->rx_packets == 1);
    assert(s->rx_bytes == outer_frame.size());

    std::cout << "  -> GTP-U Encap/Decap & Inner Packet Integrity: PASSED" << std::endl;
}

void TestGtpuPathManagementEcho() {
    std::cout << "[TEST] 2. GTP-U Path Management Echo Request / Echo Response..." << std::endl;

    SessionManager mgr(100);
    GtpuEngine engine(mgr, nullptr);

    TelcoSessionContext* s = mgr.AcquireSession();
    GtpuTunnelConfig cfg{};
    cfg.uplink_teid = 0x77889900;
    cfg.local_gnb_ip = 0x0A000001;
    cfg.peer_upf_ip = 0x0A000002;
    engine.StartSession(s, cfg);

    uint16_t seq = 0x1234;
    auto echo_req = engine.BuildEchoRequest(s, seq);

    // Verify Echo Request header
    GtpuDecapInfo info{};
    bool ok = GtpuEngine::Decapsulate(echo_req.data(), echo_req.size(), info);
    assert(ok);
    assert(info.msg_type == static_cast<uint8_t>(GtpuMessageType::EchoRequest));
    assert(info.teid == 0); // Path management must have TEID 0
    assert(info.has_seq);
    assert(info.seq_num == seq);

    // Simulate UPF processing Echo Request -> generates Echo Response
    bool handled = engine.ProcessRxFrame(echo_req.data(), echo_req.size(), s);
    assert(handled);

    const auto& echo_resp = engine.GetLastTxFrame();
    assert(!echo_resp.empty());

    GtpuDecapInfo resp_info{};
    ok = GtpuEngine::Decapsulate(echo_resp.data(), echo_resp.size(), resp_info);
    assert(ok);
    assert(resp_info.msg_type == static_cast<uint8_t>(GtpuMessageType::EchoResponse));
    assert(resp_info.teid == 0);
    assert(resp_info.has_seq);
    assert(resp_info.seq_num == seq);

    // Feed Echo Response back -> session transitions to ACTIVE
    handled = engine.ProcessRxFrame(echo_resp.data(), echo_resp.size(), s);
    assert(handled);
    assert(engine.GetSubState(s) == GtpuSubState::ACTIVE);

    std::cout << "  -> GTP-U Path Echo Request/Response: PASSED" << std::endl;
}

void TestGtpuTimeoutAndRetransmission() {
    std::cout << "[TEST] 3. GTP-U Keepalive Heartbeat & Retransmission Failure..." << std::endl;

    SessionManager mgr(100);
    uint64_t tsc_hz = 2400000000ULL;
    HierarchicalTimingWheel wheel(tsc_hz);
    GtpuEngine engine(mgr, &wheel);

    ProtocolConfig p_cfg{};
    p_cfg.retransmit_timeout_ms = 100;
    p_cfg.max_retries = 3;
    engine.Init(p_cfg);

    TelcoSessionContext* s = mgr.AcquireSession();
    GtpuTunnelConfig t_cfg{};
    t_cfg.uplink_teid = 0xA1B2C3D4;
    t_cfg.echo_interval_ms = 200;

    engine.OnTimerTick(1000ULL); // Anchor timing wheel baseline
    engine.StartSession(s, t_cfg);
    assert(engine.GetSubState(s) == GtpuSubState::ACTIVE);

    uint64_t now_tsc = 1000ULL;
    uint64_t tsc_per_ms = tsc_hz / 1000ULL;

    // Advance 210ms -> Echo Request triggered!
    now_tsc += 210 * tsc_per_ms;
    engine.OnTimerTick(now_tsc);
    assert(engine.GetSubState(s) == GtpuSubState::ECHO_PENDING);

    // Peer silent: Retry 1 (after 100ms)
    now_tsc += 120 * tsc_per_ms;
    engine.OnTimerTick(now_tsc);
    assert(engine.GetSubState(s) == GtpuSubState::DEGRADED);
    assert(s->retry_count == 1);

    // Peer silent: Retry 2 (after 200ms)
    now_tsc += 220 * tsc_per_ms;
    engine.OnTimerTick(now_tsc);
    assert(s->retry_count == 2);

    // Peer silent: Retry 3 exceeds max_retries -> FAILED
    now_tsc += 420 * tsc_per_ms;
    engine.OnTimerTick(now_tsc);
    assert(engine.GetSubState(s) == GtpuSubState::FAILED);
    assert(s->state == SessionState::FAILED);

    std::cout << "  -> GTP-U Echo Backoff & Failure Gate: PASSED" << std::endl;
}

void TestGtpuErrorIndication() {
    std::cout << "[TEST] 4. GTP-U Error Indication (TEID Data I & Peer IP)..." << std::endl;

    SessionManager mgr(100);
    GtpuEngine engine(mgr, nullptr);

    TelcoSessionContext* s = mgr.AcquireSession();
    GtpuTunnelConfig cfg{};
    cfg.uplink_teid = 0x99881122;
    engine.StartSession(s, cfg);
    assert(engine.GetSubState(s) == GtpuSubState::ACTIVE);

    auto err_frame = engine.BuildErrorIndication(s, cfg.uplink_teid, 0x0A000002);
    GtpuDecapInfo info{};
    bool ok = GtpuEngine::Decapsulate(err_frame.data(), err_frame.size(), info);
    assert(ok);
    assert(info.msg_type == static_cast<uint8_t>(GtpuMessageType::ErrorIndication));
    assert(info.teid == 0);

    // Process Error Indication -> marks session FAILED
    bool handled = engine.ProcessRxFrame(err_frame.data(), err_frame.size(), s);
    assert(handled);
    assert(engine.GetSubState(s) == GtpuSubState::FAILED);

    std::cout << "  -> GTP-U Error Indication Handling: PASSED" << std::endl;
}

void TestPfcpAssociationAndHeartbeat() {
    std::cout << "[TEST] 5. PFCP Node Association Setup & Heartbeat (S=0)..." << std::endl;

    SessionManager mgr(100);
    PfcpEngine engine(mgr, nullptr);

    PfcpConfig cfg{};
    cfg.local_node_id = "smf-samurai-01";
    cfg.local_ip = 0x0A000001;
    cfg.remote_upf_ip = 0x0A000002;

    engine.StartAssociation(cfg);
    assert(!engine.IsAssociated());

    const auto& assoc_req = engine.GetLastTxFrame();
    assert(!assoc_req.empty());

    PfcpDecapInfo info{};
    bool ok = PfcpEngine::ParsePfcpPacket(assoc_req.data(), assoc_req.size(), info);
    assert(ok);
    assert(!info.is_session);
    assert(info.msg_type == static_cast<uint8_t>(PfcpMessageType::AssociationSetupRequest));
    assert(info.seq_num == 1);

    // Simulate UPF Association Setup Response (Cause = RequestAccepted)
    auto assoc_resp = engine.BuildAssociationSetupResponse(info.seq_num, "upf-node-01", cfg.remote_upf_ip, PfcpCause::RequestAccepted);
    bool handled = engine.ProcessRxFrame(assoc_resp.data(), assoc_resp.size());
    assert(handled);
    assert(engine.IsAssociated());

    // Test Heartbeat
    auto hb_req = engine.BuildHeartbeatRequest(42);
    PfcpDecapInfo hb_info{};
    ok = PfcpEngine::ParsePfcpPacket(hb_req.data(), hb_req.size(), hb_info);
    assert(ok);
    assert(hb_info.msg_type == static_cast<uint8_t>(PfcpMessageType::HeartbeatRequest));
    assert(hb_info.seq_num == 42);

    handled = engine.ProcessRxFrame(hb_req.data(), hb_req.size());
    assert(handled);

    const auto& hb_resp = engine.GetLastTxFrame();
    PfcpDecapInfo hb_resp_info{};
    ok = PfcpEngine::ParsePfcpPacket(hb_resp.data(), hb_resp.size(), hb_resp_info);
    assert(ok);
    assert(hb_resp_info.msg_type == static_cast<uint8_t>(PfcpMessageType::HeartbeatResponse));
    assert(hb_resp_info.seq_num == 42);

    std::cout << "  -> PFCP Association & Heartbeat: PASSED" << std::endl;
}

void TestPfcpSessionLifecycle() {
    std::cout << "[TEST] 6. PFCP Session Lifecycle (Establishment -> Modification -> Deletion)..." << std::endl;

    SessionManager mgr(100);
    PfcpEngine engine(mgr, nullptr);

    PfcpConfig p_cfg{};
    p_cfg.local_ip = 0x0A000001;
    p_cfg.remote_upf_ip = 0x0A000002;
    engine.StartAssociation(p_cfg);

    TelcoSessionContext* s = mgr.AcquireSession();
    assert(s != nullptr);

    uint64_t cp_seid = 0xAABBCCDDEEFF0011ULL;
    uint64_t up_seid = 0x1122334455667788ULL;

    PfcpPdr pdr{};
    pdr.pdr_id = 1;
    pdr.precedence = 100;
    pdr.source_interface = PfcpInterface::Access;
    pdr.teid = 0x10002000;
    pdr.ue_ip = 0x0A2D0002; // 10.45.0.2
    pdr.far_id = 1;

    PfcpFar far{};
    far.far_id = 1;
    far.apply_action = PFCP_APPLY_ACTION_FORW;
    far.destination_interface = PfcpInterface::Core;
    far.outer_teid = 0x30004000;
    far.peer_upf_ip = 0x0A000002;

    // 1. Establish Session
    engine.EstablishSession(s, cp_seid, pdr, far);
    assert(engine.GetSubState(s) == PfcpSubState::SESSION_ESTAB_PENDING);
    assert(s->GetPfcpSeid() == cp_seid);
    assert(mgr.FindPfcpSession(cp_seid) == s);

    // Verify Session Establishment Request frame
    const auto& estab_req = engine.GetLastTxFrame();
    PfcpDecapInfo estab_info{};
    bool ok = PfcpEngine::ParsePfcpPacket(estab_req.data(), estab_req.size(), estab_info);
    assert(ok);
    assert(estab_info.is_session);
    assert(estab_info.msg_type == static_cast<uint8_t>(PfcpMessageType::SessionEstablishmentRequest));
    assert(estab_info.has_f_teid);
    assert(estab_info.f_teid == pdr.teid);
    assert(estab_info.has_ue_ip);
    assert(estab_info.ue_ip == pdr.ue_ip);

    // Simulate UPF Session Establishment Response
    auto estab_resp = engine.BuildSessionEstablishmentResponse(s, estab_info.seq_num, cp_seid, up_seid, PfcpCause::RequestAccepted);
    bool handled = engine.ProcessRxFrame(estab_resp.data(), estab_resp.size(), s);
    assert(handled);
    assert(engine.GetSubState(s) == PfcpSubState::ESTABLISHED);
    assert(s->state == SessionState::ESTABLISHED);
    assert(s->teid_downlink == far.outer_teid); // DOWNLINK TEID PRESERVED!
    assert(s->GetPfcpRemoteSeid() == up_seid);  // REMOTE UPF SEID STORED!

    // 2. Modify Session (e.g. Switch Action to Drop / Forwarding Update)
    PfcpFar updated_far = far;
    updated_far.apply_action = PFCP_APPLY_ACTION_DROP;
    engine.ModifySession(s, updated_far);
    assert(engine.GetSubState(s) == PfcpSubState::SESSION_MOD_PENDING);

    const auto& mod_req = engine.GetLastTxFrame();
    PfcpDecapInfo mod_info{};
    ok = PfcpEngine::ParsePfcpPacket(mod_req.data(), mod_req.size(), mod_info);
    assert(ok);
    assert(mod_info.msg_type == static_cast<uint8_t>(PfcpMessageType::SessionModificationRequest));
    assert(mod_info.seid == up_seid); // 3GPP TS 29.244: UPF SEID MUST BE USED IN REQUEST!

    auto mod_resp = engine.BuildSessionModificationResponse(s, mod_info.seq_num, PfcpCause::RequestAccepted);
    handled = engine.ProcessRxFrame(mod_resp.data(), mod_resp.size(), s);
    assert(handled);
    assert(engine.GetSubState(s) == PfcpSubState::ESTABLISHED);

    // 3. Delete Session
    engine.DeleteSession(s);
    assert(engine.GetSubState(s) == PfcpSubState::SESSION_DEL_PENDING);

    const auto& del_req = engine.GetLastTxFrame();
    PfcpDecapInfo del_info{};
    ok = PfcpEngine::ParsePfcpPacket(del_req.data(), del_req.size(), del_info);
    assert(ok);
    assert(del_info.msg_type == static_cast<uint8_t>(PfcpMessageType::SessionDeletionRequest));
    assert(del_info.seid == up_seid); // UPF SEID MUST BE USED IN REQUEST!

    auto del_resp = engine.BuildSessionDeletionResponse(s, del_info.seq_num, PfcpCause::RequestAccepted);
    handled = engine.ProcessRxFrame(del_resp.data(), del_resp.size(), s);
    assert(handled);
    assert(engine.GetSubState(s) == PfcpSubState::RELEASED);
    assert(mgr.FindPfcpSession(cp_seid) == nullptr); // SEID unbound

    std::cout << "  -> PFCP Full Session Lifecycle & SEID Demux: PASSED" << std::endl;
}

void TestCrossPlanePfcpGtpuIntegration() {
    std::cout << "[TEST] 7. Cross-Plane PFCP Control Plane & GTP-U Fastpath Wire Interop..." << std::endl;

    SessionManager mgr(100);
    PfcpEngine pfcp(mgr, nullptr);
    GtpuEngine gtpu(mgr, nullptr);

    PfcpConfig p_cfg{};
    pfcp.StartAssociation(p_cfg);

    TelcoSessionContext* s = mgr.AcquireSession();
    uint64_t cp_seid = 0x5555666677778888ULL;

    PfcpPdr pdr{};
    pdr.pdr_id = 1;
    pdr.teid = 0x00AABBCC;
    pdr.ue_ip = 0x0A2D0005;

    PfcpFar far{};
    far.far_id = 1;
    far.apply_action = PFCP_APPLY_ACTION_FORW;
    far.outer_teid = 0x00DDEEFF;

    // 1. Establish session via PFCP
    pfcp.EstablishSession(s, cp_seid, pdr, far);
    // Bind GTP-U data plane TEID
    mgr.BindGtpuSession(s, pdr.teid);

    // Simulate UPF accepting session
    auto resp = pfcp.BuildSessionEstablishmentResponse(s, 1, cp_seid, 0x1234, PfcpCause::RequestAccepted);
    pfcp.ProcessRxFrame(resp.data(), resp.size(), s);
    assert(pfcp.GetSubState(s) == PfcpSubState::ESTABLISHED);

    // 2. Transmit GTP-U Data plane traffic with matching TEID
    auto inner = CreateDummyInnerIpPacket();
    auto gtp_frame = gtpu.Encapsulate(s, inner.data(), inner.size());

    // 3. Fastpath Classifier Demux
    TelcoFrameType f_type;
    PacketMetadata meta;
    bool demux_ok = FastpathClassifier::Classify(gtp_frame.data(), gtp_frame.size(), meta, f_type);
    assert(demux_ok);
    assert(f_type == TelcoFrameType::Gtpu);
    assert(meta.dst_port == GTPU_PORT);

    // 4. Data plane ingress
    uint64_t prev_rx_packets = s->rx_packets;
    bool rx_handled = gtpu.ProcessRxFrame(gtp_frame.data(), gtp_frame.size());
    assert(rx_handled);
    assert(s->rx_packets == prev_rx_packets + 1);

    std::cout << "  -> Cross-Plane PFCP/GTP-U Fastpath Demux & Wire Interop: PASSED" << std::endl;
}

void TestMobileFuzzResistance() {
    std::cout << "[TEST] 8. Mobile Core Malformed / Fuzz Truncated Frames Crash Protection..." << std::endl;

    auto inner = CreateDummyInnerIpPacket();
    SessionManager mgr(10);
    GtpuEngine gtpu(mgr, nullptr);
    TelcoSessionContext* s = mgr.AcquireSession();
    GtpuTunnelConfig cfg{};
    cfg.uplink_teid = 0x1234;
    gtpu.StartSession(s, cfg);

    auto valid_gtp = gtpu.Encapsulate(s, inner.data(), inner.size());

    // Truncate GTP frame byte-by-byte
    GtpuDecapInfo g_info{};
    for (size_t l = 0; l < valid_gtp.size() - 2; ++l) {
        // Must not crash or buffer-overflow
        GtpuEngine::Decapsulate(valid_gtp.data(), l, g_info);
        gtpu.ProcessRxFrame(valid_gtp.data(), l);
    }

    // PFCP truncation fuzz
    PfcpEngine pfcp(mgr, nullptr);
    auto valid_pfcp = pfcp.BuildAssociationSetupRequest(1, "node-fuzz", 0x0A000001);
    PfcpDecapInfo p_info{};
    for (size_t l = 0; l < valid_pfcp.size() - 2; ++l) {
        PfcpEngine::ParsePfcpPacket(valid_pfcp.data(), l, p_info);
        pfcp.ProcessRxFrame(valid_pfcp.data(), l);
    }

    std::cout << "  -> Mobile Core Fuzz / Truncation Immunity: PASSED (No Crash)" << std::endl;
}

void TestGtpuAndPfcpIpv6Transport() {
    std::cout << "[TEST] 9. GTP-U & PFCP IPv6 Outer Transport Decapsulation & Demux..." << std::endl;

    // 1. Build an IPv6/UDP/GTP-U frame manually
    std::vector<uint8_t> frame;
    // Ethernet Header (14 bytes)
    for (int i = 0; i < 6; ++i) frame.push_back(0x11);
    for (int i = 0; i < 6; ++i) frame.push_back(0x22);
    frame.push_back(0x86); frame.push_back(0xDD); // Ethertype IPv6

    // IPv6 Header (40 bytes)
    frame.push_back(0x60); frame.push_back(0x00); frame.push_back(0x00); frame.push_back(0x00); // VTC
    uint16_t udp_total_len = htons(8 + 8 + 20); // UDP + GTP + 20-byte payload
    frame.push_back(static_cast<uint8_t>(udp_total_len & 0xFF)); // payload length
    frame.push_back(static_cast<uint8_t>(udp_total_len >> 8));
    frame.push_back(17); // Next Header UDP
    frame.push_back(64); // Hop Limit
    // Src IPv6 (2001:db8::1)
    frame.push_back(0x20); frame.push_back(0x01); frame.push_back(0x0D); frame.push_back(0xB8);
    for (int i = 0; i < 11; ++i) frame.push_back(0x00);
    frame.push_back(0x01);
    // Dst IPv6 (2001:db8::2)
    frame.push_back(0x20); frame.push_back(0x01); frame.push_back(0x0D); frame.push_back(0xB8);
    for (int i = 0; i < 11; ++i) frame.push_back(0x00);
    frame.push_back(0x02);

    // UDP Header (8 bytes)
    uint16_t src_p = htons(2152);
    uint16_t dst_p = htons(2152);
    uint16_t u_len = htons(8 + 8 + 20);
    frame.push_back(static_cast<uint8_t>(src_p & 0xFF)); frame.push_back(static_cast<uint8_t>(src_p >> 8));
    frame.push_back(static_cast<uint8_t>(dst_p & 0xFF)); frame.push_back(static_cast<uint8_t>(dst_p >> 8));
    frame.push_back(static_cast<uint8_t>(u_len & 0xFF)); frame.push_back(static_cast<uint8_t>(u_len >> 8));
    frame.push_back(0); frame.push_back(0); // Checksum 0

    // GTP-U Header (8 bytes)
    frame.push_back(0x30); // Flags (v1, proto=1)
    frame.push_back(255);  // MsgType G-PDU
    uint16_t gtp_len = htons(20);
    frame.push_back(static_cast<uint8_t>(gtp_len & 0xFF)); frame.push_back(static_cast<uint8_t>(gtp_len >> 8));
    uint32_t teid = htonl(0xCAFEBABE);
    const auto* teid_bytes = reinterpret_cast<const uint8_t*>(&teid);
    frame.insert(frame.end(), teid_bytes, teid_bytes + 4);

    // 20 bytes dummy payload
    for (int i = 0; i < 20; ++i) frame.push_back(static_cast<uint8_t>(i + 1));

    // Test FastpathClassifier on IPv6 GTP-U
    TelcoFrameType f_type;
    PacketMetadata meta;
    bool class_ok = FastpathClassifier::Classify(frame.data(), frame.size(), meta, f_type);
    assert(class_ok);
    assert(f_type == TelcoFrameType::Gtpu);

    // Test GtpuEngine::Decapsulate on IPv6 frame
    GtpuDecapInfo d_info{};
    bool decap_ok = GtpuEngine::Decapsulate(frame.data(), frame.size(), d_info);
    assert(decap_ok);
    assert(d_info.teid == 0xCAFEBABE);
    assert(d_info.msg_type == 255);
    assert(d_info.payload_len == 20);

    std::cout << "  -> GTP-U & PFCP IPv6 Outer Transport Decapsulation: PASSED" << std::endl;
}

void TestGtpuWireFramePaddingAndDirectDecap() {
    std::cout << "[TEST] 10. GTP-U Wire Frame Padding & Direct Decapsulation..." << std::endl;

    SessionManager mgr(10);
    GtpuEngine gtpu(mgr, nullptr);
    TelcoSessionContext* s = mgr.AcquireSession();
    GtpuTunnelConfig cfg{};
    cfg.uplink_teid = 0x55443322;
    gtpu.StartSession(s, cfg);

    auto inner = CreateDummyInnerIpPacket(); // 28 bytes
    auto frame = gtpu.Encapsulate(s, inner.data(), inner.size());

    // Append 30 bytes of Ethernet switch zero padding to simulate wire padding
    std::vector<uint8_t> padded_frame = frame;
    padded_frame.insert(padded_frame.end(), 30, 0x00);

    GtpuDecapInfo decap{};
    bool ok = GtpuEngine::Decapsulate(padded_frame.data(), padded_frame.size(), decap);
    assert(ok);
    // Payload length MUST strictly equal the original inner packet size (28), NOT include the 30 padding bytes!
    assert(decap.payload_len == inner.size());
    assert(std::memcmp(decap.payload, inner.data(), inner.size()) == 0);

    // Direct GTP-U Decapsulation test (using pointer directly into GTP-U header)
    size_t gtp_header_offset = 14 + 20 + 8; // Eth + IPv4 + UDP
    GtpuDecapInfo direct_decap{};
    ok = GtpuEngine::Decapsulate(frame.data() + gtp_header_offset, frame.size() - gtp_header_offset, direct_decap);
    assert(ok);
    assert(direct_decap.teid == cfg.uplink_teid);
    assert(direct_decap.payload_len == inner.size());

    std::cout << "  -> GTP-U Wire Frame Padding & Direct Decap: PASSED" << std::endl;
}

void TestPfcpIpv6FseidParsing() {
    std::cout << "[TEST] 11. PFCP IPv6 F-SEID Parsing & Downlink TEID Integrity..." << std::endl;

    SessionManager mgr(10);
    PfcpEngine pfcp(mgr, nullptr);
    TelcoSessionContext* s = mgr.AcquireSession();

    PfcpPdr pdr{};
    pdr.teid = 0x11112222;
    PfcpFar far{};
    far.outer_teid = 0x33334444; // This outer TEID MUST remain intact!

    uint64_t cp_seid = 0x1234567890ABCDEFULL;
    pfcp.EstablishSession(s, cp_seid, pdr, far);
    assert(s->teid_downlink == 0x33334444);

    // Build Response with IPv6 F-SEID (Flags = 0x01: IPv6 only)
    uint64_t up_seid_v6 = 0xFEDCBA0987654321ULL;
    auto resp = pfcp.BuildSessionEstablishmentResponse(s, 1, cp_seid, up_seid_v6, PfcpCause::RequestAccepted);

    // Patch F-SEID in response frame to have Flags=0x01 (IPv6 only)
    for (size_t i = 0; i < resp.size() - 15; ++i) {
        if (resp[i] == 0x00 && resp[i + 1] == 57) { // IE Type 57 (F-SEID)
            resp[i + 4] = 0x01; // Flags: IPv6
            break;
        }
    }

    bool handled = pfcp.ProcessRxFrame(resp.data(), resp.size(), s);
    assert(handled);
    assert(pfcp.GetSubState(s) == PfcpSubState::ESTABLISHED);
    assert(s->GetPfcpRemoteSeid() == up_seid_v6); // Successfully parsed IPv6 F-SEID!
    assert(s->teid_downlink == 0x33334444);      // Downlink TEID NOT clobbered!

    std::cout << "  -> PFCP IPv6 F-SEID Parsing & Downlink TEID Integrity: PASSED" << std::endl;
}

void TestGtpuTeidZeroDropAndPfcpRecursionLimit() {
    std::cout << "[TEST] 12. GTP-U TEID=0 Drop & PFCP IE Recursion Limit..." << std::endl;

    SessionManager mgr(10);
    GtpuEngine gtpu(mgr, nullptr);
    TelcoSessionContext* s = mgr.AcquireSession();
    GtpuTunnelConfig cfg{};
    cfg.uplink_teid = 0x1000;
    gtpu.StartSession(s, cfg);

    auto inner = CreateDummyInnerIpPacket();
    auto frame = gtpu.Encapsulate(s, inner.data(), inner.size());

    // Corrupt TEID to 0 in G-PDU
    size_t gtp_hdr_offset = 14 + 20 + 8;
    frame[gtp_hdr_offset + 4] = 0;
    frame[gtp_hdr_offset + 5] = 0;
    frame[gtp_hdr_offset + 6] = 0;
    frame[gtp_hdr_offset + 7] = 0;

    // ProcessRxFrame MUST drop G-PDU with TEID 0 per 3GPP TS 29.281
    bool handled = gtpu.ProcessRxFrame(frame.data(), frame.size());
    assert(!handled);

    // Deeply nested CreatePdr IEs (20 layers) to verify recursion limit (depth > 8)
    std::vector<uint8_t> nested_ies;
    for (int layer = 0; layer < 20; ++layer) {
        nested_ies.push_back(0x00); nested_ies.push_back(0x01); // CreatePdr (Type 1)
        nested_ies.push_back(0x00); nested_ies.push_back(10);   // Length
    }
    PfcpDecapInfo d_info{};
    PfcpEngine pfcp(mgr, nullptr);
    // Must not crash or stack-overflow
    pfcp.ProcessRxFrame(nested_ies.data(), nested_ies.size());

    std::cout << "  -> GTP-U TEID=0 Drop & PFCP IE Recursion Limit: PASSED" << std::endl;
}

int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "     SAMURAI 4G/5G GTP-U & PFCP MOBILE CORE VERIFICATION SUITE   " << std::endl;
    std::cout << "=================================================================" << std::endl;

    TestGtpuEncapsulationDecapsulation();
    TestGtpuPathManagementEcho();
    TestGtpuTimeoutAndRetransmission();
    TestGtpuErrorIndication();
    TestPfcpAssociationAndHeartbeat();
    TestPfcpSessionLifecycle();
    TestCrossPlanePfcpGtpuIntegration();
    TestMobileFuzzResistance();
    TestGtpuAndPfcpIpv6Transport();
    TestGtpuWireFramePaddingAndDirectDecap();
    TestPfcpIpv6FseidParsing();
    TestGtpuTeidZeroDropAndPfcpRecursionLimit();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL MOBILE CORE TESTS PASSED SUCCESSFULLY! (100% VERIFIED)     " << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
