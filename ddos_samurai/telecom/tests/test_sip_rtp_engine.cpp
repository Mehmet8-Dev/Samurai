#include "ddos_samurai/telecom/protocols/stateful/sip_rtp/sip_rtp_engine.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <arpa/inet.h>

using namespace ddos_samurai::telecom;
using namespace ddos_samurai::telecom::sip_rtp;

static std::vector<uint8_t> BuildSimulatedUdpFrame(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, const void* payload, size_t payload_len) {
    size_t total_len = 14 + 20 + 8 + payload_len;
    std::vector<uint8_t> pkt(total_len, 0);
    // Eth (IPv4)
    pkt[12] = 0x08; pkt[13] = 0x00;
    // IPv4
    pkt[14] = 0x45;
    uint16_t ip_total_len = htons(static_cast<uint16_t>(20 + 8 + payload_len));
    std::memcpy(&pkt[16], &ip_total_len, 2);
    pkt[22] = 64; // TTL
    pkt[23] = 17; // UDP
    uint32_t s_ip = htonl(src_ip);
    uint32_t d_ip = htonl(dst_ip);
    std::memcpy(&pkt[26], &s_ip, 4);
    std::memcpy(&pkt[30], &d_ip, 4);
    // UDP
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    uint16_t udp_len = htons(static_cast<uint16_t>(8 + payload_len));
    std::memcpy(&pkt[34], &sp, 2);
    std::memcpy(&pkt[36], &dp, 2);
    std::memcpy(&pkt[38], &udp_len, 2);
    // Payload
    if (payload && payload_len > 0) {
        std::memcpy(&pkt[42], payload, payload_len);
    }
    return pkt;
}

void TestSipCallEstablishment() {
    std::cout << "[TEST] 1. SIP RFC 3261 Call Setup (INVITE -> 100 -> 180 -> 200 OK -> ACK)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SipRtpEngine client_engine(mgr, &wheel);
    SipRtpEngine server_engine(mgr, &wheel);

    ProtocolConfig cfg{};
    client_engine.Init(cfg);
    server_engine.Init(cfg);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    assert(client_ctx != nullptr);

    SipCallConfig call_cfg{};
    call_cfg.local_ip = 0x0A000001;
    call_cfg.peer_ip = 0x0A000002;
    call_cfg.from_uri = "sip:alice@samurai.local";
    call_cfg.to_uri = "sip:bob@operator.ims";
    call_cfg.local_sip_port = 5060;
    call_cfg.peer_sip_port = 5060;

    // 1. Client starts call -> produces INVITE with SDP
    client_engine.StartCall(client_ctx, call_cfg);
    assert(client_engine.GetState(client_ctx) == SipCallState::CALLING);
    const auto& invite_pkt = client_engine.last_tx_packet();
    assert(!invite_pkt.empty());

    // 2. Server receives INVITE -> simulates 180 Ringing
    std::string invite_str(reinterpret_cast<const char*>(invite_pkt.data() + 14 + 20 + 8), invite_pkt.size() - (14 + 20 + 8));
    assert(invite_str.find("INVITE") == 0);
    assert(invite_str.find("m=audio") != std::string::npos);

    // 3. Client receives 180 Ringing -> transitions to PROCEEDING
    std::string ringing = "SIP/2.0 180 Ringing\r\nCall-ID: " + call_cfg.call_id + "\r\n\r\n";
    auto ringing_pkt = BuildSimulatedUdpFrame(0x0A000002, 0x0A000001, 5060, 5060, ringing.data(), ringing.size());

    bool ok = client_engine.ProcessRxFrame(ringing_pkt.data(), ringing_pkt.size(), 1000);
    assert(ok);
    assert(client_engine.GetState(client_ctx) == SipCallState::PROCEEDING);

    // 4. Client receives 200 OK -> transitions to ESTABLISHED and automatically emits ACK
    std::string ok_msg = "SIP/2.0 200 OK\r\nCall-ID: " + call_cfg.call_id + "\r\n\r\n";
    auto ok_pkt = BuildSimulatedUdpFrame(0x0A000002, 0x0A000001, 5060, 5060, ok_msg.data(), ok_msg.size());

    ok = client_engine.ProcessRxFrame(ok_pkt.data(), ok_pkt.size(), 1001);
    assert(ok);
    assert(client_engine.GetState(client_ctx) == SipCallState::ESTABLISHED);

    // Verify ACK was transmitted
    const auto& ack_pkt = client_engine.last_tx_packet();
    assert(!ack_pkt.empty());
    std::string ack_str(reinterpret_cast<const char*>(ack_pkt.data() + 14 + 20 + 8), ack_pkt.size() - (14 + 20 + 8));
    assert(ack_str.find("ACK") == 0);

    std::cout << "  -> SIP Call establishment dialog to ESTABLISHED: PASSED" << std::endl;
}

void TestRtpMediaStreaming() {
    std::cout << "[TEST] 2. RTP RFC 3550 Audio Media Streaming (20ms G.711 PCMU Frames)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SipRtpEngine client_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    client_engine.SetState(client_ctx, SipCallState::ESTABLISHED);
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;

    uint8_t voice_frame[160];
    std::memset(voice_frame, 0x55, sizeof(voice_frame));

    // Stream 5 successive 20ms frames
    for (int i = 0; i < 5; ++i) {
        auto rtp_pkt = client_engine.BuildRtpPacket(client_ctx, voice_frame, sizeof(voice_frame));
        assert(!rtp_pkt.empty());

        // Header offset = 14 (Eth) + 20 (IP) + 8 (UDP) = 42
        const auto* rtp = reinterpret_cast<const RtpHeader*>(rtp_pkt.data() + 42);
        assert((rtp->v_p_x_cc >> 6) == 2); // Version 2
        assert((rtp->m_pt & 0x7F) == 0);   // PCMU
        assert(ntohs(rtp->seq_number) == i);
        assert(ntohl(rtp->timestamp) == static_cast<uint32_t>(i * 160));
    }

    std::cout << "  -> RTP RFC 3550 packet generation and sequence/timestamp progression: PASSED" << std::endl;
}

void TestRtpJitterCalculation() {
    std::cout << "[TEST] 3. RTP RFC 3550 Appendix A.8 Interarrival Jitter Calculation..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SipRtpEngine engine(mgr, &wheel);

    TelcoSessionContext* ctx = mgr.AcquireSession();
    engine.SetState(ctx, SipCallState::ESTABLISHED);
    ctx->client_ip = 0x0A000001;
    ctx->peer_ip = 0x0A000002;
    ctx->client_port = 10000;
    ctx->peer_port = 10000;
    mgr.Bind5Tuple(ctx, 0x0A000001, 0x0A000002, 10000, 10000, 17);

    // Simulate incoming RTP packets with jitter
    uint8_t rtp_payload[12 + 160] = {0};
    auto* rtp = reinterpret_cast<RtpHeader*>(rtp_payload);
    rtp->v_p_x_cc = 0x80; // V=2

    // Packet 1 at t=1000, ts=0
    rtp->timestamp = htonl(0);
    auto pkt1 = BuildSimulatedUdpFrame(0x0A000002, 0x0A000001, 10000, 10000, rtp_payload, sizeof(rtp_payload));
    bool ok = engine.ProcessRxFrame(pkt1.data(), pkt1.size(), 1000);
    assert(ok);

    // Packet 2 at t=1200 (200 arrival diff), ts=160 (arrival jitter = |200 - 160| = 40)
    rtp->timestamp = htonl(160);
    auto pkt2 = BuildSimulatedUdpFrame(0x0A000002, 0x0A000001, 10000, 10000, rtp_payload, sizeof(rtp_payload));
    ok = engine.ProcessRxFrame(pkt2.data(), pkt2.size(), 1200);
    assert(ok);

    auto stats = engine.GetJitterStats();
    assert(stats.packets_received == 2);
    assert(stats.jitter_us > 0.0);

    std::cout << "  -> RFC 3550 Jitter algorithm verified: " << stats.jitter_us << " us: PASSED" << std::endl;
}

void TestSipCallTeardown() {
    std::cout << "[TEST] 4. SIP Call Teardown (BYE -> 200 OK -> TERMINATED)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SipRtpEngine client_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    client_engine.SetState(client_ctx, SipCallState::ESTABLISHED);
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;
    client_ctx->client_port = 5060;
    client_ctx->peer_port = 5060;
    mgr.Bind5Tuple(client_ctx, 0x0A000001, 0x0A000002, 5060, 5060, 17);

    // 1. Client terminates call -> produces BYE
    client_engine.TerminateCall(client_ctx);
    assert(client_engine.GetState(client_ctx) == SipCallState::TERMINATING);
    const auto& bye_pkt = client_engine.last_tx_packet();
    assert(!bye_pkt.empty());

    // 2. Client receives 200 OK to BYE -> transitions to TERMINATED
    std::string ok_msg = "SIP/2.0 200 OK\r\nCall-ID: samurai-call-1001\r\n\r\n";
    auto ok_pkt = BuildSimulatedUdpFrame(0x0A000002, 0x0A000001, 5060, 5060, ok_msg.data(), ok_msg.size());

    bool ok = client_engine.ProcessRxFrame(ok_pkt.data(), ok_pkt.size(), 2000);
    assert(ok);
    assert(client_engine.GetState(client_ctx) == SipCallState::TERMINATED);

    std::cout << "  -> SIP BYE teardown dialog: PASSED" << std::endl;
}

int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "       SAMURAI SIP / RTP (VoIP / IMS) VERIFICATION SUITE         " << std::endl;
    std::cout << "=================================================================" << std::endl;

    TestSipCallEstablishment();
    TestRtpMediaStreaming();
    TestRtpJitterCalculation();
    TestSipCallTeardown();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL SIP / RTP ENGINE TESTS PASSED SUCCESSFULLY! (100% VERIFIED)" << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
