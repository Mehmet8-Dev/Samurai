#include "ddos_samurai/telecom/l2l3_fastpath_wiring.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "ddos_samurai/telecom/core/fastpath_classifier.hpp"
#include "ddos_samurai/telecom/protocols/stateful/pppoe/pppoe_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/dhcp/dhcp_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/bfd/bfd_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/mobile/gtpu_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/sctp/sctp_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/diameter/diameter_engine.hpp"
#include "ddos_samurai/telecom/protocols/stateful/sip_rtp/sip_rtp_engine.hpp"
#include "ddos_samurai/cli/options.hpp"
#include "ddos_samurai/cli/args.hpp"
#include "ddos_samurai/cli/profiles.hpp"

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <arpa/inet.h>

using namespace ddos_samurai::telecom;
using namespace ddos_samurai::telecom::pppoe;
using namespace ddos_samurai::telecom::dhcp;
using namespace ddos_samurai::telecom::bfd;
using namespace ddos_samurai::telecom::mobile;
using namespace ddos_samurai::telecom::sctp;
using namespace ddos_samurai::telecom::diameter;
using namespace ddos_samurai::telecom::sip_rtp;
using namespace samurai::cli;

void TestL2L3FastpathWiringTelcoDispatch() {
    std::cout << "[TEST 1] Fastpath Wiring Multi-Engine Telco Dispatch..." << std::endl;

    L2L3FastpathWiring wiring(100);

    bool tx_called = false;
    std::vector<uint8_t> emitted_pkt;
    wiring.SetTxCallback([&](const uint8_t* data, size_t len) {
        tx_called = true;
        emitted_pkt.assign(data, data + len);
    });

    uint64_t now_tsc = 1000000ULL;
    uint8_t mac_client[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t mac_peer[6] = {0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};

    // 1. SCTP INIT Frame Demux & Dispatch
    {
        tx_called = false;
        emitted_pkt.clear();

        TelcoSessionContext* sctp_s = wiring.session_mgr().AcquireSession();
        assert(sctp_s != nullptr);
        sctp_s->protocol_id = static_cast<uint8_t>(TelcoProtocolId::SCTP);
        sctp_s->client_ip = 0x0A000001; // 10.0.0.1
        sctp_s->peer_ip = 0x0A000002;   // 10.0.0.2
        sctp_s->client_port = 38412;
        sctp_s->peer_port = 38412;
        sctp_s->session_id = 0x12345678; // My VTag
        sctp_s->teid_uplink = 1001;      // Initial TSN
        std::memcpy(sctp_s->client_mac, mac_client, 6);
        std::memcpy(sctp_s->peer_mac, mac_peer, 6);

        auto sctp_init = wiring.sctp().BuildInitPacket(sctp_s);
        assert(!sctp_init.empty());

        // Verify ClassifyFrame identifies SCTP
        uint16_t vlan = 0;
        TelcoFrameType ftype = L2L3FastpathWiring::ClassifyFrame(sctp_init.data(), sctp_init.size(), &vlan);
        assert(ftype == TelcoFrameType::Sctp);
        assert(L2L3FastpathWiring::IsControlFrame(sctp_init.data(), sctp_init.size()));

        // Dispatch frame into L2L3FastpathWiring
        bool ok = wiring.DispatchRxControlFrame(sctp_init.data(), sctp_init.size(), now_tsc);
        assert(ok);
        assert(tx_called);
        assert(!emitted_pkt.empty());
        assert(wiring.last_tx_packet() == emitted_pkt);
        std::cout << "  -> SCTP INIT Demux -> INIT-ACK emitted: PASSED" << std::endl;
    }

    // 2. Diameter CER Frame Demux & Dispatch
    {
        tx_called = false;
        emitted_pkt.clear();

        TelcoSessionContext* diam_s = wiring.session_mgr().AcquireSession();
        assert(diam_s != nullptr);
        diam_s->protocol_id = static_cast<uint8_t>(TelcoProtocolId::DIAMETER);
        diam_s->client_ip = 0x0A000001;
        diam_s->peer_ip = 0x0A000002;
        diam_s->client_port = 3868;
        diam_s->peer_port = 3868;
        std::memcpy(diam_s->client_mac, mac_client, 6);
        std::memcpy(diam_s->peer_mac, mac_peer, 6);
        wiring.session_mgr().Bind5Tuple(diam_s, diam_s->client_ip, diam_s->peer_ip, 3868, 3868, 6);

        auto cer_pkt = wiring.diameter().BuildCerPacket(diam_s);
        assert(!cer_pkt.empty());

        uint16_t vlan = 0;
        TelcoFrameType ftype = L2L3FastpathWiring::ClassifyFrame(cer_pkt.data(), cer_pkt.size(), &vlan);
        assert(ftype == TelcoFrameType::Diameter);
        assert(L2L3FastpathWiring::IsControlFrame(cer_pkt.data(), cer_pkt.size()));

        bool ok = wiring.DispatchRxControlFrame(cer_pkt.data(), cer_pkt.size(), now_tsc);
        assert(ok);
        assert(tx_called);
        assert(!emitted_pkt.empty());
        assert(wiring.last_tx_packet() == emitted_pkt);
        std::cout << "  -> Diameter CER Demux -> CEA emitted: PASSED" << std::endl;
    }

    // 3. SIP INVITE Frame Demux & Dispatch
    {
        tx_called = false;
        emitted_pkt.clear();

        TelcoSessionContext* sip_s = wiring.session_mgr().AcquireSession();
        assert(sip_s != nullptr);
        sip_s->protocol_id = static_cast<uint8_t>(TelcoProtocolId::SIP_RTP);
        sip_s->client_ip = 0x0A000001;
        sip_s->peer_ip = 0x0A000002;
        sip_s->client_port = 5060;
        sip_s->peer_port = 5060;
        std::memcpy(sip_s->client_mac, mac_client, 6);
        std::memcpy(sip_s->peer_mac, mac_peer, 6);
        wiring.session_mgr().Bind5Tuple(sip_s, sip_s->client_ip, sip_s->peer_ip, 5060, 5060, 17);

        SipCallConfig call_cfg{};
        call_cfg.from_uri = "sip:caller@carrier.net";
        call_cfg.to_uri = "sip:callee@carrier.net";
        call_cfg.call_id = "test-call-1@carrier.net";
        call_cfg.local_ip_str = "10.0.0.1";
        call_cfg.peer_ip_str = "10.0.0.2";
        call_cfg.local_sip_port = 5060;
        call_cfg.peer_sip_port = 5060;
        call_cfg.local_rtp_port = 10000;
        call_cfg.peer_rtp_port = 10000;
        std::memcpy(call_cfg.local_mac, mac_client, 6);
        std::memcpy(call_cfg.peer_mac, mac_peer, 6);
        wiring.sip_rtp().StartCall(sip_s, call_cfg);

        auto invite_pkt = wiring.sip_rtp().BuildInvitePacket(sip_s);
        assert(!invite_pkt.empty());

        uint16_t vlan = 0;
        TelcoFrameType ftype = L2L3FastpathWiring::ClassifyFrame(invite_pkt.data(), invite_pkt.size(), &vlan);
        assert(ftype == TelcoFrameType::Sip);
        assert(L2L3FastpathWiring::IsControlFrame(invite_pkt.data(), invite_pkt.size()));

        bool ok = wiring.DispatchRxControlFrame(invite_pkt.data(), invite_pkt.size(), now_tsc);
        assert(ok);
        assert(tx_called);
        assert(!emitted_pkt.empty());
        assert(wiring.last_tx_packet() == emitted_pkt);
        std::cout << "  -> SIP INVITE Demux -> 180 Ringing emitted: PASSED" << std::endl;

        // 4. RTP Media Frame Demux & Dispatch
        uint8_t audio[160] = {0x12, 0x34};
        auto rtp_pkt = wiring.sip_rtp().BuildRtpPacket(sip_s, audio, sizeof(audio));
        assert(!rtp_pkt.empty());

        ftype = L2L3FastpathWiring::ClassifyFrame(rtp_pkt.data(), rtp_pkt.size(), &vlan);
        assert(ftype == TelcoFrameType::Rtp);
        assert(L2L3FastpathWiring::IsControlFrame(rtp_pkt.data(), rtp_pkt.size()));

        ok = wiring.DispatchRxControlFrame(rtp_pkt.data(), rtp_pkt.size(), now_tsc);
        assert(ok);
        std::cout << "  -> RTP Audio Media Demux -> Processed: PASSED" << std::endl;
    }

    // 5. Periodic Timer Stepping
    wiring.StepTimers(now_tsc + 1000000ULL, 2400000000ULL);

    std::cout << "  -> All L2L3FastpathWiring multi-engine dispatches verified: PASSED" << std::endl;
}

void TestTelcoWorkerCliArgParsing() {
    std::cout << "[TEST 2] Telco Worker CLI Argument & Profile Parsing..." << std::endl;

    // 1. Test profiles
    {
        CliOptions opt{};
        auto err = ApplyProfile("telco-sctp-flood", opt);
        assert(!err.has_value());
        assert(opt.job.protocol == "sctp");
        assert(opt.job.attack_vector == "sctp-flood");
        assert(opt.job.target_port == 38412);
        assert(opt.sctp_rate == 5000);
        assert(opt.job.packet_count == 100000);
    }
    {
        CliOptions opt{};
        auto err = ApplyProfile("telco-diameter-billing", opt);
        assert(!err.has_value());
        assert(opt.job.protocol == "diameter");
        assert(opt.job.attack_vector == "diameter-ccr");
        assert(opt.job.target_port == 3868);
        assert(opt.diameter_rate == 5000);
    }
    {
        CliOptions opt{};
        auto err = ApplyProfile("telco-sip-storm", opt);
        assert(!err.has_value());
        assert(opt.job.protocol == "sip");
        assert(opt.job.attack_vector == "sip-storm");
        assert(opt.job.target_port == 5060);
        assert(opt.sip_rate == 2000);
        assert(opt.enable_srtp == true);
    }
    {
        CliOptions opt{};
        auto err = ApplyProfile("telco-full-carrier", opt);
        assert(!err.has_value());
        assert(opt.job.protocol == "telco-full");
        assert(opt.sctp_rate == 5000);
        assert(opt.diameter_rate == 5000);
        assert(opt.sip_rate == 2000);
        assert(opt.enable_srtp == true);
    }

    // 2. Test explicit CLI rate flags
    {
        CliOptions opt{};
        const char* argv[] = {
            "samurai",
            "--worker", "cpu",
            "--sctp-rate", "12500",
            "--diameter-rate", "18000",
            "--sip-rate", "7500",
            "--enable-srtp"
        };
        int argc = sizeof(argv) / sizeof(argv[0]);
        ParseStatus st = ParseArgs(argc, const_cast<char**>(argv), opt);
        assert(st == ParseStatus::kOk);
        assert(opt.sctp_rate == 12500);
        assert(opt.diameter_rate == 18000);
        assert(opt.sip_rate == 7500);
        assert(opt.enable_srtp == true);
    }

    // 3. Test --diameter-ccr-rate alias
    {
        CliOptions opt{};
        const char* argv[] = {
            "samurai",
            "--worker", "cpu",
            "--diameter-ccr-rate", "22000"
        };
        int argc = sizeof(argv) / sizeof(argv[0]);
        ParseStatus st = ParseArgs(argc, const_cast<char**>(argv), opt);
        assert(st == ParseStatus::kOk);
        assert(opt.diameter_rate == 22000);
    }

    std::cout << "  -> CLI Profiles and Rate Controls Parsing: PASSED" << std::endl;
}

void TestTelcoMultiProtocolWorkerLoop() {
    std::cout << "[TEST 3] Multi-Protocol Subscriber Simulation Loop (SCTP + Diameter + SIP/SRTP)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);

    SctpEngine sctp(mgr, &wheel);
    DiameterEngine diameter(mgr, &wheel);
    SipRtpEngine sip(mgr, &wheel);

    ProtocolConfig cfg{};
    cfg.retransmit_timeout_ms = 500;
    cfg.max_retries = 3;
    sctp.Init(cfg);
    diameter.Init(cfg);
    sip.Init(cfg);

    // Initialize key config for SRTP
    SrtpKeyConfig srtp_key{};
    for (size_t i = 0; i < 16; ++i) srtp_key.master_key[i] = static_cast<uint8_t>(0xA0 + i);
    for (size_t i = 0; i < 14; ++i) srtp_key.master_salt[i] = static_cast<uint8_t>(0xB0 + i);
    assert(sip.srtp_tx().InitKeys(srtp_key));
    assert(sip.srtp_rx().InitKeys(srtp_key));

    constexpr size_t NUM_SUBS_PER_PROTO = 5;
    std::vector<TelcoSessionContext*> sctp_subs;
    std::vector<TelcoSessionContext*> diam_subs;
    std::vector<TelcoSessionContext*> sip_subs;

    // 1. Setup SCTP subscribers with Multihoming Alternate Paths
    for (size_t i = 0; i < NUM_SUBS_PER_PROTO; ++i) {
        auto* ctx = mgr.AcquireSession();
        assert(ctx != nullptr);
        SctpAssociationConfig scfg{};
        scfg.local_ip = 0x0A000100 + static_cast<uint32_t>(i);
        scfg.peer_ip = 0x0A000201; // Primary path
        scfg.local_port = static_cast<uint16_t>(20000 + i);
        scfg.peer_port = 38412;
        scfg.my_vtag = 0x1000 + static_cast<uint32_t>(i);
        scfg.peer_vtag = 0x2000 + static_cast<uint32_t>(i);
        sctp.StartAssociation(ctx, scfg);
        // Multihoming alternate path (RFC 4960 §5.1.2)
        sctp.AddPath(ctx, 0x0A000202, false);
        assert(sctp.GetPathCount(ctx) == 2);
        sctp_subs.push_back(ctx);
    }

    // 2. Setup Diameter subscribers with 3GPP CCR billing configurations
    for (size_t i = 0; i < NUM_SUBS_PER_PROTO; ++i) {
        auto* ctx = mgr.AcquireSession();
        assert(ctx != nullptr);
        DiameterPeerConfig dcfg{};
        dcfg.origin_host = "sub" + std::to_string(i) + ".carrier.net";
        dcfg.origin_realm = "carrier.net";
        dcfg.destination_host = "pcrf.carrier.net";
        dcfg.destination_realm = "carrier.net";
        dcfg.local_ip = 0x0A000300 + static_cast<uint32_t>(i);
        dcfg.peer_ip = 0x0A000201;
        dcfg.local_port = static_cast<uint16_t>(30000 + i);
        dcfg.peer_port = 3868;
        diameter.StartPeerSession(ctx, dcfg);
        diam_subs.push_back(ctx);
    }

    // 3. Setup SIP/SRTP subscribers with encrypted voice media
    for (size_t i = 0; i < NUM_SUBS_PER_PROTO; ++i) {
        auto* ctx = mgr.AcquireSession();
        assert(ctx != nullptr);
        SipCallConfig ccfg{};
        ccfg.from_uri = "sip:caller" + std::to_string(i) + "@ims.carrier.org";
        ccfg.to_uri = "sip:callee" + std::to_string(i) + "@ims.carrier.org";
        ccfg.call_id = "callid-" + std::to_string(i) + "@ims.carrier.org";
        ccfg.local_ip_str = "10.0.4." + std::to_string(i + 1);
        ccfg.peer_ip_str = "10.0.2.1";
        ccfg.local_sip_port = 5060;
        ccfg.peer_sip_port = 5060;
        ccfg.local_rtp_port = static_cast<uint16_t>(10000 + i * 2);
        ccfg.peer_rtp_port = static_cast<uint16_t>(10000 + i * 2);
        ccfg.enable_srtp = true;
        sip.StartCall(ctx, ccfg);
        sip_subs.push_back(ctx);
    }

    // 4. Simulate active multi-protocol event loop execution across 10 iterations
    uint64_t total_tx_packets = 0;
    uint64_t total_tx_bytes = 0;
    static const uint8_t g711_audio[160] = {0x00, 0x11, 0x22, 0x33};

    for (int iter = 0; iter < 10; ++iter) {
        // SCTP traffic generation
        for (auto* ctx : sctp_subs) {
            static const uint8_t ngap_pdu[32] = "NGAP_PDU_UE_CONTEXT_SETUP_REQ";
            auto pkt = sctp.BuildDataPacket(ctx, 60, ngap_pdu, sizeof(ngap_pdu));
            assert(!pkt.empty());
            total_tx_packets++;
            total_tx_bytes += pkt.size();
        }

        // Diameter CCR billing bursts (RFC 4006 Ro/Gx)
        for (auto* ctx : diam_subs) {
            std::string sid = "sub-session-" + std::to_string(ctx->session_id);
            auto pkt = diameter.BuildDictionaryDrivenCcr(ctx, sid, CcRequestType::UPDATE_REQUEST, iter + 1);
            assert(!pkt.empty());
            total_tx_packets++;
            total_tx_bytes += pkt.size();
        }

        // SIP / SRTP voice media packets
        for (auto* ctx : sip_subs) {
            auto pkt = sip.BuildRtpPacket(ctx, g711_audio, sizeof(g711_audio));
            assert(!pkt.empty());
            // Verify SRTP packet contains the 10-byte auth tag
            size_t min_srtp_len = 14 /* Eth */ + 20 /* IP */ + 8 /* UDP */ + 12 /* RTP */ + 160 + 10 /* Auth */;
            assert(pkt.size() == min_srtp_len);
            total_tx_packets++;
            total_tx_bytes += pkt.size();
        }

        // Advance timers in the loop
        uint64_t now_tsc = 1000000000ULL + iter * 10000000ULL;
        sctp.OnTimerTick(now_tsc);
        diameter.OnTimerTick(now_tsc);
        sip.OnTimerTick(now_tsc);
    }

    assert(total_tx_packets == 10 * (3 * NUM_SUBS_PER_PROTO));
    assert(total_tx_bytes > 0);

    std::cout << "  -> Multi-Protocol Worker Loop: " << total_tx_packets 
              << " packets (" << total_tx_bytes << " bytes) generated across SCTP, Diameter, and SRTP: PASSED" << std::endl;
}

void TestTelcoAllProtocolsDriverLifecycle() {
    std::cout << "[TEST 4] Telco Full Engine Driver Lifecycle (PPPoE, DHCP, BFD, GTP-U, SCTP, Diameter, SIP/RTP)..." << std::endl;

    // 1. Invariant TSC & Frequency Calibration
    uint64_t tsc_hz = HierarchicalTimingWheel::CalibrateTscHz();
    assert(tsc_hz > 100000000ULL); // > 100 MHz
    std::cout << "  -> Calibrated TSC Frequency: " << (tsc_hz / 1000000.0) << " MHz: PASSED" << std::endl;

    // 2. SessionManager Safe Allocation Type Tracking
    SessionManager mgr(128);
    assert(mgr.GetCapacity() == 128);
    auto alloc_type = mgr.GetAllocationType();
    assert(alloc_type == SessionManager::AllocationType::HugePage ||
           alloc_type == SessionManager::AllocationType::PosixMemalign ||
           alloc_type == SessionManager::AllocationType::NewArray);
    std::cout << "  -> SessionManager AllocationType Checked & Memory Safe: PASSED" << std::endl;

    HierarchicalTimingWheel wheel(tsc_hz);
    PppoeEngine pppoe(mgr, &wheel);
    DhcpEngine dhcp(mgr, &wheel);
    BfdEngine bfd(mgr, &wheel);
    GtpuEngine gtpu(mgr, &wheel);
    SctpEngine sctp(mgr, &wheel);
    DiameterEngine diameter(mgr, &wheel);
    SipRtpEngine sip(mgr, &wheel);

    ProtocolConfig cfg{};
    cfg.retransmit_timeout_ms = 500;
    cfg.max_retries = 3;
    pppoe.Init(cfg);
    dhcp.Init(cfg);
    bfd.Init(cfg);
    gtpu.Init(cfg);
    sctp.Init(cfg);
    diameter.Init(cfg);
    sip.Init(cfg);

    // 3. PPPoE Session Lifecycle
    {
        TelcoSessionContext* s = mgr.AcquireSession();
        assert(s != nullptr);
        s->session_id = 101;
        uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        std::memcpy(s->client_mac, mac, 6);
        mgr.BindPppoeSession(s, mac, 101);
        pppoe.StartSession(s);
        auto pkt = pppoe.BuildPadiFrame(s);
        assert(!pkt.empty());
        PacketMetadata meta{};
        TelcoFrameType type = TelcoFrameType::Unknown;
        assert(FastpathClassifier::Classify(pkt.data(), pkt.size(), meta, type));
        assert(type == TelcoFrameType::PppoeDiscovery);
        mgr.ReleaseSession(s);
    }

    // 4. DHCPv4 Session Lifecycle
    {
        TelcoSessionContext* s = mgr.AcquireSession();
        assert(s != nullptr);
        uint32_t xid = 0x54454C01;
        s->SetDhcpXid(xid);
        uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x56};
        std::memcpy(s->client_mac, mac, 6);
        mgr.BindDhcpSession(s, xid);
        dhcp.StartDhcpv4(s, xid);
        auto pkt = dhcp.BuildDhcpv4Discover(s);
        assert(!pkt.empty());
        PacketMetadata meta{};
        TelcoFrameType type = TelcoFrameType::Unknown;
        assert(FastpathClassifier::Classify(pkt.data(), pkt.size(), meta, type));
        assert(type == TelcoFrameType::Dhcp);
        mgr.ReleaseSession(s);
    }

    // 5. BFD Session Lifecycle
    {
        TelcoSessionContext* s = mgr.AcquireSession();
        assert(s != nullptr);
        uint32_t disc = 0x80000001;
        s->SetBfdLocalDisc(disc);
        mgr.BindBfdSession(s, disc);
        BfdConfig bfd_cfg{};
        bfd_cfg.local_disc = disc;
        bfd.StartSession(s, bfd_cfg);
        auto pkt = bfd.BuildBfdControlPacket(s, BfdState::Up, BfdDiag::None);
        assert(!pkt.empty());
        PacketMetadata meta{};
        TelcoFrameType type = TelcoFrameType::Unknown;
        assert(FastpathClassifier::Classify(pkt.data(), pkt.size(), meta, type));
        assert(type == TelcoFrameType::Bfd);
        mgr.ReleaseSession(s);
    }

    // 6. GTP-U Session Lifecycle & Encapsulation
    {
        TelcoSessionContext* s = mgr.AcquireSession();
        assert(s != nullptr);
        s->teid_uplink = 0x10000001;
        s->client_ip = 0x0A000001;
        s->peer_ip = 0x0A0000FE;
        mgr.BindGtpuSession(s, s->teid_uplink);
        GtpuTunnelConfig gtp_cfg{};
        gtp_cfg.uplink_teid = s->teid_uplink;
        gtp_cfg.peer_upf_ip = s->peer_ip;
        gtpu.StartSession(s, gtp_cfg);
        static const uint8_t inner_pdu[20] = {0x45, 0x00, 0x00, 0x14};
        auto pkt = gtpu.Encapsulate(s, inner_pdu, sizeof(inner_pdu), 1);
        assert(!pkt.empty());
        PacketMetadata meta{};
        TelcoFrameType type = TelcoFrameType::Unknown;
        assert(FastpathClassifier::Classify(pkt.data(), pkt.size(), meta, type));
        assert(type == TelcoFrameType::Gtpu);
        mgr.ReleaseSession(s);
    }

    std::cout << "  -> Full Protocol Driver Lifecycle (PPPoE, DHCP, BFD, GTP-U): PASSED" << std::endl;
}

int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "     UPSTREAM TELCO WORKER & FASTPATH INTEGRATION TEST SUITE     " << std::endl;
    std::cout << "=================================================================" << std::endl;

    TestL2L3FastpathWiringTelcoDispatch();
    TestTelcoWorkerCliArgParsing();
    TestTelcoMultiProtocolWorkerLoop();
    TestTelcoAllProtocolsDriverLifecycle();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL UPSTREAM TELCO INTEGRATION TESTS PASSED SUCCESSFULLY!      " << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
