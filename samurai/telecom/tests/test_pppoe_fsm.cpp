#include "samurai/telecom/core/session_context.hpp"
#include "samurai/telecom/core/session_manager.hpp"
#include "samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "samurai/telecom/protocols/stateful/pppoe/pppoe_engine.hpp"
#include "samurai/telecom/protocols/stateful/pppoe/pppoe_types.hpp"
#include "samurai/telecom/protocols/stateful/pppoe/pppoe_fsm.hpp"

#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace samurai::telecom;
using namespace samurai::telecom::pppoe;

// BRAS Emülatör Yardımcıları (Test için BRAS yanıtları üretir)
std::vector<uint8_t> BuildBrasPado(const uint8_t client_mac[6], const uint8_t bras_mac[6],
                                   const std::string& ac_name, const std::string& cookie) {
    std::vector<uint8_t> frame;
    frame.reserve(128);

    // Eth
    for (int i = 0; i < 6; ++i) frame.push_back(client_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(bras_mac[i]);
    frame.push_back(0x88); frame.push_back(0x63);

    size_t tag_len = sizeof(PppoeTag) + ac_name.size() + sizeof(PppoeTag) + cookie.size();

    // PPPoE PADO
    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::PADO));
    frame.push_back(0x00); frame.push_back(0x00);
    frame.push_back((tag_len >> 8) & 0xFF);
    frame.push_back(tag_len & 0xFF);

    // Tag AC-Name
    frame.push_back(0x01); frame.push_back(0x02);
    frame.push_back((ac_name.size() >> 8) & 0xFF);
    frame.push_back(ac_name.size() & 0xFF);
    for (char c : ac_name) frame.push_back(static_cast<uint8_t>(c));

    // Tag AC-Cookie
    frame.push_back(0x01); frame.push_back(0x04);
    frame.push_back((cookie.size() >> 8) & 0xFF);
    frame.push_back(cookie.size() & 0xFF);
    for (char c : cookie) frame.push_back(static_cast<uint8_t>(c));

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> BuildBrasPads(const uint8_t client_mac[6], const uint8_t bras_mac[6], uint16_t session_id) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(client_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(bras_mac[i]);
    frame.push_back(0x88); frame.push_back(0x63);

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::PADS));
    frame.push_back((session_id >> 8) & 0xFF);
    frame.push_back(session_id & 0xFF);
    frame.push_back(0x00); frame.push_back(0x00);

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> BuildBrasLcpConfReq(const uint8_t client_mac[6], const uint8_t bras_mac[6],
                                        uint16_t session_id, uint8_t identifier) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(client_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(bras_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = 4 + 4 + 5; // MRU (4) + Auth CHAP (5)
    uint16_t pppoe_len = sizeof(PppHeader) + ppp_ctrl_len;

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session_id >> 8) & 0xFF);
    frame.push_back(session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0xC0); frame.push_back(0x21); // LCP

    frame.push_back(static_cast<uint8_t>(LcpCode::CONF_REQ));
    frame.push_back(identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    // Option: MRU 1492
    frame.push_back(LCP_OPT_MRU); frame.push_back(4);
    frame.push_back(0x05); frame.push_back(0xD4);

    // Option: Auth Protocol CHAP (0xC223, Algorithm 5 = MD5)
    frame.push_back(LCP_OPT_AUTH); frame.push_back(5);
    frame.push_back(0xC2); frame.push_back(0x23); frame.push_back(0x05);

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> BuildBrasLcpConfAck(const uint8_t client_mac[6], const uint8_t bras_mac[6],
                                        uint16_t session_id, uint8_t identifier) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(client_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(bras_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = 4;
    uint16_t pppoe_len = sizeof(PppHeader) + ppp_ctrl_len;

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session_id >> 8) & 0xFF);
    frame.push_back(session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0xC0); frame.push_back(0x21);

    frame.push_back(static_cast<uint8_t>(LcpCode::CONF_ACK));
    frame.push_back(identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> BuildBrasChapChallenge(const uint8_t client_mac[6], const uint8_t bras_mac[6],
                                           uint16_t session_id, uint8_t identifier,
                                           const uint8_t challenge[16]) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(client_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(bras_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = 4 + 1 + 16 + 8; // Header + Value-size + 16-byte challenge + 8-byte name "BRAS-01"
    uint16_t pppoe_len = sizeof(PppHeader) + ppp_ctrl_len;

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session_id >> 8) & 0xFF);
    frame.push_back(session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0xC2); frame.push_back(0x23); // CHAP

    frame.push_back(static_cast<uint8_t>(ChapCode::CHALLENGE));
    frame.push_back(identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    frame.push_back(16); // challenge length
    for (int i = 0; i < 16; ++i) frame.push_back(challenge[i]);

    const char* bras_name = "BRAS-01";
    for (int i = 0; i < 7; ++i) frame.push_back(static_cast<uint8_t>(bras_name[i]));

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> BuildBrasChapSuccess(const uint8_t client_mac[6], const uint8_t bras_mac[6],
                                         uint16_t session_id, uint8_t identifier) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(client_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(bras_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    const char* msg = "Welcome!";
    uint16_t ppp_ctrl_len = static_cast<uint16_t>(4 + std::strlen(msg));
    uint16_t pppoe_len = sizeof(PppHeader) + ppp_ctrl_len;

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session_id >> 8) & 0xFF);
    frame.push_back(session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0xC2); frame.push_back(0x23);

    frame.push_back(static_cast<uint8_t>(ChapCode::SUCCESS));
    frame.push_back(identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    for (size_t i = 0; i < std::strlen(msg); ++i) frame.push_back(static_cast<uint8_t>(msg[i]));

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> BuildBrasIpcpConfNak(const uint8_t client_mac[6], const uint8_t bras_mac[6],
                                         uint16_t session_id, uint8_t identifier,
                                         uint32_t assigned_ip, uint32_t dns1) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(client_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(bras_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = 4 + 6 + 6; // IP option (6) + DNS1 option (6)
    uint16_t pppoe_len = sizeof(PppHeader) + ppp_ctrl_len;

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session_id >> 8) & 0xFF);
    frame.push_back(session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0x80); frame.push_back(0x21); // IPCP

    frame.push_back(static_cast<uint8_t>(LcpCode::CONF_NAK));
    frame.push_back(identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    // IP Option
    frame.push_back(IPCP_OPT_IP); frame.push_back(6);
    frame.push_back((assigned_ip >> 24) & 0xFF);
    frame.push_back((assigned_ip >> 16) & 0xFF);
    frame.push_back((assigned_ip >> 8) & 0xFF);
    frame.push_back(assigned_ip & 0xFF);

    // DNS1 Option
    frame.push_back(IPCP_OPT_PRIMARY_DNS); frame.push_back(6);
    frame.push_back((dns1 >> 24) & 0xFF);
    frame.push_back((dns1 >> 16) & 0xFF);
    frame.push_back((dns1 >> 8) & 0xFF);
    frame.push_back(dns1 & 0xFF);

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

std::vector<uint8_t> BuildBrasIpcpConfAck(const uint8_t client_mac[6], const uint8_t bras_mac[6],
                                         uint16_t session_id, uint8_t identifier,
                                         uint32_t assigned_ip, uint32_t dns1) {
    std::vector<uint8_t> frame;
    frame.reserve(64);

    for (int i = 0; i < 6; ++i) frame.push_back(client_mac[i]);
    for (int i = 0; i < 6; ++i) frame.push_back(bras_mac[i]);
    frame.push_back(0x88); frame.push_back(0x64);

    uint16_t ppp_ctrl_len = 4 + 6 + 6;
    uint16_t pppoe_len = sizeof(PppHeader) + ppp_ctrl_len;

    frame.push_back(0x11);
    frame.push_back(static_cast<uint8_t>(PppoeCode::DATA));
    frame.push_back((session_id >> 8) & 0xFF);
    frame.push_back(session_id & 0xFF);
    frame.push_back((pppoe_len >> 8) & 0xFF);
    frame.push_back(pppoe_len & 0xFF);

    frame.push_back(0x80); frame.push_back(0x21);

    frame.push_back(static_cast<uint8_t>(LcpCode::CONF_ACK));
    frame.push_back(identifier);
    frame.push_back((ppp_ctrl_len >> 8) & 0xFF);
    frame.push_back(ppp_ctrl_len & 0xFF);

    frame.push_back(IPCP_OPT_IP); frame.push_back(6);
    frame.push_back((assigned_ip >> 24) & 0xFF);
    frame.push_back((assigned_ip >> 16) & 0xFF);
    frame.push_back((assigned_ip >> 8) & 0xFF);
    frame.push_back(assigned_ip & 0xFF);

    frame.push_back(IPCP_OPT_PRIMARY_DNS); frame.push_back(6);
    frame.push_back((dns1 >> 24) & 0xFF);
    frame.push_back((dns1 >> 16) & 0xFF);
    frame.push_back((dns1 >> 8) & 0xFF);
    frame.push_back(dns1 & 0xFF);

    while (frame.size() < 60) frame.push_back(0x00);
    return frame;
}

// ---------------------------------------------------------------------------
// Ana Test Senaryosu: Uçtan Uca PPPoE Yaşam Döngüsü (PADI -> ESTABLISHED -> PADT)
// ---------------------------------------------------------------------------

void TestPppoeFullLifecycle() {
    std::cout << "[TEST] 1. PPPoE Full Lifecycle (PADI -> PADO -> PADR -> PADS -> LCP -> CHAP -> IPCP -> ESTABLISHED)..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    PppoeEngine engine(mgr, &wheel);

    ProtocolConfig cfg{};
    cfg.retransmit_timeout_ms = 500;
    cfg.max_retries = 3;
    engine.Init(cfg);
    engine.SetCredentials("test_subscriber", "samurai_secret", AuthProtocol::CHAP);

    TelcoSessionContext* session = mgr.AcquireSession();
    assert(session != nullptr);

    uint8_t client_mac[6] = {0x00, 0x50, 0x56, 0x12, 0x34, 0x56};
    uint8_t bras_mac[6]   = {0x00, 0x1B, 0x21, 0xAA, 0xBB, 0xCC};
    std::memcpy(session->client_mac, client_mac, 6);

    // 1. Discovery Başlat: PADI
    engine.StartSession(session);
    assert(session->state == SessionState::DISCOVERING);
    assert(engine.GetSubState(session) == PppoeSubState::DISCOVERY_PADI_SENT);
    assert(!engine.GetLastTxFrame().empty());

    // PADI kontrol
    const auto& padi = engine.GetLastTxFrame();
    assert(padi[12] == 0x88 && padi[13] == 0x63); // 0x8863
    assert(padi[15] == static_cast<uint8_t>(PppoeCode::PADI));

    // 2. BRAS PADO Gönderir
    auto pado = BuildBrasPado(client_mac, bras_mac, "Samurai-BRAS-1", "cookie_token_99");
    bool ok = engine.ProcessRxFrame(pado.data(), pado.size(), session);
    assert(ok);
    assert(engine.GetSubState(session) == PppoeSubState::DISCOVERY_PADR_SENT);
    assert(std::memcmp(session->peer_mac, bras_mac, 6) == 0);

    // PADR kontrol
    const auto& padr = engine.GetLastTxFrame();
    assert(padr[15] == static_cast<uint8_t>(PppoeCode::PADR));

    // 3. BRAS PADS Gönderir (Session ID = 0x2A10)
    uint16_t session_id = 0x2A10;
    auto pads = BuildBrasPads(client_mac, bras_mac, session_id);
    ok = engine.ProcessRxFrame(pads.data(), pads.size(), session);
    assert(ok);
    assert(session->state == SessionState::AUTHENTICATING);
    assert(engine.GetSubState(session) == PppoeSubState::LCP_REQ_SENT);
    assert(session->session_id == session_id);

    // SessionManager'da PPPoE MAC + ID ile bulunabilmeli
    assert(mgr.FindPppoeSession(client_mac, session_id) == session);

    // 4. LCP Pazarlığı
    // İstemci LCP Conf-Req gönderdi
    const auto& lcp_req = engine.GetLastTxFrame();
    assert(lcp_req[12] == 0x88 && lcp_req[13] == 0x64); // Session
    assert(lcp_req[20] == 0xC0 && lcp_req[21] == 0x21); // LCP

    // BRAS kendi Conf-Req'ini gönderir
    auto bras_lcp_req = BuildBrasLcpConfReq(client_mac, bras_mac, session_id, 1);
    ok = engine.ProcessRxFrame(bras_lcp_req.data(), bras_lcp_req.size(), session);
    assert(ok);

    // BRAS istemcinin Conf-Req'ini Ack'ler
    auto bras_lcp_ack = BuildBrasLcpConfAck(client_mac, bras_mac, session_id, 1);
    ok = engine.ProcessRxFrame(bras_lcp_ack.data(), bras_lcp_ack.size(), session);
    assert(ok);
    assert(engine.GetSubState(session) == PppoeSubState::LCP_OPENED);

    // 5. CHAP Kimlik Doğrulaması
    uint8_t challenge[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    auto chap_challenge = BuildBrasChapChallenge(client_mac, bras_mac, session_id, 5, challenge);
    ok = engine.ProcessRxFrame(chap_challenge.data(), chap_challenge.size(), session);
    assert(ok);
    assert(engine.GetSubState(session) == PppoeSubState::CHAP_RESP_SENT);

    // İstemcinin CHAP Response ürettiğini doğrula
    const auto& chap_resp = engine.GetLastTxFrame();
    assert(chap_resp[20] == 0xC2 && chap_resp[21] == 0x23); // CHAP
    assert(chap_resp[22] == static_cast<uint8_t>(ChapCode::RESPONSE));

    // BRAS CHAP Success döner
    auto chap_success = BuildBrasChapSuccess(client_mac, bras_mac, session_id, 5);
    ok = engine.ProcessRxFrame(chap_success.data(), chap_success.size(), session);
    assert(ok);
    assert(engine.GetSubState(session) == PppoeSubState::IPCP_REQ_SENT);

    // 6. IPCP Pazarlığı
    // İstemci IP=0.0.0.0 ile Conf-Req gönderdi
    const auto& ipcp_req = engine.GetLastTxFrame();
    assert(ipcp_req[20] == 0x80 && ipcp_req[21] == 0x21); // IPCP

    // BRAS Nak ile IP adresi tahsis eder (100.64.10.25)
    uint32_t allocated_ip = 0x64400A19; // 100.64.10.25
    uint32_t dns1 = 0x08080808;         // 8.8.8.8
    auto ipcp_nak = BuildBrasIpcpConfNak(client_mac, bras_mac, session_id, 1, allocated_ip, dns1);
    ok = engine.ProcessRxFrame(ipcp_nak.data(), ipcp_nak.size(), session);
    assert(ok);
    assert(session->client_ip == allocated_ip);
    assert(engine.GetSubState(session) == PppoeSubState::IPCP_NAK_RCVD);

    // BRAS tahsis edilen IP ile Conf-Ack döner
    auto ipcp_ack = BuildBrasIpcpConfAck(client_mac, bras_mac, session_id, 1, allocated_ip, dns1);
    ok = engine.ProcessRxFrame(ipcp_ack.data(), ipcp_ack.size(), session);
    assert(ok);

    // Oturum ESTABLISHED oldu!
    assert(session->state == SessionState::ESTABLISHED);
    assert(engine.GetSubState(session) == PppoeSubState::ESTABLISHED);

    // 5-Tuple tablosunda aktif olmalı
    TelcoSessionContext* flow_ctx = mgr.FindSessionBy5Tuple(allocated_ip, 0, 0, 0, 0);
    assert(flow_ctx == session);

    // 7. LCP Echo Keepalive Testi
    // 1 saniye sonraki zamanlayıcı tikinde Echo-Req gönderilmeli
    uint64_t tsc_now = 5000000000ULL;
    engine.OnTimerTick(tsc_now); // Initialize wheel
    engine.OnTimerTick(tsc_now + 1200 * (2400000000ULL / 1000ULL)); // 1.2s tick
    const auto& echo_req = engine.GetLastTxFrame();
    assert(echo_req[20] == 0xC0 && echo_req[21] == 0x21);
    assert(echo_req[22] == static_cast<uint8_t>(LcpCode::ECHO_REQ));

    // 8. Oturum Sonlandırma: PADT
    engine.TerminateSession(session);
    assert(session->state == SessionState::TERMINATING);
    const auto& padt = engine.GetLastTxFrame();
    assert(padt[15] == static_cast<uint8_t>(PppoeCode::PADT));

    mgr.ReleaseSession(session);
    std::cout << "  -> PPPoE Full Lifecycle (PADI -> ESTABLISHED -> Keepalive -> PADT): PASSED" << std::endl;
}

void TestPppoeTimeoutAndRetries() {
    std::cout << "[TEST] 2. PPPoE Timeout Retransmission & Failure Gate..." << std::endl;

    SessionManager mgr(50);
    HierarchicalTimingWheel wheel(2400000000ULL);
    PppoeEngine engine(mgr, &wheel);

    ProtocolConfig cfg{};
    cfg.retransmit_timeout_ms = 100;
    cfg.max_retries = 2; // Sadece 2 yeniden deneme
    engine.Init(cfg);

    TelcoSessionContext* session = mgr.AcquireSession();
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x77};
    std::memcpy(session->client_mac, mac, 6);

    uint64_t tsc = 10000000000ULL;
    uint64_t tsc_per_ms = 2400000ULL;
    wheel.Advance(tsc, [](TelcoSessionContext*) {});

    engine.StartSession(session);
    assert(session->state == SessionState::DISCOVERING);
    assert(session->retry_count == 0);

    // 1. Timeout (100ms) -> Retry 1
    engine.OnTimerTick(tsc + 110 * tsc_per_ms);
    assert(session->state == SessionState::DISCOVERING);
    assert(session->retry_count == 1);

    // 2. Timeout (200ms) -> Retry 2
    engine.OnTimerTick(tsc + 220 * tsc_per_ms);
    assert(session->state == SessionState::DISCOVERING);
    assert(session->retry_count == 2);

    // 3. Timeout (300ms) -> Exceeded max_retries -> FAILED
    engine.OnTimerTick(tsc + 330 * tsc_per_ms);
    assert(session->state == SessionState::FAILED);
    assert(engine.GetSubState(session) == PppoeSubState::FAILED);

    mgr.ReleaseSession(session);
    std::cout << "  -> PPPoE Retransmission & Max-Retries Failure Transition: PASSED" << std::endl;
}

void TestMalformedFramesSafety() {
    std::cout << "[TEST] 3. Malformed / Truncated Frames Crash & Underflow Resistance..." << std::endl;

    SessionManager mgr(10);
    HierarchicalTimingWheel wheel(2400000000ULL);
    PppoeEngine engine(mgr, &wheel);

    ProtocolConfig cfg{};
    engine.Init(cfg);

    TelcoSessionContext* session = mgr.AcquireSession();
    uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::memcpy(session->client_mac, mac, 6);

    // 1. Null / Under-length frames (< 14 bytes)
    assert(!engine.ProcessRxFrame(nullptr, 0, session));
    uint8_t short_frame[10] = {0};
    assert(!engine.ProcessRxFrame(short_frame, sizeof(short_frame), session));

    // 2. Truncated LCP Header (ctrl_len < sizeof(PppControlHeader))
    // Ethernet (14) + PPPoE Session (6) + PPP (2) + Malformed LCP (4)
    std::vector<uint8_t> malformed_lcp = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst mac
        0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // src mac
        0x88, 0x64,                         // Ethertype: PPPoE Session
        0x11, 0x00, 0x00, 0x01, 0x00, 0x06, // PPPoE: Ver/Type=1, Code=0, Session=1, Len=6
        0xC0, 0x21,                         // PPP Protocol: LCP
        0x01, 0x01, 0x00, 0x02              // LCP: Code=Conf-Req, Id=1, Length=2 (< 4, would underflow!)
    };
    bool ok = engine.ProcessRxFrame(malformed_lcp.data(), malformed_lcp.size(), session);
    assert(ok); // Returns true (packet processed/consumed) without crashing or underflow!

    // 3. Truncated CHAP frame (ctrl_len < 4)
    std::vector<uint8_t> malformed_chap = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0x88, 0x64,
        0x11, 0x00, 0x00, 0x01, 0x00, 0x05,
        0xC2, 0x23,                         // CHAP
        0x01, 0x01, 0x00, 0x03              // CHAP: Length=3 (< 4)
    };
    ok = engine.ProcessRxFrame(malformed_chap.data(), malformed_chap.size(), session);
    assert(ok);

    // 4. Truncated IPCP frame
    std::vector<uint8_t> malformed_ipcp = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0x88, 0x64,
        0x11, 0x00, 0x00, 0x01, 0x00, 0x05,
        0x80, 0x21,                         // IPCP
        0x01, 0x01, 0x00, 0x01              // IPCP: Length=1 (< 4)
    };
    ok = engine.ProcessRxFrame(malformed_ipcp.data(), malformed_ipcp.size(), session);
    assert(ok);

    // 5. Truncated PAP frame
    std::vector<uint8_t> malformed_pap = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0x88, 0x64,
        0x11, 0x00, 0x00, 0x01, 0x00, 0x05,
        0xC0, 0x23,                         // PAP
        0x01, 0x01, 0x00, 0x02              // PAP: Length=2 (< 4)
    };
    ok = engine.ProcessRxFrame(malformed_pap.data(), malformed_pap.size(), session);
    assert(ok);

    mgr.ReleaseSession(session);
    std::cout << "  -> Malformed Frames Fuzz / Bounds Protection: PASSED (No Crash)" << std::endl;
}

void TestVlanTaggedPppoe() {
    std::cout << "[TEST] 4. 802.1Q Single VLAN & 802.1ad QinQ Tagged Discovery..." << std::endl;

    SessionManager mgr(10);
    HierarchicalTimingWheel wheel(2400000000ULL);
    PppoeEngine engine(mgr, &wheel);

    ProtocolConfig cfg{};
    engine.Init(cfg);

    TelcoSessionContext* session = mgr.AcquireSession();
    uint8_t client_mac[6] = {0x00, 0x50, 0x56, 0xAA, 0xBB, 0xCC};
    uint8_t bras_mac[6]   = {0x00, 0x1B, 0x21, 0x11, 0x22, 0x33};
    std::memcpy(session->client_mac, client_mac, 6);

    engine.StartSession(session);
    assert(engine.GetSubState(session) == PppoeSubState::DISCOVERY_PADI_SENT);

    // 1. Single 802.1Q tagged PADO (VLAN 100)
    std::vector<uint8_t> vlan_pado;
    vlan_pado.reserve(128);
    for (int i = 0; i < 6; ++i) vlan_pado.push_back(client_mac[i]);
    for (int i = 0; i < 6; ++i) vlan_pado.push_back(bras_mac[i]);
    vlan_pado.push_back(0x81); vlan_pado.push_back(0x00); // 802.1Q
    vlan_pado.push_back(0x00); vlan_pado.push_back(0x64); // VLAN ID = 100
    vlan_pado.push_back(0x88); vlan_pado.push_back(0x63); // PPPoE Discovery
    // PPPoE PADO
    std::string cookie = "vlan_cookie_42";
    size_t tag_len = sizeof(PppoeTag) + cookie.size();
    vlan_pado.push_back(0x11);
    vlan_pado.push_back(static_cast<uint8_t>(PppoeCode::PADO));
    vlan_pado.push_back(0x00); vlan_pado.push_back(0x00);
    vlan_pado.push_back((tag_len >> 8) & 0xFF);
    vlan_pado.push_back(tag_len & 0xFF);
    // AC-Cookie
    vlan_pado.push_back(0x01); vlan_pado.push_back(0x04);
    vlan_pado.push_back((cookie.size() >> 8) & 0xFF);
    vlan_pado.push_back(cookie.size() & 0xFF);
    for (char c : cookie) vlan_pado.push_back(static_cast<uint8_t>(c));
    while (vlan_pado.size() < 64) vlan_pado.push_back(0x00);

    bool ok = engine.ProcessRxFrame(vlan_pado.data(), vlan_pado.size(), session);
    assert(ok);
    assert(engine.GetSubState(session) == PppoeSubState::DISCOVERY_PADR_SENT);
    assert(session->c_vlan == 100);
    assert(std::memcmp(session->peer_mac, bras_mac, 6) == 0);

    // 2. QinQ (802.1ad S-VLAN 100 + 802.1Q C-VLAN 200) PADS
    std::vector<uint8_t> qinq_pads;
    qinq_pads.reserve(128);
    for (int i = 0; i < 6; ++i) qinq_pads.push_back(client_mac[i]);
    for (int i = 0; i < 6; ++i) qinq_pads.push_back(bras_mac[i]);
    qinq_pads.push_back(0x88); qinq_pads.push_back(0xA8); // 802.1ad (S-Tag)
    qinq_pads.push_back(0x00); qinq_pads.push_back(0x64); // S-VLAN = 100
    qinq_pads.push_back(0x81); qinq_pads.push_back(0x00); // 802.1Q (C-Tag)
    qinq_pads.push_back(0x00); qinq_pads.push_back(0xC8); // C-VLAN = 200
    qinq_pads.push_back(0x88); qinq_pads.push_back(0x63); // PPPoE Discovery
    // PPPoE PADS (Session ID = 0x5566)
    uint16_t sid = 0x5566;
    qinq_pads.push_back(0x11);
    qinq_pads.push_back(static_cast<uint8_t>(PppoeCode::PADS));
    qinq_pads.push_back((sid >> 8) & 0xFF);
    qinq_pads.push_back(sid & 0xFF);
    qinq_pads.push_back(0x00); qinq_pads.push_back(0x00);
    while (qinq_pads.size() < 64) qinq_pads.push_back(0x00);

    ok = engine.ProcessRxFrame(qinq_pads.data(), qinq_pads.size(), session);
    assert(ok);
    assert(session->s_vlan == 100);
    assert(session->c_vlan == 200);
    assert(session->session_id == sid);
    assert(session->state == SessionState::AUTHENTICATING);
    assert(engine.GetSubState(session) == PppoeSubState::LCP_REQ_SENT);

    mgr.ReleaseSession(session);
    std::cout << "  -> 802.1Q Single VLAN & 802.1ad QinQ Demux and FSM Transition: PASSED" << std::endl;
}

int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "        SAMURAI PPPOE STATEFUL FSM VERIFICATION SUITE            " << std::endl;
    std::cout << "=================================================================" << std::endl;

    TestPppoeFullLifecycle();
    TestPppoeTimeoutAndRetries();
    TestMalformedFramesSafety();
    TestVlanTaggedPppoe();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL PPPOE FSM TESTS PASSED SUCCESSFULLY! (100% VERIFIED)       " << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
