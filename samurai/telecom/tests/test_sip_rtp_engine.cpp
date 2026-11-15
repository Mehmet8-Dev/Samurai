#include "samurai/telecom/protocols/stateful/sip_rtp/sip_rtp_engine.hpp"
#include "samurai/telecom/protocols/stateful/sip_rtp/sip_digest_auth.hpp"
#include "samurai/telecom/protocols/stateful/sip_rtp/srtp_engine.hpp"
#include "samurai/telecom/core/session_manager.hpp"
#include "samurai/telecom/core/hierarchical_timing_wheel.hpp"

#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>
#include <arpa/inet.h>
#include <openssl/evp.h>

using namespace samurai::telecom;
using namespace samurai::telecom::sip_rtp;

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

// ===========================================================================
// Test 1: SIP Digest Authentication Calculation (RFC 2617 & RFC 7616)
// ===========================================================================
void TestSipDigestAuthCalculation() {
    std::cout << "[TEST] 1. SIP Digest Auth Calculation (RFC 2617 & RFC 3261 Section 22)..." << std::endl;

    // RFC 2617 Section 3.5 official test vector
    std::string username = "Mufasa";
    std::string realm = "testrealm@host.com";
    std::string password = "Circle Of Life";
    std::string method = "GET";
    std::string uri = "/dir/index.html";
    std::string nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
    std::string nc = "00000001";
    std::string cnonce = "0a4f113b";
    std::string qop = "auth";

    // 1. Verify HA1 and HA2 MD5 calculations
    std::string ha1 = ComputeMd5Hex(username + ":" + realm + ":" + password);
    assert(ha1 == "939e7578ed9e3c518a452acee763bce9");

    std::string ha2 = ComputeMd5Hex(method + ":" + uri);
    assert(ha2 == "39aff3a2bab6126f332b942af96d3366");

    // 2. Verify RFC 2617 Digest Response with qop="auth"
    std::string response = CalculateDigestResponse(username, realm, password, method, uri, nonce, nc, cnonce, qop, "MD5");
    assert(response == "6629fae49393a05397450978507c4ef1");

    // 3. Verify RFC 2069 backward compatibility (no qop, no cnonce, no nc)
    std::string resp_no_qop = CalculateDigestResponse(username, realm, password, method, uri, nonce, "", "", "", "MD5");
    assert(resp_no_qop == "670fd8c2df070c60b045671b8b24ff02");

    // 4. Verify SHA-256 Digest response (RFC 7616 / RFC 8760)
    std::string resp_sha256 = CalculateDigestResponse(username, realm, password, method, uri, nonce, nc, cnonce, qop, "SHA-256");
    assert(resp_sha256 == "5abdd07184ba512a22c53f41470e5eea7dcaa3a93a59b630c13dfe0a5dc6e38b");

    // 5. Verify BuildAuthorizationHeader generator
    DigestCredentials creds;
    creds.username = username;
    creds.realm = realm;
    creds.nonce = nonce;
    creds.uri = uri;
    creds.response = response;
    creds.algorithm = "MD5";
    creds.cnonce = cnonce;
    creds.nc = nc;
    creds.qop = qop;
    creds.opaque = "5ccc069c403ebaf9f0171e9517f40e41";

    std::string auth_hdr = BuildAuthorizationHeader(creds, false);
    assert(auth_hdr.find("Authorization: Digest ") == 0);
    assert(auth_hdr.find("username=\"Mufasa\"") != std::string::npos);
    assert(auth_hdr.find("response=\"6629fae49393a05397450978507c4ef1\"") != std::string::npos);
    assert(auth_hdr.find("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"") != std::string::npos);

    // 6. Verify Proxy-Authorization header
    std::string proxy_hdr = BuildAuthorizationHeader(creds, true);
    assert(proxy_hdr.find("Proxy-Authorization: Digest ") == 0);

    std::cout << "  -> RFC 2617 & RFC 7616 SIP digest calculations: PASSED" << std::endl;
}

// ===========================================================================
// Test 2: SIP 401 Unauthorized Challenge Handshake (FSM Integration)
// ===========================================================================
void TestSip401UnauthorizedChallengeHandshake() {
    std::cout << "[TEST] 2. SIP 401 Challenge Handshake & CSeq Increment Re-INVITE..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SipRtpEngine client_engine(mgr, &wheel);

    ProtocolConfig cfg{};
    client_engine.Init(cfg);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    assert(client_ctx != nullptr);

    SipCallConfig call_cfg{};
    call_cfg.local_ip = 0x0A000001;
    call_cfg.peer_ip = 0x0A000002;
    call_cfg.from_uri = "sip:alice@samurai.local";
    call_cfg.to_uri = "sip:bob@operator.ims";
    call_cfg.auth_username = "alice";
    call_cfg.auth_password = "SecretPassword123!";
    call_cfg.auth_cnonce = "0a4f113b";
    call_cfg.auth_nc = 1;

    // Step 1: Initial INVITE sent (CSeq = 1)
    client_engine.StartCall(client_ctx, call_cfg);
    assert(client_engine.GetState(client_ctx) == SipCallState::CALLING);
    assert(client_engine.current_cseq() == 1);

    const auto& invite_1 = client_engine.last_tx_packet();
    std::string invite_str1(reinterpret_cast<const char*>(invite_1.data() + 42), invite_1.size() - 42);
    assert(invite_str1.find("CSeq: 1 INVITE") != std::string::npos);
    assert(invite_str1.find("Authorization:") == std::string::npos);

    // Step 2: Server responds with 401 Unauthorized containing WWW-Authenticate
    std::string challenge_401 = 
        "SIP/2.0 401 Unauthorized\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-samurai-1\r\n"
        "From: <sip:alice@samurai.local>;tag=tag-samurai-client\r\n"
        "To: <sip:bob@operator.ims>;tag=srv-1\r\n"
        "Call-ID: " + call_cfg.call_id + "\r\n"
        "CSeq: 1 INVITE\r\n"
        "WWW-Authenticate: Digest realm=\"operator.ims\", nonce=\"9a8b7c6d5e4f3a2b\", opaque=\"opq999\", algorithm=MD5, qop=\"auth\"\r\n"
        "Content-Length: 0\r\n\r\n";

    auto pkt_401 = BuildSimulatedUdpFrame(0x0A000002, 0x0A000001, 5060, 5060, challenge_401.data(), challenge_401.size());
    bool ok = client_engine.ProcessRxFrame(pkt_401.data(), pkt_401.size(), 1000);
    assert(ok);

    // Step 3: Verify client transitioned to AUTHENTICATING and incremented CSeq to 2
    assert(client_engine.GetState(client_ctx) == SipCallState::AUTHENTICATING);
    assert(client_engine.current_cseq() == 2);

    // Verify re-issued INVITE contains Authorization header with valid response
    const auto& invite_2 = client_engine.last_tx_packet();
    std::string invite_str2(reinterpret_cast<const char*>(invite_2.data() + 42), invite_2.size() - 42);
    assert(invite_str2.find("CSeq: 2 INVITE") != std::string::npos);
    assert(invite_str2.find("Authorization: Digest") != std::string::npos);
    assert(invite_str2.find("username=\"alice\"") != std::string::npos);
    assert(invite_str2.find("realm=\"operator.ims\"") != std::string::npos);
    assert(invite_str2.find("nonce=\"9a8b7c6d5e4f3a2b\"") != std::string::npos);

    // Step 4: Server accepts credentials and sends 200 OK
    std::string ok_200 = 
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-samurai-2\r\n"
        "From: <sip:alice@samurai.local>;tag=tag-samurai-client\r\n"
        "To: <sip:bob@operator.ims>;tag=srv-1\r\n"
        "Call-ID: " + call_cfg.call_id + "\r\n"
        "CSeq: 2 INVITE\r\n"
        "Content-Length: 0\r\n\r\n";

    auto pkt_200 = BuildSimulatedUdpFrame(0x0A000002, 0x0A000001, 5060, 5060, ok_200.data(), ok_200.size());
    ok = client_engine.ProcessRxFrame(pkt_200.data(), pkt_200.size(), 1001);
    assert(ok);

    // Step 5: Verify call is ESTABLISHED and ACK has CSeq 2
    assert(client_engine.GetState(client_ctx) == SipCallState::ESTABLISHED);
    const auto& ack_pkt = client_engine.last_tx_packet();
    std::string ack_str(reinterpret_cast<const char*>(ack_pkt.data() + 42), ack_pkt.size() - 42);
    assert(ack_str.find("ACK") == 0);
    assert(ack_str.find("CSeq: 2 ACK") != std::string::npos);

    std::cout << "  -> SIP 401 challenge handshake and authenticated re-INVITE: PASSED" << std::endl;
}

// ===========================================================================
// Test 3: SRTP Key Derivation Function Vectors (RFC 3711 Appendix B.3)
// ===========================================================================
void TestSrtpKeyDerivationVectors() {
    std::cout << "[TEST] 3. SRTP RFC 3711 Appendix B.3 Key Derivation Test Vectors..." << std::endl;

    // RFC 3711 Appendix B.3 Official Test Vectors
    // Master Key:  E1F97A0D3E018BE0D64FA32C06DE4139
    // Master Salt: 0EC675AD498AFEEBB6960B3AABE6
    SrtpKeyConfig cfg{};
    const uint8_t mk[16] = {
        0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0,
        0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39
    };
    const uint8_t ms[14] = {
        0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB,
        0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6
    };
    std::memcpy(cfg.master_key, mk, 16);
    std::memcpy(cfg.master_salt, ms, 14);

    uint8_t k_e[SRTP_SESSION_ENC_KEY_LEN];
    uint8_t k_a[SRTP_SESSION_AUTH_KEY_LEN];
    uint8_t k_s[SRTP_SESSION_SALT_LEN];

    bool ok = SrtpEngine::DeriveSessionKeys(cfg, k_e, k_a, k_s);
    assert(ok);

    // Expected cipher key: C61E7A93744F39EE10734AFE3FF7A087
    const uint8_t expected_ke[16] = {
        0xC6, 0x1E, 0x7A, 0x93, 0x74, 0x4F, 0x39, 0xEE,
        0x10, 0x73, 0x4A, 0xFE, 0x3F, 0xF7, 0xA0, 0x87
    };
    assert(std::memcmp(k_e, expected_ke, 16) == 0);

    // Expected cipher salt: 30CBBC08863D8C85D49DB34A9AE1
    const uint8_t expected_ks[14] = {
        0x30, 0xCB, 0xBC, 0x08, 0x86, 0x3D, 0x8C, 0x85,
        0xD4, 0x9D, 0xB3, 0x4A, 0x9A, 0xE1
    };
    assert(std::memcmp(k_s, expected_ks, 14) == 0);

    // Expected auth key: CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4
    const uint8_t expected_ka[20] = {
        0xCE, 0xBE, 0x32, 0x1F, 0x6F, 0xF7, 0x71, 0x6B,
        0x6F, 0xD4, 0xAB, 0x49, 0xAF, 0x25, 0x6A, 0x15,
        0x6D, 0x38, 0xBA, 0xA4
    };
    assert(std::memcmp(k_a, expected_ka, 20) == 0);

    std::cout << "  -> RFC 3711 Appendix B.3 derived keys match byte-for-byte: PASSED" << std::endl;
}

// ===========================================================================
// Test 4: SRTP AES-128-ICM Payload Encryption and Decryption (RFC 3711 §4.1.1 & App B.2)
// ===========================================================================
void TestSrtpAesIcmEncryptionAndDecryption() {
    std::cout << "[TEST] 4. SRTP AES-128-ICM Encryption and Decryption (RFC 3711 App B.2)..." << std::endl;

    // RFC 3711 Appendix B.2 AES-CM Test Vector
    // Session Key:  2B7E151628AED2A6ABF7158809CF4F3C
    // Session Salt: F0F1F2F3F4F5F6F7F8F9FAFBFCFD
    // SSRC: 0, Index: 0
    const uint8_t key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    const uint8_t salt[14] = {
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
        0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD
    };

    EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
    assert(aes_ctx != nullptr);
    assert(EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) == 1);
    EVP_CIPHER_CTX_set_padding(aes_ctx, 0);

    // Buffer for 3 blocks (48 bytes) of all zeros
    uint8_t buffer[48] = {0};
    SrtpEngine::ComputeAesIcmKeystream(aes_ctx, salt, 0, 0, buffer, sizeof(buffer));

    // Block 0 expected: E03EAD0935C95E80E166B16DD92B4EB4
    const uint8_t expected_b0[16] = {
        0xE0, 0x3E, 0xAD, 0x09, 0x35, 0xC9, 0x5E, 0x80,
        0xE1, 0x66, 0xB1, 0x6D, 0xD9, 0x2B, 0x4E, 0xB4
    };
    assert(std::memcmp(buffer, expected_b0, 16) == 0);

    // Block 1 expected: D23513162B02D0F72A43A2FE4A5F97AB
    const uint8_t expected_b1[16] = {
        0xD2, 0x35, 0x13, 0x16, 0x2B, 0x02, 0xD0, 0xF7,
        0x2A, 0x43, 0xA2, 0xFE, 0x4A, 0x5F, 0x97, 0xAB
    };
    assert(std::memcmp(buffer + 16, expected_b1, 16) == 0);

    // Block 2 expected: 41E95B3BB0A2E8DD477901E4FCA894C0
    const uint8_t expected_b2[16] = {
        0x41, 0xE9, 0x5B, 0x3B, 0xB0, 0xA2, 0xE8, 0xDD,
        0x47, 0x79, 0x01, 0xE4, 0xFC, 0xA8, 0x94, 0xC0
    };
    assert(std::memcmp(buffer + 32, expected_b2, 16) == 0);

    // Verify round-trip encryption and decryption of a 160-byte voice sample
    uint8_t original_pcm[160];
    for (size_t i = 0; i < sizeof(original_pcm); ++i) {
        original_pcm[i] = static_cast<uint8_t>(i ^ 0xAA);
    }
    uint8_t cipher_pcm[160];
    std::memcpy(cipher_pcm, original_pcm, sizeof(original_pcm));

    // Encrypt
    SrtpEngine::ComputeAesIcmKeystream(aes_ctx, salt, 0x11223344, 42, cipher_pcm, sizeof(cipher_pcm));
    assert(std::memcmp(cipher_pcm, original_pcm, sizeof(original_pcm)) != 0);

    // Decrypt (same keystream xor)
    SrtpEngine::ComputeAesIcmKeystream(aes_ctx, salt, 0x11223344, 42, cipher_pcm, sizeof(cipher_pcm));
    assert(std::memcmp(cipher_pcm, original_pcm, sizeof(original_pcm)) == 0);

    EVP_CIPHER_CTX_free(aes_ctx);
    std::cout << "  -> AES-128-ICM Appendix B.2 keystream and round-trip cryptor: PASSED" << std::endl;
}

// ===========================================================================
// Test 5: SRTP HMAC-SHA1-80 Auth Tag and Tamper Rejection
// ===========================================================================
void TestSrtpHmacSha1AuthTagAndTamperRejection() {
    std::cout << "[TEST] 5. SRTP HMAC-SHA1-80 Auth Tag & Tampering Detection..." << std::endl;

    SrtpKeyConfig key_cfg{};
    for (size_t i = 0; i < 16; ++i) key_cfg.master_key[i] = static_cast<uint8_t>(0x10 + i);
    for (size_t i = 0; i < 14; ++i) key_cfg.master_salt[i] = static_cast<uint8_t>(0x20 + i);

    SrtpEngine sender;
    SrtpEngine receiver;
    assert(sender.InitKeys(key_cfg));
    assert(receiver.InitKeys(key_cfg));

    uint8_t rtp_hdr[12] = {
        0x80, 0x00, 0x00, 0x01, // V=2, PT=0, SEQ=1
        0x00, 0x00, 0x00, 0x00, // TS=0
        0x12, 0x34, 0x56, 0x78  // SSRC
    };
    uint8_t voice_data[160];
    std::memset(voice_data, 0x55, sizeof(voice_data));

    // 1. Sender protects RTP packet
    std::vector<uint8_t> srtp_pkt;
    bool ok = sender.ProtectRtp(rtp_hdr, voice_data, sizeof(voice_data), srtp_pkt);
    assert(ok);
    assert(srtp_pkt.size() == 12 + 160 + 10);

    // RTP header remains in plaintext
    assert(std::memcmp(srtp_pkt.data(), rtp_hdr, 12) == 0);
    // Payload is encrypted
    assert(std::memcmp(srtp_pkt.data() + 12, voice_data, 160) != 0);

    // 2. Receiver unprotects valid packet -> SUCCESS
    std::vector<uint8_t> decrypted;
    ok = receiver.UnprotectRtp(srtp_pkt.data(), srtp_pkt.size(), decrypted);
    assert(ok);
    assert(decrypted.size() == 160);
    assert(std::memcmp(decrypted.data(), voice_data, 160) == 0);

    // 3. Tamper test: modify 1 byte in encrypted payload
    auto tampered_payload = srtp_pkt;
    tampered_payload[15] ^= 0x01;
    SrtpEngine receiver_tamper1;
    receiver_tamper1.InitKeys(key_cfg);
    ok = receiver_tamper1.UnprotectRtp(tampered_payload.data(), tampered_payload.size(), decrypted);
    assert(!ok); // Rejected!

    // 4. Tamper test: modify 1 byte in RTP header
    auto tampered_header = srtp_pkt;
    tampered_header[1] ^= 0x01; // flip payload type bit
    SrtpEngine receiver_tamper2;
    receiver_tamper2.InitKeys(key_cfg);
    ok = receiver_tamper2.UnprotectRtp(tampered_header.data(), tampered_header.size(), decrypted);
    assert(!ok); // Rejected!

    // 5. Tamper test: modify 1 byte in authentication tag
    auto tampered_tag = srtp_pkt;
    tampered_tag.back() ^= 0xFF;
    SrtpEngine receiver_tamper3;
    receiver_tamper3.InitKeys(key_cfg);
    ok = receiver_tamper3.UnprotectRtp(tampered_tag.data(), tampered_tag.size(), decrypted);
    assert(!ok); // Rejected!

    std::cout << "  -> HMAC-SHA1-80 tag generation and tamper rejection: PASSED" << std::endl;
}

// ===========================================================================
// Test 6: SRTP 64-Packet Sliding Replay Window Protection (RFC 3711 §3.3.2)
// ===========================================================================
void TestSrtpReplayWindowProtection() {
    std::cout << "[TEST] 6. SRTP 64-Packet Sliding Replay Window Protection..." << std::endl;

    SrtpKeyConfig key_cfg{};
    for (size_t i = 0; i < 16; ++i) key_cfg.master_key[i] = static_cast<uint8_t>(0xA0 + i);
    for (size_t i = 0; i < 14; ++i) key_cfg.master_salt[i] = static_cast<uint8_t>(0xB0 + i);

    SrtpEngine sender;
    SrtpEngine receiver;
    assert(sender.InitKeys(key_cfg));
    assert(receiver.InitKeys(key_cfg));

    auto build_srtp = [&](uint16_t seq) -> std::vector<uint8_t> {
        uint8_t hdr[12] = {0x80, 0x00, static_cast<uint8_t>(seq >> 8), static_cast<uint8_t>(seq & 0xFF),
                           0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44};
        uint8_t payload[20] = {1, 2, 3, 4, 5};
        std::vector<uint8_t> out;
        sender.ProtectRtp(hdr, payload, sizeof(payload), out);
        return out;
    };

    // 1. Initial packet with SEQ=100 -> ACCEPTED
    auto pkt100 = build_srtp(100);
    std::vector<uint8_t> dec;
    bool ok = receiver.UnprotectRtp(pkt100.data(), pkt100.size(), dec);
    assert(ok);

    // 2. Replay packet SEQ=100 -> REJECTED
    ok = receiver.UnprotectRtp(pkt100.data(), pkt100.size(), dec);
    assert(!ok);

    // 3. Receive in-order SEQ=101, 102, 103 -> ACCEPTED
    auto pkt101 = build_srtp(101);
    auto pkt102 = build_srtp(102);
    auto pkt103 = build_srtp(103);
    assert(receiver.UnprotectRtp(pkt101.data(), pkt101.size(), dec));
    assert(receiver.UnprotectRtp(pkt102.data(), pkt102.size(), dec));
    assert(receiver.UnprotectRtp(pkt103.data(), pkt103.size(), dec));

    // 4. Replay of SEQ=102 -> REJECTED
    assert(!receiver.UnprotectRtp(pkt102.data(), pkt102.size(), dec));

    // 5. Out-of-order delayed packet SEQ=99 (within 64-packet window) -> ACCEPTED
    auto pkt99 = build_srtp(99);
    assert(receiver.UnprotectRtp(pkt99.data(), pkt99.size(), dec));

    // 6. Replay of SEQ=99 -> REJECTED
    assert(!receiver.UnprotectRtp(pkt99.data(), pkt99.size(), dec));

    // 7. Advance sequence number by 70 packets: send SEQ=175 -> ACCEPTED
    auto pkt175 = build_srtp(175);
    assert(receiver.UnprotectRtp(pkt175.data(), pkt175.size(), dec));

    // 8. Packet with SEQ=98 is now outside the 64-packet sliding window -> REJECTED
    auto pkt98 = build_srtp(98);
    assert(!receiver.UnprotectRtp(pkt98.data(), pkt98.size(), dec));

    std::cout << "  -> 64-packet sliding replay window verification: PASSED" << std::endl;
}

// ===========================================================================
// Test 7: Full Media Pipeline with SRTP Audio Stream and Jitter Calculation
// ===========================================================================
void TestSipRtpEncryptedAudioStreamWithJitter() {
    std::cout << "[TEST] 7. SIP/RTP Encrypted Audio Stream with RFC 3550 Jitter..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SipRtpEngine client_engine(mgr, &wheel);
    SipRtpEngine peer_engine(mgr, &wheel);

    ProtocolConfig pcfg{};
    client_engine.Init(pcfg);
    peer_engine.Init(pcfg);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    TelcoSessionContext* peer_ctx = mgr.AcquireSession();
    assert(client_ctx != nullptr && peer_ctx != nullptr);

    SipCallConfig call_cfg{};
    call_cfg.local_ip = 0x0A000001;
    call_cfg.peer_ip = 0x0A000002;
    call_cfg.local_rtp_port = 10000;
    call_cfg.peer_rtp_port = 10000;
    call_cfg.enable_srtp = true;

    for (size_t i = 0; i < 16; ++i) call_cfg.master_key[i] = static_cast<uint8_t>(0x30 + i);
    for (size_t i = 0; i < 14; ++i) call_cfg.master_salt[i] = static_cast<uint8_t>(0x40 + i);

    client_engine.StartCall(client_ctx, call_cfg);
    client_engine.SetState(client_ctx, SipCallState::ESTABLISHED);

    peer_engine.StartCall(peer_ctx, call_cfg);
    peer_engine.SetState(peer_ctx, SipCallState::ESTABLISHED);
    mgr.Bind5Tuple(peer_ctx, 0x0A000002, 0x0A000001, 10000, 10000, 17);

    uint8_t voice_frame[160];
    std::memset(voice_frame, 0x7E, sizeof(voice_frame));

    // Stream 10 encrypted 20ms audio frames with varying simulated arrival jitter
    uint64_t current_tsc = 100000;
    for (int i = 0; i < 10; ++i) {
        auto rtp_pkt = client_engine.BuildRtpPacket(client_ctx, voice_frame, sizeof(voice_frame));
        assert(!rtp_pkt.empty());

        // Header: 14 (Eth) + 20 (IP) + 8 (UDP) + 12 (RTP) + 160 (Payload) + 10 (Tag) = 224 bytes
        assert(rtp_pkt.size() == 14 + 20 + 8 + 12 + 160 + 10);

        // Verify payload inside UDP packet is encrypted
        const uint8_t* enc_payload = rtp_pkt.data() + 14 + 20 + 8 + 12;
        assert(std::memcmp(enc_payload, voice_frame, 160) != 0);

        // Simulate interarrival jitter (+160 timestamp units per packet, jittered arrival TSC)
        current_tsc += (160 + (i % 3) * 15);
        bool ok = peer_engine.ProcessRxFrame(rtp_pkt.data(), rtp_pkt.size(), current_tsc);
        assert(ok);
    }

    auto jitter_stats = peer_engine.GetJitterStats();
    assert(jitter_stats.packets_received == 10);
    assert(jitter_stats.packets_lost == 0);
    assert(jitter_stats.jitter_us >= 0.0);

    std::cout << "  -> SRTP stream verified: 10/10 packets received, 0 loss, jitter: "
              << jitter_stats.jitter_us << " us: PASSED" << std::endl;
}

// ===========================================================================
// Existing Baseline Tests (Call setup, RTP streaming, Jitter, Teardown)
// ===========================================================================
void TestSipCallEstablishment() {
    std::cout << "[TEST] 8. Baseline SIP RFC 3261 Call Setup..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SipRtpEngine client_engine(mgr, &wheel);

    ProtocolConfig cfg{};
    client_engine.Init(cfg);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    assert(client_ctx != nullptr);

    SipCallConfig call_cfg{};
    call_cfg.local_ip = 0x0A000001;
    call_cfg.peer_ip = 0x0A000002;
    call_cfg.from_uri = "sip:alice@samurai.local";
    call_cfg.to_uri = "sip:bob@operator.ims";

    client_engine.StartCall(client_ctx, call_cfg);
    assert(client_engine.GetState(client_ctx) == SipCallState::CALLING);

    std::string ok_msg = "SIP/2.0 200 OK\r\nCall-ID: " + call_cfg.call_id + "\r\n\r\n";
    auto ok_pkt = BuildSimulatedUdpFrame(0x0A000002, 0x0A000001, 5060, 5060, ok_msg.data(), ok_msg.size());

    bool ok = client_engine.ProcessRxFrame(ok_pkt.data(), ok_pkt.size(), 1001);
    assert(ok);
    assert(client_engine.GetState(client_ctx) == SipCallState::ESTABLISHED);

    std::cout << "  -> SIP Call establishment dialog to ESTABLISHED: PASSED" << std::endl;
}

void TestRtpMediaStreaming() {
    std::cout << "[TEST] 9. Baseline RTP RFC 3550 Audio Media Streaming..." << std::endl;

    SessionManager mgr(100);
    HierarchicalTimingWheel wheel(2400000000ULL);
    SipRtpEngine client_engine(mgr, &wheel);

    TelcoSessionContext* client_ctx = mgr.AcquireSession();
    client_engine.SetState(client_ctx, SipCallState::ESTABLISHED);
    client_ctx->client_ip = 0x0A000001;
    client_ctx->peer_ip = 0x0A000002;

    uint8_t voice_frame[160];
    std::memset(voice_frame, 0x55, sizeof(voice_frame));

    for (int i = 0; i < 5; ++i) {
        auto rtp_pkt = client_engine.BuildRtpPacket(client_ctx, voice_frame, sizeof(voice_frame));
        assert(!rtp_pkt.empty());
        const auto* rtp = reinterpret_cast<const RtpHeader*>(rtp_pkt.data() + 42);
        assert((rtp->v_p_x_cc >> 6) == 2);
        assert((rtp->m_pt & 0x7F) == 0);
        assert(ntohs(rtp->seq_number) == i);
        assert(ntohl(rtp->timestamp) == static_cast<uint32_t>(i * 160));
    }

    std::cout << "  -> RTP RFC 3550 packet generation and sequence/timestamp progression: PASSED" << std::endl;
}

void TestRtpJitterCalculation() {
    std::cout << "[TEST] 10. Baseline RTP RFC 3550 Interarrival Jitter Calculation..." << std::endl;

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

    uint8_t rtp_payload[12 + 160] = {0};
    auto* rtp = reinterpret_cast<RtpHeader*>(rtp_payload);
    rtp->v_p_x_cc = 0x80;

    rtp->timestamp = htonl(0);
    auto pkt1 = BuildSimulatedUdpFrame(0x0A000002, 0x0A000001, 10000, 10000, rtp_payload, sizeof(rtp_payload));
    bool ok = engine.ProcessRxFrame(pkt1.data(), pkt1.size(), 1000);
    assert(ok);

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
    std::cout << "[TEST] 11. Baseline SIP Call Teardown (BYE -> 200 OK -> TERMINATED)..." << std::endl;

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

    client_engine.TerminateCall(client_ctx);
    assert(client_engine.GetState(client_ctx) == SipCallState::TERMINATING);

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

    // Required Area 3 Test Cases
    TestSipDigestAuthCalculation();
    TestSip401UnauthorizedChallengeHandshake();
    TestSrtpKeyDerivationVectors();
    TestSrtpAesIcmEncryptionAndDecryption();
    TestSrtpHmacSha1AuthTagAndTamperRejection();
    TestSrtpReplayWindowProtection();
    TestSipRtpEncryptedAudioStreamWithJitter();

    // Baseline FSM and Media Tests
    TestSipCallEstablishment();
    TestRtpMediaStreaming();
    TestRtpJitterCalculation();
    TestSipCallTeardown();

    std::cout << "=================================================================" << std::endl;
    std::cout << "  ALL SIP / RTP ENGINE TESTS PASSED SUCCESSFULLY! (100% VERIFIED)" << std::endl;
    std::cout << "=================================================================" << std::endl;
    return 0;
}
