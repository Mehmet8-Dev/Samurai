#pragma once

#include "ddos_samurai/telecom/core/telco_protocol_if.hpp"
#include "ddos_samurai/telecom/core/session_manager.hpp"
#include "ddos_samurai/telecom/core/hierarchical_timing_wheel.hpp"
#include "ddos_samurai/telecom/protocols/stateful/pppoe/pppoe_types.hpp"
#include "ddos_samurai/telecom/protocols/stateful/pppoe/pppoe_fsm.hpp"

#include <vector>
#include <string>
#include <memory>

namespace ddos_samurai::telecom::pppoe {

enum class AuthProtocol : uint8_t {
    PAP = 1,
    CHAP = 2
};

class PppoeEngine final : public ITelcoProtocol {
public:
    explicit PppoeEngine(SessionManager& session_mgr, HierarchicalTimingWheel* wheel = nullptr);
    ~PppoeEngine() override = default;

    bool Init(const ProtocolConfig& cfg) override;
    void Shutdown() override;

    // ITelcoProtocol DPDK mbuf I/O
    void OnRxPacket(rte_mbuf* mbuf, 
                    const PacketMetadata& meta, 
                    TelcoSessionContext* session) override;

    uint32_t OnTimerTick(uint64_t current_tsc) override;

    rte_mbuf* BuildTxPacket(rte_mempool* pool, 
                            TelcoSessionContext* session, 
                            uint16_t event_type) override;

    bool IsStateful() const noexcept override { return true; }
    TelcoProtocolId GetProtocolId() const noexcept override { return TelcoProtocolId::PPPOE; }
    std::string_view GetProtocolName() const noexcept override { return "PPPoE"; }

    // Ham paket (Raw buffer) seviyesi doğrulama ve veri düzlemi işleme
    bool ProcessRxFrame(const uint8_t* frame, size_t len, TelcoSessionContext* session = nullptr);

    // Oturum başlatma ve sonlandırma
    void StartSession(TelcoSessionContext* session);
    void TerminateSession(TelcoSessionContext* session);

    // Zaman aşımı işleyici
    void HandleTimeout(TelcoSessionContext* session);

    // Oturum alt durumları
    PppoeSubState GetSubState(const TelcoSessionContext* session) const noexcept;
    void SetSubState(TelcoSessionContext* session, PppoeSubState sub) noexcept;

    // Yapılandırma ve parametreler
    void SetCredentials(const std::string& username, const std::string& password, AuthProtocol proto = AuthProtocol::CHAP);
    void SetTimingWheel(HierarchicalTimingWheel* wheel) noexcept { timing_wheel_ = wheel; }

    const std::vector<uint8_t>& GetLastTxFrame() const noexcept { return last_tx_frame_; }

    // Çerçeve oluşturma API'leri (Wire-format RFC standardında paket üreticileri)
    std::vector<uint8_t> BuildPadiFrame(TelcoSessionContext* session, const std::string& service_name = "");
    std::vector<uint8_t> BuildPadrFrame(TelcoSessionContext* session, const std::string& service_name = "",
                                        const uint8_t* ac_cookie = nullptr, size_t cookie_len = 0);
    std::vector<uint8_t> BuildPadtFrame(TelcoSessionContext* session);

    std::vector<uint8_t> BuildLcpConfReqFrame(TelcoSessionContext* session, uint16_t mru = 1492, uint32_t magic = 0);
    std::vector<uint8_t> BuildLcpConfAckFrame(TelcoSessionContext* session, uint8_t identifier,
                                              const uint8_t* raw_options = nullptr, size_t opt_len = 0);
    std::vector<uint8_t> BuildLcpEchoReqFrame(TelcoSessionContext* session);
    std::vector<uint8_t> BuildLcpEchoRepFrame(TelcoSessionContext* session, uint8_t identifier,
                                              uint32_t magic, const uint8_t* data = nullptr, size_t data_len = 0);

    std::vector<uint8_t> BuildPapAuthReqFrame(TelcoSessionContext* session, const std::string& username, const std::string& password);
    std::vector<uint8_t> BuildChapResponseFrame(TelcoSessionContext* session, uint8_t identifier,
                                                const uint8_t* challenge, size_t challenge_len, const std::string& secret);

    std::vector<uint8_t> BuildIpcpConfReqFrame(TelcoSessionContext* session, uint32_t req_ip = 0, uint32_t dns1 = 0, uint32_t dns2 = 0);
    std::vector<uint8_t> BuildIpcpConfAckFrame(TelcoSessionContext* session, uint8_t identifier,
                                              uint32_t ip, uint32_t dns1 = 0, uint32_t dns2 = 0);

private:
    SessionManager& session_mgr_;
    HierarchicalTimingWheel* timing_wheel_{nullptr};
    ProtocolConfig config_;

    std::string username_{"samurai_user"};
    std::string password_{"samurai_pass"};
    AuthProtocol auth_proto_{AuthProtocol::CHAP};

    std::vector<uint8_t> last_tx_frame_;

    // Dahili ayrıştırıcılar
    void HandlePado(const uint8_t* frame, size_t offset, size_t len, TelcoSessionContext* session);
    void HandlePads(const uint8_t* frame, size_t offset, size_t len, TelcoSessionContext* session);
    void HandlePadt(const uint8_t* frame, size_t offset, size_t len, TelcoSessionContext* session);
    void HandleLcp(const uint8_t* frame, size_t len, TelcoSessionContext* session);
    void HandlePap(const uint8_t* frame, size_t len, TelcoSessionContext* session);
    void HandleChap(const uint8_t* frame, size_t len, TelcoSessionContext* session);
    void HandleIpcp(const uint8_t* frame, size_t len, TelcoSessionContext* session);
};

} // namespace ddos_samurai::telecom::pppoe
