#pragma once

#include "ddos_samurai/telecom/core/session_context.hpp"
#include "dhcp_types.hpp"

#include <cstdint>
#include <string_view>

namespace ddos_samurai::telecom::dhcp {

enum class DhcpSubState : uint8_t {
    INIT = 0,
    SELECTING = 1,   // Discover/Solicit sent, awaiting Offer/Advertise
    REQUESTING = 2,  // Request sent, awaiting Ack/Reply
    BOUND = 3,       // IP assigned, lease running
    RENEWING = 4,    // T1 expired, unicast renewal sent
    REBINDING = 5,   // T2 expired, broadcast rebinding sent
    RELEASED = 6,    // Release sent, session terminating
    FAILED = 7       // Rejection or max retries exceeded
};

inline std::string_view DhcpSubStateToString(DhcpSubState s) noexcept {
    switch (s) {
        case DhcpSubState::INIT: return "INIT";
        case DhcpSubState::SELECTING: return "SELECTING";
        case DhcpSubState::REQUESTING: return "REQUESTING";
        case DhcpSubState::BOUND: return "BOUND";
        case DhcpSubState::RENEWING: return "RENEWING";
        case DhcpSubState::REBINDING: return "REBINDING";
        case DhcpSubState::RELEASED: return "RELEASED";
        case DhcpSubState::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

class DhcpFsm {
public:
    static inline void SetState(TelcoSessionContext* ctx, DhcpSubState sub) noexcept {
        if (!ctx) return;
        ctx->ppp_lcp_identifier = static_cast<uint16_t>(sub);
        switch (sub) {
            case DhcpSubState::INIT:
                ctx->state = SessionState::IDLE;
                break;
            case DhcpSubState::SELECTING:
            case DhcpSubState::REQUESTING:
                ctx->state = SessionState::DISCOVERING;
                break;
            case DhcpSubState::BOUND:
                ctx->state = SessionState::ESTABLISHED;
                break;
            case DhcpSubState::RENEWING:
            case DhcpSubState::REBINDING:
                ctx->state = SessionState::ESTABLISHED; // Still active traffic
                break;
            case DhcpSubState::RELEASED:
                ctx->state = SessionState::TERMINATING;
                break;
            case DhcpSubState::FAILED:
                ctx->state = SessionState::FAILED;
                break;
        }
    }

    static inline DhcpSubState GetState(const TelcoSessionContext* ctx) noexcept {
        if (!ctx) return DhcpSubState::INIT;
        return static_cast<DhcpSubState>(ctx->ppp_lcp_identifier);
    }
};

} // namespace ddos_samurai::telecom::dhcp
