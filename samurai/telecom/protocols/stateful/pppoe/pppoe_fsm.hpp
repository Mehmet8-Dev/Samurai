#pragma once

#include "samurai/telecom/core/session_context.hpp"
#include <cstdint>
#include <string_view>

namespace samurai::telecom::pppoe {

enum class PppoeSubState : uint8_t {
    IDLE = 0,
    DISCOVERY_PADI_SENT,
    DISCOVERY_PADR_SENT,
    DISCOVERY_PADS_RCVD,
    LCP_REQ_SENT,
    LCP_ACK_RCVD,
    LCP_ACK_SENT,
    LCP_OPENED,
    PAP_REQ_SENT,
    CHAP_RESP_SENT,
    AUTH_SUCCESS,
    IPCP_REQ_SENT,
    IPCP_NAK_RCVD,
    IPCP_ACK_RCVD,
    IPCP_OPENED,
    ESTABLISHED,
    TERMINATING,
    FAILED
};

enum class PppoeEvent : uint8_t {
    START_DISCOVERY = 1,
    RX_PADO,
    RX_PADS,
    RX_PADT,
    RX_LCP_CONF_REQ,
    RX_LCP_CONF_ACK,
    RX_LCP_CONF_NAK,
    RX_LCP_CONF_REJ,
    RX_LCP_ECHO_REQ,
    RX_LCP_ECHO_REP,
    RX_LCP_TERM_REQ,
    RX_LCP_TERM_ACK,
    RX_PAP_AUTH_ACK,
    RX_PAP_AUTH_NAK,
    RX_CHAP_CHALLENGE,
    RX_CHAP_SUCCESS,
    RX_CHAP_FAILURE,
    RX_IPCP_CONF_REQ,
    RX_IPCP_CONF_ACK,
    RX_IPCP_CONF_NAK,
    RX_IPCP_CONF_REJ,
    TIMEOUT_RETRY,
    TIMEOUT_FAIL,
    TERMINATE
};

inline std::string_view PppoeSubStateToString(PppoeSubState state) noexcept {
    switch (state) {
        case PppoeSubState::IDLE: return "IDLE";
        case PppoeSubState::DISCOVERY_PADI_SENT: return "DISCOVERY_PADI_SENT";
        case PppoeSubState::DISCOVERY_PADR_SENT: return "DISCOVERY_PADR_SENT";
        case PppoeSubState::DISCOVERY_PADS_RCVD: return "DISCOVERY_PADS_RCVD";
        case PppoeSubState::LCP_REQ_SENT: return "LCP_REQ_SENT";
        case PppoeSubState::LCP_ACK_RCVD: return "LCP_ACK_RCVD";
        case PppoeSubState::LCP_ACK_SENT: return "LCP_ACK_SENT";
        case PppoeSubState::LCP_OPENED: return "LCP_OPENED";
        case PppoeSubState::PAP_REQ_SENT: return "PAP_REQ_SENT";
        case PppoeSubState::CHAP_RESP_SENT: return "CHAP_RESP_SENT";
        case PppoeSubState::AUTH_SUCCESS: return "AUTH_SUCCESS";
        case PppoeSubState::IPCP_REQ_SENT: return "IPCP_REQ_SENT";
        case PppoeSubState::IPCP_NAK_RCVD: return "IPCP_NAK_RCVD";
        case PppoeSubState::IPCP_ACK_RCVD: return "IPCP_ACK_RCVD";
        case PppoeSubState::IPCP_OPENED: return "IPCP_OPENED";
        case PppoeSubState::ESTABLISHED: return "ESTABLISHED";
        case PppoeSubState::TERMINATING: return "TERMINATING";
        case PppoeSubState::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

inline std::string_view PppoeEventToString(PppoeEvent ev) noexcept {
    switch (ev) {
        case PppoeEvent::START_DISCOVERY: return "START_DISCOVERY";
        case PppoeEvent::RX_PADO: return "RX_PADO";
        case PppoeEvent::RX_PADS: return "RX_PADS";
        case PppoeEvent::RX_PADT: return "RX_PADT";
        case PppoeEvent::RX_LCP_CONF_REQ: return "RX_LCP_CONF_REQ";
        case PppoeEvent::RX_LCP_CONF_ACK: return "RX_LCP_CONF_ACK";
        case PppoeEvent::RX_LCP_CONF_NAK: return "RX_LCP_CONF_NAK";
        case PppoeEvent::RX_LCP_CONF_REJ: return "RX_LCP_CONF_REJ";
        case PppoeEvent::RX_LCP_ECHO_REQ: return "RX_LCP_ECHO_REQ";
        case PppoeEvent::RX_LCP_ECHO_REP: return "RX_LCP_ECHO_REP";
        case PppoeEvent::RX_LCP_TERM_REQ: return "RX_LCP_TERM_REQ";
        case PppoeEvent::RX_LCP_TERM_ACK: return "RX_LCP_TERM_ACK";
        case PppoeEvent::RX_PAP_AUTH_ACK: return "RX_PAP_AUTH_ACK";
        case PppoeEvent::RX_PAP_AUTH_NAK: return "RX_PAP_AUTH_NAK";
        case PppoeEvent::RX_CHAP_CHALLENGE: return "RX_CHAP_CHALLENGE";
        case PppoeEvent::RX_CHAP_SUCCESS: return "RX_CHAP_SUCCESS";
        case PppoeEvent::RX_CHAP_FAILURE: return "RX_CHAP_FAILURE";
        case PppoeEvent::RX_IPCP_CONF_REQ: return "RX_IPCP_CONF_REQ";
        case PppoeEvent::RX_IPCP_CONF_ACK: return "RX_IPCP_CONF_ACK";
        case PppoeEvent::RX_IPCP_CONF_NAK: return "RX_IPCP_CONF_NAK";
        case PppoeEvent::RX_IPCP_CONF_REJ: return "RX_IPCP_CONF_REJ";
        case PppoeEvent::TIMEOUT_RETRY: return "TIMEOUT_RETRY";
        case PppoeEvent::TIMEOUT_FAIL: return "TIMEOUT_FAIL";
        case PppoeEvent::TERMINATE: return "TERMINATE";
        default: return "UNKNOWN";
    }
}

} // namespace samurai::telecom::pppoe
