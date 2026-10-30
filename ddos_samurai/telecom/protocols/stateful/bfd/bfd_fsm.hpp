#pragma once

#include "ddos_samurai/telecom/core/session_context.hpp"
#include "bfd_types.hpp"

#include <cstdint>

namespace ddos_samurai::telecom::bfd {

class BfdFsm {
public:
    static inline void SetState(TelcoSessionContext* ctx, BfdState s) noexcept {
        if (!ctx) return;
        ctx->ppp_lcp_identifier = static_cast<uint16_t>(s);
        switch (s) {
            case BfdState::AdminDown:
            case BfdState::Down:
                ctx->state = SessionState::FAILED;
                break;
            case BfdState::Init:
                ctx->state = SessionState::DISCOVERING;
                break;
            case BfdState::Up:
                ctx->state = SessionState::ESTABLISHED;
                break;
        }
    }

    static inline BfdState GetState(const TelcoSessionContext* ctx) noexcept {
        if (!ctx) return BfdState::Down;
        return static_cast<BfdState>(ctx->ppp_lcp_identifier);
    }

    // RFC 5880 Section 6.8.1 State Transitions
    static inline bool TransitionOnRx(TelcoSessionContext* ctx, BfdState r_state, BfdDiag& out_diag) noexcept {
        if (!ctx) return false;
        BfdState current = GetState(ctx);
        bool failover = false;
        out_diag = BfdDiag::None;

        if (r_state == BfdState::AdminDown) {
            SetState(ctx, BfdState::Down);
            out_diag = BfdDiag::NeighborSignaledDown;
            failover = true;
        } else if (current == BfdState::Down) {
            if (r_state == BfdState::Down) {
                SetState(ctx, BfdState::Init);
            } else if (r_state == BfdState::Init || r_state == BfdState::Up) {
                SetState(ctx, BfdState::Up);
            }
        } else if (current == BfdState::Init) {
            if (r_state == BfdState::Init || r_state == BfdState::Up) {
                SetState(ctx, BfdState::Up);
            }
        } else if (current == BfdState::Up) {
            if (r_state == BfdState::Down) {
                SetState(ctx, BfdState::Down);
                out_diag = BfdDiag::NeighborSignaledDown;
                failover = true;
            }
        }

        return failover;
    }

    static inline bool TransitionOnTimeout(TelcoSessionContext* ctx, BfdDiag& out_diag) noexcept {
        if (!ctx) return false;
        BfdState current = GetState(ctx);
        if (current == BfdState::Up || current == BfdState::Init) {
            SetState(ctx, BfdState::Down);
            out_diag = BfdDiag::ControlDetectionTimeExpired;
            return true;
        }
        return false;
    }
};

} // namespace ddos_samurai::telecom::bfd
