"""Flow-level IPS/NSM state features — the Suricata/inline-IPS adaptation axis.

An inline IPS drops/resets packets instead of returning 429/403, so the reaction
lives in the userspace-TCP counters (tcp_peer_rst / connect_timeout / retransmit /
timeout_close), each normalized per connection-attempt. build_dataset appends four
flow rates + ONE shared flow_known bit AFTER the ban features, and the known bit is
gated by the run's transport: only a flow-capable transport (custom_tcp / dpdk /
af_xdp / af_packet) actually measures them, so a kernel_socket (or transport-less
legacy) corpus is masked. These lock the encoding + transport gating that the C++
serving path (rl_policy BuildFeatures) mirrors.
"""

from __future__ import annotations

import numpy as np

from ddos_samurai.models.rl import ActionSpec, build_dataset
from ddos_samurai.models.rl.config import RLConfig


def _rec(win, transport, *, rst=0, ctimeout=0, retrans=0, tclose=0,
         att=100.0, rps=300.0, s_valid=True, done=False):
    # Chained-window realism: s carries the same defense block as s2 (in a real
    # corpus each window's s is the previous window's s2), so both `states` and
    # `next_states` carry the flow counters.
    defense = {
        "responses_total": rps * 5, "status_2xx": rps * 5,
        "l7_conn_attempted": att, "l7_conn_established": att,
        "tcp_peer_rst_count": rst, "tcp_connect_timeout_count": ctimeout,
        "tcp_retransmit_count": retrans, "tcp_timeout_close_count": tclose,
    }
    base_s = {"valid": True, "rps": rps, "attempted": rps * 5, "errors": 0.0,
              "error_pct": 0.0, "loss_pct": -1.0, "rate_accuracy_pct": -1.0,
              "p99_ms": -1.0, "defense": dict(defense)}
    s2 = dict(base_s)
    s2["defense"] = dict(defense)
    return {
        "run_id": f"cl-{transport}", "win": win, "ts_ms": 1_700_000_000_000 + win,
        "transport": transport,
        "strategy": "aimd", "min_rps": 50.0, "max_rps": 2000.0, "window_s": 5,
        "slo": {"max_error_pct": 100.0, "max_loss_pct": 0.0,
                "min_rate_accuracy_pct": 0.0, "max_latency_ms": 0.0},
        "action_rps": rps,
        "action": {"rps": rps, "pacing_mode": 1, "concurrency": 4,
                   "connections": -1, "request_mix": 0, "source_rotation": -1},
        "s_valid": s_valid, "s": base_s, "s2": s2,
        "healthy": True, "phase": "probe", "done": done,
    }


def _write(tmp_path, name, recs):
    import json
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(r) for r in recs))
    return str(p)


def test_flow_off_by_default_keeps_base_width(tmp_path):
    cfg = RLConfig()  # flow disabled
    assert cfg.flow_feature_count == 0
    path = _write(tmp_path, "c.ndjson",
                  [_rec(1, "custom_tcp", s_valid=False), _rec(2, "custom_tcp", rst=5),
                   _rec(3, "custom_tcp", rst=5, done=True)])
    ds = build_dataset([path], cfg, action_spec=ActionSpec(("rps",)))
    assert ds.states.shape[1] == cfg.feature_count  # 20, no flow dims
    assert "rst_rate" not in ds.feature_names


def test_flow_width_and_names(tmp_path):
    cfg = RLConfig(flow_state_features=True)
    assert cfg.flow_feature_count == 5
    assert cfg.state_dim == cfg.feature_count + 5
    path = _write(tmp_path, "c.ndjson",
                  [_rec(1, "custom_tcp", s_valid=False), _rec(2, "custom_tcp", rst=8),
                   _rec(3, "custom_tcp", rst=8, done=True)])
    ds = build_dataset([path], cfg, action_spec=ActionSpec(("rps",)))
    assert ds.states.shape[1] == cfg.feature_count + 5
    assert ds.feature_names[-5:] == (
        "rst_rate", "connect_timeout_rate", "retransmit_rate",
        "timeout_close_rate", "flow_known",
    )


def test_flow_capable_transport_is_known_with_rates(tmp_path):
    cfg = RLConfig(flow_state_features=True)
    # rst=7, att=100 -> rst_rate 0.07; retransmit=3 -> 0.03. flow_known must be 1.
    recs = [_rec(1, "custom_tcp", s_valid=False),
            _rec(2, "custom_tcp", rst=7, retrans=3),
            _rec(3, "custom_tcp", rst=7, retrans=3, done=True)]
    ds = build_dataset([_write(tmp_path, "c.ndjson", recs)], cfg,
                       action_spec=ActionSpec(("rps",)))
    names = list(ds.feature_names)
    rst = names.index("rst_rate")
    retr = names.index("retransmit_rate")
    known = names.index("flow_known")
    S = ds.states
    assert np.allclose(S[:, rst], 0.07), S[:, rst]
    assert np.allclose(S[:, retr], 0.03), S[:, retr]
    assert np.all(S[:, known] == 1.0)


def test_kernel_socket_transport_is_masked(tmp_path):
    cfg = RLConfig(flow_state_features=True)
    # Even with non-zero counters, a kernel_socket run must NOT mark flow known —
    # those counters are meaningless on the kernel path, so the group is masked.
    recs = [_rec(1, "kernel_socket", s_valid=False),
            _rec(2, "kernel_socket", rst=9),
            _rec(3, "kernel_socket", rst=9, done=True)]
    ds = build_dataset([_write(tmp_path, "k.ndjson", recs)], cfg,
                       action_spec=ActionSpec(("rps",)))
    names = list(ds.feature_names)
    rst = names.index("rst_rate")
    known = names.index("flow_known")
    S = ds.states
    assert np.all(S[:, known] == 0.0), "kernel_socket must mask flow"
    assert np.all(S[:, rst] == 0.0), "masked flow rate imputed to 0"


def test_legacy_transportless_corpus_is_masked(tmp_path):
    cfg = RLConfig(flow_state_features=True)
    recs = [_rec(1, "custom_tcp", s_valid=False), _rec(2, "custom_tcp", rst=4),
            _rec(3, "custom_tcp", rst=4, done=True)]
    # Strip the transport field to simulate a pre-feature corpus.
    for r in recs:
        del r["transport"]
    ds = build_dataset([_write(tmp_path, "old.ndjson", recs)], cfg,
                       action_spec=ActionSpec(("rps",)))
    known = list(ds.feature_names).index("flow_known")
    assert np.all(ds.states[:, known] == 0.0), "legacy (no transport) must mask flow"


def test_flow_composes_after_block_and_ban(tmp_path):
    cfg = RLConfig(variant_block_features=True, ban_state_features=True,
                   flow_state_features=True, request_variant_count=5)
    # 20 base + 2*5 block + 2 ban + 5 flow = 37; flow names are the LAST five.
    assert cfg.state_dim == 20 + 10 + 2 + 5 == 37
    recs = [_rec(1, "custom_tcp", s_valid=False), _rec(2, "custom_tcp", rst=6),
            _rec(3, "custom_tcp", rst=6, done=True)]
    ds = build_dataset([_write(tmp_path, "c.ndjson", recs)], cfg,
                       action_spec=ActionSpec(("rps",)))
    assert ds.states.shape[1] == 37
    assert ds.feature_names[-5:] == (
        "rst_rate", "connect_timeout_rate", "retransmit_rate",
        "timeout_close_rate", "flow_known",
    )
