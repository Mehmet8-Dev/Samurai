# 16 - L7 Stateful Runtime V1 (Guncel Mimari)

Bu dokuman, mevcut checkout'taki stateful L7 yolunu guncel kodla birebir eslestirir.
Eski `virtual_user.py` / `h2_transport.py` anlatimi bu repoda gecerli degildir.

## Kapsam

- `ddos_samurai/l7_emu/*` profile compiler + runtime bridge
- `ddos_samurai/senders.py` stateful sender entrypoint'leri
- `ddos_samurai/stateful_runtime.py` session + hot-path contract
- `ddos_samurai/topology_native.py` topology compile/preview bridge
- `ddos_samurai/custom_tcp_dataplane.py` facade

## 1) Stateful L7 Cekirdegi (`l7_emu`)

Temel moduller:

- `l7_emu/types.py`
  - `FlowOpcode`, `FlowOp`, `FlowProgram`
  - `ConnectionTemplate`, `L7EmuProfile`, `RuntimeConfig`, `RunResult`
- `l7_emu/compiler.py`
  - `compile_l7_profile(...)`
  - `load_l7_profile_file(path)`
- `l7_emu/runtime.py`
  - `run_l7_profile(profile, runtime_cfg)`
  - native modul yoksa fail-visible `_unavailable_stats(...)`

Desteklenen protocol seti:

- `http1`
- `http2`
- `quic` (minimal HTTP/3 semantigi)

Not:

- `websocket` bu V1 stateful runtime'da destekli degildir.
- CLI tarafinda `--attack-vector websocket` v1 icin preflight hatasi uretir.

## 2) Sender Entegrasyonu (`senders.py`)

Guncel stateful sender fonksiyonlari:

- `http_app_sender(...)`
- `http2_sender(...)`
- `http_stateful_sender(...)`
- `quic_sender(...)`

Bu fonksiyonlarin ortak yolu:

1. `compile_l7_profile(...)` ile profile derlenir.
2. `run_l7_profile_public(...)` ile native runtime'a cagrilir.
3. Sonuc `l7/telemetry.py` normalize/aggregate kurallariyla uyumlu hale getirilir.

Onemli parametre eksenleri:

- `l7_profile_file`
- `l7_template_mode` (`compat|profile`)
- `stateful_runtime_backend` (`afxdp|dpdk`)
- `custom_tcp_backend` (`af_xdp|txring`)

## 3) Custom TCP Runtime Bridge

Stateful strict yolda beklenen transport:

- `runtime_transport_backend=custom_tcp`

Bridge akisinda kritik fonksiyonlar:

- `_resolve_custom_tcp_flush_transport(...)`
- `_flush_custom_tcp_tx_packets(...)`
- `_service_custom_tcp_runtime(...)`

Contract kurali:

- fallback veya MIXED path strict profilde kabul edilmez.
- `evaluate_hot_path_contract(...)` ile fail-visible kosullar uretilir.

## 4) `stateful_runtime.py` Rolu

Bu modulde:

- `StatefulRuntimeSessionConfig`
- `StatefulRuntimeSession`
- `open_session(...)`
- `evaluate_hot_path_contract(...)`

`snapshot()` alanlari runtime kanitini tasir:

- `runtime_backend`
- `runtime_hot_path_level`
- `runtime_transport_backend`
- `legacy_path_used`

## 5) Topology Modu (`--topo-*`)

CLI tarafinda topology aktif oldugunda:

- `--topo-spec-json`
- `--topo-seed`
- `--topo-strict`

Validation akisi:

1. `validation._validate_sender_route_args(...)`
2. `topology_native.parse_compile_topology_spec(...)`
3. `topology_tuple_preview(...)`

Derlenen plan bilgisi args'a islenir:

- `topology_plan_id`
- `topology_client_pool_size`
- `topology_server_pool_size`
- `topology_compiled_plan_json`
- `topology_tuple_preview_json`

## 6) Dedicated Lab ve Strict Davranis

`--lab-profile dedicated` seciminde preflight:

- `dataplane_core_mode=required`
- `kpi_gate_profile=dedicated_lab`
- `kpi_hard_fail=true`
- `l7_capability_strict=true`
- `stateful_runtime_backend=afxdp`
- `custom_tcp_mode=required`
- `custom_tcp_backend=af_xdp`

QUIC icin ek kural:

- native zorunlulukta py-bridge/autopromote kapanir.

## 7) Guncel Test Referanslari

Stateful/topology/custom tcp kapsaminda:

- `tests/test_l7_emu_v1.py`
- `tests/test_l7_dataplane_contract.py`
- `tests/test_stateful_topology_contract.py`
- `tests/test_custom_tcp_dataplane.py`

Bu set, eski Faz 2/3 dokumanindaki dosya adlarindan daha guncel referanstir.
