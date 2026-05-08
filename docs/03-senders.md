# Senders

Sender katmani, runtime'dan gelen "paket/payload + policy" bilgisini gercek transport yoluna cevirir.
Facade: `ddos_samurai/senders.py`
Icerik moduller: `ddos_samurai/_senders/*`

## Moduler Yapi

- `runtime.py`: backend/fallback resolver + optional import yardimcilari
- `l2l3_entry.py`: XDP tabanli ana gonderim yolu
- `l2l3_raw.py`: raw socket / txring alternatifleri
- `gpu_defense.py`: send-path classifier bridge
- `stats_core.py`: ortak stats/telemetry normalize
- `context.py`: sender context cleanup

## Policy Gercegi

Su an backend policy bilincli olarak dar:

- backend secimi: `xdp`
- fallback policy: `fail`

Bu davranis `ddos_samurai/_senders/runtime.py` icindeki resolver ile enforce edilir.

## XDP Yolunun Akisi

`_senders/l2l3_entry.py::xdp_sender`

1. XDP module availability kontrolu
2. Route/gateway MAC resolve
3. Buffer normalize ve stride kontrol
4. (Opsiyonel) GPU defense classify
5. XDP send loop / pacing entegrasyonu
6. Stats donus ve fail-visible alanlari

## Stats Semasi

`stats_core.py` tarafi su alanlari normalize eder:

- attempted/sent/errors
- sender_path
- sender_fallback_reason
- pacing metrikleri (`actual_rps`, `rate_accuracy_pct`, jitter vb.)
- loss telemetry alanlari

## L7 ve Stateful Integrasyon

Facade yalnizca L2/L3 degil, L7 stateful runtime cagrilarini da kapsar.
Ozellikle:

- custom TCP bridge
- L7 emulation path
- stateful_runtime_backend metadata

## Performans ve Guvenilirlik

- Copy/copyless path ayrimi buffer normalize ile kontrol edilir
- Pacing entegrasyonu live progress ile uyumlu tutulur
- Fallback yerine fail-visible davranis tercih edilerek benchmark sapmalari gizlenmez
