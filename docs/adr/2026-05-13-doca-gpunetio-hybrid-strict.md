# ADR: DOCA GPUNetIO Gecisi (Hybrid + Strict Fail-Fast)

- Date: 2026-05-13
- Status: Accepted

## Context

Proje, mevcut CUDA persistent yapisini koruyarak DOCA GPUNetIO/DOCA Flow yeteneklerini eklemek istiyor.
Ana gereksinim:

- mevcut `af_xdp/af_packet` yapiyi kaldirmamak
- DOCA yolunu moduler backend olarak eklemek
- production modunda fallback yerine strict fail-fast davranis vermek

## Decision

Asagidaki kararlar alindi:

1. DOCA yolu additive backend olarak uygulanir: `SAMURAI_GPU_TX_BACKEND=doca_gpunetio`.
2. `persistent + stream` modunda strict kontrat zorunlu tutulur (`SAMURAI_GPU_TX_BACKEND_STRICT=1`).
3. `doca_gpunetio` seciminde preflight tarafinda zorunlu parametreler denetlenir:
   - `SAMURAI_GPU_DOCA_ENABLE=1`
   - `SAMURAI_GPU_DOCA_DEVICE=<mlx5_x>`
   - `--xdp-interface`
4. Defense tarafinda DOCA RX device path tercih edilir; strict durumda dogrudan fail-visible cikis verilir.
5. DOCA Flow steering entegrasyonu stream-rule ABI ile backend seviyesinde kapsullenir.

## Consequences

### Positive

- Mevcut mimari yatirimi korunur, gecis asamali ilerler.
- DOCA uyumlu donanimda daha dusuk latency/hedeflenen daha yuksek throughput acilir.
- Strict mode sayesinde ortamdaki uyumsuzluklar erken ve acik gorulur.

### Tradeoffs

- Donanim/driver bagimliligi artar (ConnectX/BlueField + DOCA stack).
- Lab disinda gercek performans kapanisi yapilamaz.
- Multi-backend bakim maliyeti surer.

## Validation

Yazilim seviyesi dogrulama:

- Native build + bridge testleri
- Strict preflight davranisi
- Backend ABI/symbol uyumlulugu

Donanim seviyesi dogrulama:

- Gercek NIC/DPU uzerinde perf ve jitter metrikleri (ayri lab kosusu)

## Follow-up

1. Multi-GPU runtime tasarimini production-ready kapat.
2. DOCA lab benchmark runbook'unu standart kabul kriterlerine bagla.
3. Operasyon dokumanlarinda DOCA preflight checklist'i zorunlu adim olarak yayinla.
