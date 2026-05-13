# 33 - DOCA GPUNetIO Gecis Durumu ve Operasyon Notlari

- Tarih: 2026-05-13
- Kapsam: Mevcut CUDA persistent dataplane + DOCA GPUNetIO/DOCA Flow gecisinin yazilim durumu
- Durum: Yazilim entegrasyonu ileri seviyede, donanim lab dogrulamasi beklemede

## 1) Hedef Mimari

Hedef, mevcut yapiyi kaldirmadan yeni bir backend ekleyerek gecmek:

- Mevcut backendler korunur: `af_xdp`, `af_packet`
- Yeni backend: `doca_gpunetio`
- Persistent + stream modunda strict fail-fast kontrati korunur
- Uygun olmayan ortamda fallback yerine fail-visible davranis verilir

## 2) Faz Durumu (Ozet)

1. Faz 1 - Hybrid backend secimi: Tamam
2. Faz 2 - Native DOCA TX entegrasyonu: Tamam (host-side backend ve GPU handle export dahil)
3. Faz 3 - Native DOCA RX + defense baglantisi: Tamam (device receive path + GPU RXQ handle akisi)
4. Faz 4 - DOCA Flow steering: Tamam (single-pipe + multi-pipe stream rule injection)

Not: "Tamam" ifadesi kod entegrasyonu icindir. Gercek NIC/DPU uzerinde throughput/latency KPI kapanisi ayrica lab kosusu gerektirir.

## 3) Strict/Fallback Politikasi

`persistent + stream` modunda backend kontrati:

- `SAMURAI_GPU_TX_BACKEND` yalnizca `af_xdp|af_packet|doca_gpunetio`
- `SAMURAI_GPU_TX_BACKEND_STRICT=1` zorlanir (preflight)
- `doca_gpunetio` seciminde:
  - `SAMURAI_GPU_DOCA_ENABLE=1` zorunlu
  - `SAMURAI_GPU_DOCA_DEVICE` zorunlu (orn: `mlx5_0`)
  - `--xdp-interface` zorunlu

Bu davranis fallback yerine fail-fast stratejisini korur.

## 4) Faz 3/4 Teknik Cikti Basliklari

- DOCA RX queue create/destroy akisi native backend tarafina baglandi
- `receive_burst_view + release` tek akisa indirildi
- GPU RXQ handle defense runtime tarafina export edildi
- Device-side `doca_gpu_dev_eth_rxq_receive_block(...)` kullanimi aktif
- Flow steering icin stream-bazli rule ABI ve multi-pipe programlama eklendi

## 5) Donanim Olmadan Dogrulama

Donanim yokken kosulabilen dogrulama:

```bash
python setup.py build_ext --inplace
pytest tests/native_gpu/test_cuda_backend_bridge.py -q
pytest tests/native_gpu/test_backend_facade.py -q
pytest tests/native_gpu/test_defense_cuda_backend_bridge.py -q
```

Beklenti:

- ABI/symbol kontratlari dogrulanir
- Strict preflight kontrolleri dogrulanir
- Gercek line-rate/perf metrikleri dogrulanmaz (lab gerekir)

## 6) Kalan Isler

1. Multi-GPU runtime topolojisi (`per-GPU PersistentRuntime`) tamamlama
2. DOCA lab benchmark seti ile Faz 2/3/4 KPI kapanisi
3. Uretim runbook'una donanim preflight adimlarini ekleme

## 7) Ilgili Belgeler

- [05 - GPU](./05-gpu.md)
- [20 - Env + CLI Tam Referans](./20-env-cli-reference.md)
- [ADR: DOCA Hybrid + Strict](./adr/2026-05-13-doca-gpunetio-hybrid-strict.md)
- [Perf: DOCA GPUNetIO Progress Report](./perf/doca-gpunetio-progress-report.md)
