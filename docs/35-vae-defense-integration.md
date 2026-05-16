# 35 - VAE Defense Integration (Mimari + Kullanim)

Bu dokuman, DDoSamurai icindeki savunma odakli VAE katmaninin mimarisini, egitim akisini, runtime entegrasyonunu ve operasyonel kullanimini anlatir.

## 1) Amac ve Kapsam

VAE katmaninin amaci:

- Normal sistem davranisini ogrenmek
- Canli metrik pencerelerini skorlamak
- Normal disi paternleri anomaly olarak isaretlemek

VAE katmani tek basina kok neden analizi yapmaz. Teknik yorumlama icin rule tag mekanizmasi kullanilir.

## 2) Kod Konumu

Ana moduller:

- `ddos_samurai/models/vae/config.py`
- `ddos_samurai/models/vae/model.py`
- `ddos_samurai/models/vae/artifacts.py`
- `ddos_samurai/models/vae/windowing.py`
- `ddos_samurai/models/vae/rules.py`
- `ddos_samurai/models/vae/service.py`
- `ddos_samurai/models/vae/train.py`

Runtime baglantisi:

- CLI flagleri: `ddos_samurai/cli/args.py`
- Live mode post-analysis + event persist: `ddos_samurai/cli/runtime.py`
- Canli metrik sampling: `ddos_samurai/utils.py`
- Worker resource metrik yayini: `ddos_samurai/orchestrator.py`

## 3) Mimari Ozeti

Akis (mevcut v1):

1. Worker tarafi runtime metrikleri `resource_stats` icine yazar.
2. Live monitor her ~1 saniyede AI sample cikarir.
3. Run tamamlandiginda `VAEDefenseService` sample akisini isler.
4. 60s pencere + 5s stride ile anomaly inference calisir.
5. Anomaly event'ler JSONL olarak kaydedilir.
6. Run report icine `vae_defense` ozeti eklenir.

Not: Bu surumde inference run sonu post-analysis olarak calisir. Online (run sirasinda) alert modunda degildir.

## 4) Feature Set ve Pencereleme

Sabit feature set (8):

- `rps`
- `p95_latency`
- `p99_latency`
- `error_rate`
- `cpu_usage`
- `memory_usage`
- `active_connections`
- `timeout_count`

Varsayilan pencere parametreleri:

- `window_size = 60`
- `step_size = 5`
- `sampling_rate = 1s`

Model input boyutu:

- `input_dim = 60 x 8 = 480`

## 5) Dense VAE Tasarimi

Model tipi: Fully-connected Dense VAE.

- Encoder: `480 -> hidden -> hidden`
- Latent: `latent_dim` (varsayilan `16`)
- Decoder: `latent -> hidden -> hidden -> 480`

Skor formulu:

- `score = reconstruction_error + beta_kl * KL`

Karar:

- `score <= threshold` -> normal
- `score > threshold` -> anomaly

Severity:

- `< threshold` -> `normal`
- `< threshold * 1.5` -> `low`
- `< threshold * 2.5` -> `medium`
- `>= threshold * 2.5` -> `high`

## 6) Sifirdan Egitim Pipeline'i

Notebook zorunlu degildir. Sistem icinde sifirdan egitim scripti vardir:

- `python -m ddos_samurai.models.vae.train`

Ornek komut:

```bash
python -m ddos_samurai.models.vae.train \
  --input-glob "data/vae/*.csv" \
  --label-col Label \
  --normal-label BENIGN \
  --model-version vae-loadtest-v1
```

Beklenen CSV kolonlari:

- 8 feature kolonu (tam isimlerle)
- Label kolonu (`--label-col`)

Egitim mantigi:

1. Sadece `normal_label` satirlari secilir.
2. 60'lik window'lar uretilir.
3. Train/validation ayrimi yapilir.
4. Scaler train setten fit edilir.
5. Dense VAE egitilir.
6. Validation skor dagilimindan threshold cikarilir (`threshold_quantile`).

## 7) Artifact Standardi

Her model versiyonu icin artifact klasoru:

- `ddos_samurai/models/vae/artifacts/<model_version>/l4_vae.pt`
- `ddos_samurai/models/vae/artifacts/<model_version>/l4_scaler.npz`
- `ddos_samurai/models/vae/artifacts/<model_version>/l4_vae_meta.json`
- `ddos_samurai/models/vae/artifacts/<model_version>/l4_vae_history.json`

`l4_vae_meta.json` icindeki kritik alanlar:

- `feature_names`
- `window_size`
- `input_dim`
- `hidden_dim`
- `latent_dim`
- `beta_kl`
- `threshold`
- `model_version`

## 8) Runtime Kullanimi

VAE acik calistirma:

```bash
python -m ddos_samurai.cli \
  --target 127.0.0.1 --port 8080 \
  --protocol tcp --attack-vector basic \
  --count 200000 --workers 4 --confirm \
  --vae-enable
```

Opsiyonel override flagleri:

- `--vae-model-path`
- `--vae-scaler-path`
- `--vae-meta-path`
- `--vae-model-version`
- `--vae-event-out`
- `--vae-threshold-override`

## 9) Cikti Formatlari

### 9.1 VAE inference sonucu (tek pencere)

Sabit alanlar:

- `test_id`
- `timestamp`
- `is_anomaly`
- `anomaly_score`
- `threshold`
- `severity`
- `top_contributors`
- `reason_tag`
- `message`
- `model_version`

### 9.2 Event persist

Anomaly event'ler JSONL formatinda yazilir:

- default: `<report_base>.vae.anomaly_events.jsonl`
- veya `--vae-event-out <path>`

### 9.3 Run report

`results.vae_defense` altinda ozet alanlari bulunur:

- `enabled`
- `status`
- `samples_total`
- `windows_evaluated`
- `anomalies_total`
- `severity_counts`
- `model_version`
- `threshold`

## 10) Rule Tag ve Contributor Mantigi

`top_contributors` feature-bazli reconstruction error'dan cikartilir.

`reason_tag` su kurallardan turetilir:

- `latency_timeout_degradation`
- `possible_cpu_saturation`
- `possible_downstream_or_network_issue`
- `possible_memory_pressure`
- `unknown_pattern`

## 11) Operasyonel Notlar

- Bu katman savunma odaklidir; run quality ve davranis anomalilerini isaretler.
- PyTorch kurulumu yoksa VAE inference/training calismaz.
- Feature isim ve sirasi degistirilirse eski model artifact'lariyla uyumsuzluk olusur.
- Farkli window/feature konfigleri yeni model versiyonu gerektirir.

## 12) Sorun Giderme

`VAE artifact not found`:

- Path'leri kontrol edin veya yeni model egitin.

`Feature name order mismatch`:

- `meta.feature_names` ile runtime config'in birebir ayni oldugundan emin olun.

`PyTorch is required`:

- `pip install -r requirements-ml.txt` ile kurulum yapin.

`No samples / windows=0`:

- Run suresi cok kisa olabilir (60s pencere dolmamis olabilir).

## 13) Yol Haritasi (Kisa)

- Post-analysis'ten online inference'a gecis (her 5s canli karar)
- Feature coverage genisletme (stabil kaynaklarla)
- Event sink entegrasyonu (DB/stream)
- Model registry + versiyon rollout politikasi

