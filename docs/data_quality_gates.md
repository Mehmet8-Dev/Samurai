# Data Quality Gates

## Amaç

Bu doküman, canonical event schema uretiltikten sonra modelden once calismasi gereken veri kalite kapilarini tanımlar.

Temel kural:

- ham veri -> normalize / canonical schema
- canonical schema -> quality gates
- quality gates basariliysa -> train / eval / infer icin kullan

Quality gate'ler opsiyonel degildir.

## Neden Gerekli?

Bu repo baglaminda en buyuk risk model secimi degil, veri hatasidir.

Ozellikle:

- CICIDS2017 gibi flow-feature veri setleri dogrudan event sequence degildir
- train/val/test leakage kolayca olusabilir
- label mapping heuristik olabilir
- sentetik event acilimi gercekci gorunup aslinda bozuk olabilir

Bu nedenle kalite kapilari model oncesi zorunlu guvenlik mekanizmasidir.

## Gate 1 - Schema Gate

Kontroller:

- zorunlu alanlar mevcut mu
- `schema_version` bos mu
- `dataset_origin` bos mu
- `trace_id` bos mu
- `source_file` bos mu
- `split_group_id` bos mu
- `session_id` bos mu
- `events` bos mu

Fail kosulu:

- herhangi bir zorunlu alan eksikse

## Gate 2 - Enum Gate

Kontroller:

- `protocol` destekli enum mu
- `label` destekli enum mu
- `event_type` destekli enum mu
- `delay_bucket`, `method`, `path_bucket`, `header_profile`, `payload_class` izinli mi

Fail kosulu:

- izinli enum disi deger varsa

## Gate 3 - Sequence Grammar Gate

Kontroller:

- ilk event `connect_open` mi
- son event `close|reset` mi
- `connect_open` sadece step 0'da mi
- terminal event erken geliyor mu
- `step_index` sirali mi

Fail kosulu:

- event grammar bozuksa

## Gate 4 - Protocol Consistency Gate

Kontroller:

- `http1` session icinde `quic_*` event'leri var mi
- `http2` session icinde `http_request` yerine `http2_headers` kullaniliyor mu
- `quic` session icinde `tls_client_hello` veya `http_request` gibi uyumsuz event var mi
- `websocket` akisi kendi event tipleri ile tutarli mi

Fail kosulu:

- protocol ile event sequence uyusmuyorsa

## Gate 5 - Label Mapping Gate

Kontroller:

- ham etiket -> canonical label map deterministik mi
- bilinmeyen label orani nedir
- fallback label kullanimi ne kadar
- class collapse asiri mi

Warning kosulu:

- fallback label kullanimi esigi asarsa

Fail kosulu:

- map edilemeyen label varsa veya mapping nondeterministic ise

## Gate 6 - Coverage Gate

Kontroller:

- train label set, val/test label setini kapsiyor mu
- train protocol set, val/test protocol setini kapsiyor mu
- train vocab / codec, val/test session'larini encode edebiliyor mu

Fail kosulu:

- val/test train coverage disinda kalıyorsa

## Gate 7 - Leakage Gate

Kontroller:

- train/val `trace_id` overlap
- train/test `trace_id` overlap
- val/test `trace_id` overlap
- train/val `session_id` overlap
- train/test `session_id` overlap
- val/test `session_id` overlap
- gerekiyorsa `source_file` overlap

Varsayilan kural:

- `trace_id` overlap sifir olmali
- `session_id` overlap sifir olmali

Fail kosulu:

- overlap > 0

## Gate 8 - Distribution Gate

Kontroller:

- `event_type` dagilimi
- `session_len` dagilimi
- `delay_bucket` dagilimi
- `path_bucket` dagilimi
- `payload_class` dagilimi
- `mutation_signature` dagilimi

Amaç:

- train ve val/test arasinda patolojik dagilim kaymasini fark etmek

Warning kosulu:

- ciddi dengesizlik veya beklenmeyen class çökmesi

## Gate 9 - Session Integrity Gate

Kontroller:

- asiri kisa session
- tek eventli session
- terminal event'siz session
- duplicate event tekrar patlamasi
- anlamsiz `retry` zinciri

Fail kosulu:

- minimum sequence semantigi saglanmiyorsa

## Gate 10 - Heuristic Inflation Gate

Bu gate özellikle CICIDS2017 gibi flow-feature kaynaklar için zorunludur.

Kontroller:

- bir ham satirdan kac event turetildi
- ortalama event/session degeri ne kadar
- request count üretimi patolojik mi
- label bazli event inflation asimetrik mi

Warning kosulu:

- sentetik acilim veri gerceginden fazla uzaklasiyorsa

Fail kosulu:

- belirlenen inflation limitleri asiliyorsa

## Gate 11 - Null / Invalid Metric Gate

Kontroller:

- `NaN`
- `inf/-inf`
- negatif duration/iat benzeri fiziksel olarak anlamsiz degerler
- constant kolonlar
- asiri bos kolonlar

Fail kosulu:

- temizlenmemis invalid metric kalmissa

## Gate 12 - Provenance Gate

Kontroller:

- her SessionRecord provenance tasiyor mu
- `dataset_origin`
- `source_file`
- `trace_id`
- `split_group_id`
- `schema_version`

Fail kosulu:

- provenance eksikse

## Gate 13 - Export Contract Gate

Model egitimi icin yazilan tum dataset export'lari:

- versionlanmali
- summary uretmeli
- split profilleri raporlamali
- leakage sayaclari icermeli

Onerilen artifact'ler:

- `summary.json`
- `split_profiles.json`
- `quality_report.json`
- `schema_version.txt`

## CICIDS2017 Özel Karar

Ham CICIDS2017 CSV:

- dogrudan train datası degildir
- flow-feature kaynak veridir

Bu nedenle minimum pipeline:

1. label normalization
2. protocol inference
3. canonical event expansion
4. feature bucket stabilization
5. leakage-safe split
6. quality gates
7. model input export

Bu adimlardan biri atlanirsa veri, sequence planner icin yeterince guvenilir kabul edilmemelidir.

## Bu Repo Icin Onerilen Fail/Warning Politikasi

Fail:

- schema bozuk
- enum bozuk
- grammar bozuk
- protocol inconsistency
- train/val/test leakage
- coverage eksigi
- provenance eksigi

Warning:

- distribution drift
- heuristic inflation yuksek
- fallback label kullanimi yuksek
- class imbalance beklenenden fazla

## Minimum Uygulama

Bu repo icin quality gate runner en az su bilgileri raporlamalidir:

```json
{
  "schema_version": "samurai_event_v1",
  "dataset_origin": "cicids2017",
  "rows_input": 2830751,
  "sessions_output": 123456,
  "split_mode": "trace_session",
  "leakage": {
    "train_val_trace_overlap": 0,
    "train_test_trace_overlap": 0,
    "val_test_trace_overlap": 0,
    "train_val_session_overlap": 0,
    "train_test_session_overlap": 0,
    "val_test_session_overlap": 0
  },
  "coverage": {
    "train_labels": ["benign", "evasive", "aggressive"],
    "val_labels_missing_from_train": [],
    "test_labels_missing_from_train": []
  },
  "status": "ok|warn|fail"
}
```

## Son Karar

Bu projede:

- data engineering birinci sinif vatandastir
- quality gate'ler modelden daha az onemli degildir
- canonical schema olmadan train etmek kabul edilmemelidir
