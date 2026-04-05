# Canonical Event Schema

## Amaç

Bu doküman, ham trafik kaynakları ile model girdisi arasındaki resmi ara temsili tanımlar.

Samurai tarafında:

- ham PCAP dogrudan modele verilmez
- ham CICIDS2017 CSV satırı da dogrudan modele verilmez
- once canonical event schema uretilir
- sonra quality gate'lerden gecirilir
- en son model/tokenizer/runtime materializer tarafina verilir

Bu sayede:

- veri kaynagi ile model kontrati ayrilir
- provenance kaybolmaz
- leakage kontrolu standardize edilir
- ayni event temsili Mamba / Transformer / gelecekteki diger planner modelleri tarafindan ortak kullanilir

## Tasarim Ilkeleri

1. Temsil packet-centric degil session-centric olmalidir.
2. Event sirasi protokol-semantigine uygun olmalidir.
3. Provenance alanlari zorunlu olmalidir.
4. Split/partition bilgisi event kaydindan kopuk olmamalidir.
5. Runtime materialization ile learned representation ayrik tutulmalidir.

## Ust Seviye Nesneler

### 1. SessionRecord

Modelin egitime girecegi ana birimdir.

Zorunlu alanlar:

- `schema_version`
- `dataset_origin`
- `trace_id`
- `source_file`
- `split_group_id`
- `session_id`
- `protocol`
- `label`
- `events`

Onerilen Python formu:

```python
@dataclass(frozen=True)
class SessionRecord:
    schema_version: str
    dataset_origin: str
    trace_id: str
    source_file: str
    split_group_id: str
    session_id: str
    protocol: str
    label: str
    session_metrics: Dict[str, float]
    events: List[EventRecord]
```

### 2. EventRecord

Modelin sequence seviyesinde ogrendigi atomik davranis birimidir.

Onerilen alanlar:

- `event_type`
- `delay_bucket`
- `method`
- `path_bucket`
- `header_profile`
- `payload_class`
- `mutation_signature`
- `response_time_bucket`
- `retry_count`
- `close_reason`

Onerilen Python formu:

```python
@dataclass(frozen=True)
class EventRecord:
    event_type: str
    delay_bucket: str = "none"
    method: str = "none"
    path_bucket: str = "other"
    header_profile: str = "none"
    payload_class: str = "none"
    mutation_signature: str = "none"
    response_time_bucket: str = "unknown"
    retry_count: int = 0
    close_reason: str = ""
```

### 3. SessionPlan

Model inference sonrasinda runtime-benzeri event listesine acilan yapidir.

Bu nesne egitim girdisi degil, ciktidir.

## Zorunlu Enum Sozlesmeleri

### protocol

- `http1`
- `http2`
- `websocket`
- `quic`

### label

- `benign`
- `evasive`
- `aggressive`

### event_type

- `connect_open`
- `tls_client_hello`
- `http_request`
- `http2_headers`
- `ws_open`
- `ws_frame`
- `quic_open`
- `quic_request`
- `idle_wait`
- `retry`
- `reset`
- `close`

### delay_bucket

- `none`
- `0_5ms`
- `6_20ms`
- `21_100ms`
- `101_500ms`
- `500ms_plus`

### method

- `none`
- `get`
- `post`
- `put`
- `patch`
- `delete`
- `head`
- `options`

### path_bucket

- `root`
- `api`
- `ws`
- `static`
- `auth`
- `search`
- `media`
- `other`

### header_profile

- `none`
- `unknown`
- `modern_browser`
- `api_json`
- `generic_http`
- `http_csv`
- `h2_csv`
- `quic_csv`
- `quic`

### payload_class

- `none`
- `empty`
- `tiny`
- `small`
- `medium`
- `large`

## Provenance Alanlari

Bu alanlar opsiyonel degil, zorunludur.

### schema_version

Canonical event format versiyonu.

Baslangic degeri:

- `samurai_event_v1`

### dataset_origin

Verinin geldigi veri kaynagi.

Ornekler:

- `cicids2017`
- `csecicids2018`
- `pcap_live_capture`
- `samurai_synthetic`

### trace_id

Kaynak dosya veya kaynak topluluga bagli trace birimi.

Amac:

- anti-leakage split
- provenance
- ayni trace icindeki benzer session'lari birlikte tutmak

### source_file

Ham dosya adi.

Ornek:

- `Wednesday-workingHours.pcap_ISCX.csv`

### split_group_id

Train/val/test ayriminda kullanilan resmi grup kimligi.

Onerilen format:

- `trace_session:<trace_id>:<session_id>`

Alternatif:

- `trace:<trace_id>`
- `session:<session_id>`

Ama default tercih:

- `trace_session`

## Session Metrics

`session_metrics` alani modele token olarak verilmek zorunda degildir ama canonical schema'nin parcasidir.

Zorunlu onerilen metrikler:

- `total_pkts`
- `total_bytes`
- `flow_duration_ms`
- `iat_mean_ms`
- `iat_max_ms`
- `packet_len_std`

Amac:

- audit/debug
- feature engineering tekrarlanabilirligi
- quality gate hesaplari

## Ham CICIDS2017 -> Canonical Event Dönüşümü

CICIDS2017 CSV yapisi flow-feature tablosudur.

Yani:

- gercek packet order yok
- gercek request/response event stream yok
- bircok kolon aggregate istatistik tasir

Bu nedenle ham veri:

- dogrudan sequence modele verilmez
- once event iskeletine acilir

Onerilen donusum:

1. `Label` -> `benign/evasive/aggressive`
2. `Protocol` + port bilgisi -> `http1/http2/quic`
3. packet/iat/sure metrikleri -> event count + delay bucket + payload class
4. flag bilgileri -> retry/reset gibi event ipuclari
5. flow davranisi -> `mutation_signature`

Bu donusum:

- protocol-valid olmali
- deterministik olmali
- quality gate ile denetlenmeli

## Runtime Materialization Ayrimi

Canonical schema, runtime'da kullanilan somut HTTP path veya ms degerleri ile ayni sey degildir.

Ornek:

- model `PATH:api` ogrenebilir
- runtime materializer bunu `/api/v1/resource` gibi somut bir path'e acar

Bu ayrim korunmalidir.

Sozlesme:

- learned representation: `EventRecord`
- runtime expansion: `SessionEvent`

## Bu Repo Icin Minimum Uygulama Notu

Sequence planner notebook ve Mamba monolith tarafinda en az su alanlar tutulmalidir:

- `schema_version="samurai_event_v1"`
- `dataset_origin="cicids2017"`
- `trace_id`
- `source_file`
- `split_group_id`
- `session_metrics`

Bu alanlardan biri yoksa veri artik canonical schema degil, ara/eksik temsildir.
