# 13 - API (ddos_samurai/api.py)

Bu dokuman, Dashboard'in konustugu FastAPI katmanini ozetler.
Amac: UI icin stabil bir kontrol ve gozlem API'si saglamak.

## Genel

- ASGI app: `ddos_samurai/api.py`
- Varsayilan port: Docker stack'te `5099`
- CORS: UI icin acik (gelistirme kolayligi)

## Endpoint'ler

### `POST /attack/start`

Giris:

- JSON body: `AttackConfig` (Pydantic model)

Davranis:

- Hali hazirda calisan bir proses varsa 400 dondurur.
- Bazı vektor/protokoller icin root/capability kontrolu yapar.
- `python -m ddos_samurai.cli ...` komutunu subprocess ile baslatir.
- CLI stdout/stderr akisini okur, log event'lere cevirir.

Cikis:

- `{ "status": "started", "pid": <pid> }`

### `POST /attack/stop`

Davranis:

- Calisan subprocess agacini (parent + child) kill eder.

### `GET /stats`

Davranis:

- Calisma durumu (`is_running`) ve sayaclari dondurur.
- Loglar bir "event stream" gibi kullanilir:
  - API, log deque'yi response'a koyar
  - Sonra deque'yi temizler (UI duplicate kontrolu daha kolay olsun diye)

## Operasyon Notlari

- Ham soket/low-level yollar Linux ve yetki gerektirir.
- Docker ile calisirken `cap_add: NET_RAW/NET_ADMIN` yetmeyebilir; `privileged` gerekebilir.
- Bu API katmani bir "kontrol yuzeyi" oldugu icin production ortamda:
  - authN/authZ
  - rate limit
  - audit log
  - network segmentation
  gibi konular dusunulmelidir.

## TestStartRequest Semasi (trex_path v2)

`POST /attack/start` endpointine gonderilen JSON body su alanlari icerir:

```python
class TestStartRequest:
    target: str          # Hedef IP/hostname
    port: int = 80       # Hedef port
    count: int = 1000    # Toplam gonderim sayisi
    workers: int = 1     # Worker (process) sayisi
    duration: int = 0    # Saniye cinsinden sure limiti (0=sinirsiz)
    protocol: str = "tcp"
    attack_vector: str = "basic"
    user_agent: str = "none"       # Legacy: onceden TLS profili olarak da kullaniliyordu
    ja3_profile: str = "none"      # YENİ: TLS/JA3 profil adi (firefox_120, chrome_120, vb.)
    h2_profile: str = "none"       # YENİ: HTTP/2 profil adi (edge_120, vb.)
    # ... (diger alanlar)
```

### API -> CLI Arg Mapping Kurallari

`_build_test_command()` su kurallari izler:

| Alan | CLI Flag | Kural |
|---|---|---|
| `ja3_profile` | `--tls-profile` | `ja3_profile != "none"` ise kullanilir |
| `user_agent` | `--tls-profile` (fallback) | `ja3_profile == "none"` ise `user_agent` deger olarak kullanilir |
| `h2_profile` | `--h2-profile` | `h2_profile != "none"` ise kullanilir |
| `user_agent` | `--h2-profile` (fallback) | `h2_profile == "none"` ve `attack_vector == "http2"` ise fallback |

### Onceki vs. Sonraki

**Onceki (Hatali):**
```python
cmd.extend(["--tls-profile", payload.user_agent])  # user_agent uzerinden
if payload.attack_vector == "http2":
    cmd.extend(["--h2-profile", payload.user_agent])  # ayni deger tekrar
```

**Sonraki (Duzeltilmis):**
```python
tls_val = payload.ja3_profile if payload.ja3_profile != "none" else payload.user_agent
cmd.extend(["--tls-profile", tls_val])

if payload.attack_vector == "http2":
    h2_val = payload.h2_profile if payload.h2_profile != "none" else payload.user_agent
    cmd.extend(["--h2-profile", h2_val])
```

Bu duzeltme ile TLS ve HTTP/2 profilleri birbirinden bagimsiz olarak kontrol edilebilir.
