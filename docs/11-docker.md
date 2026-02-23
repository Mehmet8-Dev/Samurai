# 11 - Docker (Compose) ile Calistirma

Bu dokuman, projeyi Docker ile "tek komutla" calistirmak isteyenler icin yazildi.
Odak: gelistirme ve gozlem (Dashboard + API) ve opsiyonel CLI runner.

> Not (safety): Bu proje yalnizca izinli/test ortamlarinda kullanilmalidir.
> Dokumantasyon operasyonel "saldiri nasil yapilir" yonlendirmesi amaclamaz.

## 1) Neler Calisiyor?

Repo kokundeki `docker-compose.yml` su servisleri tanimlar:

- `api`: FastAPI sunucusu (`ddos_samurai/api.py`) ve arka planda CLI calistirma (subprocess)
- `dashboard`: Vite ile build edilmis UI (nginx ile servis edilir)
- `samurai` (opsiyonel, `profiles: ["cli"]`): `python -m ddos_samurai.cli` icin interaktif runner

Ayrica `monitoring/` altindaki stack ayri bir compose'tur:

- `monitoring/docker-compose.yml`: Prometheus + Grafana + node-exporter (host metrikleri)

## 2) Hizli Baslangic (UI + API)

Kok dizinde:

```bash
docker compose up -d --build
```

Beklenen endpointler:

- Dashboard: `http://localhost:8080`
- API: `http://localhost:5099` (Dashboard default olarak buraya baglanir)

Durdurmak icin:

```bash
docker compose down
```

Log izleme:

```bash
docker compose logs -f api
docker compose logs -f dashboard
```

## 3) CLI Runner (Opsiyonel)

CLI runner profile ile acilir:

```bash
docker compose --profile cli run --rm samurai --help
```

Bu servis `network_mode: host` ile tanimli oldugu icin (Linux) host network stack'ini kullanir.

## 4) Yetki / Capability Notlari (Linux)

Bazı yollar (raw socket, paket craft, benzeri hizli gonderim yolları) ek yetki ister.
Compose'ta `api` ve `samurai` icin asgari su capability'ler eklenmistir:

- `NET_RAW`
- `NET_ADMIN`

Eger yine de "Operation not permitted" gorurseniz:

- Host cekirdegi / container runtime kisitlari sebebiyle `privileged: true` gerekebilir.
- Bu, guvenlik acisindan daha agresif bir ayardir; sadece izole test ortaminda kullanin.

## 5) Dashboard API Adresi (VITE_API_BASE_URL)

Dashboard, API adresini su env ile okur:

- `VITE_API_BASE_URL` (default: `http://localhost:5099`)

Yerel gelistirme icin:

- `dashboard/.env` icine yazabilirsiniz (ornegi: `dashboard/.env.example`).

> Not: Vite `import.meta.env` degerlerini build-time'da embed eder.
> Docker ile deploy senaryolarinda URL degistirecekseniz dashboard imajini yeniden build etmeniz gerekir.

## 6) GPU / CUDA (Durum)

Bu repoda GPU modulleri var; ancak Docker tarafinda GPU enable etmek (NVIDIA Container Toolkit, `--gpus`, driver uyumu)
ayri bir entegrasyon konusu. Bu dokuman kapsaminda "hazir calisir" varsayimi yapmaz.

