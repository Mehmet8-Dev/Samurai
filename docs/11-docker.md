# 11 - Docker (Legacy Notu)

Bu belge tarihsel icerik kapsamindadir.

## Repo Durumu (2026-03-14)

- Kokte `docker-compose.yml` dosyasi bulunur.
- Compose icinde `api` ve `dashboard` servisleri tanimlidir.
- Ancak bu checkout'ta `dashboard/` dizini ve `ddos_samurai/api.py` kaynaklari bulunmadigi icin stack dogrudan calismaz.

## Bu Checkout'ta Calisan Yol

Monitoring stack ayri ve calisabilir durumdadir:

```bash
cd monitoring
docker compose up -d
```

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`

## Not

Eger API/UI stack tekrar eklenecekse bu belge o anda guncel topolojiye gore yeniden yazilmalidir.
