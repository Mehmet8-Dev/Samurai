# Docker

Bu checkout'ta container-native calisma icin birincil yol distributed compose + helm'dir.

## 1) Docker Compose (Distributed)

Dosya: `docker-compose.distributed.yml`

Calistirma:

```bash
docker compose -f docker-compose.distributed.yml up --build --scale slave=3
```

Beklenen roller:

- `master`: control-plane + management API
- `slave`: worker execution

## 2) Production Image

```bash
docker build -f Dockerfile.prod -t ddos-samurai:prod .
```

CI'da da ayni Dockerfile smoke edilir.

## 3) Monitoring Stack

Ayrik monitoring compose:

```bash
cd monitoring
docker compose up -d
```

- Prometheus: `:9090`
- Grafana: `:3000`

## 4) Yetki/CAP Notlari

Dusus seviyeli network path'ler icin container capability gerekebilir.
Ozellikle:

- `NET_RAW`
- `NET_ADMIN`

Policy geregi privileged calisma sadece izole test ortaminda onerilir.

## 5) Legacy Notu

Klasik api/dashboard stack referanslari tarihsel olabilir.
Aktif runtime odagi distributed compose + management API + monitoring stack'tir.
