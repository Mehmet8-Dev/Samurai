# 11 - Docker ve Dağıtık Konteyner Mimarisi

DDoSamurai, Docker konteynerleri üzerinde hem tekil (standalone) hem de küme (cluster) modunda çalıştırılabilir.

---

## 1. Docker Compose ile Dağıtık Küme

[`docker-compose.distributed.yml`](file:///home/mehmet/Masa%C3%BCst%C3%BC/Python/v11/DDoSamurai/docker-compose.distributed.yml) dosyası Master, Master-Follower (HA), Redis koordinatörü ve çoklu Slave düğümlerini ayağa kaldırır:

```bash
# 4 adet Slave düğümü ile başlatma
docker compose -f docker-compose.distributed.yml up --build --scale slave=4
```

---

## 2. Üretim İmajını Derleme

```bash
docker build -f Dockerfile.prod -t ddos-samurai:latest .
```

---

## 3. Konteyner Ağ Yetkileri (Capabilities)

Düşük seviyeli ağ motorları (AF_XDP, raw socket, DPDK) için konteyner başlatılırken aşağıdaki yetkiler tanımlanmalıdır:

```yaml
cap_add:
  - NET_ADMIN
  - NET_RAW
  - SYS_NICE
```
