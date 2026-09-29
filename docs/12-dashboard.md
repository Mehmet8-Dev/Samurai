# 12 - İzleme, Grafana ve Telemetri Görünürlüğü

DDoSamurai, çalışma zamanı metriklerini hem anlık CLI üzerinden hem de Prometheus ve Grafana üzerinden izlenebilir kılar.

---

## 1. İzleme Mimarisi

1. **Prometheus Metrik Çıkışı:**
   Master ve Management API (`:8089/metrics`), kümedeki tüm worker'ların paket/istek oranlarını (RPS/pps), hata sayılarını, retransmission ve latency istatistiklerini Prometheus formatında sunar.

2. **Grafana Dashboardları:**
   `monitoring/` dizinindeki hazır Docker Compose stack'i Prometheus ve önceden yapılandırılmış Grafana panellerini barındırır:
   ```bash
   cd monitoring && docker compose up -d
   ```
   - Prometheus UI: `http://localhost:9090`
   - Grafana UI: `http://localhost:3000`

---

## 2. Canlı Olay Akışı (Live Streaming)

Management API üzerinden anlık durum güncellemeleri Server-Sent Events (SSE) ve WebSocket protokolleriyle alınabilir:
- `GET /v1/cluster/live/sse`
- `WS /v1/cluster/live/ws`
