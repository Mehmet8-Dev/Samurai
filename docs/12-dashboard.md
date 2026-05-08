# Dashboard

Bu repo checkout'unda bagimsiz bir React/Vite dashboard kaynagi yoktur.

## Mevcut Gorunurluk Kaynaklari

1. Grafana/Prometheus
- `monitoring/` altindaki stack
- Runtime ve distributed metrikleri buradan izlenir

2. Management API live endpointleri
- SSE: `/v1/cluster/live/sse`
- WebSocket: `/v1/cluster/live/ws`

3. Run report artefaktlari
- JSON/Markdown ciktilar (`--run-report`)
- KPI/soak benchmark raporlari

## Ne Eksik?

- Dogrudan urun icinde ship edilen web UI katmani
- Tenant bazli front-end role ekranlari

## Onerilen Yol (UI sonradan)

- Kisa vadede: Management API + Grafana panel setleri
- Uzun vadede: Ayrik `web_console` paketi (OIDC + tenant aware)
