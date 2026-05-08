# API

Bu checkout'ta klasik monolit `ddos_samurai/api.py` bulunmuyor.
Aktif API katmani distributed management API'dir.

Kaynak: `ddos_samurai/control/management_api.py`

## Endpointler

- `GET /healthz`
- `GET /v1/cluster/summary`
- `GET /v1/cluster/workers`
- `GET /v1/cluster/shards`
- `GET /v1/cluster/events`
- `POST /v1/jobs/abort`
- `GET /metrics`
- `GET /v1/cluster/live/sse`
- `WS  /v1/cluster/live/ws`

## Auth Modelleri

1. Role token
- admin/operator/viewer tokenlari

2. JWT
- role ve tenant claim tabanli

3. Trusted identity headers (reverse proxy)
- OIDC/SAML forward-auth proxy ile
- role + tenant headerlari + shared secret dogrulama

## Tenant Izolasyonu

- Query tenant + app tenant + claim tenant kontrolu birlikte yapilir
- Tenant mismatch durumunda 403 doner

## SSE/WS Live Akisi

- Snapshot tabanli yayin
- Cursor (`since_ts_ms`) destekli incremental event akisi

## Metrik Export

- `/metrics` endpointi plain text Prometheus formatinda cikti verir
- Uretilecek metrikler master state aggregator tarafinda normalize edilir

## Not

Purchase/portal/licensing API'leri ayrik `license_server` projesindedir (`license_server/*`).
