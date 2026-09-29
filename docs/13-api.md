# 13 - Native HTTP Management API (`:8089`)

Master düğümünde `--management-listen` parametresi verildiğinde devreye giren Management API, saf POSIX socket tabanlı, sıfır harici web kütüphanesi bağımlılığına sahip yerel bir C++ HTTP REST sunucusudur (`ddos_samurai/control/management_api.cpp`).

---

## 1. REST Endpointleri

| Metot | Yol | Açıklama |
| :--- | :--- | :--- |
| `GET` | `/healthz` | Sunucu sağlık kontrolü (`200 OK`). |
| `GET` | `/v1/cluster/summary` | Bağlı worker sayısı, aktif shard'lar ve toplam metrik özeti. |
| `GET` | `/v1/cluster/workers` | Kayıtlı tüm worker'ların detaylı listesi ve son heartbeat zamanları. |
| `GET` | `/v1/cluster/shards` | Çalışan veya tamamlanan iş parçalarının (shards) durumu. |
| `POST` | `/v1/jobs/abort` | Yürütülmekte olan aktif test/saldırı işini anında durdurma. |
| `GET` | `/metrics` | Prometheus uyumlu ham metrik çıktısı. |
| `GET` | `/v1/cluster/live/sse` | Server-Sent Events (SSE) ile canlı küme durumu akışı. |
| `GET` | `/v1/cluster/live/ws` | WebSocket ile canlı durum akışı. |

---

## 2. Kimlik Doğrulama ve Yetkilendirme (Auth)

API istekleri 3 yöntemden biriyle yetkilendirilebilir:
1. **Role Token:** `Authorization: Bearer <ADMIN_OR_OPERATOR_TOKEN>`
2. **HMAC-SHA256 JWT:** OpenSSL ile doğrulanmış tenant ve role claim'leri.
3. **Trusted Identity Headers:** Kurumsal ters vekil sunucuların (Reverse Proxy / OIDC) ilettiği `X-Forwarded-User` ve `X-Forwarded-Roles` başlıkları.
