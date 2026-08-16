# 08 - Konfigürasyon ve Profil Yapılandırması

Native CLI ve Daemon'lar, komut satırı bayrakları, JSON test profilleri ve ortam değişkenleri (Environment Variables) üzerinden yapılandırılır.

---

## 1. Test Profilleri (`profiles.cpp`)

Sık kullanılan test kalıpları hazır profiller halinde kaydedilebilir veya çağrılabilir:

```bash
# Mevcut profilleri listeleme
./build/ddos_samurai/cli/samurai --list-profiles

# Belirli bir profili çalıştırma
./build/ddos_samurai/cli/samurai --profile dedicated_lab --confirm
```

---

## 2. Ortam Değişkenleri (Environment Variables)

| Değişken Adı | Varsayılan | Açıklama |
| :--- | :--- | :--- |
| `SAMURAI_CLUSTER_SECRET` | Boş | Master ve Slave düğümleri arasındaki ortak doğrulama anahtarı. |
| `SAMURAI_JWT_SECRET` | Boş | Management API ve Control Plane için HMAC-SHA256 gizli anahtarı. |
| `SAMURAI_XDP_INTERFACE` | Boş | AF_XDP motorunun bağlanacağı ağ kartı arayüzü (örneğin `eth0`). |
| `SAMURAI_XDP_QUEUE_ID` | `0` | Bağlanılacak NIC kuyruk numarası. |
| `SAMURAI_L7_TRANSPORT` | `kernel_socket` | L7 için transport seçimi (`kernel_socket`, `custom_tcp`, `custom_quic`). |
| `SAMURAI_TENANT_NAMESPACE` | `default` | Çoklu kiracı (Multi-tenant) izolasyon alanı. |
