# Troubleshooting

Bu belge sahada en sik gorulen hata siniflarini ve hizli tani adimlarini toplar.

## 1) Lisans dogrulama basarisiz

Belirti:

- process `78` ile cikiyor
- log: `Lisans doğrulaması başarısız`

Kontrol:

1. `--license-key` veya `SAMURAI_LICENSE_KEY` var mi?
2. Lisans sunucusuna erisim var mi?
3. Sistem saati dogru mu (token/expiry etkiler)?

## 2) Raw socket/XDP yetki hatalari

Belirti:

- `Operation not permitted`
- root/capability uyarilari

Kontrol:

- root veya gerekli capability set edildi mi?
- container ise NET_RAW/NET_ADMIN var mi?
- XDP iface dogru mu?

## 3) XDP yolu acilmiyor

Belirti:

- `xdp_unavailable` / module not available

Kontrol:

1. `python setup.py build_ext --inplace`
2. NIC/driver XDP uygunlugu
3. `--xdp-interface` degeri

## 4) GPU classifier init hatasi

Belirti:

- engine load/init hatasi
- `gpu_classifier_hard_fail`

Kontrol:

- `--gpu-classifier-engine-path` dogru mu?
- TensorRT/CUDA surum uyumu var mi?
- `--gpu-defense-mode on` gerekli mi?

## 5) Soak run beklenmedik abort

Belirti:

- monitor tarafinda alarm + auto-abort

Kontrol:

- `--safety-auto-abort` aktif mi?
- thresholdlar (error rate, backlog, growth) fazla siki mi?
- kaynak metrikleri (RSS/VRAM/pinned) baseline'a gore normal mi?

## 6) Distributed slave register olmuyor

Belirti:

- slave, master register reddi veya timeout

Kontrol:

1. `--control-endpoints` dogru mu?
2. `--cluster-secret` uyusuyor mu?
3. tenant namespace mismatch var mi?
4. TLS/mTLS dosyalari dogru mu?

## 7) Management API 401/403

Belirti:

- `/v1/cluster/*` endpointleri yetki reddi

Kontrol:

- bearer token/role token dogru mu?
- JWT role/tenant claim adlari uyusuyor mu?
- trusted identity header kullaniyorsaniz secret/header isimleri uyumlu mu?

## 8) CI'da grpc/protobuf eksikligi

Belirti:

- distributed testlerde import hatalari

Kontrol:

- `pip install -e '.[distributed]'`
- protobuf/grpc paketleri mevcut mu?

## 9) Dashboard/API legacy beklentisi

Not:

- Bu checkout'ta klasik `dashboard/` ve `ddos_samurai/api.py` yok
- Aktif API, distributed management API katmanidir (`control/management_api.py`)

## 10) Hizli Tani Komutlari

```bash
python -m ddos_samurai.cli --self-test
python -m ddos_samurai.cli --list-profiles
pytest tests/test_cli_parser.py -q -rs
pytest tests/test_distributed_management_api.py -q -rs
```
