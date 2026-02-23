# 07 - Safety Gate'leri (ddos_samurai/utils.py)

## Hedef

Kod tabaninda "yanlis hedefe calistirma" riskini dusurmek icin temel bir güvenlik kapisi vardir.
Bu kapinin mantigi `utils.validate_target_safety()` ile uygulanir.

## Default Politika

- Sadece IPv4 desteklenir.
- Multicast/unspecified bloklanir.
- Allowlist verilmemisse:
  - Private veya loopback hedefler OK
  - Public hedefler default olarak BLOK

## Override Mekanizmalari

- `--allow-target` (tekrarlanabilir): IP veya CIDR allowlist
- `--allow-public-target`: public hedef kilidini kaldirir

## Etik Uyari Akisi

- `utils.ethical_warning()` interaktif onay ister.
- CLI'da `--confirm` ile bu interaktif adim atlanabilir.

Urunlestirme icin not:

- Interaktif prompt, servis/CI calistirmalarinda problem yaratabilir.
- Bu davranis "policy module" haline getirilip ortama gore degistirilebilir.

