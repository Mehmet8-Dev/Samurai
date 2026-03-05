# 10 - Troubleshooting

## 1) Pytest Collection Asamasinda PermissionError (Scapy / Netlink)

Belirti:

- `PermissionError: [Errno 1] Operation not permitted`
- Stacktrace Scapy'nin interface reload / netlink bolumune gider

Kok neden:

- Ortam, `AF_NETLINK` soket acimina izin vermiyor (sandbox/container policy).

Gelistirme yonu:

- Scapy importunu calisma anina ertelemek (lazy import).
- CI icin "pure unit" modunda scapy bagimliligini stub/mocking ile izole etmek.

## 2) Raw Socket Hatalari

Belirti:

- "Raw socket creation failed. Please run ... with sudo/root privileges."

Kok neden:

- Root/cap_net_raw yetkisi yok.

Not:

- Bu proje, birden fazla transport yolu kullaniyor; urun senaryosuna gore hangi yollarin supported oldugu netlestirilmeli.

## 3) GPU Modunda CUDA Init / Context Hatalari

Belirti:

- CUDA context destroy / init race benzeri hatalar

Yapilanlar:

- Lazy import (CLI orchestrator importu geciktiriyor)
- Multiprocessing start method `spawn`

Ek tanilama:

- GPU modulleri icinde `cuda.is_available()` ve memory info raporlari mevcut.

## 4) Dashboard "Disconnected" / API Offline

Belirti:

- UI ust bar'da API Offline gorunur
- Console'da `API unreachable` uyarisi gorunebilir

Kontrol listesi:

- API gercekten ayakta mi?
  - Docker: `docker compose logs -f api`
- Port mapping dogru mu?
  - Beklenen: host `5099` -> api container `5099`
- Dashboard hangi API base URL'i kullaniyor?
  - Dev mod: `dashboard/.env` icindeki `VITE_API_BASE_URL`
  - Production build: Vite env degeri build-time'da embed edilir; degistirdiyseniz yeniden build gerekir.

## 5) Docker icinde "Operation not permitted" (NET_RAW / NET_ADMIN)

Belirti:

- Raw socket / netlink / low-level network operasyonlarinda `Operation not permitted`

Kok neden:

- Container capability/privilege yetersiz

Yapilabilecekler:

- `docker-compose.yml` icinde `cap_add: [NET_RAW, NET_ADMIN]` kullanmak
- Gerekirse (izole test ortaminda) `privileged: true`

Detay: `docs/11-docker.md`

## 6) `run_quality` Beklenenden Farkli (`interrupted` / `invalid_metrics`)

Belirti:

- Run raporunda `results.run_quality` degeri `valid` degil.

Kontrol listesi:

- `workers_total > 0` mi?
- `attempted_total > 0` mi?
- `warnings` icinde `run_interrupted_by_user` var mi?

Yorum:

- `interrupted`: kosu kullanici veya dis etkenden erken kesildi.
- `invalid_metrics`: metrik zemini eksik oldugu icin benchmark/parity skoruna girmemeli.

## 7) Sender Backend/Fallback Sorunlari

Belirti:

- Beklenen backend kullanilmiyor, `sender_paths_used` farkli cikiyor.
- `sender_fallback_reason` bos veya beklenmeyen bir deger.

Kontrol listesi:

- `--sender-backend` dogru secildi mi (`auto|txring|c_ext_l3|python|xdp`)?
- `--sender-fallback-policy fail` kullaniliyorsa `--sender-backend auto` secilmemeli.
- XDP yolu icin `--xdp-interface` zorunludur.

Not:

- Deterministik benchmark icin `--sender-backend` explicit secilmeli, `auto` yalnizca genel fallback modunda kullanilmalidir.
