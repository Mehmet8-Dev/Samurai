# 01 - CLI (ddos_samurai/cli.py)

## Rol

`ddos_samurai/cli.py`, tum calistirma parametrelerini tek yerde toplar ve worker'lara dagitilacak "args snapshot" olusturur.

## Onemli Fonksiyonlar

- `build_parser()`: tum bayraklari/opsiyonlari tanimlar.
- `main()`: config merge, safety gate, dry-run, worker spawn.

## YAML Config Merge Mantigi

Akis:

1. `--config` ile YAML dosyasi okunur.
2. YAML icindeki key'ler argparse dest isimlerine map edilir:
   - Ust seviye dict -> dogrudan `set_defaults`.
   - Ic dict (nested) -> `"{main_key}_{sub_key}"` seklinde flatten edilip `set_defaults`'a eklenir.

Not: Bu flatten kuralini degistirirken testler ve mevcut config dosyalariyla uyumu gozden gecirin.

## Safety Gate

`--dry-run` degilse:

- `--confirm` verilmemisse `utils.ethical_warning()` calisir (interaktif).
- Ardindan `utils.validate_target_safety()` ile hedef kontrol edilir.

Gelistirme icin kritik nokta:

- "public hedef kilidi" default olarak aktif.
- CI/sandbox gibi ortamlarda interaktif input istemeyen senaryolar icin `--confirm` ve allowlist bayraklari kullanilir (urun akisi ihtiyacina gore yeniden tasarlanabilir).

## Worker Bolme

- `--workers` default: CPU core sayisi
- `count` toplam is parcaciklarina bolunur; remainder ilk worker'lara dagitilir.
- `--rps` verilirse worker basina rps bolunur (toplam rps hedefi korunur).

## CUDA + Multiprocessing

`if __name__ == '__main__'` altinda `spawn` start method'u ayarlanir.
Bu, CUDA context ve fork etkileisimlerini daha kontrol edilebilir hale getirir.

## Faz 2/3 ile Eklenen Bayraklar

HTTP/2:

- `--h2-transport {auto,httpx,hyper-h2}`
  - `auto`: uygun kosulda `hyper-h2`, degilse `httpx` fallback
  - `httpx`: mevcut transport davranisini zorlar
  - `hyper-h2`: profile-aware transportu zorlar (destek yoksa fail-visible)

WebSocket scenario:

- `--ws-scenario`
- `--ws-auth-message`
- `--ws-subscribe-message ...`
- `--ws-ping-count`
- `--ws-await-response`

PCAP replay:

- `--pcap-use-l2`
  - PCAP replay yolunu L2 TX_RING hattina zorlar
- `--pcap-no-flow-aware`
  - TCP seq/ack flow-aware rewrite'i kapatir

Run report input snapshot alanlari da guncellendi:

- `ws_scenario`
- `h2_transport`
