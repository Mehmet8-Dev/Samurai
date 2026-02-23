# 05 - GPU Engine (ddos_samurai/gpu_packet.py, gpu_payload.py, anomaly_packet.py)

## Rol

GPU yolu iki ana hedefe hizmet eder:

- Paket/payload uretimini GPU'da parallelize etmek
- Uretilmis buffer'i tek parca halinde CPU'ya alip hizli sender ile iletmek

Bu repo, GPU tarafinda Numba CUDA kernel'lari ve CuPy buffer'lari kullanir.

## Core Fonksiyonlar (gpu_packet.py)

Orchestrator'in kullandigi ana fonksiyonlar:

- `generate_packets_from_template_pool(...)`
  - CPU'da uretilmis ve normalize edilmis template listesi alir
  - Her paket icin template secimi + per-packet randomizasyon/spoof uygular
  - Sonuc: `(packets_gpu_array, packet_size)` seklinde contiguous buffer

- `generate_amplification_packets(...)`
- `generate_stateful_packets(...)`
- `generate_fragmented_packets(...)` (not: tum flow'lar bu fonksiyonu kullanmiyor)

## Template Normalizasyon Neden Gerekli?

`raw_socket_sender` tarafinda buffer parcasi `packet_size` ile dilimleniyor.
Bu nedenle GPU buffer icindeki her paketin boyu sabit olmalidir.

Orchestrator bu yuzden:

- template_pool olusturur
- hepsini ayni boyda pad/truncate eder

## GPU Payload Engine (gpu_payload.py)

Bu modul, bazi L7 benzeri payload uretimlerini GPU'da yapmaya yonelik bir altyapi gibi konumlanmis.
Orchestrator icinde belirli kosullarda (ornek: belirli vector/backends) kullaniliyor.

Not: GPU payload/packet tarafinda hata ayiklama icin stream synchronize, OOM handling vb. yardimci fonksiyonlar mevcut.

## Anomaly Engine (anomaly_packet.py)

Anomaly vektoru CUDA ile sinirli olacak sekilde gate edilmis (`cli.py`).
Burada hedef, standart paket uretiminden farkli olarak "malformed" varyasyonlarin GPU uzerinde uretilmesi ve Savunma sistemlerinin tepkisini ölçmektir.

