# 02 - Orchestrator (`ddos_samurai/orchestrator.py`)

## Rol

Orchestrator, worker bazında saldırı vektörünü doğru sender/engine yoluna dispatch eder ve ortak istatistik şemasını döner.

## Giriş Fonksiyonları

- `start_worker(...)`: worker process bootstrap
- `worker_process(...)`: async dispatch ve sonuç toplama

## Sorumluluklar

- Worker içi route seçimi (L3/L4/L7/GPU)
- Pacing konfigürasyonu ve pacing metrikleri
- Dataplane queue/affinity metadata üretimi
- Stateful runtime + topology entegrasyonu
- Worker event/stat sözleşmesi üretimi

## Dispatch Gerçeği

- L7 vektörleri `senders` içindeki L7 yollarına aktarılır
- Raw/L3/L4 vektörleri packet/sender zinciriyle işlenir
- CUDA backend seçilirse GPU üretim yolu devreye girer

## Metrik Yaklaşımı

Worker event içinde sadece temel sayaçlar değil, pacing/txring/loss/runtime alanları da toplanır. Böylece run report ve KPI gate katmanları aynı şemayı tüketir.

## Önemli Davranış

`progress` güncellemesi gönderilen gerçek wire paketinden ziyade worker görev ilerlemesini de temsil eder; bu nedenle progress ve wire-loss metrikleri farklı anlam taşır.
