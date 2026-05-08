# Safety

Safety katmani, aracin yanlis hedefe veya kontrolsuz kosullarda calismasini azaltmak icin tasarlanmistir.
Ana implementasyon: `ddos_samurai/utils.py::validate_target_safety`

## Hedef Guvenlik Politikasi

Varsayilan davranis:

- Yalnizca IPv4 desteklenir
- Multicast ve unspecified adresler reddedilir
- Allowlist verilmediyse sadece private/loopback kabul edilir
- Public hedef default olarak blok

## Kontrol Bayraklari

- `--allow-target` (tekrarlanabilir)
  - IP veya CIDR allowlist
- `--allow-public-target`
  - Public hedef kilidini bilincli olarak kaldirir
- `--safety-global-deny-target` (tekrarlanabilir)
  - Her kosulda yasak hedef listesi
  - allow_public veya allowlist'ten daha onceliklidir

## Etik Onay Akisi

- `utils.ethical_warning()` interaktif YES onayi ister
- `--confirm` ile interaktif adim atlanabilir

## Runtime Emniyet Davranisi

Soak/monitoring alarmi geldiginde:

- `--safety-auto-abort` aktifse workerlar terminate edilir
- `--disable-safety-auto-abort` ile bu davranis kapatilabilir

Bu kontrol, yanlis konfigürasyon veya bozulan kosullarda hasari sinirlamak icindir.

## Operasyon Onerisi

Prod benzeri ortamlarda su kombinasyon onerilir:

- Public hedefte `--allow-public-target` sadece degisiklik kaydi ile
- Kurumsal denyliste `--safety-global-deny-target` zorunlu
- Uzun sureli kosularda auto-abort acik
