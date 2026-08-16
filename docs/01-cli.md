# 01 - Native CLI (`samurai`) Kullanımı

`samurai`, DDoSamurai platformunun C++ ile derlenmiş ana komut satırı arayüzüdür (`ddos_samurai/cli/main.cpp`).

---

## 1. Temel Kullanım Sözdizimi

```bash
./build/ddos_samurai/cli/samurai --worker <cpu|gpu|dpdk|afxdp|doca|l7|defense|scenario> [seçenekler]
```

### Zorunlu / Temel Parametreler

- `--worker <kind>`: Çalıştırılacak native motor türü (`cpu`, `afxdp`, `dpdk`, `gpu`, `doca`, `l7`, `scenario`, `defense`).
- `--target <IP>`: Hedef IPv4 adresi (Varsayılan: `127.0.0.1`).
- `--port <N>`: Hedef port (Varsayılan: `80`).
- `--protocol <P>`: Protokol adı (`tcp`, `udp`, `icmp`, `http1`, `http2`, `quic`, `dns`).
- `--count <N>`: Gönderilecek toplam paket veya istek sayısı.
- `--confirm`: Etik onay uyarısını atlayarak testi başlatır.

---

## 2. Yaygın Kullanım Örnekleri

### A) CPU Raw Socket ile UDP Testi
```bash
./build/ddos_samurai/cli/samurai \
  --worker cpu \
  --target 127.0.0.1 \
  --port 8080 \
  --protocol udp \
  --count 100000 \
  --size 64 \
  --confirm
```

### B) AF_XDP Kernel-Bypass ile Ultra Hızlı Test
```bash
sudo ./build/ddos_samurai/cli/samurai \
  --worker afxdp \
  --target 10.0.0.50 \
  --port 80 \
  --protocol tcp \
  --count 5000000 \
  --confirm
```

### C) L7 HTTP/2 Stres Testi
```bash
./build/ddos_samurai/cli/samurai \
  --worker l7 \
  --target 10.0.0.50 \
  --port 443 \
  --protocol http2 \
  --scheme https \
  --concurrency 100 \
  --max-connections 50 \
  --count 200000 \
  --confirm
```

### D) Scenario Engine (Web/Mobile Persona) Testi
```bash
./build/ddos_samurai/cli/samurai \
  --worker scenario \
  --target 10.0.0.50 \
  --scenario-payload-ref docs/scenario_web_mobile.yaml \
  --count 50000 \
  --confirm
```

---

## 3. Güvenlik ve Doğrulama Bayrakları

- `--allow-public-target`: Genel (Public) IP adreslerine test gönderimine izin verir (Varsayılan olarak sadece yerel/özel IP'lere izin verilir).
- `--allow-target <CIDR>`: İzin verilen IP/Subnet listesi tanımlar.
- `--safety-global-deny-target <CIDR>`: Asla trafik gönderilmeyecek IP bloklarını kilitler.

---

## 4. Özel Test Modları

- `--self-test`: Dahili self-testleri çalıştırır.
- `--list-profiles`: Önceden tanımlanmış test profillerini listeler.
- `--profile <name>`: Belirtilen profili yükler.
- `--rfc-suite <suite>`: RFC uyumluluk test paketini çalıştırır.
