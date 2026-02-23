# 09 - Gelistirme ve Test

## Testleri Calistirma

Bu repoda test runner olarak `pytest` yerine Python standart kutuphanesi `unittest` kullanilir.

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

## Testlerin Yapisi

`tests/` dizinindeki unit test'ler genelde:

- CLI parser'da beklenen flag setleri
- Orchestrator dispatch davranisi (sender fonksiyonlarini monkeypatch ederek)
- Packet builder (payload/padding/fragment flag semantigi)
- Fragmentation sender davranisi
- Safety gate

## Sandbox/CI Ortami Notu (Scapy PermissionError)

Bazi kilitli ortamlarda (container/sandbox), Scapy import sirasinda netlink soketi acip interface listesini reload etmeye calisir.
Bu da test import/collection asamasinda `PermissionError: [Errno 1] Operation not permitted` uretebilir.

Gelistirme hedefi:

- Scapy importunu "lazy" hale getirip (gerekmedikce import etmeyerek)
- Veya interface reload'u gerektirmeyen bir konfig ile (ortama gore) calistirarak

testlerin non-root/sandbox ortamlarda da kosmasini saglamak.

Bu, urunlestirme ve CI icin onemlidir.

Bu repo bunun icin iki seyi yapar:

- `ddos_samurai/scapy_support.py`: scapy importunu lazy hale getirir.
- `tests/_scapy_fake.py`: scapy gerekmeden logic test edilebilsin diye minimal fake saglar.

## Local Degisim Rehberi

Degisiklik yaparken su ayrimi korumaya calisin:

- "args parse / config / safety": `cli.py` ve `utils.py`
- "dispatch": `orchestrator.py`
- "packet format": `packet.py` ve GPU modulleri
- "transport": `senders.py` + C extensions

## Dashboard (UI) Gelistirme

UI kodu `dashboard/` altindadir.

```bash
npm -C dashboard install
npm -C dashboard run dev
```

API adresi icin `dashboard/.env` kullanin:

- `VITE_API_BASE_URL=http://localhost:5099`

Detay: `docs/12-dashboard.md`

## Dashboard (UI) Testleri

Dashboard tarafinda test runner olarak `vitest` kullanilir.

```bash
npm -C dashboard test
npm -C dashboard test:watch
```

Testlerde su kombinasyon kullanilir:

- Unit: formatter ve form validation
- Unit: UI varyant sinif sozlesmeleri (`Button`, `Card`, `Badge`, `Tabs`)
- Unit: Start form gelismis ayar ac/kapa davranisi
- Unit: Recent runs compact/detay drawer davranisi
- Integration: route akisi, login, plan degisimi, run stop davranisi
- Mock API: `msw`

## Docker ile Smoke Calistirma

UI + API stack:

```bash
docker compose up -d --build
docker compose logs -f api
```

Detay: `docs/11-docker.md`
