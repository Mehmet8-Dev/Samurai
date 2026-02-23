# 12 - Dashboard (UI)

Bu doküman `dashboard/` arayüzünün Claude-benzeri sol rail tasarımına taşınmış güncel yapısını açıklar.

## Teknoloji

- React 18 + Vite
- Routing: `react-router-dom`
- Data: `@tanstack/react-query`
- Doğrulama: `zod`
- HTTP: `axios`
- Test: `vitest`, `@testing-library/*`, `msw`
- Font: self-host (`@fontsource/instrument-sans`, `@fontsource/public-sans`, `@fontsource/ibm-plex-mono`)

## URL Davranışı

- `/`: Ana dashboard (auth gerekli)
- `/upgrade`: Plan yönetimi (auth gerekli)
- `/login`: Giriş
- `/register`: Kayıt

Kök URL (`/`) korunur.

## Bilgi Mimarisi

- `AppShell` sol rail + içerik çerçevesi modelindedir.
- Sol rail alanları:
  - Marka bloğu
  - Ana menü (`Anasayfa`, `Plan`)
  - İkincil aksiyon (`Hesap`)
  - API sağlık, tema, çıkış
- İçerik çerçevesi:
  - Üst topbar (başlık, açıklama, hızlı aksiyon)
  - Sayfa içeriği

## Dashboard (`/`) Yapısı

- Üstte operasyon özeti (4 KPI)
- Sol ana kolon:
  - `Test Başlat` komut paneli (Temel + `Gelişmiş Ayarlar` aç/kapa)
  - `Recent Runs` compact tablo + satır detay drawer
- Sağ yan kolon:
  - `Hesap Bağlamı` paneli (Tabs: `Hesap`, `Abonelik`, `Faturalama`)
  - Runtime stats

## Upgrade (`/upgrade`) Yapısı

- Aktif plan özeti
- Plan karşılaştırma strip’i
- Kart içinde CTA: `Bu Plana Geç`
- Aktif plan kartı görsel olarak vurgulanır

## Auth (`/login`, `/register`) Yapısı

- Sade merkezlenmiş auth layout
- Tab geçişi (`Giriş Yap` / `Kayıt Ol`)
- Alan bazlı hata + üst hata özeti

## Veri Akışı

`useDashboardData` query’leri:

- `GET /health`
- `GET /auth/me`
- `GET /subscription/me`
- `GET /billing/summary`
- `GET /plans`
- `GET /tests/runs`
- `GET /stats`

Polling:

- Görünür sekmede 5 sn
- Auth yoksa query disable

Mutasyonlar (`useTestActions`):

- `POST /tests/start`
- `POST /tests/{id}/stop`
- `POST /subscription/change`

## Tema

- `light` varsayılan, `dark` opsiyonel
- Persist: `localStorage.samurai_theme`
- Root attribute: `data-theme=\"light|dark\"`

## Çalıştırma

```bash
npm -C dashboard install
npm -C dashboard run dev
```

`.env`:

- `VITE_API_BASE_URL=http://localhost:5099`

## Test

```bash
npm -C dashboard test
npm -C dashboard test:watch
```

Kapsam:

- Auth integration
- Route/integration (`/`, `/upgrade`, geri/ileri)
- StartTestForm validasyon + gelişmiş ayar toggling
- RecentRuns compact/detay davranışı
- UI variant sınıf sözleşmeleri (`Button`, `Card`, `Badge`, `Tabs`)
- Tema persist
