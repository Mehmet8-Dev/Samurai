# 42 — RL Kapalı-Döngü Autopilot: Değerlendirme Metodolojisi ve Bulgular

Bu doküman, closed-loop autopilot'un **öğrenilmiş politika** katmanının (Mahoraga RL)
canlı WAF-lab'a karşı nasıl değerlendirildiğini, hangi kök-nedenlerin bulunup
düzeltildiğini ve hangi sevk (ship) kararının verildiğini kayda geçer. Amaç:
sonuçları tekrar üretilebilir kılmak ve "RL kendini amorti ediyor mu?" sorusuna
dürüst, ölçülebilir bir cevap bırakmak.

İlgili kaynaklar: `ddos_samurai/control/closed_loop.{hpp,cpp}` (kontrolcü + SLO),
`ddos_samurai/models/rl/` (IQL/RL²/reward/OPE), `deploy/waf-lab/` (lab + koşu
scriptleri). Kısa bağlam için `MEMORY.md`'deki `waf-defense-zoo` notu.

---

## 1. Politikalar: AIMD, FF, RL²

Kapalı-döngü her ölçüm penceresinde "sonraki yükü ne yapayım?" kararını verir
(rps + concurrency + pacing_mode + request_mix + source_rotation = Mahoraga aksiyonu).
Üç aday:

| Kol | Ne | Nasıl karar verir |
|-----|-----|-------------------|
| **AIMD** | Öğrenilmemiş baseline | Additive-increase / multiplicative-decrease; sadece rps'i ayarlar, Mahoraga lever'larına dokunmaz |
| **FF** | Feedforward IQL politikası | Yalnız **o anki** state'e bakar (reaktif); stateless |
| **RL²** | Recurrent meta-RL (GRU) | O anki state **+ episode-içi biriktirdiği bağlam** (adaptif) |

FF = `train_iql` (`ddos_samurai/models/rl/train.py`), RL² = `train_rl2`
(`rl2.py`). İkisi de offline RL: loglanmış `(s, a, s')` üçlülerinden öğrenir,
sıfırdan online keşif yapmaz.

---

## 2. Değerlendirme enstrümanı: canlı on-policy A/B

**Kritik ders: offline OPE (FQE), RL²/FF karşılaştırması için yanlış enstrümandır.**
FQE değeri, politikayı loglanan (davranış politikasının) trajektorisi üzerinden
değerlendirir; recurrent bir politikanın bağlamı kendi aksiyonlarıyla değil,
davranış politikasının aksiyonlarıyla beslenir → **counterfactual/off-policy context
uyuşmazlığı**. `ope.py`'ye trajectory-wide değerleme eklenmiş olsa da
(`FQEConfig.trajectory_value`, s0-çapa yerine tüm pencere) bu duvar tam aşılamaz.

Doğru enstrüman: **canlı, self-driven A/B** — her politika gerçek lab'ı **kendisi
sürer**, kendi bağlamını kendi aksiyonlarıyla kurar (nasıl ship'lenecekse öyle).

- `deploy/waf-lab/ab-live.sh` — üç kolu (AIMD/FF/RL²) sırayla canlı hedefe sürer;
  rep'ler **serpiştirilmiş** (lab drift her kolu eşit vurur, karşılaştırma rep'e göre
  eşleştirilebilir); shift modunda tüm kollar **aynı** episode-ortası hedef
  değişimine maruz.
- `deploy/waf-lab/ab_report.py` — birincil metrik **EffectiveThroughput** (eğitim
  objektifi: served 2xx − λ_defense·pushback − λ_flow·flow − λ_slo·overshoot −
  step_cost). Ham 2xx/s **kullanılmaz** — o sadece en çok rps basanı ödüllendirir;
  EffectiveThroughput offline "+X AIMD'yi geçiyor" ile aynı cetveldir. Rep-eşleştirilmiş
  bootstrap CI + RL²-vs-FF verdict basar.

Hedef rejimleri (port-güdümlü): `STATIC_PORT` (sabit tavan), `SHIFT_A/B_PORT`
(episode-ortası geçiş).

---

## 3. Lab substratı ve kritik düzeltmeler

### 3.1 Limiter gerçekten reddetmeli (nodelay)
`waf-heavy` nginx profili `limit_req burst=20` idi ama **`nodelay` yoktu** →
aşan istekler reddedilmiyor, kuyruğa alınıp geciktiriliyordu, sonra 200 dönüyordu.
Pace'li kapalı-döngü kuyruğu taşırmadığı için limiter yalnız **latency** yükseltip
hata-tabanlı SLO'ya görünmez kalıyordu (`docs`/nginx logu: DELAYED, 0 REJECTED).
Fix: `limit_req ... nodelay` → aşan rps anında 429 (`profiles/waf-heavy/nginx.conf`).

> Docker tuzağı: bind-mount edilen conf'u editörle değiştirmek inode değiştirir →
> çalışan container eskisini görür. `docker compose up -d --force-recreate nginx` şart.

### 3.2 Çok-tavanlı biting-wall substratı
`deploy/waf-lab/docker-compose.ratedrop.yml` — saf-rate nginx hedefleri, hepsi
nodelay (reddeder):
- Eğitim tavanları: `:8084`=50 r/s, `:8083`=100, `:8086`=200.
- **Holdout `:8085`=150 r/s** — eğitimde HİÇ yok, yalnız genelleme gate'i (görülmemiş tavan).

### 3.3 Pushback SLO — asıl kilidi açan düzeltme
En derin kök-neden: **SLO 429'u ihlal saymıyordu.** 429 error_pct'i yükseltmediği için
kontrolcü rate duvarına körce rampalıyordu, honored tavanı hiç bulmuyordu; her kol
net-negatif, AIMD sadece "en az kötü". Bir yük-testi için istekler reddediliyorsa test
hedef yükü **teslim edemiyor** demektir → bu gerçek bir SLO ihlalidir.

Fix (`ddos_samurai/control/closed_loop.{hpp,cpp}`, `daemon/master_main.cpp`):
`slo_max_pushback_pct` (config + `LoadSample.pushback_pct` + `IsHealthy` kuralı);
master `(4xx+5xx)/responses_total` ile doldurur; CLI `--cl-slo-max-pushback-pct`;
selftest kapsar. Bu, AIMD/binsearch'ün geri çekilip **tavanı bulmasını** ve RL
shield'ının reddeden pencerede backoff yapmasını sağlar.

---

## 4. Bulgular (canlı A/B, EffectiveThroughput, 5 rep, pushback SLO=20)

FF ve RL² için 5-profil biting-wall havuzunda eğitim (2992 transition / 176 episode).

| Rejim | AIMD | FF | RL² | **FF−AIMD** | **RL²−AIMD** | RL²−FF |
|-------|------|-----|-----|-------------|--------------|--------|
| Holdout `:8085` (görülmemiş) | −0.328 | **−0.110** | −0.110 | **+0.218** | **+0.218** | +0.000 |
| Rate-drop `:8083↔:8084` | −0.461 | −0.328 | −0.333 | **+0.134** | **+0.128** | −0.006 |
| Coraza `:8080` (WAF+rate) | −0.477 | −0.281 | −0.313 | **+0.196** | **+0.164** | −0.032 |

Tüm `−AIMD` farklarının %90 CI'ı sıfırı geçiyor.

**Mekanizma:** `slo_ok` — AIMD %20–33 yeşil vs FF/RL² %50. AIMD hâlâ salınıyor
(backoff→overshoot); öğrenilmiş politikalar tavanı **sabit tutup** çok daha az
pushback cezası yiyor. AIMD biraz daha çok servis eder (31 vs 25) ama ağır 429
bedeliyle → EffectiveThroughput'ta geride.

### İki sevk-edilebilir sonuç
1. **RL katmanı işe yarıyor** — *doğru objektifle* (pushback SLO). Öğrenilmiş politika
   3/3 rejimde, holdout dahil, AIMD'yi anlamlı geçti. Sorun hiçbir zaman
   mimari/algoritma değildi; **objektifin tutarsızlığıydı** (SLO tavanı ödüllendirmiyordu).
2. **Ship edilecek FF, RL² değil.** Recurrent RL² her yerde FF ile eşit/geride;
   ek karmaşıklık (context reset, recurrent serving) gerekçesiz. Basit olan kazandı.

---

## 5. Metodolojik dersler (dürüst kayıt)

- **Canlı gate gerçeğin kaynağıdır.** OPE (s0 ya da trajectory) mutlak kalite ve
  RL²-vs-FF için güvenilmez; yalnız ucuz bir smoke.
- **"Yeterli veri" kural-of-thumb ile değil, öğrenme eğrisiyle** belirlenir — ve burada
  **iki eğri ayrışıyor.** Offline OPE, veriyle **doymadan yükselmeye devam ediyor**:
  FF'nin OPE değeri 17→136 episode arası −3.84→−2.73, ve havuz 2992→6630 transition'a
  (176→390 ep) iki katlanınca −2.49→−2.13'e çıktı. AMA **canlı holdout gate DEĞİŞMEDİ**:
  612 / 2992 / 6630 transition'ın üçünde de FF holdout eff = **−0.110** (birebir),
  FF−AIMD = +0.218. **Kanıt: canlı (ship edilen) performans ~3000 transition'da DOYMUŞ;
  veriyi ikiye katlamak sıfır canlı kazanç getirdi.** Offline OPE'nin yükselmesi yalnız
  daha iyi Q-fit'tir, gerçek politikanın iyileşmesi değil — "OPE zayıf enstrüman"ın en
  net kanıtı. Kesin söz canlı gate'in: bu görev/lab için FF veri-doymuş.
- **Prod-grade ölçek ≠ 100k–400k episode.** O rakam sıfırdan online deep-RL
  dünyasından. Bu düşük-boyutlu offline problemde canlı performans ~3000 transition'da
  düzleşti (6630'a çıkarmak ölçülebilir canlı kazanç vermedi; 400k ≈ 315 gün kesintisiz
  yük — imkânsız/gereksiz). Prod-grade için asıl gereken **ortam çeşitliliği** (farklı
  savunma motorları/tavanları) + **online per-target adaptasyon** + güvenlik gate'leri,
  ham episode sayısı değil.
- **RL²'nin hakkını vereceği rejim henüz kurulmadı:** hafıza ancak geçmiş geleceği
  **tahmin ediyorsa** kazandırır (progresif/tırmanan limiter, ban döngüleri, adaptif
  WAF). Bizim shift'ler rastgele → hafıza sömürülemedi. Bu, RL²'yi *silmek* değil
  *park etmek* için gerekçe; tahmin-edilebilir-adversary substratı gelecek iş.

### Operasyonel not
`ab-live`/`train-run-*` içindeki socat shift-proxy'si SIGTERM'e ölmeyince teardown'daki
reap `wait`'i sonsuza asılabiliyordu (bir koşu 8 saat kilitlendi). Fix: socat'ı
`kill -9` ile öldür (garanti ölür), reap kill'den ayrık. Uzun koşularda **stall-timeout**
şart — sessiz "tamamlanmadı" beklemesine güvenme.

---

## 6. Tekrar üretim

```bash
# lab + biting-wall substratı
docker compose -f deploy/waf-lab/docker-compose.yml up -d
docker compose -f deploy/waf-lab/docker-compose.ratedrop.yml up -d
docker exec samurai-lab-nginx nginx -s reload   # nodelay conf için --force-recreate gerekebilir

# 5-profil biting-wall capture + FF/RL² train (pushback SLO on)
CL_SLO_MAX_PUSHBACK_PCT=20 BW_STATIC_TARGETS="8084 8083 8086 8080 8081" \
  STATIC_SWEEPS=28 SHIFT_SWEEPS=18 bash deploy/waf-lab/train-run-bitewall.sh

# canlı A/B gate (holdout / rate-drop / Coraza), FF-bw ağırlıklarıyla
export RL2_POLICY=artifacts/rl/mahoraga-rl2-bw.srlp FF_POLICY=artifacts/rl/mahoraga-ff-bw.srlp
REPS=5 SHIFT=0 STATIC_PORT=8085 CL_SLO_MAX_PUSHBACK_PCT=20 bash deploy/waf-lab/ab-live.sh
REPS=5 SHIFT=1 SHIFT_A_PORT=8083 SHIFT_B_PORT=8084 CL_SLO_MAX_PUSHBACK_PCT=20 bash deploy/waf-lab/ab-live.sh
```

Ağırlıklar ve korpuslar `.gitignore`'dadır (`artifacts/rl/`, `data/rl-corpus*/`);
scriptler ve kod versiyonlanır, veri/ağırlık üretilir.

---

## 7. Karar özeti

- **Ship: FF** (`mahoraga-ff-bw.srlp`), serving `--cl-strategy rl --rl-policy <ff> --cl-slo-max-pushback-pct 20`.
- **Pushback SLO'yu üretim varsayılanı yap** (429 = ihlal — doğru yük-testi semantiği).
- **RL²: park** — tahmin-edilebilir/tırmanan-adversary rejimi hedeflenene kadar.
- **Champion-challenger:** bir politika ancak canlı A/B'de AIMD'yi geçerse promote edilir.
