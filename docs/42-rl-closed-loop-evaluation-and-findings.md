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

---

## 8. 8+ profil FF accumulate koşusu (2026-09-12)

Amaç: feed-forward (FF) politikasını **en az 8 farklı savunma profiliyle**, mevcut
korpus havuzunun **üstüne** (accumulate — hiçbir şey ezilmez), ~45 dakika yeniden
eğitmek. Çeşitlilik, `state-marginal` aşırı-öğrenmeye karşı belgelenen panzehir:
hangi lever/rate'in duvara toslayacağı **hedefe göre** değişince politika
reaction-conditioning sinyali alır.

**Orkestratör:** `deploy/waf-lab/train-run-8profile.sh` — `CAP_MIN` dakikalık
wall-clock capture bütçesi; Coraza profilleri blok halinde (tier başına bir
recreate), ardından statik hedefler capture deadline'a kadar round-robin. Bitince
**yalnız FF** (`train_iql`) tüm biriken havuzla retrain edilir (RL² dokunulmaz),
eski FF `mahoraga-ff.<stamp>.bak.srlp` olarak yedeklenir.

**9 canlı profil:**

| Profil | Port | Savunma karakteri |
|--------|------|-------------------|
| coraza strict-waf | 8080 | variant2 (POST/login) → 403, rate ~200 |
| coraza rate-only  | 8080 | WAF-block yok, uniform rate ~500 |
| coraza waf-heavy  | 8080 | variant1+3 → 403, rate ~100 |
| ModSecurity+CRS   | 8081 | farklı bloklu-variant haritası (ikinci motor) |
| Anubis PoW        | 8082 | proof-of-work challenge gateway |
| rate-drop r50     | 8084 | `limit_req` ~50 r/s |
| rate-drop r100    | 8083 | `limit_req` ~100 r/s |
| rate-drop r150    | 8085 | `limit_req` ~150 r/s |
| rate-drop r200    | 8086 | `limit_req` ~200 r/s |

**Sonuç:** +1440 yeni transition (coraza 3×36, modsec 234, anubis 234, rd-* 4×216)
havuza eklendi → havuz **24 dosya / 7774 transition / 422 episode**. FF retrain
(`in_dim=20`, `action_dim=5`, RLConfig() defaultları = mevcut 25 KB serving
kontratıyla uyumlu, block/ban kapalı).

```
OPE (FQE) gate — FF, tüm biriken havuz:
  behavior (AIMD) : -4.255
  FF   fqe=-0.226  gate=PASS  imp_ci=[+3.737, +4.321]
```

improvement CI kesinlikle pozitif → pesimistik gate marjla geçti; FF, AIMD'yi net
yeniyor. Native doğrulama: `export.load_policy(mahoraga-ff.srlp)` → in_dim 20 /
action 5 / non-recurrent, forward OK; `samurai_control_selftest` all-passed.

**Dürüst sınır:** OPE-from-s0 gate "AIMD'yi yener mi" kapısıdır (sağlam), RL²-vs-FF
kıyası için değil (§2). behavior −4.255, önceki regime-shift havuzunun −10.7'sinden
daha yumuşak; çünkü eklenen rate-drop/anubis/modsec profilleri episode-içi rejim
kaydırması içermez. Ağırlık/korpus `.gitignore`'dadır (üretilir); yalnız
orkestratör script'i versiyonlanır.

```bash
# tekrar üretim (9 profil de ayakta ve /healthz=200 olmalı)
CAP_MIN=37 bash deploy/waf-lab/train-run-8profile.sh
```

### 8.1 Canlı A/B doğrulaması (champion-challenger)

8-profil FF ağırlığı canlı on-policy A/B'ye sokuldu (static rate-drop r150 :8085,
4 rep serpiştirilmiş, `CL_SLO_MAX_PUSHBACK_PCT=20` → 429 = SLO ihlali):

| Kol | eff_mean | CI90 | served/s | slo_ok |
|-----|----------|------|----------|--------|
| AIMD | -0.326 | [-0.327, -0.325] | 31.6 | 33.3% |
| FF   | -0.109 | [-0.110, -0.109] | 25.4 | 50.0% |
| RL²  | -0.110 | [-0.110, -0.110] | 25.4 | 50.0% |

- **FF − AIMD = +0.216**, CI90 [+0.216, +0.217] → sıfırı net geçti: **FF promote**.
- **FF ≈ RL²** (Δ −0.001) → FF ship kararı korunur.
- **Nüans:** FF'in *ham* served/s'i AIMD'den düşük (25.4 < 31.6) ama *effective*
  throughput'u yüksek — AIMD rate duvarını zorlayıp 429 cezası yerken (SLO %33),
  FF honored tavanın altında parkedip SLO'yu %50'ye çıkarıyor. Eğitim objektifi
  tam da bu (SLO-güvenli served), OPE değil canlı A/B promote eder.

```bash
REPS=4 SHIFT=0 STATIC_PORT=8085 CL_SLO_MAX_PUSHBACK_PCT=20 bash deploy/waf-lab/ab-live.sh
```

### 8.2 Kapsam sınırı: Cloudflare / Suricata'ya hazır mı?

Bu FF dokuz profil gördü ama hepsi tek sınıftan: **L7 HTTP-status savunmaları**
(WAF 403 + rate 429/503 + PoW challenge), hepsi **kernel_socket** ile. Dolayısıyla:

- **Cloudflare** — WAF/rate katmanı FF'in gördüğü sınıfla aynı, kısmen transfer
  eder; ama JS/managed-challenge + bot-fingerprint için **sinyal yok** (bizim
  "challenge" feature'ı expectation_failures türevi, gerçek CF challenge'ı değil),
  ayrıca public target → rıza + `--allow-public-target` şart. → veri+rıza boşluğu.
- **Suricata / IPS** — imza flow/paket seviyesinde (RST/drop). Flow sinyalleri
  20-feature serving vektöründe **yok** ve tüm eğitim kernel_socket (bu sayaçlar 0)
  → IPS reaksiyonu state'e ulaşmıyor. Çözüm "daha çok profil" değil: **custom_tcp
  capture + flow sinyallerini serving vektörüne bağlamak** (SRLP in_dim değişir).

Lab sınıfı (Coraza/ModSec/nginx-rate) hazır; CF challenge ve IPS için yeni
sinyal/transport gerekir.

## 9. IDS/IPS/NSM ekseninde genişletme — Faz 1: flow-level IPS state

Mahoraga saldırgan-taraf adaptif bir kontrolcü; yalnızca **gözleyebildiği**
reaksiyonlardan öğrenir. Üç eksen bu açıdan eşit değil:

- **IDS (tespit+alarm):** inline değil, trafiği kesmez → client tarafında
  gözlemlenebilir reaksiyon yok. Ayrı eksen olarak öğrenilemez; ancak tetiklediği
  ban/blok üzerinden aksiyona döner (zaten `ban_pressure` feature'ı var).
- **IPS (inline block):** kötü trafiği düşürür/reset'ler → **flow-seviye** sinyal
  (RST / connect-timeout / retransmit / timeout-close). Gerçek, öğrenilebilir eksen.
- **NSM (pasif metadata/flow/JA3):** reaksiyon üretmez ama defender'ın fingerprint
  yüzeyini çıkarır → **Faz 2'de lever ailesi** (JA3/TLS/header-sırası/SNI), CF bot
  katmanını da açar. Henüz uygulanmadı.

**Faz 1 (uygulandı):** opt-in `RLConfig.flow_state_features`. Ban feature'larından
SONRA dört per-connection-attempt flow oranı + **tek paylaşılan** `flow_known` bit
(5 dim) eklenir. Sinyaller yalnız **flow-capable transport**'ta (custom_tcp / dpdk /
af_xdp / af_packet) anlamlıdır; `kernel_socket` (ya da transport-alanı olmayan eski)
korpus tamamen maskelenir (değer 0, known 0) — böylece dev kernel-socket havuzu
"flow hep sıfır" öğretmez. Transport artık her korpus transition'ına yazılır
(master `--transport`); paylaşılan known bit width decode'u da çakışmasız tutar
(5, V=5'teki block/ban kombinasyonlarının hiçbiriyle çakışmaz → SRLP formatı
değişmedi). Native serving (rl_policy `BuildFeatures`) aynı transport-gated
maskelemeyi birebir yansıtır; selftest golden width 25/37'yi ve non-capable
maskelemeyi Python encoding'e karşı sabitler.

Doğrulama: `tests/models/test_rl_flow_state.py` 6 test + C++ selftest golden yeşil;
canlı `custom_tcp` capture `transport=custom_tcp` kaydediyor ve uçtan-uca dataset
custom_tcp satırlarında `flow_known=1`, kernel_socket'te 0 üretiyor.

**Açık (veri adımı, kod değil):** sıfır-dışı flow sinyali için **inline IPS** gerek
(Suricata NFQUEUE ya da `iptables -j REJECT --reject-with tcp-reset`); bu NET_ADMIN
ister. Sonraki adım: Suricata-IPS lab + `TRANSPORT=custom_tcp` capture +
`flow_state_features=True` ile retrain. Kod yolu hazır ve maskelenmiş sıfır
sinyalle güvenli (temiz hedefte flow=0/known=1, davranış bozulmaz).

```bash
# flow-capable capture (gerçek IPS hedefine karşı)
TRANSPORT=custom_tcp WAF_LAB_PORT=<ips-port> bash deploy/waf-lab/run-corpus.sh
# flow feature'ı açık retrain
python -c "from ddos_samurai.models.rl.config import RLConfig; RLConfig(flow_state_features=True)"
```
