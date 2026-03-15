# 20) Env ve CLI Referans Dokumani

Bu dokuman, `ddos_samurai/cli.py` merkezli olmak uzere projedeki:
- CLI argumanlarini
- `SAMURAI_*` environment variable akislarini
- CLI -> runtime env bridge davranisini

tek yerde, detayli bir referans olarak toplar.

## Kapsam

Bu dokuman su kaynaklardan derlendi:
- `ddos_samurai/cli.py`
- `ddos_samurai/dataplane.py`
- `ddos_samurai/fast_sender.c`
- `ddos_samurai/pacing_engine.c`
- `ddos_samurai/senders.py`
- `ddos_samurai/orchestrator.py`
- `ddos_samurai/l7_state_engine.c`
- Not: Bu checkout'ta API/dashboard kaynaklari olmadigi icin API/SaaS env'leri aktif runtime'in parcasi degildir; tarihsel referanstir.

Not: Buradaki tablo ve envanterler kod bazli bir referanstir; davranis dogrulamada yine calisma ortami/runtime sonuclari esas alinmalidir.

## Konfigurasyon Onceligi (Precedence)

`main()` akisina gore (`cli.py:1605+`) oncelik su sekildedir:

1. `build_parser()` ile parser defaultlari kurulur (cogu env + hardcoded varsayilan).
2. `parse_known_args()` ile sadece `--config` yakalanir.
3. Config dosyasi (`--config`) okunur ve `parser.set_defaults(**defaults_from_config)` ile parser defaultlari override edilir.
4. Son `parse_args(argv)` ile CLI'da acik verilen argumanlar en yuksek oncelige sahip olur.
5. Preflight/validasyon adimlari (`_resolve_profile_args`, `_preflight_lab_profile`, vb.) bazi alanlari bilincli olarak mutasyona ugratarak zorunlu profile davranisi uygular.
6. Son asamada secilen ayarlar `os.environ[...]` uzerinden runtime modullere bridge edilir.

Pratikte genel kural:
- Explicit CLI > config dosyasi > env default > hardcoded default
- Ancak preflight/profil zorlamalari bu degerleri policy geregi degistirebilir.

## CLI Tarafindan Okunan Env Varsayilanlari
| Env | Kod Referansi | Not |
|---|---|---|
| `SAMURAI_AF_PACKET_BLOCK_SIZE_KB` | `cli.py:984` | Parser default/preflight |
| `SAMURAI_AF_PACKET_BUSY_POLL_US` | `cli.py:1014` | Parser default/preflight |
| `SAMURAI_AF_PACKET_FRAMES_PER_BLOCK` | `cli.py:996` | Parser default/preflight |
| `SAMURAI_AF_PACKET_FRAME_SIZE` | `cli.py:990` | Parser default/preflight |
| `SAMURAI_AF_PACKET_HUGEPAGE_MODE` | `cli.py:961` | Parser default/preflight |
| `SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB` | `cli.py:972` | Parser default/preflight |
| `SAMURAI_AF_PACKET_MLOCK_RING` | `cli.py:1045` | Parser default/preflight |
| `SAMURAI_AF_PACKET_POLL_TIMEOUT_MS` | `cli.py:1002` | Parser default/preflight |
| `SAMURAI_AF_PACKET_PREFAULT_RING` | `cli.py:1060` | Parser default/preflight |
| `SAMURAI_AF_PACKET_QDISC_BYPASS` | `cli.py:1030` | Parser default/preflight |
| `SAMURAI_AF_PACKET_RING_TARGET_MB` | `cli.py:978` | Parser default/preflight |
| `SAMURAI_AF_PACKET_SPIN_LIMIT` | `cli.py:1008` | Parser default/preflight |
| `SAMURAI_DATAPLANE_CORE_ENABLE` | `cli.py:951` | Parser default/preflight |
| `SAMURAI_DP_QUEUES` | `cli.py:1077` | Parser default/preflight |
| `SAMURAI_DP_QUEUE_MAP` | `cli.py:1083` | Parser default/preflight |
| `SAMURAI_DP_QUEUE_STRATEGY` | `cli.py:1071` | Parser default/preflight |
| `SAMURAI_GPU_BATCH` | `cli.py:1176` | Parser default/preflight |
| `SAMURAI_GPU_FULL_VARIATION` | `cli.py:1194` | Parser default/preflight |
| `SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT` | `cli.py:1303` | Parser default/preflight |
| `SAMURAI_GPU_PINNED_MAX_MB` | `cli.py:1200` | Parser default/preflight |
| `SAMURAI_GPU_PIPELINE_DEPTH` | `cli.py:1188` | Parser default/preflight |
| `SAMURAI_GPU_RING_CAPACITY` | `cli.py:1170` | Parser default/preflight |
| `SAMURAI_GPU_RNG_SEED` | `cli.py:1309` | Parser default/preflight |
| `SAMURAI_GPU_STREAMS` | `cli.py:1182` | Parser default/preflight |
| `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4` | `cli.py:1158` | Parser default/preflight |
| `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7` | `cli.py:1164` | Parser default/preflight |
| `SAMURAI_KPI_GATE_PROFILE` | `cli.py:1092` | Parser default/preflight |
| `SAMURAI_L7_CAPABILITY_STRICT` | `cli.py:1145` | Parser default/preflight |
| `SAMURAI_L7_ENGINE` | `cli.py:1103` | Parser default/preflight |
| `SAMURAI_L7_FALLBACK_POLICY` | `cli.py:1139` | Parser default/preflight |
| `SAMURAI_L7_HTTP2_ENGINE` | `cli.py:1109` | Parser default/preflight |
| `SAMURAI_L7_QUIC_AUTO_BRIDGE` | `cli.py:1127` | Parser default/preflight |
| `SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE` | `cli.py:1133` | Parser default/preflight |
| `SAMURAI_L7_QUIC_ENGINE` | `cli.py:1115` | Parser default/preflight |
| `SAMURAI_L7_QUIC_REQUIRE_NATIVE` | `cli.py:1121` | Parser default/preflight |
| `SAMURAI_LAB_PROFILE` | `cli.py:1065` | Parser default/preflight |
| `SAMURAI_QUIC_BUILD_MODE` | `cli.py:680` | Native QUIC required preflight override kontrolu |
| `SAMURAI_STATE_LOCK_COUNT` | `cli.py:1218` | Parser default/preflight |
| `SAMURAI_STATE_SWEEP_INTERVAL_MS` | `cli.py:1230` | Parser default/preflight |
| `SAMURAI_STATE_TABLE_SIZE` | `cli.py:1212` | Parser default/preflight |
| `SAMURAI_STATE_TIMEOUT_SEC` | `cli.py:1224` | Parser default/preflight |

## CLI Tarafindan Export Edilen Env Degiskenleri
| Env | Kod Referansi | Uretim |
|---|---|---|
| `SAMURAI_AF_PACKET_BLOCK_SIZE_KB` | `cli.py:1700` | `os.environ["SAMURAI_AF_PACKET_BLOCK_SIZE_KB"] = str(` |
| `SAMURAI_AF_PACKET_BUSY_POLL_US` | `cli.py:1715` | `os.environ["SAMURAI_AF_PACKET_BUSY_POLL_US"] = str(` |
| `SAMURAI_AF_PACKET_FRAMES_PER_BLOCK` | `cli.py:1706` | `os.environ["SAMURAI_AF_PACKET_FRAMES_PER_BLOCK"] = str(` |
| `SAMURAI_AF_PACKET_FRAME_SIZE` | `cli.py:1703` | `os.environ["SAMURAI_AF_PACKET_FRAME_SIZE"] = str(` |
| `SAMURAI_AF_PACKET_HUGEPAGE_MODE` | `cli.py:1693` | `os.environ["SAMURAI_AF_PACKET_HUGEPAGE_MODE"] = _afpacket_hp_mode` |
| `SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB` | `cli.py:1694` | `os.environ["SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB"] = str(` |
| `SAMURAI_AF_PACKET_MLOCK_RING` | `cli.py:1721` | `os.environ["SAMURAI_AF_PACKET_MLOCK_RING"] = "1" if bool(getattr(args, "afpacket_mlock_ring", False)) else "0"` |
| `SAMURAI_AF_PACKET_POLL_TIMEOUT_MS` | `cli.py:1709` | `os.environ["SAMURAI_AF_PACKET_POLL_TIMEOUT_MS"] = str(` |
| `SAMURAI_AF_PACKET_PREFAULT_RING` | `cli.py:1722` | `os.environ["SAMURAI_AF_PACKET_PREFAULT_RING"] = "1" if bool(` |
| `SAMURAI_AF_PACKET_QDISC_BYPASS` | `cli.py:1718` | `os.environ["SAMURAI_AF_PACKET_QDISC_BYPASS"] = "1" if bool(` |
| `SAMURAI_AF_PACKET_RING_TARGET_MB` | `cli.py:1697` | `os.environ["SAMURAI_AF_PACKET_RING_TARGET_MB"] = str(` |
| `SAMURAI_AF_PACKET_SPIN_LIMIT` | `cli.py:1712` | `os.environ["SAMURAI_AF_PACKET_SPIN_LIMIT"] = str(` |
| `SAMURAI_DATAPLANE_CORE_ENABLE` | `cli.py:1689` | `os.environ["SAMURAI_DATAPLANE_CORE_ENABLE"] = "1" if _dp_mode in {"auto", "required"} else "0"` |
| `SAMURAI_DATAPLANE_CORE_MODE` | `cli.py:1688` | `os.environ["SAMURAI_DATAPLANE_CORE_MODE"] = _dp_mode` |
| `SAMURAI_DP_QUEUES` | `cli.py:1727` | `os.environ["SAMURAI_DP_QUEUES"] = str(int(getattr(args, "dp_queues", 1) or 1))` |
| `SAMURAI_DP_QUEUE_MAP` | `cli.py:1728` | `os.environ["SAMURAI_DP_QUEUE_MAP"] = str(getattr(args, "dp_queue_map", "") or "")` |
| `SAMURAI_DP_QUEUE_STRATEGY` | `cli.py:1726` | `os.environ["SAMURAI_DP_QUEUE_STRATEGY"] = str(getattr(args, "dp_queue_strategy", "rr") or "rr")` |
| `SAMURAI_GPU_BATCH` | `cli.py:1673` | `os.environ["SAMURAI_GPU_BATCH"] = str(int(getattr(args, "gpu_batch_size", 100000) or 100000))` |
| `SAMURAI_GPU_FULL_VARIATION` | `cli.py:1676` | `os.environ["SAMURAI_GPU_FULL_VARIATION"] = "1" if bool(getattr(args, "gpu_full_variation", True)) else "0"` |
| `SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT` | `cli.py:1781` | `os.environ["SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT"] = "1" if bool(getattr(args, "gpu_packet_zerocopy_output", False)) else "0"` |
| `SAMURAI_GPU_PINNED_MAX_MB` | `cli.py:1677` | `os.environ["SAMURAI_GPU_PINNED_MAX_MB"] = str(int(getattr(args, "gpu_pinned_max_mb", 512) or 512))` |
| `SAMURAI_GPU_PIPELINE_DEPTH` | `cli.py:1675` | `os.environ["SAMURAI_GPU_PIPELINE_DEPTH"] = str(int(getattr(args, "gpu_pipeline_depth", 2) or 2))` |
| `SAMURAI_GPU_RING_CAPACITY` | `cli.py:1672` | `os.environ["SAMURAI_GPU_RING_CAPACITY"] = str(int(getattr(args, "gpu_ring_capacity", 3) or 3))` |
| `SAMURAI_GPU_RNG_SEED` | `cli.py:1678` | `os.environ["SAMURAI_GPU_RNG_SEED"] = str(int(getattr(args, "gpu_rng_seed", 1234) or 0))` |
| `SAMURAI_GPU_STREAMS` | `cli.py:1674` | `os.environ["SAMURAI_GPU_STREAMS"] = str(int(getattr(args, "gpu_stream_count", 3) or 3))` |
| `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4` | `cli.py:1670` | `os.environ["SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4"] = str(int(getattr(args, "gpu_template_pool_size_l4", 10) or 10))` |
| `SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7` | `cli.py:1671` | `os.environ["SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7"] = str(int(getattr(args, "gpu_template_pool_size_l7", 50) or 50))` |
| `SAMURAI_KPI_GATE_PROFILE` | `cli.py:1732` | `os.environ["SAMURAI_KPI_GATE_PROFILE"] = str(getattr(args, "kpi_gate_profile", "off") or "off")` |
| `SAMURAI_KPI_HARD_FAIL` | `cli.py:1733` | `os.environ["SAMURAI_KPI_HARD_FAIL"] = "1" if bool(getattr(args, "kpi_hard_fail", False)) else "0"` |
| `SAMURAI_L7_CAPABILITY_STRICT` | `cli.py:1741` | `os.environ["SAMURAI_L7_CAPABILITY_STRICT"] = "1" if bool(getattr(args, "l7_capability_strict", False)) else "0"` |
| `SAMURAI_L7_ENGINE` | `cli.py:1734` | `os.environ["SAMURAI_L7_ENGINE"] = str(getattr(args, "l7_engine", "python") or "python")` |
| `SAMURAI_L7_FALLBACK_POLICY` | `cli.py:1740` | `os.environ["SAMURAI_L7_FALLBACK_POLICY"] = str(getattr(args, "l7_fallback_policy", "allow") or "allow")` |
| `SAMURAI_L7_HTTP2_ENGINE` | `cli.py:1735` | `os.environ["SAMURAI_L7_HTTP2_ENGINE"] = str(getattr(args, "l7_http2_engine", "auto") or "auto")` |
| `SAMURAI_L7_QUIC_AUTO_BRIDGE` | `cli.py:1738` | `os.environ["SAMURAI_L7_QUIC_AUTO_BRIDGE"] = "1" if bool(getattr(args, "l7_quic_auto_bridge", False)) else "0"` |
| `SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE` | `cli.py:1739` | `os.environ["SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE"] = "1" if bool(getattr(args, "l7_quic_bridge_autopromote", False)) else "0"` |
| `SAMURAI_L7_QUIC_ENGINE` | `cli.py:1736` | `os.environ["SAMURAI_L7_QUIC_ENGINE"] = str(getattr(args, "l7_quic_engine", "auto") or "auto")` |
| `SAMURAI_L7_QUIC_REQUIRE_NATIVE` | `cli.py:1737` | `os.environ["SAMURAI_L7_QUIC_REQUIRE_NATIVE"] = "1" if bool(getattr(args, "l7_quic_require_native", False)) else "0"` |
| `SAMURAI_LAB_PROFILE` | `cli.py:1725` | `os.environ["SAMURAI_LAB_PROFILE"] = str(getattr(args, "lab_profile", "off") or "off")` |
| `SAMURAI_LEGACY_PATH_ENABLE` | `cli.py:1742` | `os.environ["SAMURAI_LEGACY_PATH_ENABLE"] = "1" if bool(getattr(args, "legacy_path_enable", False)) else "0"` |
| `SAMURAI_LOSS_FAIL_PCT` | `cli.py:1659` | `os.environ["SAMURAI_LOSS_FAIL_PCT"] = str(float(getattr(args, "loss_fail_pct", 5.0) or 5.0))` |
| `SAMURAI_LOSS_IFACE` | `cli.py:1662` | `os.environ["SAMURAI_LOSS_IFACE"] = loss_iface` |
| `SAMURAI_LOSS_REPORT_OUT` | `cli.py:1667` | `os.environ["SAMURAI_LOSS_REPORT_OUT"] = loss_report_out` |
| `SAMURAI_LOSS_TELEMETRY` | `cli.py:1658` | `os.environ["SAMURAI_LOSS_TELEMETRY"] = str(getattr(args, "loss_telemetry", "auto"))` |
| `SAMURAI_QUIC_BUILD_MODE` | `cli.py:682` | `os.environ["SAMURAI_QUIC_BUILD_MODE"] = "native_required"` |
| `SAMURAI_SENDER_BACKEND` | `cli.py:1683` | `os.environ["SAMURAI_SENDER_BACKEND"] = str(getattr(args, "sender_backend", "auto") or "auto")` |
| `SAMURAI_SENDER_FALLBACK_POLICY` | `cli.py:1684` | `os.environ["SAMURAI_SENDER_FALLBACK_POLICY"] = str(` |
| `SAMURAI_STATE_LOCK_COUNT` | `cli.py:1680` | `os.environ["SAMURAI_STATE_LOCK_COUNT"] = str(int(getattr(args, "state_lock_count", 256) or 256))` |
| `SAMURAI_STATE_SWEEP_INTERVAL_MS` | `cli.py:1682` | `os.environ["SAMURAI_STATE_SWEEP_INTERVAL_MS"] = str(int(getattr(args, "state_sweep_interval_ms", 1000) or 1000))` |
| `SAMURAI_STATE_TABLE_SIZE` | `cli.py:1679` | `os.environ["SAMURAI_STATE_TABLE_SIZE"] = str(int(getattr(args, "state_table_size", 65536) or 65536))` |
| `SAMURAI_STATE_TIMEOUT_SEC` | `cli.py:1681` | `os.environ["SAMURAI_STATE_TIMEOUT_SEC"] = str(int(getattr(args, "state_timeout_sec", 60) or 60))` |
| `SAMURAI_XDP_ENABLE` | `cli.py:1729` | `os.environ["SAMURAI_XDP_ENABLE"] = "1" if bool(getattr(args, "xdp_enable", False)) else "0"` |
| `SAMURAI_XDP_INTERFACE` | `cli.py:1730` | `os.environ["SAMURAI_XDP_INTERFACE"] = str(getattr(args, "xdp_interface", "") or "")` |
| `SAMURAI_XDP_QUEUE_ID` | `cli.py:1731` | `os.environ["SAMURAI_XDP_QUEUE_ID"] = str(int(getattr(args, "xdp_queue_id", 0) or 0))` |
| `SAMURAI_XDP_ATTACH_BPF` | `cli.py` | `os.environ["SAMURAI_XDP_ATTACH_BPF"] = "1" if bool(getattr(args, "xdp_attach_bpf", True)) else "0"` |
| `SAMURAI_XDP_BPF_SECTION` | `cli.py` | `os.environ["SAMURAI_XDP_BPF_SECTION"] = str(getattr(args, "xdp_bpf_section", "xdp_sock") or "xdp_sock")` |
| `SAMURAI_XDP_BPF_OBJ` | `cli.py` | `os.environ["SAMURAI_XDP_BPF_OBJ"] = str(getattr(args, "xdp_bpf_obj", "") or "")` |
| `SAMURAI_XDP_XSKMAP_PIN` | `cli.py` | `os.environ["SAMURAI_XDP_XSKMAP_PIN"] = str(getattr(args, "xdp_xskmap_pin", "") or "")` |

## CLI Disi / Ileri Seviye Env Degiskenleri
| Env | Tuketici Moduller | Aciklama |
|---|---|---|
| `SAMURAI_AF_PACKET_HUGEPAGE_MODE` | `ddos_samurai/dataplane.py`, `ddos_samurai/fast_sender.c`, `ddos_samurai/pacing_engine.c` | TX_RING/AF_PACKET C yolu tuning |
| `SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB` | `ddos_samurai/dataplane.py` | TX_RING/AF_PACKET C yolu tuning |
| `SAMURAI_AF_PACKET_MLOCK_RING` | `ddos_samurai/fast_sender.c`, `ddos_samurai/pacing_engine.c` | TX_RING/AF_PACKET C yolu tuning |
| `SAMURAI_AF_PACKET_PREFAULT_RING` | `ddos_samurai/fast_sender.c`, `ddos_samurai/pacing_engine.c` | TX_RING/AF_PACKET C yolu tuning |
| `SAMURAI_AF_PACKET_RING_TARGET_MB` | `ddos_samurai/dataplane.py` | TX_RING/AF_PACKET C yolu tuning |
| `SAMURAI_CPU_FIXED_OS_PROFILE` | `ddos_samurai/cpu_packet_engine.py` | Runtime override / internal tuning |
| `SAMURAI_DATAPLANE_CORE_MODE` | `ddos_samurai/dataplane.py` | Runtime override / internal tuning |
| `SAMURAI_ENABLE_BROWSER_AUTOMATION` | `ddos_samurai/stealth.py` | Stealth/browser automation davranışı |
| `SAMURAI_GATEWAY_CACHE_TTL_SEC` | `ddos_samurai/senders.py` | Runtime override / internal tuning |
| `SAMURAI_GPU_BATCH` | `ddos_samurai/orchestrator.py` | GPU dataplane/payload tuning |
| `SAMURAI_GPU_PIPELINE_DEPTH` | `ddos_samurai/orchestrator.py` | GPU dataplane/payload tuning |
| `SAMURAI_GPU_SESSION_CHAIN` | `ddos_samurai/gpu_payload.py` | GPU dataplane/payload tuning |
| `SAMURAI_GPU_SESSION_CHAIN_PROFILE` | `ddos_samurai/gpu_payload.py` | GPU dataplane/payload tuning |
| `SAMURAI_GPU_STREAMS` | `ddos_samurai/orchestrator.py` | GPU dataplane/payload tuning |
| `SAMURAI_KPI_GATE_PROFILE` | `ddos_samurai/reporting.py` | Runtime override / internal tuning |
| `SAMURAI_KPI_HARD_FAIL` | `ddos_samurai/reporting.py` | Runtime override / internal tuning |
| `SAMURAI_L7_MAX_ACTIVE_SESSIONS` | `ddos_samurai/senders.py` | L7 route/capability davranışı |
| `SAMURAI_L7_MAX_VUS` | `ddos_samurai/senders.py` | L7 route/capability davranışı |
| `SAMURAI_L7_QUIC_REQUIRE_NATIVE` | `ddos_samurai/l7_state_engine.c` | L7 route/capability davranışı |
| `SAMURAI_LOSS_FAIL_PCT` | `ddos_samurai/reporting.py` | Loss telemetry / KPI akışı |
| `SAMURAI_LOSS_IFACE` | `ddos_samurai/loss_telemetry.py`, `ddos_samurai/senders.py` | Loss telemetry / KPI akışı |
| `SAMURAI_LOSS_TELEMETRY` | `ddos_samurai/loss_telemetry.py`, `ddos_samurai/senders.py` | Loss telemetry / KPI akışı |
| `SAMURAI_PACING_AUTO_PIN` | `ddos_samurai/orchestrator.py` | Runtime override / internal tuning |
| `SAMURAI_PACING_PROGRESS_REFRESH_MS` | `ddos_samurai/senders.py` | Runtime override / internal tuning |
| `SAMURAI_SENDER_BACKEND` | `ddos_samurai/senders.py` | Runtime override / internal tuning |
| `SAMURAI_SENDER_FALLBACK_POLICY` | `ddos_samurai/senders.py` | Runtime override / internal tuning |
| `SAMURAI_SENDMMSG_REUSE` | `ddos_samurai/senders.py` | sendmmsg buffer reuse tuning |
| `SAMURAI_SENDMMSG_REUSE_MAX` | `ddos_samurai/senders.py` | sendmmsg buffer reuse tuning |
| `SAMURAI_TXRING_ADAPTIVE` | `ddos_samurai/fast_sender.c` | TX_RING/AF_PACKET C yolu tuning |
| `SAMURAI_TXRING_FLUSH_MODE` | `ddos_samurai/fast_sender.c` | TX_RING/AF_PACKET C yolu tuning |
| `SAMURAI_WAF_BYPASS_TIMEOUT_S` | `ddos_samurai/stealth.py` | Stealth/browser automation davranışı |
| `SAMURAI_WAF_CHALLENGE_BUDGET_S` | `ddos_samurai/stealth.py` | Stealth/browser automation davranışı |

## Tum CLI Argumanlari (Gruplandirilmis Envanter)

Asagidaki envanter dogrudan `build_parser()` aksiyonlarindan cikarilmistir.
- `Option`: CLI flag(ler)
- `Default`: Parser default degeri
- `Choices`: Varsa izin verilen secenekler
- `Description`: Yardim metni

## Group: Amplification Attack Options
| Option | Default | Choices | Description |
|---|---|---|---|
| `--reflector-file` | `None` |  | Yansıtıcı sunucu IP'lerini içeren dosyanın yolu (amplification saldırısı için gereklidir). |

## Group: Anomaly Packet Options
| Option | Default | Choices | Description |
|---|---|---|---|
| `--anomaly-types` | `None` |  | Anomaly types to use (0=InvalidIHL, 1=InvalidIPLen, 2=InvalidIPVer, 3=InvalidProto, 4=TCPFlagAbuse, 5=InvalidTCPOffset, 6=OverlapFrags, 7=TinyFrags, 8=LandAttack, 9=InvalidChecksum, 10=TTLAnomaly, 11=MalformedOptions). Default: all. |
| `--anomaly-intensity` | `75` |  | Anomaly intensity 0-100 (how malformed the packets are). Default: 75 |
| `--anomaly-suite` | `False` |  | Use full anomaly suite (standard + overlapping frags + tiny frags) |

## Group: Fault Injection
| Option | Default | Choices | Description |
|---|---|---|---|
| `--fault-inject` | `[]` | `sender-restart|nic-blip|gpu-stream-error|mix` | Soak test fault senaryolari (simulasyon). Birden fazla verilebilir. |
| `--fault-after-s` | `0.0` |  | Fault injection tetikleme suresi (s). 0=kapali. |
| `--fault-duration-s` | `2.0` |  | Fault simulasyon suresi (s). |

## Group: GPU PCAP Generator (Test)
| Option | Default | Choices | Description |
|---|---|---|---|
| `--gpu-pcap` | `False` |  | GPU üzerinde sentetik PCAP üret ve çık (trafik göndermez). |
| `--gpu-pcap-duration` | `10` |  | PCAP süresi (s) |
| `--gpu-pcap-pps` | `10000` |  | Saniye başı paket sayısı (PPS) |
| `--gpu-pcap-mode` | `mix` | `mix|tcp|udp` | Trafik modu |
| `--gpu-pcap-src-ip` | `192.168.1.100` |  | Kaynak IPv4 |
| `--gpu-pcap-dst-ip` | `` |  | Hedef IPv4 (boşsa: --target veya 127.0.0.1) |
| `--gpu-pcap-tcp-port` | `0` |  | TCP hedef port (0 ise: --port veya 80) |
| `--gpu-pcap-udp-port` | `0` |  | UDP hedef port (0 ise: --port veya 53) |
| `--gpu-pcap-chunk` | `200000` |  | Chunk başına paket sayısı |
| `--gpu-pcap-seed` | `0` |  | RNG seed (0: rastgele) |
| `--gpu-pcap-flow-count` | `4096` |  | Flow havuzu boyutu (gerçekçi modda kaynak port/IP çeşitliliği için). |
| `--gpu-pcap-realistic` | `False` |  | Gerçekçiliği artırılmış flow-aware profil (TTL/TOS varyasyonu, stateful TCP, UDP checksum). |
| `--gpu-pcap-udp-checksum` | `False` |  | UDP checksum hesaplamasını etkinleştir. |
| `--gpu-pcap-variable-size` | `False` |  | Değişken paket boyutu üretimini etkinleştir (V2). |
| `--gpu-pcap-mtu` | `1500` |  | L3 MTU değeri (128-1500). Paket boyutu dağılımı bu sınıra göre üretilir. |
| `--gpu-pcap-size-profile` | `mixed` | `mixed|web|dns` | Değişken paket boyutu profili. |
| `--gpu-pcap-realism-report` | `False` |  | Üretilen PCAP için V3 gerçekçilik skoru ve metrik raporu üret. |
| `--gpu-pcap-realism-baseline` | `` |  | Gerçekçilik skorunu bu referans PCAP'a göre hesapla (opsiyonel). |
| `--gpu-pcap-realism-sample` | `100000` |  | Gerçekçilik analizinde incelenecek maksimum paket sayısı. |
| `--gpu-pcap-realism-out` | `` |  | Gerçekçilik raporu JSON dosya adı (varsayılan: <out>.realism.json). |
| `--gpu-pcap-out` | `` |  | Çıktı dosya adı (proje klasörüne kaydedilir) |
| `--gpu-pcap-run-report` | `False` |  | GPU PCAP calismasi icin musteri-odakli run raporu uret (JSON/Markdown). |
| `--gpu-pcap-run-report-format` | `both` | `json|md|both` | Run raporu cikti formati. |
| `--gpu-pcap-run-report-out` | `` |  | Run raporu dosya adi (bossa: <out>.run.json/.md). |

## Group: IP Spoofing Options
| Option | Default | Choices | Description |
|---|---|---|---|
| `--spoof` | `False` |  | IP sahtekarlığını etkinleştir (varsayılan mod: realistic) |
| `--spoof-mode` | `realistic` | `random|realistic|subnet|list` | IP sahtekarlık modu |
| `--spoof-subnet` | `None` |  | 'subnet' modu için CIDR formatında alt ağ (örn: 192.168.1.0/24) |
| `--spoof-list-file` | `None` |  | 'list' modu için her satırda bir IP içeren dosya yolu |

## Group: PCAP Replay Options
| Option | Default | Choices | Description |
|---|---|---|---|
| `--pcap-file` | `` |  | PCAP / PCAP-NG dosyası yolu (pcap-replay vektörü için gereklidir). |
| `--pcap-timing` | `original` | `original|topspeed|multiplier|rps` | Replay zamanlama modu: original=orijinal gap, topspeed=maks hız, multiplier=N× hız çarpanı, rps=sabit paket/sn. |
| `--pcap-speed` | `1.0` |  | Hız çarpanı (multiplier modu için). 2.0 = 2× hızlı. Varsayılan: 1.0 |
| `--pcap-loops` | `1` |  | PCAP dosyasını kaç kez tekrar oynat (0 = sonsuz). Varsayılan: 1 |
| `--pcap-max-packets` | `0` |  | Oynatılacak maksimum paket sayısı (0 = hepsi). Varsayılan: 0 |
| `--pcap-filter-proto` | `None` |  | Protokol filtresi (tcp, udp, icmp). Birden fazla belirtilebilir. |
| `--pcap-filter-src-ip` | `None` |  | Kaynak IP filtresi (IP veya CIDR). Örn: 192.168.1.0/24 |
| `--pcap-filter-dst-ip` | `None` |  | Hedef IP filtresi (IP veya CIDR). |
| `--pcap-filter-src-port` | `None` |  | Kaynak port filtresi. |
| `--pcap-filter-dst-port` | `None` |  | Hedef port filtresi. |
| `--pcap-filter-min-len` | `0` |  | Minimum paket boyutu filtresi (byte). |
| `--pcap-filter-max-len` | `0` |  | Maksimum paket boyutu filtresi (byte, 0=sınırsız). |
| `--pcap-strip-eth` | `False` |  | Ethernet başlığını soyup sadece raw IP olarak gönder. |
| `--pcap-use-l2` | `False` |  | PCAP replay'i L2 TX_RING yolu ile gönder (Ethernet frame korunur). |
| `--pcap-no-flow-aware` | `False` |  | PCAP replay TCP flow-aware seq/ack delta rewrite'i kapat. |
| `--pcap-src-ip-override` | `None` |  | Tüm paketlerin kaynak IP'sini bu değerle değiştir. |
| `--pcap-src-port-override` | `None` |  | Tüm paketlerin kaynak portunu bu değerle değiştir. |
| `--pcap-batch-size` | `512` |  | Timing-aware modda batch boyutu. Varsayılan: 512 |
| `--pcap-info` | `False` |  | PCAP dosyasının özetini göster ve çık (trafik göndermez). |

## Group: Pacing Options (Deterministic Timing)
| Option | Default | Choices | Description |
|---|---|---|---|
| `--pacing-mode` | `none` | `none|rps|ipg|burst` | Paket pacing stratejisi: none=sınırsız burst, rps=rate-limit, ipg=sabit gap, burst=batch+gap |
| `--ipg` | `0` |  | Inter-Packet Gap (nanosaniye). --pacing-mode ipg ile kullanılır. Örnek: 10000 = 10µs |
| `--burst-size` | `64` |  | Burst modunda tek seferde gönderilecek paket sayısı (varsayılan: 64) |
| `--burst-gap` | `0` |  | Burst'ler arası bekleme süresi (nanosaniye) |
| `--jitter-model` | `none` | `none|uniform|gaussian|exponential` | Jitter dağılım modeli (pacing üzerine uygulanır) |
| `--jitter-pct` | `0.0` |  | Jitter yüzdesi (0.0-1.0). Base gap'in bu kadarı kadar sapma uygulanır. |
| `--pin-cpu` | `-1` |  | Pacing engine'i belirli bir CPU çekirdeğine sabitle (-1: otomatik) |
| `--use-so-txtime` | `False` |  | Kernel SO_TXTIME/ETF offload kullan (Linux 4.19+, root gerektirir) |

## Group: Reporting / Self-Test
| Option | Default | Choices | Description |
|---|---|---|---|
| `--self-test` | `False` |  | Unittest discovery calistir ve cik (trafik gondermez). |
| `--run-report` | `False` |  | Calisma raporu uret (live + offline/test modlari). |
| `--run-report-format` | `both` | `json|md|both` | Run raporu cikti formati. |
| `--run-report-out` | `` |  | Run raporu base dosya adi (bossa otomatik). Uzanti eklemeyin (ornek: reports/run_001). |
| `--run-report-dir` | `reports/runs` |  | Run raporu cikti dizini (varsayilan: reports/runs). |
| `--soak-profile` | `none` | `none|1h|6h|24h` | Soak test profili (1h/6h/24h) ve varsayilan pass/fail esikleri. |
| `--soak-snapshot-interval` | `0` |  | Soak snapshot araligi (s). 0=profile default, aralik 10-30s. |
| `--soak-warmup-s` | `0` |  | Soak warm-up suresi (s). 0=profile default; baseline bu sureden sonra kilitlenir. |
| `--soak-max-error-rate-pct` | `None` |  | Soak pass/fail: maksimum hata orani (%%). |
| `--soak-max-pps-drop-pct` | `None` |  | Soak pass/fail: baseline'e gore maksimum PPS dusus (%%). |
| `--soak-max-rss-growth-mb` | `None` |  | Soak pass/fail: maksimum RSS artis limiti (MB). |
| `--soak-max-vram-growth-mb` | `None` |  | Soak pass/fail: maksimum VRAM artis limiti (MB). |
| `--soak-max-pinned-growth-mb` | `None` |  | Soak pass/fail: maksimum pinned-memory artis limiti (MB). |
| `--soak-max-backlog` | `None` |  | Soak pass/fail: maksimum backlog limiti (paket). |
| `--loss-telemetry` | `auto` | `auto|0|1` | Wire-loss telemetry modu: auto\|0\|1 (varsayilan: auto). |
| `--loss-iface` | `` |  | Loss telemetry icin arayuz ismi (opsiyonel, bossa otomatik). |
| `--loss-fail-pct` | `5.0` |  | Wire-loss fail esigi (%%). Varsayilan: 5. |
| `--loss-report-out` | `` |  | Canli run sonunda loss telemetry JSON ciktisi (opsiyonel dosya yolu). |

## Group: Safety Options
| Option | Default | Choices | Description |
|---|---|---|---|
| `--allow-target` | `[]` |  | İzin verilen hedef(ler). IP veya CIDR. Çoklu kullanım: --allow-target 10.0.0.0/8 --allow-target 192.168.1.10 |
| `--allow-public-target` | `False` |  | Public (internet) hedeflere izin ver (tehlikeli). Varsayılan: engelli. |

## Group: options
| Option | Default | Choices | Description |
|---|---|---|---|
| `--config` | `None` |  | Tüm ayarların okunacağı YAML konfigürasyon dosyasının yolu. |
| `--list-profiles` | `False` |  | Kullanılabilir kurumsal saldırı test profillerini listele. |
| `-t`, `--target` | `None` |  | Hedef IP adresi (config dosyasında da belirtilebilir) |
| `-p`, `--port` | `None` |  | Hedef port (config dosyasında da belirtilebilir) |
| `--source-port` | `0` |  | Kaynak port (0: rastgele) |
| `-c`, `--count` | `10` |  | Gönderilecek toplam paket/istek sayısı (soak profilinde per-iterasyon batch boyutu). |
| `-P`, `--protocol` | `tcp` | `tcp|udp|icmp` | Kullanılacak protokol (tcp/udp/icmp) |
| `-d`, `--delay` | `0` |  | Paketler arası gecikme (saniye cinsinden) - RPS ile birlikte kullanılmaz |
| `--payload` | `` |  | Tek bir istek için gönderilecek sabit payload. |
| `--payload-file` | `` |  | Her satırı bir payload olan ve isteklerde rastgele kullanılacak dosyanın yolu. |
| `--tcp-flags` | `S` | `S|A|F|R|SA|FA|RA|PA|U|E|C` | TCP bayrakları (örn: S, A, F, R, SA, FA, RA, PA, U, E, C vb.) |
| `--ttl` | `None` |  | IP paketi için TTL değeri |
| `--tos` | `None` |  | IP TOS değeri (ondalık formatta, örn: 16) |
| `--window` | `None` |  | TCP pencere boyutu |
| `--os-fingerprint` | `False` |  | Enable OS fingerprint randomization for packets. |
| `--pad` | `0` |  | Minimum paket boyutu (bayt). |
| `--ninja-mode` | `False` |  | Enable WAF Bypass (Ninja Mode) using Headless Browser. |
| `--fragment` | `False` |  | IP fragmentasyonunu etkinleştir (Scapy/CPU yolu). |
| `--fragment-size` | `800` |  | Fragment boyutu (bayt). (Varsayılan: 800) |
| `--attack-vector` | `basic` | `basic|http|http2|dns|websocket|quic|slowloris|slow-post|slow-read|ntp-amp|ssdp-amp|dns-amp|memcached-amp|ldap-amp|anomaly|pcap-replay` | Saldırı vektörü seçimi |
| `--dns-name` | `example.com` |  | DNS vektörü için sorgu adı |
| `--dns-qtype` | `['A']` |  | DNS sorgu tipleri (birden fazla belirtilebilir: A AAAA MX TXT NS) |
| `--dns-edns` | `False` |  | DNS için EDNS0 OPT kaydı ekle |
| `--dns-nord` | `False` |  | DNS recursive desired kapat (rd=0) |
| `--http-path` | `['/']` |  | HTTP vektörü için istek yolları (birden fazla belirtilebilir) |
| `--http-method` | `GET` |  | HTTP vektörü için metod (GET, POST, ...) |
| `--http-concurrency` | `50` |  | HTTP vektörü eşzamanlı istek sayısı (worker başına) |
| `--http-timeout` | `5.0` |  | HTTP istek zaman aşımı (s) |
| `--http-retries` | `0` |  | HTTP istek retry sayısı |
| `--http-scheme` | `http` | `http|https` | HTTP vektörü için şema |
| `--http-verify` | `true` |  | HTTPS sertifika doğrulama (true/false) |
| `--rps` | `0` |  | Hedef toplam istek/paket saniye (tüm worker'lar için, 0: sınırsız) |
| `--jitter` | `0.0` |  | Rastgele zamanlama jitter oranı (0..1) |
| `--ramp` | `0.0` |  | RPS'e ramp-up süresi (s) |
| `--profile` | `custom` | `web-stress|web-bypass|stateful-exhaustion|volumetric-udp|dns-infrastructure|slow-exhaustion|amplification-simulation|custom` | Kurumsal saldırı testi profili (varsayılan: custom) |
| `--role` | `standalone` | `standalone|master|slave` | Distributed attack modu |
| `--confirm` | `False` |  | Etik uyarıyı atlamak için |
| `--dry-run` | `False` |  | Ayarları doğrular, örnek bir paket oluşturur ve gönderim yapmadan çıkar. |
| `-v`, `--verbose` | `False` |  | Detaylı çıktı |
| `--log` | `ddos_logs.txt` |  | Log dosyası yolu |
| `--workers` | `12` |  | Kullanılacak işçi (worker) süreç sayısı. Varsayılan: 12 |
| `--tls-profile` | `none` | `none|chrome_120|firefox_120|safari_17` | TLS/JA3 parmak izi profili |
| `--h2-profile` | `none` | `none|chrome_120|firefox_120|safari_17` | HTTP/2 profil adı |
| `--h2-transport` | `auto` | `auto|httpx|hyper-h2` | HTTP/2 transport secimi: auto\|httpx\|hyper-h2 (varsayilan: auto). |
| `--ja3-profile` | `None` | `none|chrome_120|firefox_120|safari_17` | DEPRECATED: --tls-profile alias (1 minor sürüm) |
| `--ech` | `False` |  | Encrypted Client Hello (ECH) desteğini etkinleştir (deneysel) |
| `--http2-concurrency` | `100` |  | HTTP/2 vektörü için eşzamanlı stream sayısı |
| `--http2-connections` | `1` |  | HTTP/2 için bağlantı sayısı (connection pool). |
| `--http2-streams-per-conn` | `100` |  | HTTP/2 bağlantı başına maksimum eşzamanlı stream. |
| `--ws-path` | `/` |  | WebSocket vektörü için bağlantı yolu |
| `--ws-message` | `ping` |  | WebSocket vektörü için gönderilecek mesaj |
| `--ws-concurrency` | `50` |  | WebSocket vektörü eşzamanlı bağlantı sayısı |
| `--ws-scenario` | `False` |  | WebSocket senaryo modu (auth->subscribe->ping/pong state machine). |
| `--ws-auth-message` | `` |  | WS senaryo modu auth adımı mesajı. |
| `--ws-subscribe-message` | `None` |  | WS senaryo modu subscribe adımı mesaj(ları). |
| `--ws-ping-count` | `1` |  | WS senaryo modu ping adım sayısı (varsayılan: 1). |
| `--ws-await-response` | `False` |  | WS senaryo adımlarında send sonrası recv bekle. |
| `--quic-path` | `/` |  | QUIC/HTTP3 vektörü için istek yolu |
| `--quic-method` | `GET` |  | QUIC/HTTP3 vektörü için HTTP metodu |
| `--quic-concurrency` | `50` |  | QUIC/HTTP3 vektörü eşzamanlı istek sayısı |
| `--quic-streams-per-conn` | `0` |  | Native QUIC için bağlantı başına eşzamanlı stream (0=concurrency tabanlı auto) |
| `--quic-requests-per-conn` | `0` |  | Native QUIC için bağlantı başına toplam istek (0=tek bağlantıda mümkün olduğunca çok) |
| `--quic-conn-pool-size` | `1` |  | Worker başına native QUIC bağlantı havuzu boyutu |
| `--quic-expect-status-min` | `200` |  | Native QUIC response status alt sınırı |
| `--quic-expect-status-max` | `399` |  | Native QUIC response status üst sınırı |
| `--quic-require-response-headers` | `True` |  | Native QUIC response header/status doğrulaması zorunlu (true/false) |
| `--quic-require-response-body` | `False` |  | Native QUIC için response body gelmesi zorunlu |
| `--quic-min-response-body-bytes` | `0` |  | Native QUIC response body minimum byte eşiği |
| `--quic-expect-header-name` | `` |  | Native QUIC response'da zorunlu header adı (opsiyonel, küçük/büyük harf duyarsız). |
| `--quic-expect-header-value-contains` | `` |  | Native QUIC response'da beklenen header değer alt dizesi (quic-expect-header-name ile birlikte). |
| `--quic-expect-body-substring` | `` |  | Native QUIC response body içinde zorunlu alt dize (opsiyonel). |
| `--slowloris-concurrency` | `200` |  | Slowloris vektörü eşzamanlı bağlantı sayısı |
| `--stealth-mode` | `False` |  | DEPRECATED (no-op): kaldırılacak |
| `--payload-mutation` | `False` |  | Payload mutation - her istekte payload'u değiştir |
| `--proxy-list` | `None` |  | Proxy listesi dosyası (her satırda bir proxy) |
| `--aggressive-mode` | `False` |  | Agresif mod - daha hızlı ve yoğun saldırı |
| `--connection-pool` | `100` |  | Maksimum bağlantı havuzu boyutu |
| `--burst-mode` | `False` |  | Burst mod - kısa süreli yoğun saldırı |
| `--spoof-ip` | `None` |  | Belirli bir IP adresi ile spoofing yap (örn: 1.1.1.1) |
| `--realistic-spoof` | `False` |  | Gerçekçi IP aralıklarından spoofing yap |
| `--evasion-techniques` | `None` | `case|url|comment` | DEPRECATED (no-op): kaldırılacak |
| `--compute-backend` | `cpu` | `cpu|cuda` | Paket oluşturma için kullanılacak işlem birimi (cpu veya cuda) |
| `--stateful` | `False` |  | Enable Stateful TCP Engine (Viper-State) for full 3-way handshake. |
| `--sender-backend` | `auto` | `auto|txring|c_ext_l3|python|xdp` | Raw sender backend seçimi: auto\|txring\|c_ext_l3\|python\|xdp. |
| `--sender-fallback-policy` | `allow` | `allow|fail` | Backend fallback politikası: allow=alt yola düş, fail=run'ı fail-visible bitir. |
| `--dataplane-core-mode` | `off` | `off|auto|required` | Dataplane core kullanım modu: off\|auto\|required (required=tek hot-path, legacy zincir kapalı). |
| `--afpacket-hugepage-mode` | `off` | `off|auto|required` | AF_PACKET TX_RING hugepage politikası: off\|auto\|required. |
| `--afpacket-hugepage-size-kb` | `2048` |  | AF_PACKET hugepage hedef boyutu (kB), varsayılan: 2048. |
| `--afpacket-ring-target-mb` | `64` |  | AF_PACKET TX_RING hedef toplam boyutu (MB), varsayılan: 64. |
| `--afpacket-block-size-kb` | `0` |  | AF_PACKET TX_RING block boyutu (kB). 0=auto (frame-size ve frames-per-block'e gore). |
| `--afpacket-frame-size` | `0` |  | AF_PACKET TX_RING frame boyutu (byte). 0=auto. |
| `--afpacket-frames-per-block` | `64` |  | AF_PACKET block basina hedef frame sayisi (block-size auto modunda kullanilir). |
| `--afpacket-poll-timeout-ms` | `1` |  | AF_PACKET frame bekleme poll timeout tabani (ms). |
| `--afpacket-spin-limit` | `2000` |  | AF_PACKET frame bekleme spin sayisi limiti. |
| `--afpacket-busy-poll-us` | `0` |  | SO_BUSY_POLL mikro saniye degeri (0=kapali, best-effort). |
| `--afpacket-qdisc-bypass` | `True` |  | AF_PACKET TX yolu icin PACKET_QDISC_BYPASS kullan (varsayilan: acik). |
| `--no-afpacket-qdisc-bypass` | `True` |  | AF_PACKET TX yolu icin PACKET_QDISC_BYPASS kapat. |
| `--afpacket-mlock-ring` | `False` |  | AF_PACKET ring bellek sayfalarını mlock ile sabitlemeyi dene. |
| `--no-afpacket-mlock-ring` | `False` |  | AF_PACKET ring mlock denemesini kapat. |
| `--afpacket-prefault-ring` | `True` |  | AF_PACKET ring mmap sonrası sayfaları prefault et. |
| `--no-afpacket-prefault-ring` | `True` |  | AF_PACKET ring prefault davranışını kapat. |
| `--lab-profile` | `off` | `off|dedicated` | Lab çalışma profili: off=genel geliştirici, dedicated=hard benchmark profili. |
| `--dp-queue-strategy` | `rr` | `rr|pin|map` | Dataplane queue dağıtımı: rr=round-robin, pin=worker->queue, map=explicit map. |
| `--dp-queues` | `1` |  | Dataplane queue sayısı (dedicated profilde NIC TX queue kontrolüne girer). |
| `--dp-queue-map` | `` |  | Explicit worker->queue haritası. Format: '1:0,2:1,3:2'. |
| `--xdp-enable` | `False` |  | AF_XDP sender yolunu etkinleştir (xdp backend). |
| `--xdp-interface` | `` |  | AF_XDP için NIC adı (örn: eth0). |
| `--xdp-queue-id` | `0` |  | AF_XDP queue id (varsayılan: 0). |
| `--xdp-attach-bpf` | `True` |  | XDP backend start anında eBPF programı attach et. |
| `--no-xdp-attach-bpf` | `True` |  | XDP backend için eBPF attach adımını kapat. |
| `--xdp-bpf-section` | `xdp_sock` |  | Attach edilecek BPF section adı. |
| `--xdp-bpf-obj` | `` |  | XDP BPF object yolu (boşsa varsayılan `xdp_prog.o`). |
| `--xdp-xskmap-pin` | `` |  | Pinned xsks_map yolu (queue->xsk fd map update). |
| `--kpi-gate-profile` | `off` | `off|dev|ci_safe|developer_fallback|dedicated_lab` | KPI gate profili: off\|dev\|ci_safe\|developer_fallback\|dedicated_lab. |
| `--kpi-hard-fail` | `False` |  | Dedicated gate ihlalinde non-zero exit döndür. |
| `--l7-engine` | `python` | `python|c_state` | L7 state engine seçimi: python\|c_state. |
| `--l7-http2-engine` | `auto` | `python|c_state|auto` | HTTP/2 L7 engine seçimi: python\|c_state\|auto. |
| `--l7-quic-engine` | `auto` | `python|c_state|auto` | QUIC L7 engine seçimi: python\|c_state\|auto. |
| `--l7-quic-require-native` | `False` |  | QUIC için yalnızca native C h3_stateful modunu kabul et (py-bridge kabul edilmez). |
| `--l7-quic-auto-bridge` | `False` |  | Native QUIC yoksa py-bridge yolunu otomatik etkinleştir. |
| `--l7-quic-bridge-autopromote` | `False` |  | Capability map içinde py-bridge'i otomatik h3_stateful olarak terfi ettir. |
| `--l7-fallback-policy` | `allow` | `allow|fail` | L7 C->Python fallback politikası: allow\|fail. |
| `--l7-capability-strict` | `False` |  | L7 capability strict modu: eksik capability varsa fallback yerine preflight/run fail. |
| `--legacy-path-enable` | `False` |  | Yeni engine yolu başarısız olursa legacy Python L7 yoluna dönüşe izin ver. |
| `--l7-session-repeats` | `1` |  | Stateful L7 oturumlarını kullanıcı başına tekrar sayısı. |
| `--l7-max-active-sessions` | `0` |  | Stateful L7 için eşzamanlı aktif session üst limiti (0=sınırsız). |
| `--gpu-template-pool-size-l4` | `10` |  | CUDA template-pool L4 varsayılan şablon sayısı (env: SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4). |
| `--gpu-template-pool-size-l7` | `50` |  | CUDA template-pool L7 set varsayılan şablon sayısı (env: SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7). |
| `--gpu-ring-capacity` | `3` |  | CUDA producer-consumer ring kapasitesi (env: SAMURAI_GPU_RING_CAPACITY). |
| `--gpu-batch-size` | `100000` |  | CUDA üretim batch boyutu (env: SAMURAI_GPU_BATCH). |
| `--gpu-stream-count` | `3` |  | CUDA stream sayısı (gen/copy/send overlap için). |
| `--gpu-pipeline-depth` | `2` |  | GPU pipeline overlap derinliği (ready batch kuyruk eşiği). |
| `--gpu-full-variation`, `--no-gpu-full-variation` | `True` |  | Basic L4 akışında varyasyonları tamamen GPU hot-path üzerinden üret. |
| `--gpu-pinned-max-mb` | `512` |  | Pinned host buffer pool üst sınırı MB (env: SAMURAI_GPU_PINNED_MAX_MB). |
| `--gpu-packet-zerocopy-output`, `--no-gpu-packet-zerocopy-output` | `False` |  | CUDA native path çıktı tamponu için mapped host zero-copy yolunu aç/kapat (env: SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT). |
| `--gpu-rng-seed` | `1234` |  | GPU payload RNG seed (varsayılan: deterministik 1234, env: SAMURAI_GPU_RNG_SEED). |
| `--state-table-size` | `65536` |  | State engine tablosu kapasitesi (env: SAMURAI_STATE_TABLE_SIZE). |
| `--state-lock-count` | `256` |  | State engine lock segment sayısı (env: SAMURAI_STATE_LOCK_COUNT). |
| `--state-timeout-sec` | `60` |  | State timeout süresi saniye (env: SAMURAI_STATE_TIMEOUT_SEC). |
| `--state-sweep-interval-ms` | `1000` |  | State cleanup sweep periyodu ms (env: SAMURAI_STATE_SWEEP_INTERVAL_MS). |
