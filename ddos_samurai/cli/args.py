"""Argument parser construction for the CLI."""

import argparse
import multiprocessing
import os

from ..workload_profiles import TEST_PROFILES
from ..profile_names import H2_PROFILE_CHOICES, PROFILE_NONE, TLS_PROFILE_CHOICES
from .helpers import _arg_bool, _normalize_afpacket_hugepage_mode, _normalize_dataplane_core_mode
from .env import _env_flag, _env_int
def build_parser() -> argparse.ArgumentParser:
    """
    Build the CLI argument parser.
    Kept separate to make testing and maintenance easier.
    """
    parser = argparse.ArgumentParser(
        description="Modüler ve yüksek performanslı ağ stres testi aracı - Samurai",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("--config", type=str, help="Tüm ayarların okunacağı YAML konfigürasyon dosyasının yolu.")
    parser.add_argument("--list-profiles", action="store_true", help="Kullanılabilir kurumsal saldırı test profillerini listele.")
    parser.add_argument("-t", "--target", help="Hedef IP adresi (config dosyasında da belirtilebilir)")
    parser.add_argument("-p", "--port", type=int, help="Hedef port (config dosyasında da belirtilebilir)")
    parser.add_argument("--source-port", type=int, default=0, help="Kaynak port (0: rastgele)")
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=10,
        help="Gönderilecek toplam paket/istek sayısı (soak profilinde per-iterasyon batch boyutu).",
    )
    parser.add_argument("-P", "--protocol", choices=["tcp", "udp", "icmp"], default="tcp", help="Kullanılacak protokol (tcp/udp/icmp)")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Paketler arası gecikme (saniye cinsinden) - RPS ile birlikte kullanılmaz")

    spoofing_group = parser.add_argument_group('IP Spoofing Options')
    spoofing_group.add_argument("--spoof", action="store_true", help="IP sahtekarlığını etkinleştir (varsayılan mod: realistic)")
    spoofing_group.add_argument("--spoof-mode", choices=['random', 'realistic', 'subnet', 'list'], default='realistic', help="IP sahtekarlık modu")
    spoofing_group.add_argument("--spoof-subnet", type=str, help="'subnet' modu için CIDR formatında alt ağ (örn: 192.168.1.0/24)")
    spoofing_group.add_argument("--spoof-list-file", type=str, help="'list' modu için her satırda bir IP içeren dosya yolu")

    parser.add_argument("--payload", type=str, default="", help="Tek bir istek için gönderilecek sabit payload.")
    parser.add_argument("--payload-file", type=str, default="", help="Her satırı bir payload olan ve isteklerde rastgele kullanılacak dosyanın yolu.")
    parser.add_argument("--tcp-flags", type=str, default="S", choices=["S", "A", "F", "R", "SA", "FA", "RA", "PA", "U", "E", "C"], help="TCP bayrakları (örn: S, A, F, R, SA, FA, RA, PA, U, E, C vb.)")
    parser.add_argument("--ttl", type=int, help="IP paketi için TTL değeri")
    parser.add_argument("--tos", type=int, help="IP TOS değeri (ondalık formatta, örn: 16)")
    parser.add_argument("--window", type=int, help="TCP pencere boyutu")
    parser.add_argument("--os-fingerprint", action="store_true", help="Enable OS fingerprint randomization for packets.")
    parser.add_argument("--pad", type=int, default=0, help="Minimum paket boyutu (bayt).")
    parser.add_argument("--ninja-mode", action="store_true", help="Enable WAF Bypass (Ninja Mode) using Headless Browser.")
    parser.add_argument("--fragment", action="store_true", help="IP fragmentasyonunu etkinleştir (Scapy/CPU yolu).")
    parser.add_argument("--fragment-size", type=int, default=800, help="Fragment boyutu (bayt). (Varsayılan: 800)")

    # NOTE: Keep this list aligned with ddos_samurai.orchestrator + ddos_samurai.senders.
    parser.add_argument(
        "--attack-vector",
        choices=[
            "basic",
            "http",
            "http2",
            "dns",
            "websocket",
            "quic",
            "slowloris",
            "slow-post",
            "slow-read",
            "ntp-amp",
            "ssdp-amp",
            "dns-amp",
            "memcached-amp",
            "ldap-amp",
            "anomaly",
            "pcap-replay",
        ],
        default="basic",
        help="Saldırı vektörü seçimi",
    )

    amp_group = parser.add_argument_group('Amplification Attack Options')
    amp_group.add_argument("--reflector-file", type=str, help="Yansıtıcı sunucu IP'lerini içeren dosyanın yolu (amplification saldırısı için gereklidir).")

    parser.add_argument("--dns-name", type=str, default="example.com", help="DNS vektörü için sorgu adı")
    parser.add_argument("--dns-qtype", type=str, nargs='+', default=["A"], help="DNS sorgu tipleri (birden fazla belirtilebilir: A AAAA MX TXT NS)")
    parser.add_argument("--dns-edns", action="store_true", help="DNS için EDNS0 OPT kaydı ekle")
    parser.add_argument("--dns-nord", action="store_true", help="DNS recursive desired kapat (rd=0)")
    parser.add_argument("--http-path", type=str, nargs='+', default=["/"], help="HTTP vektörü için istek yolları (birden fazla belirtilebilir)")
    parser.add_argument("--http-method", type=str, default="GET", help="HTTP vektörü için metod (GET, POST, ...)" )
    parser.add_argument("--http-concurrency", type=int, default=50, help="HTTP vektörü eşzamanlı istek sayısı (worker başına)")
    parser.add_argument("--http-timeout", type=float, default=5.0, help="HTTP istek zaman aşımı (s)")
    parser.add_argument("--http-retries", type=int, default=0, help="HTTP istek retry sayısı")
    parser.add_argument("--http-scheme", choices=["http","https"], default="http", help="HTTP vektörü için şema")
    parser.add_argument("--http-verify", type=str, default="true", help="HTTPS sertifika doğrulama (true/false)")
    parser.add_argument("--rps", type=float, default=0, help="Hedef toplam istek/paket saniye (tüm worker'lar için, 0: sınırsız)")
    parser.add_argument("--jitter", type=float, default=0.0, help="Rastgele zamanlama jitter oranı (0..1)")
    parser.add_argument("--ramp", type=float, default=0.0, help="RPS'e ramp-up süresi (s)")
    parser.add_argument("--profile", choices=list(TEST_PROFILES.keys()), default="custom", help="Kurumsal saldırı testi profili (varsayılan: custom)")
    parser.add_argument("--role", choices=["standalone", "master", "slave"], default="standalone", help="Distributed attack modu")
    parser.add_argument("--confirm", action="store_true", help="Etik uyarıyı atlamak için")
    parser.add_argument("--dry-run", action="store_true", help="Ayarları doğrular, örnek bir paket oluşturur ve gönderim yapmadan çıkar.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Detaylı çıktı")
    parser.add_argument("--log", type=str, default="ddos_logs.txt", help="Log dosyası yolu")
    parser.add_argument("--workers", type=int, default=multiprocessing.cpu_count(), help=f"Kullanılacak işçi (worker) süreç sayısı. Varsayılan: {multiprocessing.cpu_count()}")
    parser.add_argument("--tls-profile", choices=list(TLS_PROFILE_CHOICES), default=PROFILE_NONE, help="TLS/JA3 parmak izi profili")
    parser.add_argument("--h2-profile", choices=list(H2_PROFILE_CHOICES), default=PROFILE_NONE, help="HTTP/2 profil adı")
    parser.add_argument(
        "--h2-transport",
        choices=["auto", "httpx", "hyper-h2"],
        default="auto",
        help="HTTP/2 transport secimi: auto|httpx|hyper-h2 (varsayilan: auto).",
    )
    parser.add_argument("--ja3-profile", choices=list(TLS_PROFILE_CHOICES), default=None, help="DEPRECATED: --tls-profile alias (1 minor sürüm)")
    parser.add_argument("--ech", action="store_true", help="Encrypted Client Hello (ECH) desteğini etkinleştir (deneysel)")
    parser.add_argument("--http2-concurrency", type=int, default=100, help="HTTP/2 vektörü için eşzamanlı stream sayısı")
    parser.add_argument("--http2-connections", type=int, default=1, help="HTTP/2 için bağlantı sayısı (connection pool).")
    parser.add_argument("--http2-streams-per-conn", type=int, default=100, help="HTTP/2 bağlantı başına maksimum eşzamanlı stream.")
    parser.add_argument("--l7-profile-file", type=str, default="", help="Yeni L7 emulation engine için JSON profile dosyası.")
    parser.add_argument(
        "--l7-template-mode",
        choices=["compat", "profile"],
        default="compat",
        help="L7 emulation compiler modu: compat|profile.",
    )
    parser.add_argument("--ws-path", type=str, default="/", help="WebSocket vektörü için bağlantı yolu")
    parser.add_argument("--ws-message", type=str, default="ping", help="WebSocket vektörü için gönderilecek mesaj")
    parser.add_argument("--ws-concurrency", type=int, default=50, help="WebSocket vektörü eşzamanlı bağlantı sayısı")
    parser.add_argument("--ws-scenario", action="store_true", help="WebSocket senaryo modu (auth->subscribe->ping/pong state machine).")
    parser.add_argument("--ws-auth-message", type=str, default="", help="WS senaryo modu auth adımı mesajı.")
    parser.add_argument("--ws-subscribe-message", type=str, nargs="+", default=None, help="WS senaryo modu subscribe adımı mesaj(ları).")
    parser.add_argument("--ws-ping-count", type=int, default=1, help="WS senaryo modu ping adım sayısı (varsayılan: 1).")
    parser.add_argument("--ws-await-response", action="store_true", help="WS senaryo adımlarında send sonrası recv bekle.")
    parser.add_argument("--quic-path", type=str, default="/", help="QUIC/HTTP3 vektörü için istek yolu")
    parser.add_argument("--quic-method", type=str, default="GET", help="QUIC/HTTP3 vektörü için HTTP metodu")
    parser.add_argument("--quic-concurrency", type=int, default=50, help="QUIC/HTTP3 vektörü eşzamanlı istek sayısı")
    parser.add_argument("--quic-streams-per-conn", type=int, default=0, help="Native QUIC için bağlantı başına eşzamanlı stream (0=concurrency tabanlı auto)")
    parser.add_argument("--quic-requests-per-conn", type=int, default=0, help="Native QUIC için bağlantı başına toplam istek (0=tek bağlantıda mümkün olduğunca çok)")
    parser.add_argument("--quic-conn-pool-size", type=int, default=1, help="Worker başına native QUIC bağlantı havuzu boyutu")
    parser.add_argument("--quic-expect-status-min", type=int, default=200, help="Native QUIC response status alt sınırı")
    parser.add_argument("--quic-expect-status-max", type=int, default=399, help="Native QUIC response status üst sınırı")
    parser.add_argument("--quic-require-response-headers", type=_arg_bool, nargs="?", const=True, default=True, help="Native QUIC response header/status doğrulaması zorunlu (true/false)")
    parser.add_argument("--quic-require-response-body", action="store_true", help="Native QUIC için response body gelmesi zorunlu")
    parser.add_argument("--quic-min-response-body-bytes", type=int, default=0, help="Native QUIC response body minimum byte eşiği")
    parser.add_argument("--quic-expect-header-name", type=str, default="", help="Native QUIC response'da zorunlu header adı (opsiyonel, küçük/büyük harf duyarsız).")
    parser.add_argument("--quic-expect-header-value-contains", type=str, default="", help="Native QUIC response'da beklenen header değer alt dizesi (quic-expect-header-name ile birlikte).")
    parser.add_argument("--quic-expect-body-substring", type=str, default="", help="Native QUIC response body içinde zorunlu alt dize (opsiyonel).")
    parser.add_argument("--slowloris-concurrency", type=int, default=200, help="Slowloris vektörü eşzamanlı bağlantı sayısı")
    parser.add_argument("--stealth-mode", action="store_true", help="DEPRECATED (no-op): kaldırılacak")
    parser.add_argument("--payload-mutation", action="store_true", help="Payload mutation - her istekte payload'u değiştir")
    parser.add_argument("--proxy-list", type=str, help="Proxy listesi dosyası (her satırda bir proxy)")
    parser.add_argument("--aggressive-mode", action="store_true", help="Agresif mod - daha hızlı ve yoğun saldırı")
    parser.add_argument("--connection-pool", type=int, default=100, help="Maksimum bağlantı havuzu boyutu")
    parser.add_argument("--burst-mode", action="store_true", help="Burst mod - kısa süreli yoğun saldırı")
    parser.add_argument("--spoof-ip", type=str, help="Belirli bir IP adresi ile spoofing yap (örn: 1.1.1.1)")
    parser.add_argument("--realistic-spoof", action="store_true", help="Gerçekçi IP aralıklarından spoofing yap")
    parser.add_argument("--evasion-techniques", type=str, nargs='+', choices=['case', 'url', 'comment'], help="DEPRECATED (no-op): kaldırılacak")
    parser.add_argument("--compute-backend", type=str, default="cpu", choices=["cpu", "cuda"], help="Paket oluşturma için kullanılacak işlem birimi (cpu veya cuda)")
    parser.add_argument("--stateful", action="store_true", help="Enable Stateful TCP Engine (Viper-State) for full 3-way handshake.")
    parser.add_argument(
        "--sender-backend",
        choices=["xdp"],
        default="xdp",
        help="Raw sender backend seçimi: xdp (zorunlu).",
    )
    parser.add_argument(
        "--sender-fallback-policy",
        choices=["fail"],
        default="fail",
        help="Backend fallback politikası: fail (zorunlu).",
    )
    _stateful_runtime_backend_env = str(
        os.environ.get("SAMURAI_STATEFUL_RUNTIME_BACKEND", "afxdp") or "afxdp"
    ).strip().lower()
    if _stateful_runtime_backend_env not in {"afxdp"}:
        _stateful_runtime_backend_env = "afxdp"
    parser.add_argument(
        "--stateful-runtime-backend",
        choices=["afxdp"],
        default=_stateful_runtime_backend_env,
        help="Yeni stateful runtime backend seçimi: afxdp (zorunlu).",
    )
    _dp_mode_env_default = _normalize_dataplane_core_mode(
        os.environ.get(
            "SAMURAI_DATAPLANE_CORE_MODE",
            "required",
        )
    )
    parser.add_argument(
        "--dataplane-core-mode",
        choices=["off", "auto", "required"],
        default=_dp_mode_env_default,
        help="Dataplane core kullanım modu: off|auto|required (required=tek hot-path, legacy zincir kapalı).",
    )
    _afpacket_hp_env_default = _normalize_afpacket_hugepage_mode(
        os.environ.get("SAMURAI_AF_PACKET_HUGEPAGE_MODE", "off")
    )
    parser.add_argument(
        "--afpacket-hugepage-mode",
        choices=["off", "auto", "required"],
        default=_afpacket_hp_env_default,
        help="AF_PACKET TX_RING hugepage politikası: off|auto|required.",
    )
    parser.add_argument(
        "--afpacket-hugepage-size-kb",
        type=int,
        default=_env_int("SAMURAI_AF_PACKET_HUGEPAGE_SIZE_KB", 2048),
        help="AF_PACKET hugepage hedef boyutu (kB), varsayılan: 2048.",
    )
    parser.add_argument(
        "--afpacket-ring-target-mb",
        type=int,
        default=_env_int("SAMURAI_AF_PACKET_RING_TARGET_MB", 64),
        help="AF_PACKET TX_RING hedef toplam boyutu (MB), varsayılan: 64.",
    )
    parser.add_argument(
        "--afpacket-block-size-kb",
        type=int,
        default=_env_int("SAMURAI_AF_PACKET_BLOCK_SIZE_KB", 0),
        help="AF_PACKET TX_RING block boyutu (kB). 0=auto (frame-size ve frames-per-block'e gore).",
    )
    parser.add_argument(
        "--afpacket-frame-size",
        type=int,
        default=_env_int("SAMURAI_AF_PACKET_FRAME_SIZE", 0),
        help="AF_PACKET TX_RING frame boyutu (byte). 0=auto.",
    )
    parser.add_argument(
        "--afpacket-frames-per-block",
        type=int,
        default=_env_int("SAMURAI_AF_PACKET_FRAMES_PER_BLOCK", 64),
        help="AF_PACKET block basina hedef frame sayisi (block-size auto modunda kullanilir).",
    )
    parser.add_argument(
        "--afpacket-poll-timeout-ms",
        type=int,
        default=_env_int("SAMURAI_AF_PACKET_POLL_TIMEOUT_MS", 1),
        help="AF_PACKET frame bekleme poll timeout tabani (ms).",
    )
    parser.add_argument(
        "--afpacket-spin-limit",
        type=int,
        default=_env_int("SAMURAI_AF_PACKET_SPIN_LIMIT", 2000),
        help="AF_PACKET frame bekleme spin sayisi limiti.",
    )
    parser.add_argument(
        "--afpacket-busy-poll-us",
        type=int,
        default=_env_int("SAMURAI_AF_PACKET_BUSY_POLL_US", 0),
        help="SO_BUSY_POLL mikro saniye degeri (0=kapali, best-effort).",
    )
    parser.add_argument(
        "--afpacket-qdisc-bypass",
        dest="afpacket_qdisc_bypass",
        action="store_true",
        help="AF_PACKET TX yolu icin PACKET_QDISC_BYPASS kullan (varsayilan: acik).",
    )
    parser.add_argument(
        "--no-afpacket-qdisc-bypass",
        dest="afpacket_qdisc_bypass",
        action="store_false",
        help="AF_PACKET TX yolu icin PACKET_QDISC_BYPASS kapat.",
    )
    parser.set_defaults(
        afpacket_qdisc_bypass=_env_flag("SAMURAI_AF_PACKET_QDISC_BYPASS", "1")
    )
    parser.add_argument(
        "--afpacket-mlock-ring",
        dest="afpacket_mlock_ring",
        action="store_true",
        help="AF_PACKET ring bellek sayfalarını mlock ile sabitlemeyi dene.",
    )
    parser.add_argument(
        "--no-afpacket-mlock-ring",
        dest="afpacket_mlock_ring",
        action="store_false",
        help="AF_PACKET ring mlock denemesini kapat.",
    )
    parser.set_defaults(
        afpacket_mlock_ring=_env_flag("SAMURAI_AF_PACKET_MLOCK_RING", "0")
    )
    parser.add_argument(
        "--afpacket-prefault-ring",
        dest="afpacket_prefault_ring",
        action="store_true",
        help="AF_PACKET ring mmap sonrası sayfaları prefault et.",
    )
    parser.add_argument(
        "--no-afpacket-prefault-ring",
        dest="afpacket_prefault_ring",
        action="store_false",
        help="AF_PACKET ring prefault davranışını kapat.",
    )
    parser.set_defaults(
        afpacket_prefault_ring=_env_flag("SAMURAI_AF_PACKET_PREFAULT_RING", "1")
    )
    parser.add_argument(
        "--lab-profile",
        choices=["off", "dedicated"],
        default=str(os.environ.get("SAMURAI_LAB_PROFILE", "off") or "off"),
        help="Lab çalışma profili: off=genel geliştirici, dedicated=hard benchmark profili.",
    )
    parser.add_argument(
        "--dp-queue-strategy",
        choices=["rr", "pin", "map"],
        default=str(os.environ.get("SAMURAI_DP_QUEUE_STRATEGY", "rr") or "rr"),
        help="Dataplane queue dağıtımı: rr=round-robin, pin=worker->queue, map=explicit map.",
    )
    parser.add_argument(
        "--dp-queues",
        type=int,
        default=_env_int("SAMURAI_DP_QUEUES", 1),
        help="Dataplane queue sayısı (dedicated profilde NIC TX queue kontrolüne girer).",
    )
    parser.add_argument(
        "--dp-queue-map",
        type=str,
        default=str(os.environ.get("SAMURAI_DP_QUEUE_MAP", "") or ""),
        help="Explicit worker->queue haritası. Format: '1:0,2:1,3:2'.",
    )
    parser.add_argument("--xdp-enable", action="store_true", help="AF_XDP sender yolunu etkinleştir (xdp backend).")
    parser.add_argument("--xdp-interface", type=str, default="", help="AF_XDP için NIC adı (örn: eth0).")
    parser.add_argument("--xdp-queue-id", type=int, default=0, help="AF_XDP queue id (varsayılan: 0).")
    parser.add_argument(
        "--xdp-mode",
        type=int,
        choices=[0, 1, 2],
        default=_env_int("SAMURAI_XDP_MODE", 0),
        help="AF_XDP mode: 0=SKB/Copy, 1=Native/DRV, 2=Offload.",
    )
    parser.add_argument(
        "--xdp-attach-bpf",
        dest="xdp_attach_bpf",
        action="store_true",
        help="XDP backend start anında eBPF programı attach et (varsayılan: açık).",
    )
    parser.add_argument(
        "--no-xdp-attach-bpf",
        dest="xdp_attach_bpf",
        action="store_false",
        help="XDP backend için eBPF attach adımını kapat.",
    )
    parser.set_defaults(
        xdp_attach_bpf=_env_flag("SAMURAI_XDP_ATTACH_BPF", "1")
    )
    parser.add_argument(
        "--xdp-bpf-section",
        type=str,
        default=str(os.environ.get("SAMURAI_XDP_BPF_SECTION", "xdp_sock") or "xdp_sock"),
        help="Attach edilecek BPF section adı (örn: xdp_sock, xdp_sock_filter).",
    )
    parser.add_argument(
        "--xdp-bpf-obj",
        type=str,
        default=str(os.environ.get("SAMURAI_XDP_BPF_OBJ", "") or ""),
        help="XDP BPF object yolu (boşsa ddos_samurai/xdp_prog.o varsayımı).",
    )
    parser.add_argument(
        "--xdp-xskmap-pin",
        type=str,
        default=str(os.environ.get("SAMURAI_XDP_XSKMAP_PIN", "") or ""),
        help="Pinned xsks_map yolu (opsiyonel, queue->xsk fd map update için).",
    )
    parser.add_argument(
        "--state-engine-mode",
        "--engine-mode",
        dest="engine_mode",
        choices=["auto", "required"],
        default=str(os.environ.get("SAMURAI_STATE_ENGINE_MODE", "auto") or "auto"),
        help="Legacy L4 state engine modu: auto|required.",
    )
    parser.add_argument(
        "--state-table-size",
        type=int,
        default=_env_int("SAMURAI_STATE_TABLE_SIZE", 65536),
        help="Legacy L4 state engine tablo boyutu.",
    )
    parser.add_argument(
        "--state-lock-count",
        type=int,
        default=_env_int("SAMURAI_STATE_LOCK_COUNT", 256),
        help="Legacy L4 state engine shard/lock sayısı.",
    )
    parser.add_argument(
        "--state-timeout-sec",
        type=int,
        default=_env_int("SAMURAI_STATE_TIMEOUT_SEC", 60),
        help="Legacy L4 state engine timeout süresi (saniye).",
    )
    parser.add_argument(
        "--state-sweep-interval-ms",
        type=int,
        default=_env_int("SAMURAI_STATE_SWEEP_INTERVAL_MS", 1000),
        help="Legacy L4 state engine sweep aralığı (ms).",
    )
    parser.add_argument(
        "--custom-tcp-mode",
        choices=["off", "auto", "required"],
        default=str(os.environ.get("SAMURAI_CUSTOM_TCP_MODE", "required") or "required"),
        help="Custom TCP dataplane modu: off|auto|required.",
    )
    parser.add_argument(
        "--topo-spec-json",
        type=str,
        default="",
        help="ASTF-benzeri topology JSON tanımı (CLI-only).",
    )
    parser.add_argument(
        "--topo-seed",
        type=int,
        default=-1,
        help="Topology tuple üretimi için deterministik seed (topology açıkken zorunlu).",
    )
    parser.add_argument(
        "--topo-strict",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Topology schema/semantic strict validation (varsayılan: açık).",
    )
    parser.add_argument(
        "--custom-tcp-backend",
        choices=["af_xdp"],
        default=str(os.environ.get("SAMURAI_CUSTOM_TCP_BACKEND", "af_xdp") or "af_xdp"),
        help="Custom TCP dataplane backend hedefi: af_xdp (zorunlu).",
    )
    parser.add_argument(
        "--custom-tcp-initial-rto-ms",
        type=int,
        default=_env_int("SAMURAI_CUSTOM_TCP_INITIAL_RTO_MS", 250),
        help="Custom TCP başlangıç RTO değeri (ms).",
    )
    parser.add_argument(
        "--custom-tcp-max-retransmits",
        type=int,
        default=_env_int("SAMURAI_CUSTOM_TCP_MAX_RETRANSMITS", 5),
        help="Custom TCP maksimum retransmit sayısı.",
    )
    parser.add_argument(
        "--custom-tcp-connect-timeout-ms",
        type=int,
        default=_env_int("SAMURAI_CUSTOM_TCP_CONNECT_TIMEOUT_MS", 3000),
        help="Custom TCP connect timeout değeri (ms).",
    )
    parser.add_argument(
        "--custom-tcp-idle-timeout-ms",
        type=int,
        default=_env_int("SAMURAI_CUSTOM_TCP_IDLE_TIMEOUT_MS", 30000),
        help="Custom TCP idle timeout değeri (ms).",
    )
    parser.add_argument(
        "--kpi-gate-profile",
        choices=["off", "dev", "ci_safe", "developer_fallback", "dedicated_lab"],
        default=str(os.environ.get("SAMURAI_KPI_GATE_PROFILE", "off") or "off"),
        help="KPI gate profili: off|dev|ci_safe|developer_fallback|dedicated_lab.",
    )
    parser.add_argument(
        "--kpi-hard-fail",
        action="store_true",
        help="Dedicated gate ihlalinde non-zero exit döndür.",
    )
    parser.add_argument(
        "--l7-engine",
        choices=["python", "c_state"],
        default=str(os.environ.get("SAMURAI_L7_ENGINE", "python") or "python"),
        help="L7 state engine seçimi: python|c_state.",
    )
    parser.add_argument(
        "--l7-http2-engine",
        choices=["python", "c_state", "auto"],
        default=str(os.environ.get("SAMURAI_L7_HTTP2_ENGINE", "auto") or "auto"),
        help="HTTP/2 L7 engine seçimi: python|c_state|auto.",
    )
    parser.add_argument(
        "--l7-quic-engine",
        choices=["python", "c_state", "auto"],
        default=str(os.environ.get("SAMURAI_L7_QUIC_ENGINE", "auto") or "auto"),
        help="QUIC L7 engine seçimi: python|c_state|auto.",
    )
    parser.add_argument(
        "--l7-quic-require-native",
        action="store_true",
        default=str(os.environ.get("SAMURAI_L7_QUIC_REQUIRE_NATIVE", "0") or "0").strip().lower() in {"1", "true", "yes", "on"},
        help="QUIC için yalnızca native C custom_native modunu kabul et (py-bridge kabul edilmez).",
    )
    parser.add_argument(
        "--l7-quic-auto-bridge",
        action="store_true",
        default=str(os.environ.get("SAMURAI_L7_QUIC_AUTO_BRIDGE", "0") or "0").strip().lower() in {"1", "true", "yes", "on"},
        help="Native QUIC yoksa py-bridge yolunu otomatik etkinleştir.",
    )
    parser.add_argument(
        "--l7-quic-bridge-autopromote",
        action="store_true",
        default=str(os.environ.get("SAMURAI_L7_QUIC_BRIDGE_AUTOPROMOTE", "0") or "0").strip().lower() in {"1", "true", "yes", "on"},
        help="Capability map içinde py-bridge'i otomatik custom_native olarak terfi ettir.",
    )
    parser.add_argument(
        "--l7-fallback-policy",
        choices=["allow", "fail"],
        default=str(os.environ.get("SAMURAI_L7_FALLBACK_POLICY", "allow") or "allow"),
        help="L7 C->Python fallback politikası: allow|fail.",
    )
    parser.add_argument(
        "--l7-capability-strict",
        action="store_true",
        default=str(os.environ.get("SAMURAI_L7_CAPABILITY_STRICT", "0") or "0").strip().lower() in {"1", "true", "yes", "on"},
        help="L7 capability strict modu: eksik capability varsa fallback yerine preflight/run fail.",
    )
    parser.add_argument("--l7-session-repeats", type=int, default=1, help="Stateful L7 oturumlarını kullanıcı başına tekrar sayısı.")
    parser.add_argument("--l7-max-active-sessions", type=int, default=0, help="Stateful L7 için eşzamanlı aktif session üst limiti (0=sınırsız).")
    ml_group = parser.add_argument_group("Traffic Model (Mamba-2 Planner v1)")
    ml_group.add_argument(
        "--traffic-model",
        choices=["none", "mamba2"],
        default="none",
        help="Stateful trafik planner seçimi: none|mamba2. Not: mamba2 runtime entegrasyonu devre dışıdır; training/mamba2_monolith.py kullanın.",
    )
    ml_group.add_argument("--traffic-model-checkpoint", type=str, default="", help="Planner checkpoint dosya yolu.")
    ml_group.add_argument("--traffic-model-config", type=str, default="", help="Planner config dosya yolu (opsiyonel).")
    ml_group.add_argument(
        "--traffic-model-device",
        choices=["cpu"],
        default="cpu",
        help="Planner device (v1: sadece cpu).",
    )
    ml_group.add_argument("--traffic-model-seed", type=int, default=1337, help="Deterministic planner seed.")
    ml_group.add_argument(
        "--traffic-model-label-mix",
        type=str,
        default="benign=0.4,evasive=0.4,aggressive=0.2",
        help="Label dağılımı: benign=0.4,evasive=0.4,aggressive=0.2",
    )
    ml_group.add_argument(
        "--traffic-model-session-len",
        type=int,
        default=24,
        help="Session başına maksimum event sayısı.",
    )
    ml_group.add_argument(
        "--traffic-model-planner-batch",
        type=int,
        default=128,
        help="Tek plan üretim çağrısındaki session batch boyutu.",
    )
    ml_group.add_argument(
        "--traffic-model-timeout-ms",
        type=int,
        default=2500,
        help="Planner inference timeout (ms).",
    )
    ml_group.add_argument(
        "--traffic-model-fallback",
        choices=["static", "fail"],
        default="static",
        help="Planner fail olduğunda davranış: static|fail.",
    )
    ml_group.add_argument(
        "--traffic-model-export-events",
        type=str,
        default="",
        help="Generated planner event log JSONL yolu (opsiyonel).",
    )
    ml_group.add_argument(
        "--traffic-model-dataset-capture",
        type=str,
        default="",
        help="Runtime worker event'lerini JSONL dataset olarak yaz.",
    )
    ml_group.add_argument(
        "--traffic-model-pcap-profile",
        type=str,
        default="",
        help="PCAP extractor profile adı (dataset pipeline için).",
    )
    ml_group.add_argument(
        "--traffic-model-dry-validate",
        action="store_true",
        help="Sadece planner üretimi+validation çalıştır, trafik gönderme.",
    )
    parser.add_argument(
        "--gpu-template-pool-size-l4",
        type=int,
        default=_env_int("SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4", 10),
        help="CUDA template-pool L4 varsayılan şablon sayısı (env: SAMURAI_GPU_TEMPLATE_POOL_SIZE_L4).",
    )
    parser.add_argument(
        "--gpu-template-pool-size-l7",
        type=int,
        default=_env_int("SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7", 50),
        help="CUDA template-pool L7 set varsayılan şablon sayısı (env: SAMURAI_GPU_TEMPLATE_POOL_SIZE_L7).",
    )
    parser.add_argument(
        "--gpu-ring-capacity",
        type=int,
        default=_env_int("SAMURAI_GPU_RING_CAPACITY", 3),
        help="CUDA producer-consumer ring kapasitesi (env: SAMURAI_GPU_RING_CAPACITY).",
    )
    parser.add_argument(
        "--gpu-batch-size",
        type=int,
        default=_env_int("SAMURAI_GPU_BATCH", 100000),
        help="CUDA üretim batch boyutu (env: SAMURAI_GPU_BATCH).",
    )
    parser.add_argument(
        "--gpu-stream-count",
        type=int,
        default=_env_int("SAMURAI_GPU_STREAMS", 3),
        help="CUDA stream sayısı (gen/copy/send overlap için).",
    )
    parser.add_argument(
        "--gpu-pipeline-depth",
        type=int,
        default=_env_int("SAMURAI_GPU_PIPELINE_DEPTH", 2),
        help="GPU pipeline overlap derinliği (ready batch kuyruk eşiği).",
    )
    parser.add_argument(
        "--gpu-full-variation",
        action=argparse.BooleanOptionalAction,
        default=str(os.environ.get("SAMURAI_GPU_FULL_VARIATION", "1") or "1").strip().lower() in {"1", "true", "yes", "on"},
        help="Basic L4 akışında varyasyonları tamamen GPU hot-path üzerinden üret.",
    )
    parser.add_argument(
        "--gpu-pinned-max-mb",
        type=int,
        default=_env_int("SAMURAI_GPU_PINNED_MAX_MB", 512),
        help="Pinned host buffer pool üst sınırı MB (env: SAMURAI_GPU_PINNED_MAX_MB).",
    )
    parser.add_argument(
        "--gpu-packet-zerocopy-output",
        action=argparse.BooleanOptionalAction,
        default=str(os.environ.get("SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT", "0") or "0").strip().lower() in {"1", "true", "yes", "on"},
        help="CUDA native path çıktı tamponu için mapped host zero-copy yolunu aç/kapat (env: SAMURAI_GPU_PACKET_ZEROCOPY_OUTPUT).",
    )
    parser.add_argument(
        "--gpu-rng-seed",
        type=int,
        default=_env_int("SAMURAI_GPU_RNG_SEED", 1234),
        help="GPU payload RNG seed (varsayılan: deterministik 1234, env: SAMURAI_GPU_RNG_SEED).",
    )
    _gpu_vector_engine_default = str(os.environ.get("SAMURAI_GPU_VECTOR_ENGINE", "gpu_cuda") or "gpu_cuda").strip().lower()
    if _gpu_vector_engine_default != "gpu_cuda":
        _gpu_vector_engine_default = "gpu_cuda"
    parser.add_argument(
        "--gpu-vector-engine",
        choices=["gpu_cuda"],
        default=_gpu_vector_engine_default,
        help="GPU vector planner engine: gpu_cuda (legacy planner kaldırıldı).",
    )
    pcap_group = parser.add_argument_group("GPU PCAP Generator (Test)")
    pcap_group.add_argument(
        "--gpu-pcap",
        action="store_true",
        help="GPU üzerinde sentetik PCAP üret ve çık (trafik göndermez).",
    )
    pcap_group.add_argument("--gpu-pcap-duration", type=int, default=10, help="PCAP süresi (s)")
    pcap_group.add_argument("--gpu-pcap-pps", type=int, default=10000, help="Saniye başı paket sayısı (PPS)")
    pcap_group.add_argument("--gpu-pcap-mode", choices=["mix", "tcp", "udp"], default="mix", help="Trafik modu")
    pcap_group.add_argument("--gpu-pcap-src-ip", type=str, default="192.168.1.100", help="Kaynak IPv4")
    pcap_group.add_argument(
        "--gpu-pcap-dst-ip",
        type=str,
        default="",
        help="Hedef IPv4 (boşsa: --target veya 127.0.0.1)",
    )
    pcap_group.add_argument(
        "--gpu-pcap-tcp-port",
        type=int,
        default=0,
        help="TCP hedef port (0 ise: --port veya 80)",
    )
    pcap_group.add_argument(
        "--gpu-pcap-udp-port",
        type=int,
        default=0,
        help="UDP hedef port (0 ise: --port veya 53)",
    )
    pcap_group.add_argument("--gpu-pcap-chunk", type=int, default=200000, help="Chunk başına paket sayısı")
    pcap_group.add_argument("--gpu-pcap-seed", type=int, default=0, help="RNG seed (0: rastgele)")
    pcap_group.add_argument(
        "--gpu-pcap-flow-count",
        type=int,
        default=4096,
        help="Flow havuzu boyutu (gerçekçi modda kaynak port/IP çeşitliliği için).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-realistic",
        action="store_true",
        help="Gerçekçiliği artırılmış flow-aware profil (TTL/TOS varyasyonu, stateful TCP, UDP checksum).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-udp-checksum",
        action="store_true",
        help="UDP checksum hesaplamasını etkinleştir.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-variable-size",
        action="store_true",
        help="Değişken paket boyutu üretimini etkinleştir (V2).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-mtu",
        type=int,
        default=1500,
        help="L3 MTU değeri (128-1500). Paket boyutu dağılımı bu sınıra göre üretilir.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-size-profile",
        choices=["mixed", "web", "dns"],
        default="mixed",
        help="Değişken paket boyutu profili.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-realism-report",
        action="store_true",
        help="Üretilen PCAP için V3 gerçekçilik skoru ve metrik raporu üret.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-realism-baseline",
        type=str,
        default="",
        help="Gerçekçilik skorunu bu referans PCAP'a göre hesapla (opsiyonel).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-realism-sample",
        type=int,
        default=100000,
        help="Gerçekçilik analizinde incelenecek maksimum paket sayısı.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-realism-out",
        type=str,
        default="",
        help="Gerçekçilik raporu JSON dosya adı (varsayılan: <out>.realism.json).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-out",
        type=str,
        default="",
        help="Çıktı dosya adı (proje klasörüne kaydedilir)",
    )
    pcap_group.add_argument(
        "--gpu-pcap-run-report",
        action="store_true",
        help="GPU PCAP calismasi icin musteri-odakli run raporu uret (JSON/Markdown).",
    )
    pcap_group.add_argument(
        "--gpu-pcap-run-report-format",
        choices=["json", "md", "both"],
        default="both",
        help="Run raporu cikti formati.",
    )
    pcap_group.add_argument(
        "--gpu-pcap-run-report-out",
        type=str,
        default="",
        help="Run raporu dosya adi (bossa: <out>.run.json/.md).",
    )

    pacing_group = parser.add_argument_group('Pacing Options (Deterministic Timing)')
    pacing_group.add_argument(
        "--pacing-mode",
        choices=["none", "rps", "ipg", "burst"],
        default="none",
        help="Paket pacing stratejisi: none=sınırsız burst, rps=rate-limit, ipg=sabit gap, burst=batch+gap",
    )
    pacing_group.add_argument(
        "--ipg",
        type=int,
        default=0,
        help="Inter-Packet Gap (nanosaniye). --pacing-mode ipg ile kullanılır. Örnek: 10000 = 10µs",
    )
    pacing_group.add_argument(
        "--burst-size",
        type=int,
        default=64,
        help="Burst modunda tek seferde gönderilecek paket sayısı (varsayılan: 64)",
    )
    pacing_group.add_argument(
        "--burst-gap",
        type=int,
        default=0,
        help="Burst'ler arası bekleme süresi (nanosaniye)",
    )
    pacing_group.add_argument(
        "--jitter-model",
        choices=["none", "uniform", "gaussian", "exponential"],
        default="none",
        help="Jitter dağılım modeli (pacing üzerine uygulanır)",
    )
    pacing_group.add_argument(
        "--jitter-pct",
        type=float,
        default=0.0,
        help="Jitter yüzdesi (0.0-1.0). Base gap'in bu kadarı kadar sapma uygulanır.",
    )
    pacing_group.add_argument(
        "--pin-cpu",
        type=int,
        default=-1,
        help="Pacing engine'i belirli bir CPU çekirdeğine sabitle (-1: otomatik)",
    )
    pacing_group.add_argument(
        "--use-so-txtime",
        action="store_true",
        help="Kernel SO_TXTIME/ETF offload kullan (Linux 4.19+, root gerektirir)",
    )

    safety_group = parser.add_argument_group("Safety Options")
    safety_group.add_argument(
        "--allow-target",
        action="append",
        default=[],
        help="İzin verilen hedef(ler). IP veya CIDR. Çoklu kullanım: --allow-target 10.0.0.0/8 --allow-target 192.168.1.10",
    )
    safety_group.add_argument(
        "--allow-public-target",
        action="store_true",
        help="Public (internet) hedeflere izin ver (tehlikeli). Varsayılan: engelli.",
    )

    anomaly_group = parser.add_argument_group('Anomaly Packet Options')
    anomaly_group.add_argument("--anomaly-types", type=int, nargs='+', default=None,
        help="Anomaly types to use (0=InvalidIHL, 1=InvalidIPLen, 2=InvalidIPVer, 3=InvalidProto, "
             "4=TCPFlagAbuse, 5=InvalidTCPOffset, 6=OverlapFrags, 7=TinyFrags, 8=LandAttack, "
             "9=InvalidChecksum, 10=TTLAnomaly, 11=MalformedOptions). Default: all.")
    anomaly_group.add_argument("--anomaly-intensity", type=int, default=75,
        help="Anomaly intensity 0-100 (how malformed the packets are). Default: 75")
    anomaly_group.add_argument("--anomaly-suite", action="store_true",
        help="Use full anomaly suite (standard + overlapping frags + tiny frags)")

    # ── PCAP Replay Options ──────────────────────────────────────────────────
    pcap_replay_group = parser.add_argument_group('PCAP Replay Options')
    pcap_replay_group.add_argument(
        "--pcap-file", type=str, default="",
        help="PCAP / PCAP-NG dosyası yolu (pcap-replay vektörü için gereklidir).",
    )
    pcap_replay_group.add_argument(
        "--pcap-timing",
        choices=["original", "topspeed", "multiplier", "rps"],
        default="original",
        help="Replay zamanlama modu: original=orijinal gap, topspeed=maks hız, "
             "multiplier=N× hız çarpanı, rps=sabit paket/sn.",
    )
    pcap_replay_group.add_argument(
        "--pcap-speed", type=float, default=1.0,
        help="Hız çarpanı (multiplier modu için). 2.0 = 2× hızlı. Varsayılan: 1.0",
    )
    pcap_replay_group.add_argument(
        "--pcap-loops", type=int, default=1,
        help="PCAP dosyasını kaç kez tekrar oynat (0 = sonsuz). Varsayılan: 1",
    )
    pcap_replay_group.add_argument(
        "--pcap-max-packets", type=int, default=0,
        help="Oynatılacak maksimum paket sayısı (0 = hepsi). Varsayılan: 0",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-proto", type=str, nargs='+', default=None,
        help="Protokol filtresi (tcp, udp, icmp). Birden fazla belirtilebilir.",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-src-ip", type=str, default=None,
        help="Kaynak IP filtresi (IP veya CIDR). Örn: 192.168.1.0/24",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-dst-ip", type=str, default=None,
        help="Hedef IP filtresi (IP veya CIDR).",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-src-port", type=int, default=None,
        help="Kaynak port filtresi.",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-dst-port", type=int, default=None,
        help="Hedef port filtresi.",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-min-len", type=int, default=0,
        help="Minimum paket boyutu filtresi (byte).",
    )
    pcap_replay_group.add_argument(
        "--pcap-filter-max-len", type=int, default=0,
        help="Maksimum paket boyutu filtresi (byte, 0=sınırsız).",
    )
    pcap_replay_group.add_argument(
        "--pcap-strip-eth", action="store_true",
        help="Ethernet başlığını soyup sadece raw IP olarak gönder.",
    )
    pcap_replay_group.add_argument(
        "--pcap-use-l2", action="store_true",
        help="PCAP replay'i L2 TX_RING yolu ile gönder (Ethernet frame korunur).",
    )
    pcap_replay_group.add_argument(
        "--pcap-no-flow-aware", action="store_true",
        help="PCAP replay TCP flow-aware seq/ack delta rewrite'i kapat.",
    )
    pcap_replay_group.add_argument(
        "--pcap-src-ip-override", type=str, default=None,
        help="Tüm paketlerin kaynak IP'sini bu değerle değiştir.",
    )
    pcap_replay_group.add_argument(
        "--pcap-src-port-override", type=int, default=None,
        help="Tüm paketlerin kaynak portunu bu değerle değiştir.",
    )
    pcap_replay_group.add_argument(
        "--pcap-batch-size", type=int, default=512,
        help="Timing-aware modda batch boyutu. Varsayılan: 512",
    )
    pcap_replay_group.add_argument(
        "--pcap-info", action="store_true",
        help="PCAP dosyasının özetini göster ve çık (trafik göndermez).",
    )

    report_group = parser.add_argument_group("Reporting / Self-Test")
    report_group.add_argument(
        "--self-test",
        action="store_true",
        help="Unittest discovery calistir ve cik (trafik gondermez).",
    )
    report_group.add_argument(
        "--run-report",
        action="store_true",
        help="Calisma raporu uret (live + offline/test modlari).",
    )
    report_group.add_argument(
        "--run-report-format",
        choices=["json", "md", "both"],
        default="both",
        help="Run raporu cikti formati.",
    )
    report_group.add_argument(
        "--run-report-out",
        type=str,
        default="",
        help="Run raporu base dosya adi (bossa otomatik). Uzanti eklemeyin (ornek: reports/run_001).",
    )
    report_group.add_argument(
        "--run-report-dir",
        type=str,
        default="reports/runs",
        help="Run raporu cikti dizini (varsayilan: reports/runs).",
    )
    report_group.add_argument(
        "--soak-profile",
        choices=["none", "1h", "6h", "24h"],
        default="none",
        help="Soak test profili (1h/6h/24h) ve varsayilan pass/fail esikleri.",
    )
    report_group.add_argument(
        "--soak-snapshot-interval",
        type=int,
        default=0,
        help="Soak snapshot araligi (s). 0=profile default, aralik 10-30s.",
    )
    report_group.add_argument(
        "--soak-warmup-s",
        type=int,
        default=0,
        help="Soak warm-up suresi (s). 0=profile default; baseline bu sureden sonra kilitlenir.",
    )
    report_group.add_argument("--soak-max-error-rate-pct", type=float, default=None, help="Soak pass/fail: maksimum hata orani (%%).")
    report_group.add_argument("--soak-max-pps-drop-pct", type=float, default=None, help="Soak pass/fail: baseline'e gore maksimum PPS dusus (%%).")
    report_group.add_argument("--soak-max-rss-growth-mb", type=float, default=None, help="Soak pass/fail: maksimum RSS artis limiti (MB).")
    report_group.add_argument("--soak-max-vram-growth-mb", type=float, default=None, help="Soak pass/fail: maksimum VRAM artis limiti (MB).")
    report_group.add_argument("--soak-max-pinned-growth-mb", type=float, default=None, help="Soak pass/fail: maksimum pinned-memory artis limiti (MB).")
    report_group.add_argument("--soak-max-backlog", type=int, default=None, help="Soak pass/fail: maksimum backlog limiti (paket).")
    report_group.add_argument(
        "--loss-telemetry",
        choices=["auto", "0", "1"],
        default="auto",
        help="Wire-loss telemetry modu: auto|0|1 (varsayilan: auto).",
    )
    report_group.add_argument(
        "--loss-iface",
        type=str,
        default="",
        help="Loss telemetry icin arayuz ismi (opsiyonel, bossa otomatik).",
    )
    report_group.add_argument(
        "--loss-fail-pct",
        type=float,
        default=5.0,
        help="Wire-loss fail esigi (%%). Varsayilan: 5.",
    )
    report_group.add_argument(
        "--loss-report-out",
        type=str,
        default="",
        help="Canli run sonunda loss telemetry JSON ciktisi (opsiyonel dosya yolu).",
    )

    fault_group = parser.add_argument_group("Fault Injection")
    fault_group.add_argument(
        "--fault-inject",
        nargs="*",
        choices=["sender-restart", "nic-blip", "gpu-stream-error", "mix"],
        default=[],
        help="Soak test fault senaryolari (simulasyon). Birden fazla verilebilir.",
    )
    fault_group.add_argument(
        "--fault-after-s",
        type=float,
        default=0.0,
        help="Fault injection tetikleme suresi (s). 0=kapali.",
    )
    fault_group.add_argument(
        "--fault-duration-s",
        type=float,
        default=2.0,
        help="Fault simulasyon suresi (s).",
    )

    return parser
