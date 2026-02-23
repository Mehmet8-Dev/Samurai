# Product Guide: DDoSamurai v2.0

## Initial Concept
DDoSamurai v2.0, ağ güvenliği uzmanları ve sistem yöneticileri için geliştirilmiş, yüksek performanslı, modüler ve gizlilik odaklı bir ağ stres testi ve sızma testi aracıdır. Geleneksel araçların aksine, sadece hacimsel yük oluşturmayı değil, aynı zamanda modern WAF ve IPS sistemlerini atlatmayı (bypass) hedefler.

## Vision
Projenin vizyonu, GPU paralelizminin gücünü kullanarak saniyede milyonlarca paket üretebilen, aynı zamanda "Ninja Mode" gibi özelliklerle gerçek bir kullanıcı davranışını taklit ederek tespit edilmesi zor saldırı vektörleri sunan nihai stres testi platformu olmaktır. Hız, gizlilik ve akıllı davranış, DDoSamurai'ın temel taşlarıdır.

## Core Features
*   **High-Performance Packet Generation:**
    *   **GPU Acceleration (CUDA):** NVIDIA GPU'ları kullanarak (Numba & CuPy) yüksek PPS değerlerine ulaşma.
    *   **Hybrid Architecture:** CPU (Multiprocessing, Asyncio) ve C eklentileri (fast_sender, AF_PACKET/TX_RING) ile donanım limitlerini zorlama.
*   **Advanced Stealth & Evasion:**
    *   **Ninja Mode:** Playwright tabanlı headless browser ile JavaScript challenge'ları ve WAF kontrollerini (Cloudflare, Akamai vb.) aşma.
    *   **Protocol Mimicry:** JA3/JA4 TLS parmak izi taklidi ve HTTP/2 uyumluluğu.
    *   **IP Spoofing:** Subnet, Realistic ve Random modları ile kaynak gizleme.
    *   **Entropy & Timing Evasion:** Tespit sistemlerini aşmak için entropi manipülasyonu ve zamanlama varyasyonları (jitter).
*   **Multi-Vector Attacks:**
    *   **L4:** TCP (SYN, ACK, FIN), UDP, ICMP Flood.
    *   **L7:** HTTP/HTTPS Flood, Slowloris, DNS Amplification, WebSocket, QUIC/HTTP3.
*   **Observability:**
    *   Rich kütüphanesi ile modern, terminal tabanlı canlı izleme paneli.
    *   Prometheus uyumlu metrik sunucusu.

## Target Audience
*   **Ağ Güvenliği Uzmanları (Pen-Testers):** Güvenlik duvarlarının ve altyapıların sınırlarını test etmek için.
*   **Sistem Yöneticileri:** Altyapı kapasite planlaması ve DDoS dayanıklılık testleri için.
*   **Araştırmacılar:** Modern DDoS teknikleri ve savunma mekanizmaları üzerine çalışmak için.

## Success Criteria (Definition of Done)
*   **Performance:** GPU destekli modda stabil 1M+ PPS değerine ulaşılması ve CPU darboğazlarının giderilmesi.
*   **Evasion Capability:** Modern WAF çözümlerinin (standart konfigürasyonlarda) "Ninja Mode" ile başarılı bir şekilde atlatılabilmesi.
*   **Stability:** Uzun süreli testlerde bellek sızıntısı veya kilitlenme (deadlock) yaşanmaması.
*   **Usability:** Sorunsuz kurulum ve kullanıcı dostu CLI deneyimi.

## Future Roadmap (from Stealth & Evasion doc)
*   **Adversarial ML:** ML tabanlı savunma sistemlerini kandırmak için özel hazırlanmış girdiler (Adversarial Examples).
*   **Cross-Protocol Blending:** Tespiti zorlaştırmak için protokollerin karıştırılması.
*   **Timing-Aware Traffic:** İnsan davranışını ve doğal ağ gecikmelerini birebir taklit eden zamanlama algoritmaları.
