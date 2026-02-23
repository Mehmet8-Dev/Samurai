"""
DDoSamurai — Corporate Test Profiles
====================================

Professional, pre-defined test profiles for corporate clients.
These profiles are designed to simulate real-world attack scenarios,
stress testing, and infrastructure benchmarking.

Each profile maps to a set of default CLI arguments.
"""

# Define the profiles mapping
TEST_PROFILES = {
    "web-stress": {
        "description": "Standard Web Server Stress Test (HTTP/1.1 GET Flood)",
        "args": {
            "attack_vector": "http",
            "protocol": "tcp",
            "port": 80,
            "count": 100000,
            "workers": 0,  # 0 means auto (all cores)
            "http_method": "GET",
            "http_path": ["/"],
            "stealth_mode": True,
            "payload_mutation": True,
        }
    },
    "web-bypass": {
        "description": "Advanced WAF/CDN Evasion Test (Polymorphic HTTP/2 & Ninja Mode)",
        "args": {
            "attack_vector": "http2",
            "protocol": "tcp",
            "port": 443,
            "count": 50000,
            "ninja_mode": True,
            "evasion_techniques": ["case", "url", "comment"],
            "stealth_mode": True,
            "payload_mutation": True,
            "tls_profile": "chrome_120",
            "h2_profile": "chrome_120",
        }
    },
    "stateful-exhaustion": {
        "description": "Stateful Firewall & Load Balancer Exhaustion (TCP SYN Flood with OS Mimicry)",
        "args": {
            "attack_vector": "basic",
            "protocol": "tcp",
            "tcp_flags": "S",
            "count": 500000,
            "spoof": True,
            "spoof_mode": "realistic",
            "os_fingerprint": True,
            "compute_backend": "cpu", # Fallback to CPU if GPU not available
        }
    },
    "volumetric-udp": {
        "description": "Raw Volumetric Pipe Saturation (UDP Flood)",
        "args": {
            "attack_vector": "basic",
            "protocol": "udp",
            "count": 1000000,
            "pad": 1400, # Large packet size
            "spoof": True,
            "spoof_mode": "random",
            "pacing_mode": "none",
        }
    },
    "dns-infrastructure": {
        "description": "DNS Server Stress Test & Cache Poisoning Resistance (Randomized DNS Queries)",
        "args": {
            "attack_vector": "dns",
            "protocol": "udp",
            "port": 53,
            "count": 200000,
            "dns_name": "random.example.com", # Represents a randomized subdomain query trend
            "dns_qtype": ["A", "AAAA", "MX", "TXT"],
            "spoof": True,
            "spoof_mode": "realistic",
        }
    },
    "slow-exhaustion": {
        "description": "Low & Slow Application Layer Exhaustion (Slowloris/Slow-Read)",
        "args": {
            "attack_vector": "slowloris",
            "protocol": "tcp",
            "port": 443,
            "count": 10000,
            "delay": 5.0, # Slow pacing between keep-alives
            "slowloris_concurrency": 2000,
            "stealth_mode": True,
        }
    },
    "amplification-simulation": {
        "description": "Reflective Amplification Simulation (Memcached/NTP/DNS)",
        "args": {
            "attack_vector": "dns-amp",
            "protocol": "udp",
            "count": 50000,
            "spoof": True, # Crucial for amplification
        }
    },
    "custom": {
        "description": "Custom user-defined profile (No overrides)",
        "args": {}
    }
}

def print_profiles():
    """Prints a beautifully formatted table of available profiles."""
    print("\n" + "="*80)
    print(" DDoSamurai — Corporate Test Profiles ".center(80, " "))
    print("="*80)
    print(f" {'PROFILE NAME':<25} | {'DESCRIPTION'}")
    print("-" * 80)
    for name, data in TEST_PROFILES.items():
        if name == "custom": continue
        print(f" {name:<25} | {data['description']}")
    print("="*80)
    print("\nTo use a profile, supply it via: --profile <profile_name>")
    print("Example: sudo python -m ddos_samurai --profile web-bypass -t https://target.com\n")
