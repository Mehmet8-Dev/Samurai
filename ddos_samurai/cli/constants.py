"""CLI constants and presets."""

CONNECTION_POOL = 800
USER_AGENTS = [
    # A comprehensive list of user agents
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

_SOAK_PROFILE_PRESETS = {
    "none": {
        "duration_s": 0,
        "snapshot_interval_s": 0,
        "warmup_s": 0,
        "max_error_rate_pct": 100.0,
        "max_pps_drop_pct": 100.0,
        "max_rss_growth_mb": 0.0,
        "max_vram_growth_mb": 0.0,
        "max_pinned_growth_mb": 0.0,
        "max_backlog": 0,
    },
    "1h": {
        "duration_s": 3600,
        "snapshot_interval_s": 10,
        "warmup_s": 60,
        "max_error_rate_pct": 1.0,
        "max_pps_drop_pct": 20.0,
        "max_rss_growth_mb": 512.0,
        "max_vram_growth_mb": 1024.0,
        "max_pinned_growth_mb": 2048.0,
        "max_backlog": 50000,
    },
    "6h": {
        "duration_s": 21600,
        "snapshot_interval_s": 20,
        "warmup_s": 120,
        "max_error_rate_pct": 1.0,
        "max_pps_drop_pct": 25.0,
        "max_rss_growth_mb": 1024.0,
        "max_vram_growth_mb": 2048.0,
        "max_pinned_growth_mb": 4096.0,
        "max_backlog": 100000,
    },
    "24h": {
        "duration_s": 86400,
        "snapshot_interval_s": 30,
        "warmup_s": 180,
        "max_error_rate_pct": 1.0,
        "max_pps_drop_pct": 30.0,
        "max_rss_growth_mb": 2048.0,
        "max_vram_growth_mb": 3072.0,
        "max_pinned_growth_mb": 8192.0,
        "max_backlog": 200000,
    },
}
