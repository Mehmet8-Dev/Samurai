import asyncio
import logging
import os
import ssl
import random
import urllib.parse
from dataclasses import dataclass

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from .profile_names import DEFAULT_BROWSER_PROFILE, PROFILE_NONE


@dataclass(frozen=True)
class TLSProfile:
    name: str
    ciphers: str
    options: int
    min_version: ssl.TLSVersion
    max_version: ssl.TLSVersion
    alpn: tuple[str, ...]
    tcp_ttl: int
    tcp_window: int
    tcp_mss: int


TLS_PROFILES: dict[str, TLSProfile] = {
    "chrome_120": TLSProfile(
        name="chrome_120",
        ciphers="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
        options=ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1,
        min_version=ssl.TLSVersion.TLSv1_2,
        max_version=ssl.TLSVersion.TLSv1_3,
        alpn=("h2", "http/1.1"),
        tcp_ttl=128,
        tcp_window=64240,
        tcp_mss=1460,
    ),
    "firefox_120": TLSProfile(
        name="firefox_120",
        ciphers="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
        options=ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1,
        min_version=ssl.TLSVersion.TLSv1_2,
        max_version=ssl.TLSVersion.TLSv1_3,
        alpn=("h2", "http/1.1"),
        tcp_ttl=64,
        tcp_window=65535,
        tcp_mss=1440,
    ),
    "safari_17": TLSProfile(
        name="safari_17",
        ciphers="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:AES256-GCM-SHA384:AES128-GCM-SHA256",
        options=ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1,
        min_version=ssl.TLSVersion.TLSv1_2,
        max_version=ssl.TLSVersion.TLSv1_3,
        alpn=("h2", "http/1.1"),
        tcp_ttl=64,
        tcp_window=65535,
        tcp_mss=1440,
    ),
}


class TLSProfileResolver:
    @staticmethod
    def resolve(profile_name: str | None, *, allow_none: bool = True) -> TLSProfile | None:
        raw = str(profile_name or "").strip().lower()
        if not raw:
            return TLS_PROFILES[DEFAULT_BROWSER_PROFILE]
        if raw == PROFILE_NONE:
            if allow_none:
                return None
            raise ValueError("TLS profile 'none' is not valid in this context")
        profile = TLS_PROFILES.get(raw)
        if profile is None:
            raise ValueError(f"Unsupported TLS profile: {profile_name!r}")
        return profile


class TLSContextFactory:
    @staticmethod
    def create(profile: TLSProfile) -> ssl.SSLContext:
        context = ssl.create_default_context()
        context.set_ciphers(profile.ciphers)
        context.options |= profile.options
        context.minimum_version = profile.min_version
        context.maximum_version = profile.max_version
        if hasattr(context, "set_alpn_protocols"):
            context.set_alpn_protocols(list(profile.alpn))
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

def create_ja3_context(profile_name="chrome_120"):
    """
    Creates an SSLContext that mimics a specific browser's JA3/JA4 fingerprint.
    """
    profile = TLSProfileResolver.resolve(profile_name, allow_none=False)
    return TLSContextFactory.create(profile)

def get_tcp_params(profile_name="chrome_120"):
    """Returns TCP stack parameters (TTL, Window, MSS) for a profile."""
    name = profile_name
    if str(name or "").strip().lower() == PROFILE_NONE:
        name = DEFAULT_BROWSER_PROFILE
    profile = TLSProfileResolver.resolve(name, allow_none=False)
    return {
        "ttl": int(profile.tcp_ttl),
        "window": int(profile.tcp_window),
        "mss": int(profile.tcp_mss),
    }


def apply_evasion(payload: str, techniques: list[str] | None = None) -> str:
    """
    Apply lightweight payload obfuscation techniques (for testing/WAF evaluation).

    Supported techniques:
      - case    : change letter casing
      - url     : URL-encode the payload
      - comment : insert C-style comments between tokens
    """
    if techniques is None:
        return payload

    out = payload
    for t in techniques:
        t = str(t).strip().lower()
        if t == "case":
            # Deterministic-ish obfuscation: alternate case for alphabetic chars.
            chars = []
            flip = True
            for ch in out:
                if ch.isalpha():
                    chars.append(ch.upper() if flip else ch.lower())
                    flip = not flip
                else:
                    chars.append(ch)
            out = "".join(chars)
        elif t == "url":
            out = urllib.parse.quote(out, safe="")
        elif t == "comment":
            # Insert comments between whitespace-separated tokens.
            out = out.replace(" ", "/**/")
        else:
            # Unknown technique: ignore to keep caller UX forgiving.
            continue
    return out


def create_smuggled_request(host: str, port: int, variant: str = "CL.TE") -> bytes:
    """
    Build a minimal HTTP request-smuggling style payload for testing.

    Variants:
      - "CL.TE": Content-Length + Transfer-Encoding: chunked
      - "TE.CL": Transfer-Encoding: chunked + Content-Length (Content-Length: 4)
    """
    v = str(variant or "").strip().upper()
    host_hdr = f"{host}:{int(port)}"

    if v not in ("CL.TE", "TE.CL"):
        raise ValueError(f"Unknown smuggling variant: {variant!r}")

    # Keep it simple: a POST with both headers, then a smuggled GET.
    if v == "TE.CL":
        cl = "4"
    else:
        cl = "6"

    primary = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host_hdr}\r\n"
        f"Content-Length: {cl}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"0\r\n\r\n"
    )
    smuggled = (
        f"GET /404-not-found HTTP/1.1\r\n"
        f"Host: {host_hdr}\r\n"
        f"\r\n"
    )
    return (primary + smuggled).encode("ascii", "ignore")

class WAFBypass:
    def __init__(self, target_url, proxy=None, headless=True):
        self.target_url = target_url
        self.proxy = proxy
        self.headless = headless
        self.cookies = None
        self.user_agent = None
        self.enabled = str(os.environ.get("SAMURAI_ENABLE_BROWSER_AUTOMATION", "0")).strip().lower() in {"1", "true", "yes", "on"}
        self.timeout_s = max(5.0, float(os.environ.get("SAMURAI_WAF_BYPASS_TIMEOUT_S", "90") or 90))
        self.challenge_budget_s = max(5, int(os.environ.get("SAMURAI_WAF_CHALLENGE_BUDGET_S", "30") or 30))

    async def simulate_human_mouse(self, page):
        """Simulates human-like mouse movement using Bezier curves."""
        start_x, start_y = random.randint(0, 100), random.randint(0, 100)
        end_x, end_y = random.randint(800, 1000), random.randint(600, 800)
        
        # Control points for Bezier curve
        cp1_x, cp1_y = random.randint(200, 400), random.randint(0, 300)
        cp2_x, cp2_y = random.randint(600, 800), random.randint(400, 900)
        
        steps = 25
        for i in range(steps + 1):
            t = i / steps
            # Cubic Bezier formula
            x = (1-t)**3 * start_x + 3*(1-t)**2 * t * cp1_x + 3*(1-t) * t**2 * cp2_x + t**3 * end_x
            y = (1-t)**3 * start_y + 3*(1-t)**2 * t * cp1_y + 3*(1-t) * t**2 * cp2_y + t**3 * end_y
            await page.mouse.move(x, y)
            await asyncio.sleep(random.uniform(0.01, 0.03))

    async def simulate_human_scroll(self, page):
        """Simulates human-like scrolling with variable speed."""
        total_scroll = random.randint(500, 2000)
        current_scroll = 0
        while current_scroll < total_scroll:
            step = random.randint(50, 300)
            await page.mouse.wheel(0, step)
            current_scroll += step
            await asyncio.sleep(random.uniform(0.5, 1.5))

    async def bypass(self):
        """
        Launches a browser, navigates to the target, solves JS challenges,
        and extracts cookies/UA.
        """
        if not PLAYWRIGHT_AVAILABLE:
            logging.error("WAF bypass unavailable: 'playwright' is not installed.")
            return None

        if not self.enabled:
            logging.warning("WAF bypass blocked: set SAMURAI_ENABLE_BROWSER_AUTOMATION=1 to enable browser automation.")
            return None

        logging.info("Ninja mode WAF bypass starting target=%s timeout_s=%.1f", self.target_url, self.timeout_s)

        try:
            async with asyncio.timeout(self.timeout_s):
                async with async_playwright() as p:
                    browser = await p.chromium.launch(
                        headless=self.headless,
                        proxy=self.proxy,
                        args=[
                            "--disable-blink-features=AutomationControlled",
                            "--disable-infobars",
                            "--no-sandbox",
                            "--disable-setuid-sandbox",
                            "--window-position=0,0",
                            "--ignore-certificate-errors",
                        ],
                    )
                    try:
                        context = await browser.new_context(
                            viewport={"width": 1920, "height": 1080},
                            locale="en-US",
                            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                        )
                        await context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

                        page = await context.new_page()
                        await page.goto(self.target_url, timeout=60000, wait_until="networkidle")
                        await self.simulate_human_mouse(page)
                        await self.simulate_human_scroll(page)

                        for _ in range(self.challenge_budget_s):
                            title = await page.title()
                            content = await page.content()
                            if (
                                "Just a moment" not in title
                                and "Attention Required" not in title
                                and "DDOS-GUARD" not in title
                                and "Checking your browser" not in content
                            ):
                                break
                            await asyncio.sleep(1)

                        cookies_list = await context.cookies()
                        self.cookies = {c["name"]: c["value"] for c in cookies_list}
                        self.user_agent = await page.evaluate("navigator.userAgent")
                        if not self.cookies:
                            logging.warning("WAF bypass finished but no cookies were captured.")
                            return None
                        logging.info("WAF bypass succeeded cookies=%d", len(self.cookies))
                        return {"cookies": self.cookies, "user_agent": self.user_agent}
                    finally:
                        await browser.close()
        except TimeoutError:
            logging.error("WAF bypass timed out after %.1fs.", self.timeout_s)
            return None
        except Exception as e:
            logging.error("WAF bypass failed: %s", e)
            return None

if __name__ == "__main__":
    # Test
    async def test():
        waf = WAFBypass("https://nowsecure.nl", headless=False) # Test site
        await waf.bypass()
    
    asyncio.run(test())
