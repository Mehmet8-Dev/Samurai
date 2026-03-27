#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shlex
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence


DEFAULT_SITES = [
    "https://www.cloudflare.com",
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.wikipedia.org",
    "https://www.bbc.com",
    "https://www.mozilla.org",
    "https://www.github.com",
    "https://www.python.org",
    "https://www.stackoverflow.com",
    "https://www.reddit.com",
    "https://www.nytimes.com",
    "https://www.cnn.com",
    "https://www.amazon.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.instagram.com",
    "https://www.linkedin.com",
    "https://www.booking.com",
    "https://www.netflix.com",
    "https://www.spotify.com",
]

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
]


@dataclass
class FetchResult:
    url: str
    proto: str
    ok: bool
    status: int
    elapsed_ms: int
    err: str


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generate mixed HTTP1/HTTP2/HTTP3 web traffic and capture PCAP files."
    )
    p.add_argument("--out-dir", type=str, default="data/raw/benign", help="PCAP output directory")
    p.add_argument("--prefix", type=str, default="webmix", help="Output file prefix")
    p.add_argument("--interface", type=str, default="", help="Capture interface (default: auto detect)")
    p.add_argument(
        "--capture-backend",
        choices=["auto", "tshark", "tcpdump"],
        default="auto",
        help="Packet capture backend",
    )
    p.add_argument(
        "--capture-filter",
        type=str,
        default="tcp port 80 or tcp port 443 or udp port 443",
        help="BPF filter",
    )
    p.add_argument("--duration-sec", type=int, default=300, help="Capture duration")
    p.add_argument(
        "--rotate-sec", type=int, default=120, help="Rotate capture file every N seconds"
    )
    p.add_argument("--ring-files", type=int, default=12, help="Ring buffer file count")
    p.add_argument(
        "--sites-file",
        type=str,
        default="",
        help="Optional text file with one URL per line",
    )
    p.add_argument("--max-sites", type=int, default=20, help="Max sites loaded from list")
    p.add_argument(
        "--protocols",
        type=str,
        default="h1,h2,h3",
        help="Comma-separated protocols: h1,h2,h3",
    )
    p.add_argument(
        "--parallelism", type=int, default=12, help="Concurrent requests per round"
    )
    p.add_argument(
        "--round-delay-ms", type=int, default=300, help="Delay between rounds in milliseconds"
    )
    p.add_argument(
        "--curl-timeout-sec", type=int, default=20, help="Per-request timeout seconds"
    )
    p.add_argument(
        "--traffic-client",
        choices=["curl"],
        default="curl",
        help="Traffic generator backend",
    )
    p.add_argument(
        "--h3-via-browser",
        choices=["none", "chrome", "firefox"],
        default="chrome",
        help="When curl lacks HTTP/3 support, try this browser for H3 generation.",
    )
    p.add_argument(
        "--ssl-keylog-file",
        type=str,
        default="",
        help="Path to SSL key log file (exported as SSLKEYLOGFILE)",
    )
    return p


def _which(name: str) -> str:
    path = subprocess.run(
        ["which", name], capture_output=True, text=True, check=False
    ).stdout.strip()
    return path


def _curl_supports_http3() -> bool:
    out = subprocess.run(
        ["curl", "-V"], capture_output=True, text=True, check=False
    ).stdout
    # libcurl reports protocol capabilities in version output.
    # Example: "Features: ... HTTP3 ..."
    return "HTTP3" in out


def _auto_interface() -> str:
    out = subprocess.run(
        ["ip", "route", "get", "1.1.1.1"], capture_output=True, text=True, check=False
    ).stdout.strip()
    m = re.search(r"\bdev\s+(\S+)", out)
    if m:
        return m.group(1)
    return "any"


def _load_sites(path: str, max_sites: int) -> List[str]:
    sites: List[str] = []
    if path:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        for line in lines:
            v = line.strip()
            if not v or v.startswith("#"):
                continue
            if not v.startswith("http://") and not v.startswith("https://"):
                v = "https://" + v
            sites.append(v)
    else:
        sites = list(DEFAULT_SITES)
    sites = list(dict.fromkeys(sites))
    if max_sites > 0:
        sites = sites[:max_sites]
    return sites


def _capture_command(
    backend: str,
    interface: str,
    out_dir: Path,
    prefix: str,
    rotate_sec: int,
    ring_files: int,
    capture_filter: str,
    duration_sec: int,
) -> List[str]:
    if backend == "tshark":
        out_file = str(out_dir / f"{prefix}.pcap")
        return [
            "tshark",
            "-i",
            interface,
            "-f",
            capture_filter,
            "-a",
            f"duration:{duration_sec + 5}",
            "-b",
            f"duration:{max(5, rotate_sec)}",
            "-b",
            f"files:{max(1, ring_files)}",
            "-F",
            "pcap",
            "-w",
            out_file,
        ]
    out_file = str(out_dir / f"{prefix}_%Y%m%d_%H%M%S.pcap")
    return [
        "tcpdump",
        "-i",
        interface,
        "-n",
        "-s",
        "0",
        "-B",
        "4096",
        "-G",
        str(max(5, rotate_sec)),
        "-W",
        str(max(1, ring_files)),
        "-w",
        out_file,
        capture_filter,
    ]


def _pick_backend(requested: str) -> str:
    if requested in {"tshark", "tcpdump"}:
        return requested
    euid = os.geteuid()
    if _which("tshark"):
        return "tshark"
    if _which("tcpdump") and euid == 0:
        return "tcpdump"
    raise RuntimeError("No usable capture backend found (need tshark or root tcpdump).")


def _curl_cmd(url: str, proto: str, timeout_sec: int, ua: str) -> List[str]:
    proto_flag = {
        "h1": "--http1.1",
        "h2": "--http2",
        "h3": "--http3-only",
    }[proto]
    return [
        "curl",
        proto_flag,
        "-L",
        "-sS",
        "--compressed",
        "--connect-timeout",
        "8",
        "--max-time",
        str(timeout_sec),
        "-A",
        ua,
        "-o",
        "/dev/null",
        url,
    ]


def _run_fetch(url: str, proto: str, timeout_sec: int, env: Dict[str, str]) -> FetchResult:
    ua = random.choice(USER_AGENTS)
    cmd = _curl_cmd(url=url, proto=proto, timeout_sec=timeout_sec, ua=ua)
    t0 = time.time()
    cp = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
    elapsed_ms = int((time.time() - t0) * 1000)
    err = (cp.stderr or "").strip().splitlines()
    err_s = err[-1] if err else ""
    return FetchResult(
        url=url,
        proto=proto,
        ok=(cp.returncode == 0),
        status=cp.returncode,
        elapsed_ms=elapsed_ms,
        err=err_s,
    )


def _run_h3_browser_fetch(
    url: str,
    browser: str,
    timeout_sec: int,
    env: Dict[str, str],
) -> FetchResult:
    t0 = time.time()
    if browser == "chrome":
        chrome = _which("google-chrome") or _which("chromium") or _which("chromium-browser")
        if not chrome:
            return FetchResult(url=url, proto="h3", ok=False, status=127, elapsed_ms=0, err="chrome not found")
        cmd = [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--enable-quic",
            "--dump-dom",
            url,
        ]
    elif browser == "firefox":
        firefox = _which("firefox")
        if not firefox:
            return FetchResult(url=url, proto="h3", ok=False, status=127, elapsed_ms=0, err="firefox not found")
        cmd = [
            firefox,
            "--headless",
            "--screenshot",
            "/tmp/h3-firefox-shot.png",
            url,
        ]
    else:
        return FetchResult(url=url, proto="h3", ok=False, status=2, elapsed_ms=0, err="h3 browser fallback disabled")

    try:
        cp = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        elapsed_ms = int((time.time() - t0) * 1000)
        return FetchResult(
            url=url,
            proto="h3",
            ok=False,
            status=124,
            elapsed_ms=elapsed_ms,
            err=f"{browser} timeout ({timeout_sec}s)",
        )
    except Exception as exc:
        elapsed_ms = int((time.time() - t0) * 1000)
        return FetchResult(
            url=url,
            proto="h3",
            ok=False,
            status=125,
            elapsed_ms=elapsed_ms,
            err=f"{browser} error: {exc}",
        )
    elapsed_ms = int((time.time() - t0) * 1000)
    err = (cp.stderr or "").strip().splitlines()
    err_s = err[-1] if err else ""
    return FetchResult(
        url=url,
        proto="h3",
        ok=(cp.returncode == 0),
        status=cp.returncode,
        elapsed_ms=elapsed_ms,
        err=err_s,
    )


def _terminate_process(p: subprocess.Popen[bytes], grace_sec: int = 5) -> None:
    if p.poll() is not None:
        return
    try:
        p.send_signal(signal.SIGINT)
        p.wait(timeout=grace_sec)
    except Exception:
        try:
            p.terminate()
            p.wait(timeout=grace_sec)
        except Exception:
            p.kill()


def main() -> int:
    args = build_parser().parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    interface = args.interface.strip() or _auto_interface()
    backend = _pick_backend(args.capture_backend)
    keylog = args.ssl_keylog_file.strip() or str(out_dir / f"{args.prefix}.sslkeys.log")
    Path(keylog).parent.mkdir(parents=True, exist_ok=True)

    protocols = [x.strip() for x in args.protocols.split(",") if x.strip()]
    for proto in protocols:
        if proto not in {"h1", "h2", "h3"}:
            raise SystemExit(f"Unsupported proto: {proto}")

    sites = _load_sites(args.sites_file, args.max_sites)
    if not sites:
        raise SystemExit("No sites loaded.")

    cap_cmd = _capture_command(
        backend=backend,
        interface=interface,
        out_dir=out_dir,
        prefix=args.prefix,
        rotate_sec=args.rotate_sec,
        ring_files=args.ring_files,
        capture_filter=args.capture_filter,
        duration_sec=args.duration_sec,
    )
    print(f"[capture] backend={backend} iface={interface} out_dir={out_dir}")
    print(f"[capture] cmd={shlex.join(cap_cmd)}")
    cap_proc = subprocess.Popen(cap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.0)
    if cap_proc.poll() is not None:
        stderr = (cap_proc.stderr.read() if cap_proc.stderr else b"").decode("utf-8", errors="replace")
        raise SystemExit(f"Capture process failed to start:\n{stderr}")

    env = os.environ.copy()
    env["SSLKEYLOGFILE"] = keylog
    curl_h3_supported = _curl_supports_http3()
    h3_browser = str(args.h3_via_browser)

    stats = {
        "ok": 0,
        "fail": 0,
        "h1_ok": 0,
        "h2_ok": 0,
        "h3_ok": 0,
        "h1_fail": 0,
        "h2_fail": 0,
        "h3_fail": 0,
    }
    samples: List[dict] = []

    start = time.time()
    end_ts = start + max(5, int(args.duration_sec))
    round_idx = 0
    try:
        while time.time() < end_ts:
            round_idx += 1
            random.shuffle(sites)
            tasks = []
            for url in sites:
                for proto in protocols:
                    tasks.append((url, proto))
            random.shuffle(tasks)

            with ThreadPoolExecutor(max_workers=max(1, int(args.parallelism))) as ex:
                futures = [
                    ex.submit(
                        _run_fetch,
                        url=url,
                        proto=proto,
                        timeout_sec=int(args.curl_timeout_sec),
                        env=env,
                    )
                    for (url, proto) in tasks
                ]
                for fut in as_completed(futures):
                    try:
                        r = fut.result()
                    except Exception as exc:
                        # Never crash the long-running capture loop because one request worker failed.
                        r = FetchResult(
                            url="<internal>",
                            proto="h3",
                            ok=False,
                            status=126,
                            elapsed_ms=0,
                            err=f"worker exception: {exc}",
                        )
                    if (
                        r.proto == "h3"
                        and (not r.ok)
                        and (not curl_h3_supported)
                        and h3_browser != "none"
                        and r.status == 2
                    ):
                        r = _run_h3_browser_fetch(
                            url=r.url,
                            browser=h3_browser,
                            timeout_sec=int(args.curl_timeout_sec),
                            env=env,
                        )
                    key_ok = f"{r.proto}_ok"
                    key_fail = f"{r.proto}_fail"
                    if r.ok:
                        stats["ok"] += 1
                        stats[key_ok] += 1
                    else:
                        stats["fail"] += 1
                        stats[key_fail] += 1
                    if len(samples) < 30:
                        samples.append(
                            {
                                "url": r.url,
                                "proto": r.proto,
                                "ok": r.ok,
                                "status": r.status,
                                "elapsed_ms": r.elapsed_ms,
                                "err": r.err,
                            }
                        )

            left = int(end_ts - time.time())
            print(
                f"[traffic] round={round_idx} left={max(0, left)}s ok={stats['ok']} fail={stats['fail']} "
                f"h1={stats['h1_ok']}/{stats['h1_fail']} "
                f"h2={stats['h2_ok']}/{stats['h2_fail']} "
                f"h3={stats['h3_ok']}/{stats['h3_fail']}"
            )
            if time.time() < end_ts:
                time.sleep(max(0.0, float(args.round_delay_ms) / 1000.0))
    finally:
        _terminate_process(cap_proc)

    pcaps = sorted(str(p) for p in out_dir.glob(f"{args.prefix}*.pcap*"))
    summary = {
        "status": "ok",
        "started_at": int(start),
        "ended_at": int(time.time()),
        "duration_sec": int(time.time() - start),
        "interface": interface,
        "backend": backend,
        "sites_count": len(sites),
        "sites_file": args.sites_file,
        "protocols": protocols,
        "curl_http3_supported": curl_h3_supported,
        "h3_fallback_browser": h3_browser,
        "stats": stats,
        "ssl_keylog_file": keylog,
        "pcap_files": pcaps,
        "sample_results": samples,
    }
    summary_path = out_dir / f"{args.prefix}.summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"[capture] summary={summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
