"""
Samurai C Extensions Setup
==========================

Build instructions:
  python setup.py build_ext --inplace
"""

from __future__ import annotations

import ctypes.util
import os
import platform
import shlex
import subprocess
from typing import Dict, List, Tuple

from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext


def _env_flag(name: str, default: str = "0") -> bool:
    raw = str(os.environ.get(name, default) or default).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _pkg_config_exists(package: str) -> bool:
    try:
        proc = subprocess.run(
            ["pkg-config", "--exists", package],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return int(proc.returncode) == 0
    except Exception:
        return False


def _pkg_config_tokens(flag: str, packages: List[str]) -> List[str]:
    cmd = ["pkg-config", flag] + [p for p in packages if p]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if int(proc.returncode) != 0:
            return []
        return [tok for tok in shlex.split(str(proc.stdout or "").strip()) if tok]
    except Exception:
        return []


def _dedupe(seq: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in seq:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


class OptionalBuildExt(build_ext):
    """Custom build_ext that makes XDP extension optional."""

    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception as exc:
            if "xdp_sender" in ext.name:
                print(f"\nWarning: Could not build {ext.name}: {exc}")
                print("XDP functionality will not be available.\n")
            else:
                raise


def detect_l7_capabilities() -> Dict[str, bool]:
    openssl_header_candidates = [
        "/usr/include/openssl/ssl.h",
        "/usr/local/include/openssl/ssl.h",
    ]
    has_openssl_headers = any(os.path.exists(p) for p in openssl_header_candidates)
    has_openssl_libs = (
        ctypes.util.find_library("ssl") is not None and
        ctypes.util.find_library("crypto") is not None
    )
    openssl_enabled = (
        (not _env_flag("SAMURAI_DISABLE_OPENSSL", "0"))
        and has_openssl_headers
        and has_openssl_libs
    )

    nghttp2_enabled = False
    if _env_flag("SAMURAI_FORCE_NGHTTP2", "0"):
        # Explicit override for environments where maintainers ensure flags/libs externally.
        nghttp2_enabled = True
    elif not _env_flag("SAMURAI_DISABLE_NGHTTP2", "0"):
        # CI-safe gate: require pkg-config metadata for deterministic cflags/libs resolution.
        # Runtime-only libnghttp2 (versioned .so) is insufficient for editable build linking.
        nghttp2_enabled = _pkg_config_exists("nghttp2")

    quic_enabled = False
    if _env_flag("SAMURAI_FORCE_QUIC", "0"):
        # Explicit override for maintainers who inject cflags/libs externally.
        quic_enabled = True
    elif not _env_flag("SAMURAI_DISABLE_QUIC", "0"):
        # CI-safe gate: require pkg-config metadata for deterministic ngtcp2/nghttp3 link flags.
        quic_enabled = (
            openssl_enabled
            and _pkg_config_exists("ngtcp2")
            and _pkg_config_exists("nghttp3")
        )

    return {
        "openssl": bool(openssl_enabled),
        "nghttp2": bool(nghttp2_enabled),
        "quic": bool(quic_enabled),
    }


def _resolve_l7_flags() -> Tuple[List[str], List[str], List[Tuple[str, str]]]:
    compile_args = ["-O2", "-Wall", "-fPIC"]
    link_args = ["-lpthread", "-lm"]
    macros: List[Tuple[str, str]] = []

    caps = detect_l7_capabilities()
    pkg_names: List[str] = []

    if caps["openssl"]:
        macros.append(("SAMURAI_WITH_OPENSSL", "1"))
        link_args.extend(["-lssl", "-lcrypto"])
    else:
        print("Warning: OpenSSL dev files not found (or disabled); l7_state_engine TLS/WSS support disabled.")

    if caps["nghttp2"]:
        macros.append(("SAMURAI_WITH_NGHTTP2", "1"))
        pkg_names.append("nghttp2")
    else:
        print(
            "Warning: nghttp2 dev metadata not found (or disabled); "
            "C HTTP/2 mode will report capability_unavailable. "
            "Use SAMURAI_FORCE_NGHTTP2=1 only if linker flags are provided externally."
        )

    if caps["quic"]:
        macros.extend([
            ("SAMURAI_WITH_NGTCP2", "1"),
            ("SAMURAI_WITH_NGHTTP3", "1"),
        ])
        pkg_names.extend(["ngtcp2", "nghttp3"])
        crypto_pkg = None
        for candidate in (
            "ngtcp2_crypto_ossl",
            "ngtcp2_crypto_openssl",
            "ngtcp2_crypto_quictls",
        ):
            if _pkg_config_exists(candidate):
                crypto_pkg = candidate
                break
        if crypto_pkg:
            pkg_names.append(crypto_pkg)
        else:
            # Fallback linker names when pkg-config modules are unavailable.
            link_args.extend(["-lngtcp2", "-lnghttp3"])
    else:
        print(
            "Warning: ngtcp2/nghttp3 dev metadata (or OpenSSL) not found/disabled; "
            "C QUIC mode will report capability_unavailable. "
            "Use SAMURAI_FORCE_QUIC=1 only if linker flags are provided externally."
        )

    if pkg_names:
        compile_args.extend(_pkg_config_tokens("--cflags", pkg_names))
        link_args.extend(_pkg_config_tokens("--libs", pkg_names))

    return _dedupe(compile_args), _dedupe(link_args), macros


def get_extensions() -> List[Extension]:
    extensions: List[Extension] = []

    fast_sender = Extension(
        "ddos_samurai.fast_sender",
        sources=["ddos_samurai/fast_sender.c"],
        extra_compile_args=["-O2", "-Wall", "-fPIC"],
        extra_link_args=["-lpthread", "-lm"],
    )
    extensions.append(fast_sender)

    pacing_engine = Extension(
        "ddos_samurai.pacing_engine",
        sources=["ddos_samurai/pacing_engine.c"],
        extra_compile_args=["-O2", "-Wall", "-fPIC"],
        extra_link_args=["-lpthread", "-lm"],
    )
    extensions.append(pacing_engine)

    dataplane_core = Extension(
        "ddos_samurai.dataplane_core",
        sources=["ddos_samurai/dataplane_core.c"],
        extra_compile_args=["-O2", "-Wall", "-fPIC"],
        extra_link_args=["-lpthread", "-lm"],
    )
    extensions.append(dataplane_core)

    l7_compile_args, l7_link_args, l7_macros = _resolve_l7_flags()
    l7_state_engine = Extension(
        "ddos_samurai.l7_state_engine",
        sources=["ddos_samurai/l7_state_engine.c"],
        extra_compile_args=l7_compile_args,
        extra_link_args=l7_link_args,
        define_macros=l7_macros,
    )
    extensions.append(l7_state_engine)

    if platform.system() == "Linux":
        xdp_compile_args = ["-O2", "-Wall", "-Wextra"]
        xdp_link_args = ["-lpthread"]
        if os.path.exists("/usr/include/bpf/libbpf.h"):
            xdp_link_args.append("-lbpf")
            xdp_compile_args.append("-DHAVE_LIBBPF")
        xdp_sender = Extension(
            "ddos_samurai.xdp_sender",
            sources=["ddos_samurai/xdp_sender.c"],
            extra_compile_args=xdp_compile_args,
            extra_link_args=xdp_link_args,
        )
        extensions.append(xdp_sender)
    else:
        print(f"Warning: XDP sender not available on {platform.system()} (Linux only)")

    return extensions


def build_setup_kwargs() -> Dict[str, object]:
    return {
        "name": "ddos_samurai",
        "version": "2.0.0",
        "description": "High-Performance Network Testing Tool with GPU Acceleration and AF_XDP Support",
        "author": "DDoSamurai Team",
        "packages": find_packages(include=["ddos_samurai", "ddos_samurai.*"]),
        "ext_modules": get_extensions(),
        "cmdclass": {"build_ext": OptionalBuildExt},
        "python_requires": ">=3.8",
        "install_requires": [
            "scapy>=2.4.0",
            "numpy>=1.19.0",
            "fastapi>=0.110.0",
            "uvicorn>=0.29.0",
            "sqlalchemy>=2.0.0",
            "psycopg[binary]>=3.1.0",
            "python-jose[cryptography]>=3.3.0",
            "passlib[bcrypt]>=1.7.4",
            "python-multipart>=0.0.9",
            "prometheus-client>=0.20.0",
            "email-validator>=2.1.0",
        ],
        "extras_require": {
            "gpu": ["cupy>=9.0.0"],
            "http2": ["httpx[http2]>=0.20.0"],
            "all": ["cupy>=9.0.0", "httpx[http2]>=0.20.0", "h2>=4.0.0"],
        },
        "classifiers": [
            "Development Status :: 4 - Beta",
            "Environment :: Console",
            "Intended Audience :: Developers",
            "Intended Audience :: System Administrators",
            "License :: OSI Approved :: MIT License",
            "Operating System :: POSIX :: Linux",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.8",
            "Programming Language :: Python :: 3.9",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12",
            "Programming Language :: C",
            "Topic :: System :: Networking",
        ],
    }


def main() -> None:
    setup(**build_setup_kwargs())


if __name__ == "__main__":
    main()
