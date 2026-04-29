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
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext


def _read_package_version() -> str:
    init_file = Path(__file__).resolve().parent / "ddos_samurai" / "__init__.py"
    content = init_file.read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', content, flags=re.MULTILINE)
    if not match:
        raise RuntimeError("Could not parse __version__ from ddos_samurai/__init__.py")
    return str(match.group(1)).strip()


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


def _pkg_config_first(candidates: List[str]) -> str:
    for name in [str(x or "").strip() for x in candidates]:
        if name and _pkg_config_exists(name):
            return name
    return ""


def _has_header(paths: List[str]) -> bool:
    return any(os.path.exists(str(p)) for p in paths)


def _has_lib(names: List[str]) -> bool:
    for name in names:
        if ctypes.util.find_library(str(name)) is not None:
            return True
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


def _normalize_quic_crypto_backend(raw: str | None) -> str:
    val = str(raw or "auto").strip().lower()
    aliases = {
        "ossl": "openssl",
        "open_ssl": "openssl",
        "tls": "openssl",
        "qtls": "quictls",
        "none": "none",
        "off": "none",
        "disabled": "none",
    }
    val = aliases.get(val, val)
    if val in {"auto", "gnutls", "openssl", "quictls", "none"}:
        return val
    return "auto"


def _normalize_quic_build_mode(raw: str | None) -> str:
    val = str(raw or "auto").strip().lower()
    aliases = {
        "strict": "native_required",
        "required": "native_required",
        "native": "native_required",
        "bridge": "bridge_only",
        "bridge_only": "bridge_only",
        "bridge-only": "bridge_only",
        "off": "disabled",
        "none": "disabled",
    }
    mode = aliases.get(val, val)
    if mode in {"auto", "native_required", "bridge_only", "disabled"}:
        return mode
    return "auto"


def _resolve_quic_crypto_backend() -> Tuple[str, str, str]:
    """
    Resolve QUIC crypto backend with deterministic preference and optional override.

    Returns:
        backend: resolved backend name (gnutls|openssl|quictls|none)
        pkg_name: matching pkg-config module when available, else ""
        link_name: fallback -l<name> library name when pkg-config module is missing, else ""
    """
    requested = _normalize_quic_crypto_backend(os.environ.get("SAMURAI_QUIC_CRYPTO_BACKEND", "auto"))
    candidates_by_backend = {
        "gnutls": [
            ("ngtcp2_crypto_gnutls", "ngtcp2_crypto_gnutls"),
            ("libngtcp2_crypto_gnutls", "ngtcp2_crypto_gnutls"),
        ],
        "openssl": [
            ("ngtcp2_crypto_ossl", "ngtcp2_crypto_ossl"),
            ("ngtcp2_crypto_openssl", "ngtcp2_crypto_openssl"),
            ("libngtcp2_crypto_ossl", "ngtcp2_crypto_ossl"),
            ("libngtcp2_crypto_openssl", "ngtcp2_crypto_openssl"),
        ],
        "quictls": [
            ("ngtcp2_crypto_quictls", "ngtcp2_crypto_quictls"),
            ("libngtcp2_crypto_quictls", "ngtcp2_crypto_quictls"),
        ],
    }
    ordered_backends = (
        ["gnutls", "openssl", "quictls"]
        if requested == "auto"
        else ([requested] if requested in candidates_by_backend else [])
    )
    if requested == "none":
        return "none", "", ""

    for backend in ordered_backends:
        for pkg_name, link_name in candidates_by_backend.get(backend, []):
            if _pkg_config_exists(pkg_name):
                return backend, pkg_name, ""
        for _, link_name in candidates_by_backend.get(backend, []):
            if ctypes.util.find_library(link_name) is not None:
                return backend, "", link_name
    return "none", "", ""


def _dedupe(seq: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in seq:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _assert_no_embedded_virtualenv() -> None:
    embedded = Path(__file__).resolve().parent / "ddos_samurai" / "venv" / "pyvenv.cfg"
    if embedded.exists() and not _env_flag("SAMURAI_ALLOW_EMBEDDED_VENV", "0"):
        raise RuntimeError(
            "Refusing to build/package with embedded virtualenv at ddos_samurai/venv. "
            "Remove it or set SAMURAI_ALLOW_EMBEDDED_VENV=1 for a local-only override."
        )


def _resolve_nvcc_path() -> str:
    nvcc = str(os.environ.get("SAMURAI_NVCC", "") or "").strip()
    if nvcc:
        return nvcc if os.path.exists(nvcc) else ""
    auto = shutil.which("nvcc") or "/usr/local/cuda/bin/nvcc"
    return auto if os.path.exists(auto) else ""


def _resolve_cuda_home(nvcc_path: str) -> str:
    cuda_home = str(os.environ.get("CUDA_HOME", "") or "").strip()
    if cuda_home:
        return cuda_home
    if nvcc_path:
        return os.path.dirname(os.path.dirname(nvcc_path))
    return ""


def _resolve_cuda_runtime_lib_dir(cuda_home: str) -> str:
    for candidate in [
        os.path.join(cuda_home, "lib64"),
        os.path.join(cuda_home, "targets", "x86_64-linux", "lib"),
    ]:
        if candidate and os.path.exists(candidate):
            return candidate
    return ""


class OptionalBuildExt(build_ext):
    """Custom build_ext that makes XDP extension optional."""

    def run(self):
        super().run()
        self._build_cuda_module()

    def build_extensions(self):
        nvcc = _resolve_nvcc_path()
        if nvcc and hasattr(self.compiler, "src_extensions") and hasattr(self.compiler, "_compile"):
            if ".cu" not in self.compiler.src_extensions:
                self.compiler.src_extensions.append(".cu")

            default_compiler_so = self.compiler.compiler_so
            default_compile = self.compiler._compile

            def _compile(obj, src, ext, cc_args, extra_postargs, pp_opts):
                if os.path.splitext(src)[1] == ".cu":
                    cuda_postargs = []
                    if isinstance(extra_postargs, dict):
                        cuda_postargs = list(extra_postargs.get("nvcc", []))
                    elif isinstance(extra_postargs, list):
                        cuda_postargs = list(extra_postargs)
                    self.compiler.set_executable("compiler_so", nvcc)
                    try:
                        return default_compile(obj, src, ext, cc_args, cuda_postargs, pp_opts)
                    finally:
                        self.compiler.compiler_so = default_compiler_so
                cxx_postargs = extra_postargs
                if isinstance(extra_postargs, dict):
                    cxx_postargs = list(extra_postargs.get("cxx", []))
                return default_compile(obj, src, ext, cc_args, cxx_postargs, pp_opts)

            self.compiler._compile = _compile
        super().build_extensions()

    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception as exc:
            if "xdp_sender" in ext.name:
                strict_raw = os.environ.get("SAMURAI_REQUIRE_XDP_BUILD")
                if strict_raw is not None:
                    strict_xdp = str(strict_raw).strip().lower() in {"1", "true", "yes", "on"}
                else:
                    env_name = str(os.environ.get("SAMURAI_ENV", "") or "").strip().lower()
                    ci_mode = str(os.environ.get("CI", "") or "").strip().lower() in {"1", "true", "yes", "on"}
                    strict_xdp = ci_mode or env_name in {"prod", "production"}
                if strict_xdp:
                    raise
                print(f"\nWarning: Could not build {ext.name}: {exc}")
                print("XDP functionality will not be available.\n")
            else:
                raise

    def _build_cuda_module(self) -> None:
        if _env_flag("SAMURAI_SKIP_CUDA_BUILD", "0"):
            print("\nInfo: SAMURAI_SKIP_CUDA_BUILD=1; skipping gpu_packet_cuda.cu build.\n")
            return

        project_root = os.path.abspath(os.path.dirname(__file__))
        src_path = os.path.join(project_root, "ddos_samurai", "gpu_packet_cuda.cu")
        if not os.path.exists(src_path):
            return

        nvcc = _resolve_nvcc_path()
        if not os.path.exists(nvcc):
            print("\nWarning: nvcc not found; skipping gpu_packet_cuda.cu build.\n")
            return

        cuda_home = _resolve_cuda_home(nvcc)
        cuda_include = os.path.join(cuda_home, "include")

        build_temp = os.path.abspath(self.build_temp or os.path.join(project_root, "build", "temp"))
        os.makedirs(build_temp, exist_ok=True)

        if bool(getattr(self, "inplace", False)):
            out_dir = os.path.join(project_root, "ddos_samurai")
        else:
            out_dir = os.path.join(os.path.abspath(self.build_lib), "ddos_samurai")
        os.makedirs(out_dir, exist_ok=True)

        obj_path = os.path.join(build_temp, "gpu_packet_cuda.o")
        lib_path = os.path.join(out_dir, "libgpu_packet_cuda.so")

        compile_cmd = [
            nvcc,
            "-std=c++20",
            "-O3",
            "-Xcompiler",
            "-fPIC",
            "-diag-suppress=177",
            "-I",
            project_root,
            "-I",
            cuda_include,
            "-c",
            src_path,
            "-o",
            obj_path,
        ]
        bridge_obj_paths = [
            os.path.join(build_temp, "ddos_samurai", "xdp_sender.o"),
            os.path.join(build_temp, "ddos_samurai", "fast_sender.o"),
            os.path.join(build_temp, "ddos_samurai", "pacing_engine.o"),
        ]
        bridge_objs = [p for p in bridge_obj_paths if os.path.exists(p)]
        link_cmd = [
            nvcc,
            "-shared",
            obj_path,
            *bridge_objs,
            "-o",
            lib_path,
        ]

        try:
            print(f"\nBuilding CUDA module: {src_path}")
            subprocess.run(compile_cmd, check=True)
            subprocess.run(link_cmd, check=True)
            print(f"Built CUDA library: {lib_path}\n")
        except subprocess.CalledProcessError as exc:
            print(f"\nWarning: CUDA module build failed: {exc}\n")

        self._build_cuda_defense_module(project_root, nvcc, cuda_include, build_temp, out_dir)

    def _build_cuda_defense_module(
        self,
        project_root: str,
        nvcc: str,
        cuda_include: str,
        build_temp: str,
        out_dir: str,
    ) -> None:
        src_path = os.path.join(project_root, "ddos_samurai", "gpu_packet_cuda", "gpu_packet_cuda_defense.cu")
        if not os.path.exists(src_path):
            return

        with_trt = _env_flag("SAMURAI_WITH_TENSORRT", "0")
        with_gpudirect = _env_flag("SAMURAI_WITH_GPUDIRECT_RDMA", "0")
        compile_cmd = [
            nvcc,
            "-std=c++20",
            "-O3",
            "-Xcompiler",
            "-fPIC",
            "-I",
            project_root,
            "-I",
            cuda_include,
        ]
        if with_trt:
            compile_cmd.extend(["-DSAMURAI_WITH_TENSORRT=1"])
        if with_gpudirect:
            compile_cmd.extend(["-DSAMURAI_WITH_GPUDIRECT_RDMA=1"])
        compile_cmd.extend(["-c", src_path, "-o", os.path.join(build_temp, "gpu_packet_cuda_defense.o")])

        link_cmd = [
            nvcc,
            "-shared",
            os.path.join(build_temp, "gpu_packet_cuda_defense.o"),
            "-o",
            os.path.join(out_dir, "libgpu_packet_cuda_defense.so"),
        ]
        if with_gpudirect:
            link_cmd.extend(["-libverbs", "-lmlx5"])
        try:
            print(f"\nBuilding CUDA defense module: {src_path}")
            subprocess.run(compile_cmd, check=True)
            subprocess.run(link_cmd, check=True)
            print("Built CUDA defense library: libgpu_packet_cuda_defense.so\n")
        except subprocess.CalledProcessError as exc:
            print(f"\nWarning: CUDA defense module build failed: {exc}\n")


def detect_l7_capabilities() -> Dict[str, bool]:
    quic_build_mode = _normalize_quic_build_mode(os.environ.get("SAMURAI_QUIC_BUILD_MODE", "auto"))
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

    nghttp2_pkg = _pkg_config_first(["nghttp2", "libnghttp2"])
    ngtcp2_pkg = _pkg_config_first(["ngtcp2", "libngtcp2"])
    nghttp3_pkg = _pkg_config_first(["nghttp3", "libnghttp3"])
    gnutls_pkg = _pkg_config_first(["gnutls", "libgnutls"])
    nghttp2_headers = _has_header(
        ["/usr/include/nghttp2/nghttp2.h", "/usr/local/include/nghttp2/nghttp2.h"]
    )
    ngtcp2_headers = _has_header(
        ["/usr/include/ngtcp2/ngtcp2.h", "/usr/local/include/ngtcp2/ngtcp2.h"]
    )
    nghttp3_headers = _has_header(
        ["/usr/include/nghttp3/nghttp3.h", "/usr/local/include/nghttp3/nghttp3.h"]
    )
    nghttp2_lib = _has_lib(["nghttp2"])
    ngtcp2_lib = _has_lib(["ngtcp2"])
    nghttp3_lib = _has_lib(["nghttp3"])
    gnutls_headers = _has_header(
        ["/usr/include/gnutls/gnutls.h", "/usr/local/include/gnutls/gnutls.h"]
    )
    gnutls_lib = _has_lib(["gnutls"])

    nghttp2_enabled = False
    if _env_flag("SAMURAI_FORCE_NGHTTP2", "0"):
        # Explicit override for environments where maintainers ensure flags/libs externally.
        nghttp2_enabled = True
    elif not _env_flag("SAMURAI_DISABLE_NGHTTP2", "0"):
        # Prefer pkg-config metadata, but allow header+library fallback for distro setups
        # where .pc files are unavailable yet development headers/libs are installed.
        nghttp2_enabled = bool(nghttp2_pkg) or bool(nghttp2_headers and nghttp2_lib)

    quic_enabled = False
    if quic_build_mode in {"disabled", "bridge_only"}:
        quic_enabled = False
    elif _env_flag("SAMURAI_FORCE_QUIC", "0"):
        # Explicit override for maintainers who inject cflags/libs externally.
        quic_enabled = True
    elif not _env_flag("SAMURAI_DISABLE_QUIC", "0"):
        # Prefer pkg-config metadata, but allow header+library fallback for systems where
        # ngtcp2/nghttp3 are installed without pkg-config modules.
        quic_enabled = bool(
            (ngtcp2_pkg and nghttp3_pkg)
            or (ngtcp2_headers and nghttp3_headers and ngtcp2_lib and nghttp3_lib)
        )

    return {
        "openssl": bool(openssl_enabled),
        "nghttp2": bool(nghttp2_enabled),
        "quic": bool(quic_enabled),
        "gnutls": bool(gnutls_pkg or (gnutls_headers and gnutls_lib)),
    }


def _resolve_l7_flags() -> Tuple[List[str], List[str], List[Tuple[str, str]]]:
    compile_args = ["-O2", "-Wall", "-fPIC"]
    link_args = ["-lpthread", "-lm"]
    macros: List[Tuple[str, str]] = []
    quic_build_mode = _normalize_quic_build_mode(os.environ.get("SAMURAI_QUIC_BUILD_MODE", "auto"))

    caps = detect_l7_capabilities()
    pkg_names: List[str] = []
    nghttp2_pkg = _pkg_config_first(["nghttp2", "libnghttp2"])
    ngtcp2_pkg = _pkg_config_first(["ngtcp2", "libngtcp2"])
    nghttp3_pkg = _pkg_config_first(["nghttp3", "libnghttp3"])

    if caps["openssl"]:
        macros.append(("SAMURAI_WITH_OPENSSL", "1"))
        link_args.extend(["-lssl", "-lcrypto"])
    else:
        print("Warning: OpenSSL dev files not found (or disabled); l7_state_engine TLS/WSS support disabled.")

    if caps["nghttp2"]:
        macros.append(("SAMURAI_WITH_NGHTTP2", "1"))
        if nghttp2_pkg:
            pkg_names.append(nghttp2_pkg)
        else:
            link_args.append("-lnghttp2")
    else:
        print(
            "Warning: nghttp2 dev metadata not found (or disabled); "
            "C HTTP/2 mode will report capability_unavailable. "
            "Use SAMURAI_FORCE_NGHTTP2=1 only if linker flags are provided externally."
        )

    if quic_build_mode == "disabled":
        print("Info: SAMURAI_QUIC_BUILD_MODE=disabled -> native C QUIC build kapalı.")
    elif quic_build_mode == "bridge_only":
        print("Info: SAMURAI_QUIC_BUILD_MODE=bridge_only -> native C QUIC build kapalı (bridge-only).")
    elif caps["quic"]:
        quic_crypto_is_gnutls = False
        quic_crypto_linked = False
        macros.extend([
            ("SAMURAI_WITH_NGTCP2", "1"),
            ("SAMURAI_WITH_NGHTTP3", "1"),
        ])
        if ngtcp2_pkg:
            pkg_names.append(ngtcp2_pkg)
        if nghttp3_pkg:
            pkg_names.append(nghttp3_pkg)
        crypto_backend, crypto_pkg, crypto_link_name = _resolve_quic_crypto_backend()
        if crypto_pkg:
            pkg_names.append(crypto_pkg)
            quic_crypto_linked = True
        elif crypto_link_name:
            link_args.append(f"-l{crypto_link_name}")
            # Fallback linker names when pkg-config modules are unavailable.
            link_args.extend(["-lngtcp2", "-lnghttp3"])
            quic_crypto_linked = True
        if quic_crypto_linked and crypto_backend == "gnutls":
            quic_crypto_is_gnutls = True
            macros.append(("SAMURAI_WITH_NGTCP2_CRYPTO", "1"))
            macros.append(("SAMURAI_WITH_GNUTLS", "1"))
            macros.append(("SAMURAI_WITH_NGTCP2_GNUTLS", "1"))
            if not crypto_pkg:
                link_args.append("-lgnutls")
            if quic_build_mode == "native_required":
                print("Info: native_required mode: ngtcp2/nghttp3 + gnutls doğrulandı.")
        elif quic_crypto_linked:
            if quic_build_mode == "native_required":
                raise RuntimeError(
                    "SAMURAI_QUIC_BUILD_MODE=native_required: ngtcp2 crypto backend gnutls olmalı "
                    f"(resolved={crypto_backend})."
                )
            print(
                "Warning: ngtcp2 crypto backend resolved but non-gnutls "
                f"({crypto_backend}); native C QUIC loop requires gnutls and will stay disabled."
            )
        else:
            if quic_build_mode == "native_required":
                requested_backend = _normalize_quic_crypto_backend(os.environ.get("SAMURAI_QUIC_CRYPTO_BACKEND", "auto"))
                raise RuntimeError(
                    "SAMURAI_QUIC_BUILD_MODE=native_required: ngtcp2 crypto backend bulunamadı "
                    f"(requested={requested_backend})."
                )
            requested_backend = _normalize_quic_crypto_backend(os.environ.get("SAMURAI_QUIC_CRYPTO_BACKEND", "auto"))
            print(
                "Warning: ngtcp2 crypto backend not found "
                f"(requested={requested_backend}); native C QUIC loop disabled "
                "(py bridge/fallback paths remain available)."
            )
    else:
        if quic_build_mode == "native_required":
            raise RuntimeError(
                "SAMURAI_QUIC_BUILD_MODE=native_required: ngtcp2/nghttp3 bağımlılıkları eksik veya devre dışı."
            )
        print(
            "Warning: ngtcp2/nghttp3 dev metadata not found/disabled; "
            "C QUIC mode will report capability_unavailable. "
            "Use SAMURAI_FORCE_QUIC=1 only if linker flags are provided externally."
        )

    if pkg_names:
        compile_args.extend(_pkg_config_tokens("--cflags", pkg_names))
        link_args.extend(_pkg_config_tokens("--libs", pkg_names))

    return _dedupe(compile_args), _dedupe(link_args), macros


def get_extensions() -> List[Extension]:
    extensions: List[Extension] = []
    l4se_std_flag = "-std=c++23" if _env_flag("SAMURAI_L4SE_CXX23", "0") else "-std=c++20"
    project_root = os.path.abspath(os.path.dirname(__file__))
    pybind11_include = os.path.join(project_root, "third_party", "pybind11", "include")

    l4_state_engine = Extension(
        "ddos_samurai.l4.state_engine",
        sources=[
            "ddos_samurai/l4/state_engine_module.cpp",
            "ddos_samurai/l4/l4_state_engine_ffi.cpp",
            "ddos_samurai/l4/l4_state_engine_core.cpp",
            "ddos_samurai/l4/tcp_dataplane_ffi.cpp",
            "ddos_samurai/l4/tcp_dataplane_core.cpp",
        ],
        language="c++",
        extra_compile_args=["-O2", "-Wall", "-fPIC", l4se_std_flag],
        extra_link_args=["-lpthread", "-lm"],
    )
    extensions.append(l4_state_engine)

    cpu_packet_engine_native = Extension(
        "ddos_samurai._cpu_packet_engine_native",
        sources=[
            "ddos_samurai/cpu_native/module.cpp",
            "ddos_samurai/cpu_native/common.cpp",
            "ddos_samurai/cpu_native/spoofing.cpp",
            "ddos_samurai/cpu_native/packets.cpp",
            "ddos_samurai/cpu_native/pool.cpp",
            "ddos_samurai/cpu_native/amp.cpp",
        ],
        include_dirs=[pybind11_include],
        language="c++",
        extra_compile_args=["-O2", "-Wall", "-Wextra", "-fPIC", "-std=c++20"],
        extra_link_args=["-lpthread", "-lm"],
    )
    extensions.append(cpu_packet_engine_native)

    l7_compile_args, l7_link_args, l7_macros = _resolve_l7_flags()
    l7_emu_native = Extension(
        "ddos_samurai._l7_emu_native",
        sources=[
            "ddos_samurai/l7_emu_native/module.cpp",
            "ddos_samurai/l7_emu_native/engine.cpp",
            "ddos_samurai/l7_emu_native/custom_quic_stack/quic_stack.cpp",
            "ddos_samurai/l7_emu_native/custom_quic_stack/udp_io.cpp",
            "ddos_samurai/l7_emu_native/custom_quic_stack/crypto_backend.cpp",
            "ddos_samurai/l7_emu_native/custom_quic_stack/h3_minimal_client.cpp",
            "ddos_samurai/l7_emu_native/custom_quic_stack/h3_control_plane.cpp",
            "ddos_samurai/l7_emu_native/custom_quic_stack/h3_parity_state.cpp",
            "ddos_samurai/l7_emu_native/custom_quic_stack/loss_recovery.cpp",
            "ddos_samurai/l7_emu_native/custom_quic_stack/quic_metrics.cpp",
            "ddos_samurai/l4/tcp_dataplane_ffi.cpp",
            "ddos_samurai/l4/tcp_dataplane_core.cpp",
        ],
        include_dirs=[pybind11_include],
        language="c++",
        extra_compile_args=_dedupe(["-O2", "-Wall", "-Wextra", "-fPIC", "-std=c++20"] + l7_compile_args),
        extra_link_args=_dedupe(["-lpthread", "-lm"] + l7_link_args),
        define_macros=l7_macros,
    )
    extensions.append(l7_emu_native)

    gpu_cuda_payload_sources = [
        "ddos_samurai/gpu_cuda_payload/src/bridge_pybind.cpp",
        "ddos_samurai/gpu_cuda_payload/src/compiler.cpp",
        "ddos_samurai/gpu_cuda_payload/src/vector_spec_parser.cpp",
        "ddos_samurai/gpu_cuda_payload/src/plan_batch.cpp",
        "ddos_samurai/gpu_cuda_payload/src/oracle.cpp",
    ]
    gpu_cuda_payload_include_dirs = [
        pybind11_include,
        os.path.join(project_root, "ddos_samurai", "gpu_cuda_payload", "include"),
    ]
    gpu_cuda_payload_compile_args: List[str] | Dict[str, List[str]] = ["-O2", "-Wall", "-Wextra", "-fPIC", "-std=c++20"]
    gpu_cuda_payload_link_args = ["-lpthread", "-lm"]
    gpu_cuda_payload_macros: List[Tuple[str, str]] = []
    gpu_cuda_payload_library_dirs: List[str] = []

    nvcc_path = _resolve_nvcc_path()
    cuda_home = _resolve_cuda_home(nvcc_path)
    cuda_include = os.path.join(cuda_home, "include") if cuda_home else ""
    cuda_lib_dir = _resolve_cuda_runtime_lib_dir(cuda_home) if cuda_home else ""
    enable_payload_cuda = (
        (not _env_flag("SAMURAI_SKIP_CUDA_BUILD", "0"))
        and bool(nvcc_path)
        and bool(cuda_include)
        and os.path.exists(cuda_include)
    )
    if enable_payload_cuda:
        gpu_cuda_payload_sources.extend([
            "ddos_samurai/gpu_cuda_payload/cuda/planner_kernels.cu",
            "ddos_samurai/gpu_cuda_payload/cuda/rng_kernels.cu",
            "ddos_samurai/gpu_cuda_payload/cuda/template_expand_kernels.cu",
        ])
        gpu_cuda_payload_include_dirs.append(cuda_include)
        if cuda_lib_dir:
            gpu_cuda_payload_library_dirs.append(cuda_lib_dir)
        gpu_cuda_payload_link_args.append("-lcudart")
        gpu_cuda_payload_macros.append(("SAMURAI_GPU_CUDA_PAYLOAD_KERNELS", "1"))
        gpu_cuda_payload_compile_args = {
            "cxx": ["-O2", "-Wall", "-Wextra", "-fPIC", "-std=c++20"],
            "nvcc": ["-O3", "-std=c++20", "-Xcompiler", "-fPIC", "-diag-suppress=177"],
        }
    else:
        print("Info: CUDA planner kernels disabled for _gpu_cuda_payload_native (nvcc/CUDA headers not found).")

    gpu_cuda_payload_native = Extension(
        "ddos_samurai._gpu_cuda_payload_native",
        sources=gpu_cuda_payload_sources,
        include_dirs=gpu_cuda_payload_include_dirs,
        library_dirs=gpu_cuda_payload_library_dirs,
        language="c++",
        extra_compile_args=gpu_cuda_payload_compile_args,
        extra_link_args=gpu_cuda_payload_link_args,
        define_macros=gpu_cuda_payload_macros,
    )
    extensions.append(gpu_cuda_payload_native)

    fast_sender = Extension(
        "ddos_samurai.fast_sender",
        sources=["ddos_samurai/fast_sender.c"],
        extra_compile_args=["-O2", "-Wall", "-fPIC"],
        extra_link_args=["-lpthread", "-lm"],
    )
    extensions.append(fast_sender)

    pacing_engine = Extension(
        "ddos_samurai.pacing_engine",
        sources=[
            "ddos_samurai/pacing_engine.c",
            "ddos_samurai/xdp_core.c",
        ],
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
    _assert_no_embedded_virtualenv()
    return {
        "name": "ddos_samurai",
        "version": _read_package_version(),
        "description": "High-Performance Network Testing Tool with GPU Acceleration and AF_XDP Support",
        "license": "MIT",
        "author": "Samurai Team",
        "packages": find_packages(include=["ddos_samurai", "ddos_samurai.*"]),
        "ext_modules": get_extensions(),
        "cmdclass": {"build_ext": OptionalBuildExt},
        "python_requires": ">=3.8",
        "install_requires": [
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
            "ml": [
                "torch>=2.2.0",
                "mamba-ssm>=2.2.2",
                "pandas>=2.0.0",
                "pyarrow>=14.0.0",
            ],
            "all": [
                "cupy>=9.0.0",
                "httpx[http2]>=0.20.0",
                "h2>=4.0.0",
                "torch>=2.2.0",
                "mamba-ssm>=2.2.2",
                "pandas>=2.0.0",
                "pyarrow>=14.0.0",
            ],
        },
        "classifiers": [
            "Development Status :: 4 - Beta",
            "Environment :: Console",
            "Intended Audience :: Developers",
            "Intended Audience :: System Administrators",
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
