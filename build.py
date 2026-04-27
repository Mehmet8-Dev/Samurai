#!/usr/bin/env python3
"""DDoSamurai Build Script — tek binary dağıtım paketi oluşturur.

Kullanım:
    python build.py [--backend pyinstaller|nuitka] [--platform linux|darwin|win32]

Varsayılan: PyInstaller ile Linux binary.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"


def _get_version() -> str:
    """__init__.py'den versiyon oku."""
    init_file = PROJECT_ROOT / "ddos_samurai" / "__init__.py"
    for line in init_file.read_text().splitlines():
        if line.strip().startswith("__version__"):
            return line.split("=", 1)[1].strip().strip("'\"")
    return "0.0.0"


def _find_native_extensions() -> list[str]:
    """Derlenmiş C/C++ native modülleri bul (.so / .pyd / .dylib)."""
    extensions = []
    native_dirs = [
        PROJECT_ROOT / "ddos_samurai" / "native",
        PROJECT_ROOT / "ddos_samurai",
    ]
    for d in native_dirs:
        if not d.exists():
            continue
        for f in d.rglob("*"):
            if f.suffix in (".so", ".pyd", ".dylib"):
                extensions.append(str(f))
    return extensions


def build_pyinstaller(onefile: bool = True) -> Path:
    """PyInstaller ile binary oluştur."""
    version = _get_version()
    name = f"samurai-{version}-{platform.system().lower()}-{platform.machine()}"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "samurai",
        "--console",
        "--noconfirm",
        "--clean",
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR / "pyinstaller"),
    ]

    if onefile:
        cmd.append("--onefile")

    # Hidden imports — dinamik olarak yüklenen modüller
    hidden_imports = [
        "ddos_samurai.licensing",
        "ddos_samurai.licensing.client",
        "ddos_samurai.licensing.cache",
        "ddos_samurai.licensing.features",
        "ddos_samurai.licensing.gates",
        "ddos_samurai.licensing.hwid",
        "ddos_samurai.orchestrator",
        "ddos_samurai.metrics",
        "ddos_samurai.reporting",
        "ddos_samurai.stealth",
        "cryptography",
        "cryptography.fernet",
    ]
    for mod in hidden_imports:
        cmd.extend(["--hidden-import", mod])

    # Native extension'ları data olarak ekle
    for ext_path in _find_native_extensions():
        rel = os.path.relpath(ext_path, PROJECT_ROOT)
        dest_dir = os.path.dirname(rel)
        cmd.extend(["--add-data", f"{ext_path}{os.pathsep}{dest_dir}"])

    # Entry point
    cmd.append(str(PROJECT_ROOT / "ddos_samurai" / "cli" / "__main__.py"))

    print(f"[BUILD] PyInstaller: {name}")
    print(f"[BUILD] Komut: {' '.join(cmd)}")

    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if result.returncode != 0:
        print(f"[BUILD] PyInstaller BAŞARISIZ (exit={result.returncode})")
        sys.exit(1)

    output = DIST_DIR / "samurai"
    if platform.system() == "Windows":
        output = output.with_suffix(".exe")

    print(f"[BUILD] Çıktı: {output}")
    print(f"[BUILD] Boyut: {output.stat().st_size / (1024 * 1024):.1f} MB")

    # İsimlendir
    final_name = name + (".exe" if platform.system() == "Windows" else "")
    final_path = DIST_DIR / final_name
    if output != final_path:
        shutil.move(str(output), str(final_path))
        print(f"[BUILD] Yeniden adlandırıldı: {final_path}")

    return final_path


def build_nuitka(onefile: bool = True) -> Path:
    """Nuitka ile optimize binary oluştur."""
    version = _get_version()
    name = f"samurai-{version}-{platform.system().lower()}-{platform.machine()}"

    cmd = [
        sys.executable, "-m", "nuitka",
        "--output-dir=" + str(DIST_DIR),
        "--remove-output",
        "--assume-yes-for-downloads",
        "--python-flag=no_site",
    ]

    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--standalone")

    # Optimizasyon
    cmd.extend([
        "--enable-plugin=anti-bloat",
        "--nofollow-import-to=tkinter",
        "--nofollow-import-to=unittest",
        "--nofollow-import-to=test",
    ])

    # Entry point
    cmd.append(str(PROJECT_ROOT / "ddos_samurai" / "cli" / "__main__.py"))

    print(f"[BUILD] Nuitka: {name}")
    print(f"[BUILD] Komut: {' '.join(cmd)}")

    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if result.returncode != 0:
        print(f"[BUILD] Nuitka BAŞARISIZ (exit={result.returncode})")
        sys.exit(1)

    # Nuitka çıktı adını bul
    output = DIST_DIR / "__main__.bin"
    if platform.system() == "Windows":
        output = DIST_DIR / "__main__.exe"

    if not output.exists():
        # Alternatif isimler
        for candidate in DIST_DIR.glob("__main__*"):
            if candidate.is_file() and candidate.suffix not in (".py", ".pyi"):
                output = candidate
                break

    final_name = name + (".exe" if platform.system() == "Windows" else "")
    final_path = DIST_DIR / final_name
    if output.exists() and output != final_path:
        shutil.move(str(output), str(final_path))

    print(f"[BUILD] Çıktı: {final_path}")
    if final_path.exists():
        print(f"[BUILD] Boyut: {final_path.stat().st_size / (1024 * 1024):.1f} MB")

    return final_path


def create_archive(binary_path: Path) -> Path:
    """Binary'yi tar.gz veya zip olarak paketle."""
    version = _get_version()
    base_name = f"samurai-{version}-{platform.system().lower()}-{platform.machine()}"
    archive_dir = DIST_DIR / base_name

    archive_dir.mkdir(exist_ok=True)
    shutil.copy2(str(binary_path), str(archive_dir / binary_path.name))

    # README ve LICENSE kopyala
    for extra in ("README.md", "LICENSE"):
        src = PROJECT_ROOT / extra
        if src.exists():
            shutil.copy2(str(src), str(archive_dir / extra))

    if platform.system() == "Windows":
        archive_path = shutil.make_archive(str(DIST_DIR / base_name), "zip", str(DIST_DIR), base_name)
    else:
        archive_path = shutil.make_archive(str(DIST_DIR / base_name), "gztar", str(DIST_DIR), base_name)

    shutil.rmtree(str(archive_dir))
    print(f"[BUILD] Arşiv: {archive_path}")
    return Path(archive_path)


def main():
    parser = argparse.ArgumentParser(description="DDoSamurai Build Script")
    parser.add_argument(
        "--backend",
        choices=["pyinstaller", "nuitka"],
        default="pyinstaller",
        help="Build backend (varsayılan: pyinstaller)",
    )
    parser.add_argument(
        "--no-onefile",
        action="store_true",
        help="Tek dosya yerine klasör olarak derle",
    )
    parser.add_argument(
        "--archive",
        action="store_true",
        help="Binary'yi tar.gz/zip olarak paketle",
    )
    args = parser.parse_args()

    DIST_DIR.mkdir(exist_ok=True)
    BUILD_DIR.mkdir(exist_ok=True)

    onefile = not args.no_onefile

    if args.backend == "nuitka":
        binary = build_nuitka(onefile=onefile)
    else:
        binary = build_pyinstaller(onefile=onefile)

    if args.archive and binary.exists():
        create_archive(binary)

    print(f"\n[BUILD] ✓ Tamamlandı!")


if __name__ == "__main__":
    main()
