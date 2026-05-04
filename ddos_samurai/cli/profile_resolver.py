"""CLI profile application and normalization."""

from __future__ import annotations

import argparse
import sys

from .. import utils
from ..profile_names import PROFILE_NONE
from ..workload_profiles import TEST_PROFILES


def apply_profile(args, argv=None) -> None:
    profile = args.profile
    if profile == "custom" or profile not in TEST_PROFILES:
        return

    argv_list = list(sys.argv[1:] if argv is None else argv)
    explicit_flags = {
        str(tok).strip().lstrip("-").replace("-", "_")
        for tok in argv_list
        if str(tok).startswith("--")
    }
    prof = TEST_PROFILES[profile]["args"]
    utils.log_info(f"[{profile.upper()}] Corporate Profile Applied: {TEST_PROFILES[profile]['description']}")
    for key, val in prof.items():
        if hasattr(args, key) and key not in explicit_flags:
            setattr(args, key, val)
    utils.log_info(f" -> Setting inherited arguments: {prof}")


def _resolve_profile_args(parser: argparse.ArgumentParser, args: argparse.Namespace, argv) -> None:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    tls_explicit = "--tls-profile" in argv_list
    ja3_explicit = "--ja3-profile" in argv_list

    legacy = getattr(args, "ja3_profile", None)
    if legacy is not None and (ja3_explicit or str(legacy) != str(getattr(args, "tls_profile", PROFILE_NONE))):
        if tls_explicit and str(args.tls_profile) != str(legacy):
            parser.error("Hata: --tls-profile ve --ja3-profile farklı değerlerle birlikte kullanılamaz.")
        args.tls_profile = str(legacy)
        utils.log_warning("DEPRECATION: --ja3-profile yakında kaldırılacak; yerine --tls-profile kullanın.")

    if str(getattr(args, "tls_profile", PROFILE_NONE)).strip().lower() == "":
        args.tls_profile = PROFILE_NONE
    if str(getattr(args, "h2_profile", PROFILE_NONE)).strip().lower() == "":
        args.h2_profile = PROFILE_NONE

    args.ja3_profile = args.tls_profile
