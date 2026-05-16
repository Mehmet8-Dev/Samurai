from __future__ import annotations


def reason_tag_from_contributors(window_mean: dict[str, float], top_features: list[str]) -> str:
    tf = set(top_features)
    p99 = float(window_mean.get("p99_latency", 0.0))
    timeout = float(window_mean.get("timeout_count", 0.0))
    cpu = float(window_mean.get("cpu_usage", 0.0))
    err = float(window_mean.get("error_rate", 0.0))
    mem = float(window_mean.get("memory_usage", 0.0))

    if {"p99_latency", "timeout_count"}.issubset(tf) and (p99 > 0 and timeout > 0):
        return "latency_timeout_degradation"
    if {"cpu_usage", "p99_latency"}.issubset(tf) and cpu >= 85.0:
        return "possible_cpu_saturation"
    if "error_rate" in tf and err > 0.03 and cpu < 80.0:
        return "possible_downstream_or_network_issue"
    if {"memory_usage", "p99_latency"}.issubset(tf) and mem >= 85.0:
        return "possible_memory_pressure"
    return "unknown_pattern"
