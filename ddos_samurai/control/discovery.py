"""Endpoint discovery abstraction (manual first; optional K8s)."""

from __future__ import annotations

from .auth import split_endpoints


class EndpointDiscovery:
    def __init__(
        self,
        manual_endpoints: str,
        *,
        prefer_k8s: bool = False,
        k8s_namespace: str = "default",
        k8s_selector: str = "",
        k8s_port: int = 5099,
    ) -> None:
        self._manual = split_endpoints(manual_endpoints)
        self._prefer_k8s = bool(prefer_k8s)
        self._k8s_namespace = str(k8s_namespace or "default").strip() or "default"
        self._k8s_selector = str(k8s_selector or "").strip()
        self._k8s_port = int(k8s_port or 5099)

    def resolve(self) -> list[str]:
        # v1 decision: manual endpoints are first-class and always win when present.
        return list(self._manual)

    def resolve_with_fallback(self) -> list[str]:
        manual = self.resolve()
        if manual:
            return manual
        if self._prefer_k8s:
            return self.resolve_from_k8s()
        return []

    def resolve_from_k8s(self) -> list[str]:
        try:
            from kubernetes import client, config
        except ImportError:
            return []

        try:
            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config()
            api = client.CoreV1Api()
            pods = api.list_namespaced_pod(
                namespace=self._k8s_namespace,
                label_selector=self._k8s_selector or None,
            )
        except Exception:
            return []

        out: list[str] = []
        seen = set()
        for pod in list(getattr(pods, "items", []) or []):
            status = getattr(pod, "status", None)
            ip = str(getattr(status, "pod_ip", "") or "").strip()
            phase = str(getattr(status, "phase", "") or "").strip().lower()
            if not ip or phase not in {"running"}:
                continue
            if not self._is_pod_ready(pod):
                continue
            ep = f"{ip}:{self._k8s_port}"
            if ep in seen:
                continue
            seen.add(ep)
            out.append(ep)
        return sorted(out)

    @staticmethod
    def _is_pod_ready(pod) -> bool:
        status = getattr(pod, "status", None)
        conds = list(getattr(status, "conditions", []) or [])
        for c in conds:
            ctype = str(getattr(c, "type", "") or "").strip().lower()
            cstatus = str(getattr(c, "status", "") or "").strip().lower()
            if ctype == "ready":
                return cstatus == "true"
        # If explicit readiness info does not exist, fall back to phase check.
        return True
