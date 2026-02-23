export function Badge({ tone = "neutral", size = "md", quiet = false, children }) {
  const toneClass =
    tone === "ok"
      ? "badge-ok"
      : tone === "warn"
        ? "badge-warn"
        : tone === "danger"
          ? "badge-danger"
          : tone === "info"
            ? "badge-info"
            : "badge-neutral";
  const sizeClass = size === "sm" ? "badge-sm" : "badge-md";
  return <span className={`badge ${toneClass} ${sizeClass} ${quiet ? "is-quiet" : ""}`.trim()}>{children}</span>;
}
