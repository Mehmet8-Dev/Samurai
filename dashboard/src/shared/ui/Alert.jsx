export function Alert({ tone = "info", children, role = "status", quiet = false }) {
  const toneClass =
    tone === "success" ? "success" : tone === "error" ? "error" : tone === "warn" ? "warn" : "info";
  return (
    <div className={`alert ${toneClass} ${quiet ? "is-quiet" : ""}`.trim()} role={role}>
      {children}
    </div>
  );
}
