export function StatTile({ label, value, tone = "neutral", compact = false }) {
  const toneClass = tone === "brand" ? "stat-brand" : tone === "danger" ? "stat-danger" : "stat-neutral";
  return (
    <article className={`stat-tile ${toneClass} ${compact ? "compact" : ""}`.trim()}>
      <span className="stat-label">{label}</span>
      <strong className="stat-value">{value}</strong>
    </article>
  );
}
