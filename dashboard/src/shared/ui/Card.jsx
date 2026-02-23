export function Card({
  title,
  subtitle,
  className = "",
  children,
  headerRight,
  surface = "default",
  density = "comfortable",
  tone = "neutral",
  quiet = false,
  ...props
}) {
  return (
    <section
      className={`card card-${surface} card-${density} tone-${tone} ${quiet ? "is-quiet" : ""} ${className}`.trim()}
      {...props}
    >
      {(title || subtitle || headerRight) && (
        <div className="card-row-title card-header">
          <div>
            {title ? <h2 className="card-title">{title}</h2> : null}
            {subtitle ? <p className="card-subtitle">{subtitle}</p> : null}
          </div>
          {headerRight || null}
        </div>
      )}
      {children}
    </section>
  );
}
