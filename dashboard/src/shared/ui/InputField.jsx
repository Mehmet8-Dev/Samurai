export function InputField({
  label,
  help,
  error,
  id,
  className = "",
  density = "comfortable",
  quiet = false,
  ...props
}) {
  const densityClass = density === "compact" ? "field-compact" : "field-comfortable";
  const describedBy = [help ? `${id}-help` : null, error ? `${id}-error` : null].filter(Boolean).join(" ") || undefined;

  return (
    <label className={`field ${densityClass} ${quiet ? "is-quiet" : ""} ${className}`.trim()} htmlFor={id}>
      <span className="field-label">{label}</span>
      <input id={id} aria-invalid={Boolean(error)} aria-describedby={describedBy} {...props} />
      {help ? <span className="field-help" id={`${id}-help`}>{help}</span> : null}
      {error ? <span className="field-error" id={`${id}-error`}>{error}</span> : null}
    </label>
  );
}
