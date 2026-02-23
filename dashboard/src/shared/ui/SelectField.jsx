export function SelectField({
  label,
  id,
  options = [],
  className = "",
  help,
  error,
  density = "comfortable",
  quiet = false,
  ...props
}) {
  const densityClass = density === "compact" ? "field-compact" : "field-comfortable";
  const describedBy = [help ? `${id}-help` : null, error ? `${id}-error` : null].filter(Boolean).join(" ") || undefined;

  return (
    <label className={`field ${densityClass} ${quiet ? "is-quiet" : ""} ${className}`.trim()} htmlFor={id}>
      <span className="field-label">{label}</span>
      <select id={id} aria-invalid={Boolean(error)} aria-describedby={describedBy} {...props}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {help ? <span className="field-help" id={`${id}-help`}>{help}</span> : null}
      {error ? <span className="field-error" id={`${id}-error`}>{error}</span> : null}
    </label>
  );
}
