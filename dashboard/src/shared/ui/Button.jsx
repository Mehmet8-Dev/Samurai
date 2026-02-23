export function Button({
  className = "",
  variant = "default",
  size = "md",
  quiet = false,
  type = "button",
  ...props
}) {
  const variantClass =
    variant === "primary"
      ? "btn-primary"
      : variant === "danger"
        ? "btn-danger"
        : variant === "ghost"
          ? "btn-ghost"
          : variant === "quiet"
            ? "btn-quiet"
            : "btn-default";

  const sizeClass = size === "sm" ? "btn-sm" : size === "lg" ? "btn-lg" : "btn-md";

  return (
    <button
      type={type}
      className={`btn ${variantClass} ${sizeClass} ${quiet ? "is-quiet" : ""} ${className}`.trim()}
      {...props}
    />
  );
}
