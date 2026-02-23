export function Skeleton({ height = 16, width = "100%" }) {
  return <div className="skeleton" style={{ height, width }} aria-hidden="true" />;
}
