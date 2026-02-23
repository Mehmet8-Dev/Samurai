import { Card, Skeleton } from "../../../shared/ui";

export function DashboardSkeleton() {
  return (
    <section className="stack" aria-label="Yükleniyor">
      <Card className="summary-band" surface="elevated">
        <Skeleton height={24} width="42%" />
        <Skeleton height={14} width="62%" />
      </Card>
      <section className="workspace-grid">
        <section className="workspace-main stack">
          <Card><Skeleton height={220} /></Card>
          <Card><Skeleton height={240} /></Card>
        </section>
        <aside className="workspace-side stack">
          <Card><Skeleton height={180} /></Card>
          <Card><Skeleton height={140} /></Card>
        </aside>
      </section>
    </section>
  );
}
