import { useEffect, useMemo, useState } from "react";
import { Alert, Card, StatTile, Tabs } from "../../shared/ui";
import { useAuth } from "../../hooks/useAuth";
import { useDashboardData } from "../../hooks/useDashboardData";
import { useTestActions } from "../../hooks/useTestActions";
import { getErrorMessage } from "../../shared/utils/errors";
import { formatDateRange, formatMoney } from "./formatters";
import { DashboardSkeleton } from "./components/DashboardSkeleton";
import { KeyValueList } from "./components/KeyValueList";
import { RecentRunsTable } from "./components/RecentRunsTable";
import { StartTestForm } from "./components/StartTestForm";

export function DashboardHomePage() {
  const { isAuthenticated, flashMessage, setFlashMessage } = useAuth();
  const data = useDashboardData(isAuthenticated);
  const [contextTab, setContextTab] = useState("account");
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (flashMessage) {
      setNotice(flashMessage);
      setFlashMessage("");
    }
  }, [flashMessage, setFlashMessage]);

  useEffect(() => {
    if (!data.dashboardError) {
      setError("");
      return;
    }

    const detail = getErrorMessage(data.dashboardError, "");
    const baseMessage = "Dashboard verisi alınamadı";
    setError(detail ? `${baseMessage}: ${detail}` : baseMessage);
  }, [data.dashboardError]);

  const actions = useTestActions({
    onSuccessMessage: (message) => {
      setError("");
      setNotice(message);
    },
    onErrorMessage: (message) => {
      setNotice("");
      setError(message);
    },
  });

  const user = data.meQuery.data;
  const subscription = data.subscriptionQuery.data;
  const billing = data.billingQuery.data;
  const stats = data.statsQuery.data;

  const summaryStats = useMemo(
    () => [
      { label: "Aktif Run", value: data.runningRuns.length },
      { label: "Toplam Run", value: data.runs.length },
      { label: "Dönem Tutarı", value: billing ? formatMoney(billing.total_due, 4) : "$0.0000" },
      { label: "Son güncelleme", value: new Date().toLocaleTimeString("tr-TR") },
    ],
    [data.runningRuns.length, data.runs.length, billing]
  );

  if (data.isLoadingDashboard) {
    return <DashboardSkeleton />;
  }

  return (
    <section className="stack dashboard-page">
      {notice ? <Alert tone="success">{notice}</Alert> : null}
      {error ? <Alert tone="error" role="alert">{error}</Alert> : null}

      {data.health.isError ? (
        <Alert tone="error" role="alert">
          API bağlantısı kurulamadı. Sunucunun erişilebilir olduğundan emin olun.
        </Alert>
      ) : null}

      <Card className="summary-band" surface="elevated">
        <div className="card-row-title">
          <div>
            <h2 className="card-title">Hoş geldin, {user?.username || "kullanıcı"}</h2>
            <p className="card-subtitle">Operasyon özeti</p>
          </div>
        </div>
        <div className="stat-strip">
          {summaryStats.map((item) => (
            <StatTile key={item.label} label={item.label} value={item.value} compact tone="brand" />
          ))}
        </div>
      </Card>

      <section className="workspace-grid">
        <section className="workspace-main stack">
          <Card
            id="start-test"
            className="command-panel"
            title="Test Başlat"
            subtitle="Temel alanlar önce gelir. Gelişmiş ayarları gerektiğinde açabilirsiniz."
          >
            <StartTestForm
              mode="compact"
              disabled={actions.isActionPending}
              onSubmit={async (payload) => {
                try {
                  await actions.startTest(payload);
                } catch {
                  // Error handling mutation hook içinde mesaj olarak ele alınıyor.
                }
              }}
            />
          </Card>

          <Card className="runs-panel" title="Recent Runs" subtitle="Varsayılan görünüm compact, detaylar satır içinden açılır.">
            <RecentRunsTable
              mode="compact"
              runs={data.runs}
              stopDisabled={actions.isActionPending}
              onStopRun={async (runId) => {
                try {
                  await actions.stopTest(runId);
                } catch {
                  // Error handling mutation hook içinde mesaj olarak ele alınıyor.
                }
              }}
            />
          </Card>
        </section>

        <aside className="workspace-side stack">
          <Card id="context-panel" className="context-panel" title="Hesap Bağlamı" subtitle="Hesap, abonelik ve faturalama tek panelde">
            <Tabs
              density="compact"
              quiet
              active={contextTab}
              onChange={setContextTab}
              tabs={[
                { value: "account", label: "Hesap" },
                { value: "subscription", label: "Abonelik" },
                { value: "billing", label: "Faturalama" },
              ]}
            />

            {contextTab === "account" ? (
              <KeyValueList
                items={[
                  { label: "Kullanıcı", value: user?.username || "-" },
                  { label: "E-posta", value: user?.email || "-" },
                  { label: "Rol", value: user?.role || "-" },
                ]}
              />
            ) : null}

            {contextTab === "subscription" ? (
              <KeyValueList
                items={[
                  { label: "Plan", value: subscription?.plan?.name || "-" },
                  { label: "Durum", value: subscription?.status || "-" },
                  { label: "Cycle", value: formatDateRange(subscription?.cycle_start, subscription?.cycle_end) },
                  { label: "Plan Kodu", value: subscription?.plan?.code || "-" },
                ]}
              />
            ) : null}

            {contextTab === "billing" ? (
              <KeyValueList
                items={[
                  { label: "Usage Units", value: billing?.total_usage_units ?? "-" },
                  { label: "Pay-as-you-go", value: billing ? formatMoney(billing.payg_total, 4) : "-" },
                  { label: "Monthly Fee", value: billing ? formatMoney(billing.monthly_fee, 2) : "-" },
                  { label: "Total Due", value: billing ? formatMoney(billing.total_due, 4) : "-" },
                  { label: "Quota Remaining", value: billing?.remaining_quota ?? "Unlimited" },
                ]}
              />
            ) : null}
          </Card>

          <Card title="Runtime Stats" surface="elevated">
            <KeyValueList
              items={[
                { label: "Running", value: stats?.running_count ?? "-" },
                { label: "Completed", value: stats?.completed_count ?? "-" },
                { label: "Failed", value: stats?.failed_count ?? "-" },
                { label: "Stopped", value: stats?.stopped_count ?? "-" },
              ]}
            />
          </Card>
        </aside>
      </section>
    </section>
  );
}
