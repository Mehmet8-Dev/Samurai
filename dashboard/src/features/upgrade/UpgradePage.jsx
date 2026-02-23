import { useState } from "react";
import { Alert, Button, Card } from "../../shared/ui";
import { useAuth } from "../../hooks/useAuth";
import { useDashboardData } from "../../hooks/useDashboardData";
import { useTestActions } from "../../hooks/useTestActions";
import { formatMoney } from "../dashboard/formatters";
import { KeyValueList } from "../dashboard/components/KeyValueList";

export function UpgradePage() {
  const { isAuthenticated } = useAuth();
  const { paidPlans, subscriptionQuery } = useDashboardData(isAuthenticated);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const actions = useTestActions({
    onSuccessMessage: (message) => {
      setNotice(message);
      setError("");
    },
    onErrorMessage: (message) => {
      setError(message);
      setNotice("");
    },
  });

  const currentCode = String(subscriptionQuery.data?.plan?.code || "").toLowerCase();
  const currentPlanName = subscriptionQuery.data?.plan?.name || "Free";

  return (
    <section className="stack pricing-page">
      {notice ? <Alert tone="success">{notice}</Alert> : null}
      {error ? <Alert tone="error" role="alert">{error}</Alert> : null}

      <Card
        title="Aboneliğini Yükselt"
        subtitle="Yeni hesaplar Free planla başlar. İhtiyaca göre PAYG veya Premium seviyesine geçiş yapabilirsiniz."
        surface="elevated"
      >
        <p className="text-soft">Aktif plan: <strong>{currentPlanName}</strong></p>
      </Card>

      <section className="pricing-strip" aria-label="Plan karşılaştırması">
        {paidPlans.map((plan) => {
          const isCurrent = String(plan.code).toLowerCase() === currentCode;
          return (
            <Card
              key={plan.id}
              className={`pricing-card ${isCurrent ? "active" : ""}`}
              title={plan.name}
              subtitle={plan.description || ""}
              density="compact"
              surface={isCurrent ? "elevated" : "default"}
            >
              <KeyValueList
                items={[
                  { label: "Kod", value: String(plan.code).toUpperCase() },
                  { label: "Aylık Ücret", value: formatMoney(plan.monthly_fee, 2) },
                  { label: "API Birim Ücreti", value: formatMoney(plan.price_per_test, 4) },
                  { label: "Aylık Kota", value: plan.monthly_test_quota ?? "Unlimited" },
                ]}
              />

              <div className="pricing-actions">
                <Button
                  variant="primary"
                  size="sm"
                  disabled={isCurrent || actions.isActionPending}
                  onClick={async () => {
                    try {
                      await actions.changePlan(plan.code);
                    } catch {
                      // Error handling mutation hook içinde mesaj olarak ele alınıyor.
                    }
                  }}
                >
                  {isCurrent ? "Aktif Plan" : "Bu Plana Geç"}
                </Button>
                <p className="text-faint">Değişiklik hemen uygulanır, faturalama bir sonraki cycle’da dengelenir.</p>
              </div>
            </Card>
          );
        })}
      </section>
    </section>
  );
}
