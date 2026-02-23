import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  fetchBillingSummary,
  fetchMe,
  fetchPlans,
  fetchRuns,
  fetchStats,
  fetchSubscription,
  healthCheck,
} from "../api/services";

function isVisible() {
  if (typeof document === "undefined") return false;
  return document.visibilityState === "visible";
}

function refetchOnVisible() {
  return isVisible() ? 5000 : false;
}

export function useDashboardData(isAuthenticated) {
  const healthQuery = useQuery({
    queryKey: ["health"],
    queryFn: healthCheck,
    refetchInterval: 12000,
    retry: 1,
  });

  const meQuery = useQuery({
    queryKey: ["me"],
    queryFn: fetchMe,
    enabled: isAuthenticated,
    refetchInterval: refetchOnVisible,
  });

  const subscriptionQuery = useQuery({
    queryKey: ["subscription"],
    queryFn: fetchSubscription,
    enabled: isAuthenticated,
    refetchInterval: refetchOnVisible,
  });

  const billingQuery = useQuery({
    queryKey: ["billing"],
    queryFn: fetchBillingSummary,
    enabled: isAuthenticated,
    refetchInterval: refetchOnVisible,
  });

  const plansQuery = useQuery({
    queryKey: ["plans"],
    queryFn: fetchPlans,
    enabled: isAuthenticated,
    refetchInterval: refetchOnVisible,
  });

  const runsQuery = useQuery({
    queryKey: ["runs"],
    queryFn: fetchRuns,
    enabled: isAuthenticated,
    refetchInterval: refetchOnVisible,
  });

  const statsQuery = useQuery({
    queryKey: ["stats"],
    queryFn: fetchStats,
    enabled: isAuthenticated,
    refetchInterval: refetchOnVisible,
  });

  const dashboardError = useMemo(() => {
    const failed = [meQuery, subscriptionQuery, billingQuery, plansQuery, runsQuery, statsQuery].find(
      (query) => query.isError
    );
    return failed?.error || null;
  }, [meQuery, subscriptionQuery, billingQuery, plansQuery, runsQuery, statsQuery]);

  const runs = runsQuery.data || [];
  const runningRuns = runs.filter((run) => String(run.status || "").toLowerCase() === "running");

  const paidPlans = (plansQuery.data || []).filter((plan) => {
    const code = String(plan.code || "").toLowerCase();
    return code === "payg" || code === "premium";
  });

  const dashboardQueries = [meQuery, subscriptionQuery, billingQuery, plansQuery, runsQuery, statsQuery];
  const hasRenderableState = dashboardQueries.some((query) => query.isError || query.data !== undefined);
  const isLoadingDashboard = !hasRenderableState && dashboardQueries.some((query) => query.isLoading);

  return {
    health: healthQuery,
    meQuery,
    subscriptionQuery,
    billingQuery,
    plansQuery,
    runsQuery,
    statsQuery,
    dashboardError,
    runs,
    runningRuns,
    paidPlans,
    isLoadingDashboard,
  };
}
