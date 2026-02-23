import api from "./client";
import {
  billingSchema,
  healthSchema,
  parseOrThrow,
  plansSchema,
  runsSchema,
  statsSchema,
  subscriptionSchema,
  tokenSchema,
  userSchema,
  runSchema,
} from "./schemas";

export async function healthCheck() {
  const { data } = await api.get("/health");
  return parseOrThrow(healthSchema, data, "health");
}

export async function loginRequest({ username, password }) {
  const form = new URLSearchParams();
  form.append("username", username);
  form.append("password", password);
  const { data } = await api.post("/auth/token", form, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  return parseOrThrow(tokenSchema, data, "token");
}

export async function registerRequest(payload) {
  const { data } = await api.post("/auth/register", payload);
  return parseOrThrow(userSchema, data, "register");
}

export async function fetchMe() {
  const { data } = await api.get("/auth/me");
  return parseOrThrow(userSchema, data, "me");
}

export async function fetchSubscription() {
  const { data } = await api.get("/subscription/me");
  return parseOrThrow(subscriptionSchema, data, "subscription");
}

export async function fetchBillingSummary() {
  const { data } = await api.get("/billing/summary");
  return parseOrThrow(billingSchema, data, "billing");
}

export async function fetchPlans() {
  const { data } = await api.get("/plans");
  return parseOrThrow(plansSchema, data, "plans");
}

export async function fetchRuns() {
  const { data } = await api.get("/tests/runs");
  return parseOrThrow(runsSchema, data, "runs");
}

export async function fetchStats() {
  const { data } = await api.get("/stats");
  return parseOrThrow(statsSchema, data, "stats");
}

export async function startTest(payload) {
  const { data } = await api.post("/tests/start", payload);
  return parseOrThrow(runSchema, data, "start_test");
}

export async function stopTest(runId) {
  const { data } = await api.post(`/tests/${runId}/stop`, {});
  return parseOrThrow(runSchema, data, "stop_test");
}

export async function changePlan(planCode) {
  const { data } = await api.post("/subscription/change", { plan_code: planCode });
  return parseOrThrow(subscriptionSchema, data, "change_plan");
}
