import { http, HttpResponse } from "msw";

const API = "http://localhost:5099";

const user = {
  id: 1,
  email: "mehmet@example.com",
  username: "mehmet",
  role: "admin",
  is_active: true,
};

const plans = [
  {
    id: 1,
    code: "free",
    name: "Free",
    description: "Starter tier",
    monthly_test_quota: 10000,
    price_per_test: 0,
    monthly_fee: 0,
    is_active: true,
  },
  {
    id: 2,
    code: "payg",
    name: "Pay As You Go",
    description: "Kullandıkça öde",
    monthly_test_quota: null,
    price_per_test: 0.0015,
    monthly_fee: 0,
    is_active: true,
  },
  {
    id: 3,
    code: "premium",
    name: "Premium",
    description: "Kurumsal plan",
    monthly_test_quota: 200000,
    price_per_test: 0.0004,
    monthly_fee: 99,
    is_active: true,
  },
];

let currentPlanCode = "free";
let runs = [
  {
    id: 200,
    status: "running",
    target: "127.0.0.1",
    port: 80,
    protocol: "tcp",
    attack_vector: "basic",
    requested_count: 1000,
    requested_duration: 30,
    requested_rps: 0,
    workers: 2,
    backend: "cpu",
    process_pid: 4231,
    started_at: "2026-02-21T10:00:00Z",
    finished_at: null,
  },
  {
    id: 201,
    status: "completed",
    target: "127.0.0.2",
    port: 443,
    protocol: "tcp",
    attack_vector: "http",
    requested_count: 500,
    requested_duration: 10,
    requested_rps: 50,
    workers: 1,
    backend: "cpu",
    process_pid: null,
    started_at: "2026-02-21T08:00:00Z",
    finished_at: "2026-02-21T08:05:00Z",
  },
];

function requireAuth(request) {
  const token = request.headers.get("authorization");
  return Boolean(token?.startsWith("Bearer "));
}

function getActivePlan() {
  return plans.find((plan) => plan.code === currentPlanCode) || plans[0];
}

function createSubscription() {
  return {
    plan: getActivePlan(),
    status: "active",
    cycle_start: "2026-02-01T00:00:00Z",
    cycle_end: "2026-03-01T00:00:00Z",
  };
}

function createBilling() {
  return {
    currency: "USD",
    cycle_start: "2026-02-01T00:00:00Z",
    cycle_end: "2026-03-01T00:00:00Z",
    total_usage_units: 1500,
    payg_total: 2.25,
    monthly_fee: getActivePlan().monthly_fee,
    total_due: 2.25 + Number(getActivePlan().monthly_fee || 0),
    monthly_test_quota: getActivePlan().monthly_test_quota,
    remaining_quota:
      getActivePlan().monthly_test_quota === null
        ? null
        : Math.max(0, Number(getActivePlan().monthly_test_quota) - 1500),
  };
}

function createStats() {
  return {
    is_running: runs.some((run) => run.status === "running"),
    running_count: runs.filter((run) => run.status === "running").length,
    completed_count: runs.filter((run) => run.status === "completed").length,
    failed_count: runs.filter((run) => run.status === "failed").length,
    stopped_count: runs.filter((run) => run.status === "stopped").length,
    total_runs: runs.length,
    buffered_logs: 0,
  };
}

export const handlers = [
  http.get(`${API}/health`, () => HttpResponse.json({ status: "ok", service: "samurai-saas-api" })),

  http.post(`${API}/auth/token`, async ({ request }) => {
    const bodyText = await request.text();
    const params = new URLSearchParams(bodyText);
    const username = params.get("username");
    const password = params.get("password");

    if (!username || !password || username === "wrong") {
      return HttpResponse.json({ detail: "Invalid credentials" }, { status: 401 });
    }

    return HttpResponse.json({ access_token: "token-123", token_type: "bearer", expires_in: 3600 });
  }),

  http.post(`${API}/auth/register`, async ({ request }) => {
    const body = await request.json();
    if (!body?.email || !body?.username || !body?.password) {
      return HttpResponse.json({ detail: "Validation failed" }, { status: 400 });
    }
    return HttpResponse.json({ ...user, email: body.email, username: body.username }, { status: 201 });
  }),

  http.get(`${API}/auth/me`, ({ request }) => {
    if (!requireAuth(request)) return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });
    return HttpResponse.json(user);
  }),

  http.get(`${API}/plans`, ({ request }) => {
    if (!requireAuth(request)) return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });
    return HttpResponse.json(plans);
  }),

  http.get(`${API}/subscription/me`, ({ request }) => {
    if (!requireAuth(request)) return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });
    return HttpResponse.json(createSubscription());
  }),

  http.get(`${API}/billing/summary`, ({ request }) => {
    if (!requireAuth(request)) return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });
    return HttpResponse.json(createBilling());
  }),

  http.get(`${API}/tests/runs`, ({ request }) => {
    if (!requireAuth(request)) return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });
    return HttpResponse.json(runs);
  }),

  http.get(`${API}/stats`, ({ request }) => {
    if (!requireAuth(request)) return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });
    return HttpResponse.json(createStats());
  }),

  http.post(`${API}/tests/start`, async ({ request }) => {
    if (!requireAuth(request)) return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });

    const payload = await request.json();
    if (payload.target === "quota.exceeded") {
      return HttpResponse.json({ detail: "Monthly quota exceeded for this subscription" }, { status: 402 });
    }

    const newRun = {
      id: 300,
      status: "running",
      target: payload.target,
      port: Number(payload.port),
      protocol: payload.protocol,
      attack_vector: payload.attack_vector,
      requested_count: Number(payload.count),
      requested_duration: Number(payload.duration),
      requested_rps: Number(payload.rps),
      workers: Number(payload.workers),
      backend: payload.backend,
      process_pid: 999,
      started_at: "2026-02-21T12:00:00Z",
      finished_at: null,
    };

    runs = [newRun, ...runs];
    return HttpResponse.json(newRun);
  }),

  http.post(`${API}/tests/:runId/stop`, ({ request, params }) => {
    if (!requireAuth(request)) return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });

    const runId = Number(params.runId);
    const current = runs.find((run) => run.id === runId);
    if (!current) return HttpResponse.json({ detail: "Run not found" }, { status: 404 });

    const updated = {
      ...current,
      status: "stopped",
      finished_at: "2026-02-21T12:03:00Z",
    };

    runs = runs.map((run) => (run.id === runId ? updated : run));
    return HttpResponse.json(updated);
  }),

  http.post(`${API}/subscription/change`, async ({ request }) => {
    if (!requireAuth(request)) return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });

    const body = await request.json();
    currentPlanCode = String(body.plan_code || "free").toLowerCase();
    return HttpResponse.json(createSubscription());
  }),
];

export function resetMockState() {
  currentPlanCode = "free";
  runs = [
    {
      id: 200,
      status: "running",
      target: "127.0.0.1",
      port: 80,
      protocol: "tcp",
      attack_vector: "basic",
      requested_count: 1000,
      requested_duration: 30,
      requested_rps: 0,
      workers: 2,
      backend: "cpu",
      process_pid: 4231,
      started_at: "2026-02-21T10:00:00Z",
      finished_at: null,
    },
    {
      id: 201,
      status: "completed",
      target: "127.0.0.2",
      port: 443,
      protocol: "tcp",
      attack_vector: "http",
      requested_count: 500,
      requested_duration: 10,
      requested_rps: 50,
      workers: 1,
      backend: "cpu",
      process_pid: null,
      started_at: "2026-02-21T08:00:00Z",
      finished_at: "2026-02-21T08:05:00Z",
    },
  ];
}
