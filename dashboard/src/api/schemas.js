import { z } from "zod";

const decimalLikeSchema = z
  .union([z.number(), z.string().trim().regex(/^-?\d+(\.\d+)?$/)])
  .transform((value) => Number(value));

export const tokenSchema = z.object({
  access_token: z.string().min(1),
  token_type: z.string().optional(),
  expires_in: z.number().optional(),
});

export const userSchema = z.object({
  id: z.number(),
  email: z.string().email(),
  username: z.string().min(1),
  role: z.string().min(1),
  is_active: z.boolean().optional(),
});

export const planSchema = z.object({
  id: z.number(),
  code: z.string().min(1),
  name: z.string().min(1),
  description: z.string().nullable().optional(),
  monthly_test_quota: z.number().nullable().optional(),
  price_per_test: z.union([z.number(), z.string()]),
  monthly_fee: z.union([z.number(), z.string()]),
  is_active: z.boolean().optional(),
});

export const subscriptionSchema = z.object({
  plan: planSchema,
  status: z.string(),
  cycle_start: z.string(),
  cycle_end: z.string(),
});

export const billingSchema = z.object({
  currency: z.string(),
  cycle_start: z.string(),
  cycle_end: z.string(),
  total_usage_units: z.number(),
  payg_total: z.union([z.number(), z.string()]),
  monthly_fee: z.union([z.number(), z.string()]),
  total_due: z.union([z.number(), z.string()]),
  monthly_test_quota: z.number().nullable().optional(),
  remaining_quota: z.number().nullable().optional(),
});

export const runSchema = z.object({
  id: z.number(),
  status: z.string().min(1).transform((value) => value.toLowerCase()),
  target: z.string(),
  port: z.number(),
  protocol: z.string(),
  attack_vector: z.string(),
  requested_count: z.number(),
  requested_duration: z.number(),
  requested_rps: decimalLikeSchema,
  workers: z.number(),
  backend: z.string(),
  process_pid: z.number().nullable().optional(),
  started_at: z.string(),
  finished_at: z.string().nullable().optional(),
});

export const statsSchema = z.object({
  is_running: z.boolean(),
  running_count: z.number(),
  completed_count: z.number(),
  failed_count: z.number(),
  stopped_count: z.number(),
  total_runs: z.number(),
  buffered_logs: z.number(),
});

export const healthSchema = z.object({
  status: z.string(),
  service: z.string().optional(),
});

export const plansSchema = z.array(planSchema);
export const runsSchema = z.array(runSchema);

export function parseOrThrow(schema, data, label) {
  const parsed = schema.safeParse(data);
  if (!parsed.success) {
    const firstIssue = parsed.error.issues[0];
    const path = firstIssue?.path?.length ? firstIssue.path.join(".") : "root";
    const detail = firstIssue?.message ? ` (${path}: ${firstIssue.message})` : "";
    throw new Error(`Geçersiz ${label} cevabı${detail}`);
  }
  return parsed.data;
}
