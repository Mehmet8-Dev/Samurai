import { describe, expect, it } from "vitest";
import { runSchema, runsSchema } from "./schemas";

describe("run schemas", () => {
  it("requested_rps string değerini parse eder ve status alanını normalize eder", () => {
    const run = runSchema.parse({
      id: 1,
      status: "RUNNING",
      target: "127.0.0.1",
      port: 80,
      protocol: "tcp",
      attack_vector: "basic",
      requested_count: 1000,
      requested_duration: 30,
      requested_rps: "0.25",
      workers: 2,
      backend: "cpu",
      process_pid: null,
      started_at: "2026-02-21T12:00:00Z",
      finished_at: null,
    });

    expect(run.requested_rps).toBe(0.25);
    expect(run.status).toBe("running");
  });

  it("runs listesinde mixed numeric/string requested_rps kabul eder", () => {
    const parsed = runsSchema.parse([
      {
        id: 1,
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
        process_pid: 10,
        started_at: "2026-02-21T12:00:00Z",
        finished_at: null,
      },
      {
        id: 2,
        status: "COMPLETED",
        target: "127.0.0.2",
        port: 443,
        protocol: "tcp",
        attack_vector: "http",
        requested_count: 200,
        requested_duration: 10,
        requested_rps: "12.5",
        workers: 1,
        backend: "cpu",
        process_pid: null,
        started_at: "2026-02-21T13:00:00Z",
        finished_at: "2026-02-21T13:01:00Z",
      },
    ]);

    expect(parsed[1].requested_rps).toBe(12.5);
    expect(parsed[1].status).toBe("completed");
  });
});
