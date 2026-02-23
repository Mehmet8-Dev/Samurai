import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { RecentRunsTable } from "./RecentRunsTable";

const sampleRuns = [
  {
    id: 10,
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
    process_pid: 123,
    started_at: "2026-02-21T13:00:00Z",
    finished_at: null,
  },
  {
    id: 11,
    status: "completed",
    target: "127.0.0.2",
    port: 443,
    protocol: "tcp",
    attack_vector: "http",
    requested_count: 200,
    requested_duration: 12,
    requested_rps: 50,
    workers: 1,
    backend: "cpu",
    process_pid: null,
    started_at: "2026-02-21T10:00:00Z",
    finished_at: "2026-02-21T10:01:00Z",
  },
];

describe("RecentRunsTable", () => {
  it("compact modda detay drawer açar", async () => {
    const user = userEvent.setup();
    render(<RecentRunsTable runs={sampleRuns} onStopRun={vi.fn()} stopDisabled={false} mode="compact" />);

    expect(screen.queryByText(/Protocol:/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run 10 detay" }));
    expect(screen.getByText(/Protocol:/i)).toBeInTheDocument();
  });

  it("yalnızca running run için durdur butonu render eder", () => {
    render(<RecentRunsTable runs={sampleRuns} onStopRun={vi.fn()} stopDisabled={false} mode="compact" />);
    expect(screen.getAllByRole("button", { name: /Run .* durdur/i })).toHaveLength(1);
  });
});
