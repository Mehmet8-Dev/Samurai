import { useState } from "react";
import { Button, DataTable } from "../../../shared/ui";
import { formatDate } from "../formatters";

export function RecentRunsTable({ runs, onStopRun, stopDisabled, mode = "compact" }) {
  const [expandedRunId, setExpandedRunId] = useState(null);

  const isCompact = mode === "compact";
  const columns = [
    { key: "id", header: "ID" },
    {
      key: "target",
      header: "Target",
      render: (row) => `${row.target}:${row.port}`,
    },
    ...(isCompact ? [] : [{ key: "attack_vector", header: "Vector" }]),
    { key: "status", header: "Status" },
    {
      key: "started_at",
      header: "Started",
      render: (row) => formatDate(row.started_at),
    },
    {
      key: "action",
      header: "Action",
      render: (row) => (
        <div className="row-between run-actions">
          {String(row.status || "").toLowerCase() === "running" ? (
            <Button
              variant="danger"
              size="sm"
              onClick={() => onStopRun(row.id)}
              disabled={stopDisabled}
              aria-label={`Run ${row.id} durdur`}
            >
              Durdur
            </Button>
          ) : (
            <span className="text-faint">-</span>
          )}
          <Button
            variant="quiet"
            size="sm"
            onClick={() => setExpandedRunId((current) => (current === row.id ? null : row.id))}
            aria-label={`Run ${row.id} detay`}
          >
            {expandedRunId === row.id ? "Kapat" : "Detay"}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={runs}
      rowKey={(row) => row.id}
      emptyText="Henüz run kaydı yok."
      density={isCompact ? "compact" : "comfortable"}
      expandedRowKey={expandedRunId}
      renderExpanded={(row) => (
        <div className="run-detail-drawer">
          <div><strong>Protocol:</strong> {row.protocol}</div>
          <div><strong>Vector:</strong> {row.attack_vector}</div>
          <div><strong>Backend:</strong> {row.backend}</div>
          <div><strong>Count:</strong> {row.requested_count}</div>
          <div><strong>Duration:</strong> {row.requested_duration}s</div>
          <div><strong>RPS:</strong> {row.requested_rps}</div>
          <div><strong>PID:</strong> {row.process_pid ?? "-"}</div>
          <div><strong>Finished:</strong> {formatDate(row.finished_at)}</div>
        </div>
      )}
    />
  );
}
