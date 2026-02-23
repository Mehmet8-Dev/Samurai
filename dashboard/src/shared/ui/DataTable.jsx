import { Fragment } from "react";

export function DataTable({
  columns,
  rows,
  emptyText = "Kayıt yok",
  rowKey,
  density = "compact",
  surface = "default",
  quiet = false,
  expandedRowKey = null,
  renderExpanded,
}) {
  if (!rows.length) {
    return <div className="table-empty">{emptyText}</div>;
  }

  return (
    <div className={`table-wrap table-${surface} table-${density} ${quiet ? "is-quiet" : ""}`.trim()}>
      <table className="data-table">
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key}>{column.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey(row);
            return (
              <Fragment key={key}>
                <tr>
                  {columns.map((column) => (
                    <td key={column.key}>{column.render ? column.render(row) : row[column.key]}</td>
                  ))}
                </tr>
                {expandedRowKey === key && renderExpanded ? (
                  <tr className="table-expanded-row">
                    <td colSpan={columns.length}>{renderExpanded(row)}</td>
                  </tr>
                ) : null}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
