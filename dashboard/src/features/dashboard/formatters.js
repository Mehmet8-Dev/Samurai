export function formatMoney(value, digits = 2) {
  const number = Number(value || 0);
  return `$${number.toFixed(digits)}`;
}

export function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString("tr-TR");
}

export function formatDateRange(start, end) {
  if (!start || !end) return "-";
  const startDate = new Date(start).toLocaleDateString("tr-TR");
  const endDate = new Date(end).toLocaleDateString("tr-TR");
  return `${startDate} - ${endDate}`;
}
