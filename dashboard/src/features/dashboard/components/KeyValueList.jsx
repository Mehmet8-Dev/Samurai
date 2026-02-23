export function KeyValueList({ items }) {
  return (
    <ul className="kv-list">
      {items.map((item) => (
        <li key={item.label}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
        </li>
      ))}
    </ul>
  );
}
