export function Tabs({ tabs, active, onChange, density = "comfortable", quiet = false }) {
  const densityClass = density === "compact" ? "tabs-compact" : "tabs-comfortable";
  return (
    <div className={`tabs ${densityClass} ${quiet ? "is-quiet" : ""}`.trim()} role="tablist" aria-label="Panel sekmeleri">
      {tabs.map((tab) => (
        <button
          key={tab.value}
          className={`tab-btn ${active === tab.value ? "active" : ""}`.trim()}
          role="tab"
          aria-selected={active === tab.value}
          onClick={() => onChange(tab.value)}
          type="button"
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
