import { useEffect, useMemo, useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { Badge, Button } from "../ui";
import { useTheme } from "../theme/ThemeProvider";

function resolveHealthTone(apiHealth) {
  if (apiHealth === "online") return "ok";
  if (apiHealth === "offline") return "danger";
  return "warn";
}

export function AppShell({ isAuthenticated, username, apiHealth, onLogout, children }) {
  const { theme, toggleTheme } = useTheme();
  const location = useLocation();
  const navigate = useNavigate();
  const [isRailOpen, setIsRailOpen] = useState(false);

  const pageMeta = useMemo(() => {
    if (location.pathname === "/upgrade") {
      return {
        kicker: "Billing",
        title: "Plan ve Fiyatlandırma",
        subtitle: "Abonelik seviyeni operasyon ihtiyaçlarına göre yönet.",
      };
    }
    return {
      kicker: "Operations",
      title: "Control Center",
      subtitle: "Mühendislik odaklı test operasyon paneli",
    };
  }, [location.pathname]);

  useEffect(() => {
    setIsRailOpen(false);
  }, [location.pathname]);

  const handleJumpToContext = () => {
    if (location.pathname !== "/") {
      navigate("/");
      return;
    }
    document.getElementById("context-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <div className={`app-shell ${isRailOpen ? "rail-open" : ""}`.trim()}>
      <button
        type="button"
        className="rail-toggle"
        onClick={() => setIsRailOpen((current) => !current)}
        aria-label="Menüyü aç"
        aria-expanded={isRailOpen}
      >
        Menu
      </button>

      {isRailOpen ? (
        <button type="button" className="rail-overlay" aria-label="Menüyü kapat" onClick={() => setIsRailOpen(false)} />
      ) : null}

      <aside className="left-rail" aria-label="Ana menü">
        <div className="rail-brand">
          <span className="app-kicker">Samurai</span>
          <h1 className="rail-title">Samurai Console</h1>
          <p className="rail-subtitle">Operasyon yüzeyi</p>
        </div>

        <nav className="rail-nav" aria-label="Ana navigasyon">
          <NavLink to="/" className={({ isActive }) => `rail-link ${isActive ? "active" : ""}`.trim()} end>
            Anasayfa
          </NavLink>
          <NavLink to="/upgrade" className={({ isActive }) => `rail-link ${isActive ? "active" : ""}`.trim()}>
            Plan
          </NavLink>
          <button type="button" className="rail-link rail-link-btn" onClick={handleJumpToContext}>
            Hesap
          </button>
        </nav>

        <div className="rail-actions">
          <Badge tone={resolveHealthTone(apiHealth)}>API: {apiHealth}</Badge>
          {isAuthenticated && username ? <Badge tone="info">{username}</Badge> : null}
          <Button type="button" variant="ghost" onClick={toggleTheme} aria-label="Tema değiştir">
            {theme === "light" ? "Koyu" : "Açık"}
          </Button>
          {isAuthenticated ? (
            <Button type="button" variant="danger" onClick={onLogout}>
              Çıkış Yap
            </Button>
          ) : null}
        </div>
      </aside>

      <div className="content-frame">
        <header className="topbar">
          <div className="topbar-copy">
            <p className="topbar-kicker">{pageMeta.kicker}</p>
            <h2 className="topbar-title">{pageMeta.title}</h2>
            <p className="topbar-subtitle">{pageMeta.subtitle}</p>
          </div>

          <div className="topbar-actions">
            <Badge tone={resolveHealthTone(apiHealth)} size="sm" quiet>
              API {apiHealth}
            </Badge>
            {location.pathname === "/" ? (
              <Button variant="quiet" size="sm" onClick={() => navigate("/upgrade")}>
                Planı Gör
              </Button>
            ) : (
              <Button variant="quiet" size="sm" onClick={() => navigate("/")}>
                Dashboard
              </Button>
            )}
          </div>
        </header>

        <main className="content-scroll">{children}</main>
      </div>
    </div>
  );
}
