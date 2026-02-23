import { Card } from "../ui";

export function AuthLayout({ children }) {
  return (
    <div className="auth-wrap">
      <section className="auth-layout auth-layout-single">
        <div className="auth-header">
          <span className="app-kicker">Samurai Console</span>
          <h1 className="auth-title">Kontrollü test operasyonları</h1>
          <p className="auth-copy">Kimlik doğrulama sonrası dashboard ve plan yönetimi ekranlarına erişebilirsin.</p>
        </div>
        <Card className="auth-card" surface="elevated" density="comfortable">
          {children}
        </Card>
      </section>
    </div>
  );
}
