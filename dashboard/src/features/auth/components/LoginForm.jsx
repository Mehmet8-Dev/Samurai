import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button, InputField } from "../../../shared/ui";
import { getErrorMessage } from "../../../shared/utils/errors";
import { useAuth } from "../../../hooks/useAuth";

export function LoginForm() {
  const navigate = useNavigate();
  const { login, setFlashMessage } = useAuth();
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState({ username: "", password: "" });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setFieldErrors({ username: "", password: "" });

    const nextFieldErrors = {
      username: form.username.trim() ? "" : "Bu alan zorunludur.",
      password: form.password.trim() ? "" : "Bu alan zorunludur.",
    };
    if (nextFieldErrors.username || nextFieldErrors.password) {
      setFieldErrors(nextFieldErrors);
      setError("Kullanıcı adı/e-posta ve şifre zorunludur.");
      return;
    }

    try {
      setLoading(true);
      await login({ username: form.username.trim(), password: form.password });
      setFlashMessage("Giriş başarılı.");
      navigate("/", { replace: true });
    } catch (submitError) {
      setError(getErrorMessage(submitError, "Giriş başarısız"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <form className="form-grid" onSubmit={handleSubmit} aria-label="Giriş formu">
      {error ? <p className="form-error-summary" role="alert">{error}</p> : null}

      <InputField
        id="login-username"
        label="Kullanıcı adı veya e-posta"
        autoComplete="username"
        value={form.username}
        error={fieldErrors.username}
        density="compact"
        onChange={(event) => setForm((state) => ({ ...state, username: event.target.value }))}
        required
      />

      <InputField
        id="login-password"
        type="password"
        label="Şifre"
        autoComplete="current-password"
        value={form.password}
        error={fieldErrors.password}
        density="compact"
        onChange={(event) => setForm((state) => ({ ...state, password: event.target.value }))}
        required
      />

      <Button type="submit" variant="primary" disabled={loading}>
        {loading ? "Bekleyin..." : "Giriş Yap"}
      </Button>

      <p className="auth-links">
        Hesabın yok mu? <button className="link-button" type="button" onClick={() => navigate("/register")}>Kayıt ol</button>
      </p>
    </form>
  );
}
