import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button, InputField } from "../../../shared/ui";
import { useAuth } from "../../../hooks/useAuth";

export function RegisterForm() {
  const navigate = useNavigate();
  const { register, setFlashMessage } = useAuth();
  const [form, setForm] = useState({ email: "", username: "", password: "", confirmPassword: "" });
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState({
    email: "",
    username: "",
    password: "",
    confirmPassword: "",
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setFieldErrors({ email: "", username: "", password: "", confirmPassword: "" });

    const nextFieldErrors = {
      email: form.email.trim() ? "" : "Bu alan zorunludur.",
      username: form.username.trim() ? "" : "Bu alan zorunludur.",
      password: form.password.trim() ? "" : "Bu alan zorunludur.",
      confirmPassword: form.confirmPassword.trim() ? "" : "Bu alan zorunludur.",
    };

    if (nextFieldErrors.email || nextFieldErrors.username || nextFieldErrors.password || nextFieldErrors.confirmPassword) {
      setFieldErrors(nextFieldErrors);
      setError("E-posta, kullanıcı adı ve şifre zorunludur.");
      return;
    }

    if (form.password.length < 8) {
      setFieldErrors((state) => ({ ...state, password: "En az 8 karakter olmalıdır." }));
      setError("Şifre en az 8 karakter olmalıdır.");
      return;
    }

    if (form.password !== form.confirmPassword) {
      setFieldErrors((state) => ({ ...state, confirmPassword: "Şifre tekrar alanı eşleşmiyor." }));
      setError("Şifre tekrar alanı eşleşmiyor.");
      return;
    }

    try {
      setLoading(true);
      await register({
        email: form.email.trim(),
        username: form.username.trim(),
        password: form.password,
      });
      setFlashMessage("Hesap oluşturuldu. Giriş yapabilirsiniz.");
      navigate("/login", { replace: true });
    } catch (submitError) {
      setError(submitError.message || "Kayıt başarısız");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form className="form-grid" onSubmit={handleSubmit} aria-label="Kayıt formu">
      {error ? <p className="form-error-summary" role="alert">{error}</p> : null}

      <InputField
        id="register-email"
        type="email"
        label="E-posta"
        autoComplete="email"
        value={form.email}
        error={fieldErrors.email}
        density="compact"
        onChange={(event) => setForm((state) => ({ ...state, email: event.target.value }))}
        required
      />

      <InputField
        id="register-username"
        label="Kullanıcı adı"
        autoComplete="username"
        value={form.username}
        error={fieldErrors.username}
        density="compact"
        onChange={(event) => setForm((state) => ({ ...state, username: event.target.value }))}
        required
      />

      <InputField
        id="register-password"
        type="password"
        label="Şifre"
        autoComplete="new-password"
        minLength={8}
        value={form.password}
        error={fieldErrors.password}
        density="compact"
        onChange={(event) => setForm((state) => ({ ...state, password: event.target.value }))}
        required
      />

      <InputField
        id="register-password-confirm"
        type="password"
        label="Şifre (tekrar)"
        autoComplete="new-password"
        minLength={8}
        value={form.confirmPassword}
        error={fieldErrors.confirmPassword}
        density="compact"
        onChange={(event) => setForm((state) => ({ ...state, confirmPassword: event.target.value }))}
        required
      />

      <Button type="submit" variant="primary" disabled={loading}>
        {loading ? "Bekleyin..." : "Hesap Oluştur"}
      </Button>

      <p className="auth-links">
        Hesabın var mı? <button className="link-button" type="button" onClick={() => navigate("/login")}>Giriş yap</button>
      </p>
    </form>
  );
}
