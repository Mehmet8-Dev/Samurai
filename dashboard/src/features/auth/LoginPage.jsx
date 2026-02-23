import { useNavigate } from "react-router-dom";
import { Tabs } from "../../shared/ui";
import { AuthLayout } from "../../shared/layout/AuthLayout";
import { LoginForm } from "./components/LoginForm";

export function LoginPage() {
  const navigate = useNavigate();
  return (
    <AuthLayout>
      <Tabs
        active="login"
        density="compact"
        quiet
        onChange={(value) => navigate(value === "login" ? "/login" : "/register")}
        tabs={[
          { value: "login", label: "Giriş Yap" },
          { value: "register", label: "Kayıt Ol" },
        ]}
      />
      <LoginForm />
    </AuthLayout>
  );
}
