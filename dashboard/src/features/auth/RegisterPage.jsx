import { useNavigate } from "react-router-dom";
import { Tabs } from "../../shared/ui";
import { AuthLayout } from "../../shared/layout/AuthLayout";
import { RegisterForm } from "./components/RegisterForm";

export function RegisterPage() {
  const navigate = useNavigate();
  return (
    <AuthLayout>
      <Tabs
        active="register"
        density="compact"
        quiet
        onChange={(value) => navigate(value === "login" ? "/login" : "/register")}
        tabs={[
          { value: "login", label: "Giriş Yap" },
          { value: "register", label: "Kayıt Ol" },
        ]}
      />
      <RegisterForm />
    </AuthLayout>
  );
}
