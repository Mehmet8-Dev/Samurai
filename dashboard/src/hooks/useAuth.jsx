import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { loginRequest, registerRequest } from "../api/services";
import { setAuthTokenGetter, setUnauthorizedHandler } from "../api/client";
import { getErrorMessage } from "../shared/utils/errors";

export const AUTH_STORAGE_KEY = "samurai_token";

const AuthContext = createContext(null);

function readStoredToken() {
  const token = localStorage.getItem(AUTH_STORAGE_KEY);
  return token || "";
}

export function AuthProvider({ children }) {
  const [token, setToken] = useState(readStoredToken);
  const [flashMessage, setFlashMessage] = useState("");

  useEffect(() => {
    setAuthTokenGetter(() => token);
  }, [token]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      localStorage.removeItem(AUTH_STORAGE_KEY);
      setToken("");
      setFlashMessage("Oturum süreniz doldu. Tekrar giriş yapın.");
    });

    return () => {
      setUnauthorizedHandler(null);
    };
  }, []);

  const value = useMemo(() => {
    const persistToken = (nextToken) => {
      localStorage.setItem(AUTH_STORAGE_KEY, nextToken);
      setToken(nextToken);
    };

    const clearToken = () => {
      localStorage.removeItem(AUTH_STORAGE_KEY);
      setToken("");
    };

    const login = async (credentials) => {
      const data = await loginRequest(credentials);
      persistToken(data.access_token);
      setFlashMessage("");
      return data;
    };

    const register = async (payload) => {
      try {
        return await registerRequest(payload);
      } catch (error) {
        throw new Error(getErrorMessage(error, "Kayıt oluşturulamadı"));
      }
    };

    const logout = () => {
      clearToken();
      setFlashMessage("Çıkış yapıldı.");
    };

    return {
      token,
      isAuthenticated: Boolean(token),
      flashMessage,
      setFlashMessage,
      login,
      register,
      logout,
      clearToken,
    };
  }, [token, flashMessage]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
