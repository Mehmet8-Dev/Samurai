import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { renderApp } from "../test/renderApp";
import { server } from "../test/server";

const API = "http://localhost:5099";

describe("dashboard routes and integration", () => {
  it("/ route token yokken login ekranına düşer", async () => {
    renderApp("/");
    expect(await screen.findByRole("form", { name: "Giriş formu" })).toBeInTheDocument();
  });

  it("/register route render davranışı doğrudur", async () => {
    renderApp("/register");
    expect(await screen.findByRole("button", { name: "Hesap Oluştur" })).toBeInTheDocument();
  });

  it("run stop butonu yalnızca running statüde görünür", async () => {
    localStorage.setItem("samurai_token", "token-123");
    renderApp("/");

    await waitFor(() => {
      expect(screen.getByText("Recent Runs")).toBeInTheDocument();
    });

    const stopButtons = screen.getAllByRole("button", { name: /Run .* durdur/i });
    expect(stopButtons).toHaveLength(1);
  });

  it("/upgrade route ve plan değişikliği akışı çalışır", async () => {
    const user = userEvent.setup();
    localStorage.setItem("samurai_token", "token-123");
    renderApp("/upgrade");

    await waitFor(() => {
      expect(screen.getByText("Aboneliğini Yükselt")).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getAllByRole("button", { name: "Bu Plana Geç" }).length).toBeGreaterThan(0);
    });

    await user.click(screen.getAllByRole("button", { name: "Bu Plana Geç" })[0]);

    expect(await screen.findByText("Abonelik planı güncellendi.")).toBeInTheDocument();
  });

  it("geri/ileri navigasyon URL senkron çalışır", async () => {
    const user = userEvent.setup();
    localStorage.setItem("samurai_token", "token-123");
    renderApp("/");

    await waitFor(() => {
      expect(screen.getByText("Anasayfa")).toBeInTheDocument();
    });

    await user.click(screen.getByRole("link", { name: "Plan" }));
    expect(await screen.findByText("Aboneliğini Yükselt")).toBeInTheDocument();

    await act(async () => {
      window.history.back();
      window.dispatchEvent(new PopStateEvent("popstate"));
    });

    await waitFor(() => {
      expect(screen.getByText("Recent Runs")).toBeInTheDocument();
    });
  });

  it("sol rail aktif link durumu route ile senkron kalır", async () => {
    const user = userEvent.setup();
    localStorage.setItem("samurai_token", "token-123");
    renderApp("/upgrade");

    const planLink = await screen.findByRole("link", { name: "Plan" });
    const homeLink = screen.getByRole("link", { name: "Anasayfa" });

    expect(planLink).toHaveClass("active");
    expect(homeLink).not.toHaveClass("active");

    await user.click(homeLink);

    await waitFor(() => {
      expect(homeLink).toHaveClass("active");
    });
  });

  it("dashboard query hata alırsa fallback uyarısı gösterir", async () => {
    server.use(http.get(`${API}/stats`, () => HttpResponse.json({ detail: "boom" }, { status: 500 })));

    localStorage.setItem("samurai_token", "token-123");
    renderApp("/");

    expect(await screen.findByText(/Dashboard verisi alınamadı/i)).toBeInTheDocument();
  });
});
