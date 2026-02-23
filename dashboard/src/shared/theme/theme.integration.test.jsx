import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { renderApp } from "../../test/renderApp";

describe("theme behaviour", () => {
  it("light varsayılan, dark toggle persist eder", async () => {
    const user = userEvent.setup();
    localStorage.setItem("samurai_token", "token-123");
    renderApp("/");

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Tema değiştir" })).toBeInTheDocument();
    });

    expect(document.documentElement.getAttribute("data-theme")).toBe("light");

    await user.click(screen.getByRole("button", { name: "Tema değiştir" }));

    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(localStorage.getItem("samurai_theme")).toBe("dark");
  });
});
