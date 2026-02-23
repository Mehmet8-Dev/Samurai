import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { renderApp } from "../../test/renderApp";

describe("auth integration", () => {
  it("hatalı girişte mesaj gösterir", async () => {
    const user = userEvent.setup();
    renderApp("/login");

    await user.type(screen.getByLabelText("Kullanıcı adı veya e-posta"), "wrong");
    await user.type(screen.getByLabelText("Şifre"), "wrong");
    await user.click(screen.getByRole("button", { name: "Giriş Yap" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid credentials");
  });

  it("başarılı girişte dashboard'a yönlendirir", async () => {
    const user = userEvent.setup();
    renderApp("/login");

    await user.type(screen.getByLabelText("Kullanıcı adı veya e-posta"), "mehmet");
    await user.type(screen.getByLabelText("Şifre"), "secret123");
    await user.click(screen.getByRole("button", { name: "Giriş Yap" }));

    await waitFor(() => {
      expect(screen.getByText(/Hoş geldin/i)).toBeInTheDocument();
    });

    expect(screen.getByText("Anasayfa")).toBeInTheDocument();
  });
});
