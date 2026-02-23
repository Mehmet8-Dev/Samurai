import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { StartTestForm } from "./StartTestForm";

describe("StartTestForm", () => {
  it("geçersiz port için validasyon mesajı gösterir", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();

    render(<StartTestForm onSubmit={onSubmit} disabled={false} />);

    const portInput = screen.getByLabelText("Port");
    await user.clear(portInput);
    await user.type(portInput, "70000");
    await user.click(screen.getByRole("button", { name: "Test Başlat" }));

    expect(await screen.findByText("Port 1-65535 aralığında olmalıdır.")).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("geçerli formda submit eder", async () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    const user = userEvent.setup();

    render(<StartTestForm onSubmit={onSubmit} disabled={false} />);

    const targetInput = screen.getByLabelText("Target");
    await user.clear(targetInput);
    await user.type(targetInput, "127.0.0.11");
    await user.click(screen.getByRole("button", { name: "Test Başlat" }));

    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(onSubmit.mock.calls[0][0].target).toBe("127.0.0.11");
  });

  it("gelişmiş ayarlar açılıp kapanır", async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();

    render(<StartTestForm onSubmit={onSubmit} disabled={false} />);

    expect(screen.queryByLabelText("Workers")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Gelişmiş Ayarlar" }));
    expect(screen.getByLabelText("Workers")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Gelişmiş Alanları Gizle" }));
    expect(screen.queryByLabelText("Workers")).not.toBeInTheDocument();
  });
});
