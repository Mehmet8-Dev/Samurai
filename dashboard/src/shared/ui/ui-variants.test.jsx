import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { Card } from "./Card";
import { Tabs } from "./Tabs";

describe("ui variants", () => {
  it("Button variant ve size class'larını uygular", () => {
    render(<Button variant="quiet" size="sm">Aksiyon</Button>);
    expect(screen.getByRole("button", { name: "Aksiyon" })).toHaveClass("btn-quiet", "btn-sm");
  });

  it("Card surface/density class'larını uygular", () => {
    render(<Card title="Kart" surface="elevated" density="compact">İçerik</Card>);
    expect(screen.getByText("Kart").closest("section")).toHaveClass("card-elevated", "card-compact");
  });

  it("Badge tone class'ını uygular", () => {
    render(<Badge tone="ok">online</Badge>);
    expect(screen.getByText("online")).toHaveClass("badge-ok");
  });

  it("Tabs active state'i aria ile işaretler", async () => {
    render(
      <Tabs
        active="a"
        onChange={vi.fn()}
        tabs={[
          { value: "a", label: "Sekme A" },
          { value: "b", label: "Sekme B" },
        ]}
      />
    );
    expect(screen.getByRole("tab", { name: "Sekme A" })).toHaveAttribute("aria-selected", "true");
  });
});
