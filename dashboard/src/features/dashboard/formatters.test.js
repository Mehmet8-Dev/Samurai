import { describe, expect, it } from "vitest";
import { formatDateRange, formatMoney } from "./formatters";

describe("dashboard formatters", () => {
  it("parasal değerleri doğru biçimler", () => {
    expect(formatMoney(2.256, 2)).toBe("$2.26");
    expect(formatMoney("3", 4)).toBe("$3.0000");
  });

  it("date range olmayan veride '-' döner", () => {
    expect(formatDateRange(null, null)).toBe("-");
  });
});
