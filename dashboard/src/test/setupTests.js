import "@testing-library/jest-dom/vitest";
import { afterAll, afterEach, beforeAll } from "vitest";
import { server } from "./server";
import { resetMockState } from "./mocks/handlers";

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  resetMockState();
  localStorage.clear();
  document.documentElement.setAttribute("data-theme", "light");
});
afterAll(() => server.close());
