import { render } from "@testing-library/react";
import { AppProviders } from "../app/providers";
import { AppRouter } from "../app/router";

export function renderApp(path = "/") {
  window.history.pushState({}, "Test", path);
  return render(
    <AppProviders>
      <AppRouter />
    </AppProviders>
  );
}
