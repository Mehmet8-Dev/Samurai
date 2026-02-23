import React from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/instrument-sans/500.css";
import "@fontsource/instrument-sans/600.css";
import "@fontsource/public-sans/400.css";
import "@fontsource/public-sans/500.css";
import "@fontsource/public-sans/600.css";
import "@fontsource/ibm-plex-mono/500.css";
import { AppProviders } from "./app/providers";
import { AppRouter } from "./app/router";
import "./styles.css";

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <AppProviders>
      <AppRouter />
    </AppProviders>
  </React.StrictMode>
);
