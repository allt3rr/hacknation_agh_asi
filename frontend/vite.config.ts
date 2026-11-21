import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// W trybie deweloperskim (npm run dev / preview) zapytania /api trafiają do backendu w Rust
// (ten sam origin, więc cookie sesji SameSite=Strict działa). Adres: ASI_API, domyślnie :8080.
export default defineConfig(({ mode }) => {
  const api = loadEnv(mode, ".", "ASI_").ASI_API ?? "http://127.0.0.1:8080";
  return {
    plugins: [react(), tailwindcss()],
    server: {
      port: 5173,
      proxy: { "/api": api },
    },
    preview: {
      proxy: { "/api": api },
    },
    build: {
      outDir: "dist",
    },
  };
});
