import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// W trybie deweloperskim (npm run dev) zapytania /api trafiają do backendu w Rust.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
  build: {
    outDir: "dist",
  },
});
