import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// App estático que lê o log de eventos de `public/dados/` (ver `scripts/sync-log.mjs`). No
// desenvolvimento, `/api` é encaminhado ao backend fino (`python -m codigo.api`, em
// `codigo/api/`). Com a porta 8000 ocupada por outra coisa, suba o backend em outra porta e
// aponte `VITE_API_URL` para ela, no ambiente ou num `.env.local` desta pasta (ignorado pelo git).
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "VITE_");
  return {
    plugins: [react()],
    server: {
      proxy: {
        "/api": env.VITE_API_URL || "http://127.0.0.1:8000",
      },
    },
  };
});
