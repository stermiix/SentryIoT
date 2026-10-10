import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Configuração mínima: um app estático que lê o log de eventos de `public/dados/` (ver
// `scripts/sync-log.mjs`). Sem backend, sem proxy de API — isso entra quando o modo ao vivo
// existir.
export default defineConfig({
  plugins: [react()],
});
