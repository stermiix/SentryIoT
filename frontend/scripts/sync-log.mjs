// Copia o log de exemplo de `codigo/mcp/exemplos/` para `public/dados/`, de onde o app estático
// lê no modo replay. Rode depois de regenerar o log (`python -m codigo.mcp.roteiro
// --sobrescrever`) ou uma vez, logo depois do `npm install` num clone novo.
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const aqui = dirname(fileURLToPath(import.meta.url));
const origem = join(aqui, "..", "..", "codigo", "mcp", "exemplos", "incidente_flood.jsonl");
const pastaDeDestino = join(aqui, "..", "public", "dados");
const destino = join(pastaDeDestino, "incidente_flood.jsonl");

mkdirSync(pastaDeDestino, { recursive: true });
copyFileSync(origem, destino);
console.log(`Log copiado de ${origem} para ${destino}`);
