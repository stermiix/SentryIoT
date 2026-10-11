// Copia o log de exemplo de `codigo/mcp/exemplos/` para `public/dados/`, de onde o app estático
// lê no modo replay. A cópia é versionada: rode este script só depois de regenerar o log
// (`python -m codigo.mcp.roteiro --sobrescrever`).
//
// Link simbólico é recusado na origem e no destino, em qualquer parte do caminho. Sem isso, um
// link versionado no lugar do log faria a cópia levar para public/, e daí para o dist/, um arquivo
// de fora do repositório, ou sobrescrever o arquivo para onde o link aponta.
import { copyFileSync, lstatSync, mkdirSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const frontend = join(dirname(fileURLToPath(import.meta.url)), "..");
const raiz = join(frontend, "..");
const origem = join(raiz, "codigo", "mcp", "exemplos", "incidente_flood.jsonl");
const pastaDeDestino = join(frontend, "public", "dados");
const destino = join(pastaDeDestino, "incidente_flood.jsonl");

function falhar(mensagem) {
  console.error(`sync:log: ${mensagem} Nada foi copiado.`);
  process.exit(1);
}

/** Informações do caminho sem seguir link, ou null se ele não existe. */
function informacoes(caminho) {
  try {
    return lstatSync(caminho);
  } catch (erro) {
    if (erro.code === "ENOENT") {
      return null;
    }
    throw erro;
  }
}

/** Recusa link simbólico em cada parte do caminho, de `base` (exclusive) até `caminho`. */
function semLink(base, caminho) {
  let atual = base;
  for (const parte of relative(base, caminho).split(sep)) {
    atual = join(atual, parte);
    const info = informacoes(atual);
    if (info === null) {
      return;
    }
    if (info.isSymbolicLink()) {
      falhar(`${atual} é um link simbólico.`);
    }
  }
}

semLink(raiz, origem);
if (!informacoes(origem)?.isFile()) {
  falhar(`${origem} não existe ou não é um arquivo comum. Gere o log com 'python -m codigo.mcp.roteiro --sobrescrever'.`);
}

semLink(frontend, destino);
mkdirSync(pastaDeDestino, { recursive: true });
const doDestino = informacoes(destino);
if (doDestino !== null && !doDestino.isFile()) {
  falhar(`${destino} existe e não é um arquivo comum.`);
}

copyFileSync(origem, destino);
console.log(`Log copiado de ${origem} para ${destino}`);
