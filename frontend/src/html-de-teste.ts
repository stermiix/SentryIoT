import { expect } from "vitest";

// Ajudantes para os testes que desenham as telas com `react-dom/server` e procuram texto no HTML.

/** O HTML do elemento que começa com `class="<classe>`, até o fim dele. */
export function recorte(html: string, classe: string): string {
  const inicio = html.indexOf(`class="${classe}`);
  expect(inicio, `painel ${classe}`).toBeGreaterThanOrEqual(0);
  const abertura = html.lastIndexOf("<", inicio);
  const tag = /^<(\w+)/.exec(html.slice(abertura))![1];
  let profundidade = 0;
  const marcas = new RegExp(`<${tag}[\\s>]|</${tag}>`, "g");
  marcas.lastIndex = abertura;
  for (let achado = marcas.exec(html); achado; achado = marcas.exec(html)) {
    profundidade += achado[0].startsWith("</") ? -1 : 1;
    if (profundidade === 0) {
      return html.slice(abertura, marcas.lastIndex);
    }
  }
  throw new Error(`o elemento ${classe} não fecha`);
}

/** O texto dentro de um trecho de HTML, sem as marcas e sem os comentários que o React põe entre textos. */
export function textoDe(html: string): string {
  let texto = "";
  let dentroDeMarca = false;
  for (const caractere of html) {
    if (caractere === "<") {
      dentroDeMarca = true;
    } else if (caractere === ">") {
      dentroDeMarca = false;
    } else if (!dentroDeMarca) {
      texto += caractere;
    }
  }
  return texto.replace(/&quot;/g, '"').replace(/&#x27;/g, "'");
}
