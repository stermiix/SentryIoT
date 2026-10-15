// Gera `src/design-system/tokens.css` a partir de `src/design-system/tokens.json`, no mesmo formato
// que a página do design system usa: as cores e as sombras do primeiro tema em `:root`, os outros
// grupos de tokens como variáveis, uma classe por estilo de texto e um `@font-face` por fonte.
//
//     npm run tokens
//
// O `tokens.json` é o arquivo do design system; o `tokens.css` não se edita à mão. Um teste
// (`src/design-system/tokens.test.ts`) confere se o CSS versionado é o que este script gera.
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PASTA = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "design-system");
const PROPRIEDADES_DO_ESTILO = [
  ["fontSize", "font-size"],
  ["lineHeight", "line-height"],
  ["fontWeight", "font-weight"],
  ["letterSpacing", "letter-spacing"],
  ["fontStyle", "font-style"],
];

/** Um valor de cor: `{outro-token}` vira `var(--outro-token)`; o resto vai como está. */
function valorDeCor(valor) {
  const alias = /^\{([A-Za-z0-9][A-Za-z0-9_.-]*)\}$/.exec(valor);
  return alias ? `var(--${alias[1]})` : valor;
}

/** O valor de um token no tema, ou no primeiro tema quando o token não define aquele. */
function noTema(token, tema, primeiro) {
  if (typeof token.value === "string") {
    return token.value;
  }
  return token.value[tema] ?? token.value[primeiro];
}

function px(valor) {
  return typeof valor === "number" ? `${valor}px` : valor;
}

export function gerarCss(tokens) {
  const temas = tokens.color.themes.map((tema) => tema.id);
  const primeiro = temas[0];
  const linhas = [`/* Gerado por scripts/gerar-tokens.mjs a partir de tokens.json (${tokens.name}). Não editar à mão. */`, ""];

  const blocoDoTema = (tema) => [
    ...tokens.color.tokens.map((token) => `  --${token.name}: ${valorDeCor(noTema(token, tema, primeiro))};`),
    ...(tokens.shadow?.tokens ?? []).map((token) => `  --${token.name}: ${noTema(token, tema, primeiro)};`),
  ];
  linhas.push(`:root, [data-theme="${primeiro}"] {`, ...blocoDoTema(primeiro), "}", "");
  for (const tema of temas.slice(1)) {
    linhas.push(`[data-theme="${tema}"] {`, ...blocoDoTema(tema), "}", "");
  }

  const outros = Object.entries(tokens).filter(
    ([chave, valor]) => !["name", "version", "meta", "color", "type", "shadow"].includes(chave) && Array.isArray(valor?.tokens),
  );
  linhas.push(":root {");
  for (const [chave, familia] of outros) {
    // Número sem unidade é px só nas medidas; em z-index e opacidade fica como está.
    const medida = ["spacing", "radius", "size"].includes(chave);
    for (const token of familia.tokens) {
      linhas.push(`  --${token.name}: ${medida ? px(token.value) : token.value};`);
    }
  }
  for (const [chave, pilha] of Object.entries(tokens.type.families)) {
    linhas.push(`  --font-${chave}: ${pilha};`);
  }
  linhas.push("}", "");

  for (const grupo of tokens.type.groups) {
    for (const estilo of grupo.styles) {
      linhas.push(`.${estilo.name} {`, `  font-family: var(--font-${estilo.family ?? grupo.family});`);
      for (const [campo, propriedade] of PROPRIEDADES_DO_ESTILO) {
        const valor = estilo[campo];
        if (valor !== undefined) {
          // Peso e altura de linha sem unidade são números do CSS; os outros números são px.
          const semUnidade = campo === "fontWeight" || (campo === "lineHeight" && typeof valor === "number");
          linhas.push(`  ${propriedade}: ${semUnidade ? valor : px(valor)};`);
        }
      }
      linhas.push("}");
    }
  }
  linhas.push("");

  for (const fonte of tokens.type.fonts) {
    const arquivo = fonte.file.includes("/") ? fonte.file : `fonts/${fonte.file}`;
    linhas.push(
      "@font-face {",
      `  font-family: "${fonte.family}";`,
      `  src: url("./${arquivo}") format("woff2");`,
      `  font-weight: ${fonte.weight};`,
      `  font-style: ${fonte.style ?? "normal"};`,
      "  font-display: swap;",
      "}",
    );
  }
  return `${linhas.join("\n")}\n`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const tokens = JSON.parse(readFileSync(join(PASTA, "tokens.json"), "utf-8"));
  writeFileSync(join(PASTA, "tokens.css"), gerarCss(tokens));
  console.log("tokens.css gerado em src/design-system/.");
}
