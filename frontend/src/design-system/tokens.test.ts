import { describe, expect, it } from "vitest";
import { gerarCss } from "../../scripts/gerar-tokens.mjs";
import ESTILO_DO_APP from "../estilo.css?raw";
import ESTILOS from "./styles.css?raw";
import tokens from "./tokens.json";
import TOKENS_CSS from "./tokens.css?raw";

// O tokens.css é gerado do tokens.json, e as telas só usam variáveis que existem.

const FONTES = new Set(Object.keys(import.meta.glob("./fonts/*.woff2")).map((caminho) => caminho.replace(/^\.\//, "")));
// Variáveis que os componentes põem no `style` de um elemento, e não em CSS.
const DEFINIDAS_NO_ELEMENTO = new Set(["pct"]);

function definidas(css: string): Set<string> {
  return new Set(Array.from(css.matchAll(/--([A-Za-z0-9_-]+)\s*:/g), (achado) => achado[1]));
}
function usadas(texto: string): string[] {
  return Array.from(texto.matchAll(/var\(--([A-Za-z0-9_-]+)/g), (achado) => achado[1]);
}

describe("tokens do design system", () => {
  it("o tokens.css versionado é o que scripts/gerar-tokens.mjs gera do tokens.json (rode npm run tokens)", () => {
    expect(TOKENS_CSS).toBe(gerarCss(tokens));
  });

  it("cada fonte do tokens.json existe em fonts/", () => {
    for (const fonte of tokens.type.fonts) {
      expect(FONTES.has(fonte.file), fonte.file).toBe(true);
    }
  });

  it("os componentes e as telas (TSX) só usam variáveis definidas", () => {
    const fontes = import.meta.glob<string>(["./components/*.tsx", "../telas/*.tsx", "../App.tsx"], { query: "?raw", import: "default", eager: true });
    expect(Object.keys(fontes).length).toBeGreaterThan(20);
    const todas = new Set([...definidas(TOKENS_CSS), ...definidas(ESTILOS), ...definidas(ESTILO_DO_APP), ...DEFINIDAS_NO_ELEMENTO]);
    const faltando = Object.entries(fontes).flatMap(([arquivo, texto]) => usadas(texto).filter((nome) => !todas.has(nome)).map((nome) => `${arquivo}: --${nome}`));
    expect(faltando).toEqual([]);
  });

  it("o CSS dos componentes e o das telas só usam variáveis definidas", () => {
    expect(ESTILOS.length).toBeGreaterThan(10_000);
    expect(ESTILO_DO_APP.length).toBeGreaterThan(500);
    const todas = new Set([...definidas(TOKENS_CSS), ...definidas(ESTILOS), ...definidas(ESTILO_DO_APP), ...DEFINIDAS_NO_ELEMENTO]);
    const faltando = [...usadas(ESTILOS), ...usadas(ESTILO_DO_APP)].filter((nome) => !todas.has(nome));
    expect(faltando).toEqual([]);
  });

  it("o CSS das telas não escreve cor à mão", () => {
    expect(ESTILO_DO_APP.match(/#[0-9a-fA-F]{3,8}\b|rgba?\(/g)).toBeNull();
  });
});
