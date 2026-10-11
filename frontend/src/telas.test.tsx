import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import textoDoExemplo from "../public/dados/incidente_flood.jsonl?raw";
import DetalheDoIncidente from "./components/DetalheDoIncidente";
import FilaDeIncidentes from "./components/FilaDeIncidentes";
import ResumoMetricas from "./components/ResumoMetricas";
import { agregar, lerLog } from "./log";
import type { Evento } from "./types";

// As telas 1 e 2 desenhadas no Node, com react-dom/server, a partir do log de exemplo e de
// variações dele.

const { eventos: base } = lerLog(textoDoExemplo);

function telas(eventos: Evento[]): string {
  const { resumo, incidentes } = agregar(eventos);
  return (
    renderToString(<ResumoMetricas resumo={resumo} incidentes={incidentes} />) +
    renderToString(<FilaDeIncidentes resumo={resumo} incidentes={incidentes} selecionadoId={incidentes[0]?.id ?? null} onSelecionar={() => {}} />) +
    (incidentes[0] ? renderToString(<DetalheDoIncidente incidente={incidentes[0]} />) : "")
  );
}

/** Lê de novo o log de exemplo com alguns eventos alterados por `alterar`. */
function variacao(alterar: (evento: Record<string, any>) => void): Evento[] {
  const linhas = base.map((evento) => {
    const copia = structuredClone(evento) as Record<string, any>;
    alterar(copia);
    return JSON.stringify(copia);
  });
  const lido = lerLog(linhas.join("\n") + "\n");
  expect(lido.avisos).toEqual([]);
  return lido.eventos;
}

describe("telas 1 e 2", () => {
  it("mostram o instante de cada item do rastro e do histórico", () => {
    const html = telas(base);
    // O rastro mostra os sete primeiros eventos até alguém pedir todos; o histórico mostra todos.
    const rastro = base.filter((e) => e.tipo === "tool_chamada" || e.tipo === "llm_chamada").slice(0, 7);
    const historico = base.filter((e) => e.tipo.startsWith("acao_") || e.tipo === "efeito_verificado" || e.tipo === "recusa");
    for (const evento of [...rastro, ...historico]) {
      expect(html).toContain(`dateTime="${evento.instante}"`);
    }
  });

  it("mostram o id da proposta ou da execução em cada linha do histórico", () => {
    const html = telas(base);
    const historico = html.slice(html.indexOf('class="action-list"'), html.indexOf('class="replay-lock"'));
    const linhas = historico.split("<li").slice(1);
    expect(linhas.length).toBeGreaterThan(0);
    for (const linha of linhas) {
      expect(linha).toMatch(/class="event-id">(prop|exec|ev)-\d+</);
    }
  });

  it("dão à recusa sem proposta nem execução citada o id do próprio evento", () => {
    const eventos = variacao((evento) => {
      if (evento.tipo === "recusa") {
        evento.dados.argumentos = {};
      }
    });
    const recusa = eventos.find((evento) => evento.tipo === "recusa");
    expect(telas(eventos)).toContain(`class="event-id">${recusa!.id}</code>`);
  });

  it("listam cada proposta com risco, aprovação e estado", () => {
    const html = telas(base);
    for (const evento of base.filter((e) => e.tipo === "acao_proposta")) {
      expect(html).toContain(`class="event-id">${evento.dados.id}</code><strong>${evento.dados.acao}</strong>`);
    }
    expect(html).toContain("Exige aprovação humana");
    expect(html).toContain('class="risk risk-alto"');
  });

  it("dão à recomendação o nome do agente e as propostas ligadas", () => {
    const html = telas(base);
    const recomendacao = base.find((e) => e.tipo === "recomendacao_emitida");
    if (recomendacao?.tipo !== "recomendacao_emitida") {
      throw new Error("o log de exemplo não tem recomendação");
    }
    expect(html).toContain("Agente de decisão");
    for (const id of recomendacao.dados.propostas) {
      expect(html).toContain(`class="event-id">${id}</code>`);
    }
  });

  it("escapam HTML vindo do log", () => {
    const eventos = variacao((evento) => {
      if (evento.tipo === "recomendacao_emitida") {
        evento.dados.texto = "<b>negrito</b>\nsegunda linha <script>alert(2)</script>";
      }
      if (evento.tipo === "recusa") {
        evento.dados.tool = '"><script>alert(1)</script>';
        evento.dados.mensagem = "<img src=x onerror=alert(1)> javascript:alert(1)";
      }
    });
    const html = telas(eventos);
    expect(html).not.toMatch(/<(script|img|b)[\s>]/);
    expect(html).toContain("&lt;script&gt;alert(2)&lt;/script&gt;");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    // A quebra de linha da recomendação chega ao HTML; o CSS (white-space: pre-line) a mostra.
    expect(html).toContain("&lt;/b&gt;\nsegunda linha");
  });

  it("mostram a marca de já resolvido na fila e no detalhe", () => {
    const abertura = base.findIndex((e) => e.tipo === "incidente_aberto");
    const incidente = base[abertura].incidente!;
    const marcacao = {
      id: "ev-999999",
      instante: base[abertura].instante,
      tipo: "incidente_marcado_resolvido",
      incidente,
      dados: { incidente, canal: "interface", usuario: "operador", motivo: "Bloqueado no firewall da borda." },
    };
    const { eventos } = lerLog([...base.slice(0, abertura + 1), marcacao].map((e) => JSON.stringify(e)).join("\n") + "\n");
    const html = telas(eventos);
    expect(html).toContain("Já resolvido");
    expect(html).toContain("Marcado como já resolvido");
    expect(html).toContain("operador");
    expect(html).toContain("pela interface");
    expect(html).toContain("Bloqueado no firewall da borda.");
  });

  it("mostram a categoria DDoS+DoS do modelo", () => {
    const eventos = variacao((evento) => {
      if (evento.tipo.startsWith("incidente_")) {
        evento.dados.categoria_do_modelo = "DDoS+DoS";
      }
    });
    expect(telas(eventos)).toContain("Saída do modelo: <strong>DDoS+DoS</strong>");
  });
});
