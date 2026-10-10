import type { Evento, Incidente, IncidenteView, ResumoGeral } from "./types";

const EVENTOS_DE_INCIDENTE = new Set(["incidente_aberto", "incidente_atualizado", "incidente_encerrado"]);

/** Lê o log JSONL (uma linha, um evento) do caminho estático servido pelo Vite. */
export async function carregarLog(caminho = "/dados/incidente_flood.jsonl"): Promise<Evento[]> {
  const resposta = await fetch(caminho);
  if (!resposta.ok) {
    throw new Error(
      `não foi possível carregar o log em ${caminho} (HTTP ${resposta.status}). ` +
        "Rode 'npm run sync:log' para copiar o exemplo de codigo/mcp/exemplos/.",
    );
  }
  const texto = await resposta.text();
  return texto
    .split("\n")
    .map((linha) => linha.trim())
    .filter((linha) => linha.length > 0)
    .map((linha) => JSON.parse(linha) as Evento);
}

/** Agrupa os eventos por incidente e soma os contadores globais (janelas, incidentes, chamadas à LLM). */
export function agregar(eventos: Evento[]): { resumo: ResumoGeral; incidentes: IncidenteView[] } {
  const porIncidente = new Map<string, IncidenteView>();
  let janelasClassificadas = 0;
  let chamadasLLM = 0;

  for (const evento of eventos) {
    if (evento.tipo === "janelas_classificadas") {
      janelasClassificadas += Number(evento.dados.janelas ?? 0);
    }
    if (evento.tipo === "llm_chamada") {
      chamadasLLM += 1;
    }
    if (!evento.incidente) {
      continue;
    }

    let view = porIncidente.get(evento.incidente);
    if (!view) {
      view = {
        id: evento.incidente,
        incidente: null,
        eventos: [],
        chamadasLLM: 0,
        tokensEntrada: 0,
        tokensSaida: 0,
        recomendacoes: [],
      };
      porIncidente.set(evento.incidente, view);
    }

    view.eventos.push(evento);
    if (EVENTOS_DE_INCIDENTE.has(evento.tipo)) {
      view.incidente = evento.dados as Incidente;
    }
    if (evento.tipo === "llm_chamada") {
      view.chamadasLLM += 1;
      view.tokensEntrada += Number(evento.dados.tokens_entrada ?? 0);
      view.tokensSaida += Number(evento.dados.tokens_saida ?? 0);
    }
    if (evento.tipo === "recomendacao_emitida") {
      view.recomendacoes.push(evento);
    }
  }

  return {
    resumo: { janelasClassificadas, totalIncidentes: porIncidente.size, chamadasLLM },
    incidentes: Array.from(porIncidente.values()),
  };
}
