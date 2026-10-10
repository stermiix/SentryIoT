import type { Evento, Incidente, IncidenteView, ResumoGeral } from "./types";

// Os três tipos de evento de incidente do contrato (`EVENTOS` em codigo/mcp/tipos.py). Cada um
// traz o incidente inteiro em `dados`; o último deles no log é o estado atual.
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
  return texto.split("\n").flatMap((linha, indice) => {
    if (linha.trim().length === 0) {
      return [];
    }
    try {
      return [JSON.parse(linha) as Evento];
    } catch {
      // A mensagem crua do JSON.parse não diz onde está o problema; a linha diz.
      throw new Error(`a linha ${indice + 1} do log em ${caminho} não é um JSON válido.`);
    }
  });
}

/** Agrupa os eventos por incidente e soma os contadores globais (janelas, incidentes, chamadas à LLM, tokens). */
export function agregar(eventos: Evento[]): { resumo: ResumoGeral; incidentes: IncidenteView[] } {
  const porIncidente = new Map<string, IncidenteView>();
  let janelasClassificadas = 0;
  let chamadasLLM = 0;
  let tokens = 0;

  for (const evento of eventos) {
    if (evento.tipo === "janelas_classificadas") {
      janelasClassificadas += Number(evento.dados.janelas ?? 0);
    }
    if (evento.tipo === "llm_chamada") {
      // Contados aqui, e não por incidente, para que chamadas e tokens do resumo sejam sempre
      // do mesmo conjunto de eventos, mesmo que uma chamada venha sem incidente.
      chamadasLLM += 1;
      tokens += Number(evento.dados.tokens_entrada ?? 0) + Number(evento.dados.tokens_saida ?? 0);
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
    resumo: { janelasClassificadas, totalIncidentes: porIncidente.size, chamadasLLM, tokens },
    incidentes: Array.from(porIncidente.values()),
  };
}
