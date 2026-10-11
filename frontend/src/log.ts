import { conferirEvento } from "./contrato";
import type {
  Evento,
  ExecucaoView,
  Incidente,
  IncidenteView,
  MarcacaoView,
  PropostaView,
  ResumoGeral,
} from "./types";

// O log de exemplo, servido de `public/dados/`. O BASE_URL mantém o caminho certo quando o app é
// servido em um subcaminho.
export const CAMINHO_DO_LOG = `${import.meta.env.BASE_URL}dados/incidente_flood.jsonl`;
// Quantas linhas um aviso cita pelo número antes de resumir o resto.
const LINHAS_POR_AVISO = 8;

export interface LogLido {
  /** Eventos válidos, sem repetição, na ordem do `id`. */
  eventos: Evento[];
  /** O que foi descartado ou reordenado na leitura, para mostrar na tela. */
  avisos: string[];
}

function citarLinhas(linhas: number[]): string {
  const citadas = linhas.slice(0, LINHAS_POR_AVISO).join(", ");
  return linhas.length > LINHAS_POR_AVISO ? `${citadas} e mais ${linhas.length - LINHAS_POR_AVISO}` : citadas;
}

/**
 * Posição do evento na sequência do log: o número no fim do `id` (`ev-000012` dá 12). Um id sem
 * número vai para o fim, na ordem do arquivo.
 */
function posicaoDoId(id: string): number {
  const achado = /(\d+)$/.exec(id);
  return achado ? Number(achado[1]) : Number.POSITIVE_INFINITY;
}

/**
 * Lê o texto do log (uma linha, um evento). Cada linha é conferida contra o contrato, e a que não
 * serve é descartada, com o número dela num aviso: uma linha ruim não derruba a tela.
 *
 * A última linha sem quebra de linha no fim é ignorada: no modo ao vivo, ela pode estar sendo
 * gravada. Evento com `id` repetido fica só na primeira vez em que aparece. Os eventos voltam em
 * ordem de `id`, que é a ordem em que foram gravados, e não a das linhas do arquivo.
 */
export function lerLog(texto: string): LogLido {
  const linhas = texto.split("\n");
  const avisos: string[] = [];
  const ultima = linhas.pop() ?? "";
  if (ultima.trim().length > 0) {
    avisos.push(
      `A linha ${linhas.length + 1} não termina em quebra de linha e foi ignorada: pode estar sendo gravada.`,
    );
  }

  const descartadas: string[] = [];
  const repetidas: number[] = [];
  const vistos = new Set<string>();
  const lidos: Evento[] = [];
  linhas.forEach((linha, indice) => {
    if (linha.trim().length === 0) {
      return;
    }
    const numero = indice + 1;
    let valor: unknown;
    try {
      valor = JSON.parse(linha);
    } catch {
      descartadas.push(`${numero} (não é um JSON válido)`);
      return;
    }
    const conferido = conferirEvento(valor);
    if (!conferido.evento) {
      descartadas.push(`${numero} (${conferido.problema})`);
      return;
    }
    if (vistos.has(conferido.evento.id)) {
      repetidas.push(numero);
      return;
    }
    vistos.add(conferido.evento.id);
    lidos.push(conferido.evento);
  });

  if (descartadas.length > 0) {
    const citadas = descartadas.slice(0, LINHAS_POR_AVISO).join("; ");
    const resto = descartadas.length > LINHAS_POR_AVISO ? `; e mais ${descartadas.length - LINHAS_POR_AVISO}` : "";
    avisos.push(`Linhas fora do contrato, descartadas: ${citadas}${resto}.`);
  }
  if (repetidas.length > 0) {
    avisos.push(`Linhas com id de evento repetido, descartadas: ${citarLinhas(repetidas)}.`);
  }

  // O sort é estável: eventos com a mesma posição ficam na ordem do arquivo.
  const eventos = [...lidos].sort((a, b) => posicaoDoId(a.id) - posicaoDoId(b.id));
  if (eventos.some((evento, indice) => evento !== lidos[indice])) {
    avisos.push("Os eventos não estão em ordem no arquivo. A tela usa a ordem dos ids.");
  }
  return { eventos, avisos };
}

/** Busca o log no caminho estático servido pelo Vite e o lê com `lerLog`. */
export async function carregarLog(caminho = CAMINHO_DO_LOG): Promise<LogLido> {
  const resposta = await fetch(caminho);
  if (!resposta.ok) {
    throw new Error(
      `não foi possível carregar o log em ${caminho} (HTTP ${resposta.status}). ` +
        "Confira se public/dados/incidente_flood.jsonl existe (npm run sync:log copia o exemplo de codigo/mcp/exemplos/).",
    );
  }
  return lerLog(await resposta.text());
}

export interface Agregado {
  resumo: ResumoGeral;
  incidentes: IncidenteView[];
  /** Eventos que não cabem no ponto em que aparecem (aprovar proposta que não existe, por exemplo). */
  avisos: string[];
}

interface Montagem extends Omit<IncidenteView, "incidente" | "abertoEm"> {
  incidente: Incidente | null;
  abertoEm: string;
}

/**
 * Agrupa os eventos por incidente, soma os contadores globais e reconstrói o estado de cada
 * proposta, seguindo as regras do `reconstruir` de `codigo/mcp/acoes.py`. Espera os eventos
 * na ordem do `id`, como saem de `lerLog`.
 *
 * Um incidente só entra na fila se o log tem o evento de abertura dele. Eventos que citam outro
 * incidente ficam contados à parte (`eventosSemAbertura`). Um evento que não cabe no estado em
 * que aparece não muda esse estado e gera um aviso, mas continua no histórico.
 */
export function agregar(eventos: Evento[]): Agregado {
  const avisos: string[] = [];
  const abertos = new Set(
    eventos.filter((evento) => evento.tipo === "incidente_aberto").map((evento) => evento.incidente as string),
  );
  const montagens = new Map<string, Montagem>();
  const propostas = new Map<string, PropostaView>();
  const execucoes = new Map<string, ExecucaoView>();
  const semAbertura = new Map<string, number>();
  let janelasClassificadas = 0;
  let chamadasLLM = 0;
  let tokens = 0;

  for (const evento of eventos) {
    if (evento.tipo === "janelas_classificadas") {
      janelasClassificadas += evento.dados.janelas;
    }
    if (evento.tipo === "llm_chamada") {
      // Contadas aqui, e não por incidente, para que chamadas e tokens do resumo sejam sempre
      // do mesmo conjunto de eventos, mesmo que uma chamada venha sem incidente.
      chamadasLLM += 1;
      tokens += evento.dados.tokens_entrada + evento.dados.tokens_saida;
    }
    if (evento.incidente === null) {
      continue;
    }
    if (!abertos.has(evento.incidente)) {
      semAbertura.set(evento.incidente, (semAbertura.get(evento.incidente) ?? 0) + 1);
      continue;
    }

    let montagem = montagens.get(evento.incidente);
    if (!montagem) {
      montagem = {
        id: evento.incidente,
        incidente: null,
        abertoEm: "",
        eventos: [],
        chamadasLLM: 0,
        tokensEntrada: 0,
        tokensSaida: 0,
        recomendacoes: [],
        propostas: [],
        marcacao: null,
      };
      montagens.set(evento.incidente, montagem);
    }
    montagem.eventos.push(evento);
    const onde = `${evento.id} (${evento.tipo})`;

    switch (evento.tipo) {
      case "incidente_aberto":
        if (montagem.incidente) {
          avisos.push(`${onde}: o incidente ${montagem.id} já tinha sido aberto. O evento foi ignorado.`);
        } else {
          montagem.incidente = evento.dados;
          montagem.abertoEm = evento.instante;
        }
        break;
      case "incidente_atualizado":
      case "incidente_encerrado":
        if (!montagem.incidente) {
          avisos.push(`${onde}: vem antes da abertura do incidente ${montagem.id}. O evento foi ignorado.`);
        } else if (montagem.incidente.estado === "encerrado") {
          avisos.push(`${onde}: o incidente ${montagem.id} já estava encerrado. O evento foi ignorado.`);
        } else {
          montagem.incidente = evento.dados;
        }
        break;
      case "llm_chamada":
        montagem.chamadasLLM += 1;
        montagem.tokensEntrada += evento.dados.tokens_entrada;
        montagem.tokensSaida += evento.dados.tokens_saida;
        break;
      case "recomendacao_emitida": {
        montagem.recomendacoes.push(evento);
        const desconhecidas = evento.dados.propostas.filter((id) => !propostas.has(id));
        if (desconhecidas.length > 0) {
          avisos.push(`${onde}: cita proposta que não existe até este ponto (${desconhecidas.join(", ")}).`);
        }
        break;
      }
      case "acao_proposta": {
        const dados = evento.dados;
        if (propostas.has(dados.id)) {
          avisos.push(`${onde}: a proposta ${dados.id} já existe. O evento foi ignorado.`);
          break;
        }
        // Como no `reconstruir`, o estado gravado não é aceito como veio: a proposta nasce
        // aguardando aprovação se é de risco alto, e liberada se é de risco baixo. Se o que veio
        // não confere, ela fica aguardando aprovação, que é o lado seguro.
        const deRiscoAlto = dados.risco === "alto";
        const confere =
          dados.exige_aprovacao === deRiscoAlto &&
          dados.estado === (deRiscoAlto ? "aguardando_aprovacao" : "liberada") &&
          (dados.motivos_de_risco_alto.length > 0) === deRiscoAlto;
        if (!confere) {
          avisos.push(`${onde}: a proposta ${dados.id} não confere com o próprio risco. Ela fica aguardando aprovação.`);
        }
        const proposta: PropostaView = {
          id: dados.id,
          acao: dados.acao,
          alvo: dados.alvo,
          justificativa: dados.justificativa,
          nova: dados.nova,
          risco: dados.risco,
          exigeAprovacao: dados.exige_aprovacao || !confere,
          motivosDeRiscoAlto: dados.motivos_de_risco_alto,
          estado: confere && !deRiscoAlto ? "liberada" : "aguardando_aprovacao",
          criadaEm: evento.instante,
          decisoes: [],
          execucoes: [],
          promovida: false,
        };
        propostas.set(proposta.id, proposta);
        montagem.propostas.push(proposta);
        break;
      }
      case "acao_aprovada":
      case "acao_rejeitada": {
        const proposta = propostas.get(evento.dados.proposta);
        if (!proposta) {
          avisos.push(`${onde}: a proposta ${evento.dados.proposta} não existe até este ponto.`);
        } else if (proposta.estado !== "aguardando_aprovacao") {
          avisos.push(`${onde}: a proposta ${proposta.id} não aguarda aprovação (está ${proposta.estado}).`);
        } else {
          proposta.estado = evento.tipo === "acao_aprovada" ? "liberada" : "rejeitada";
          proposta.decisoes.push({
            tipo: evento.tipo,
            instante: evento.instante,
            canal: evento.dados.canal,
            motivo: evento.dados.motivo,
          });
        }
        break;
      }
      case "acao_executada": {
        const dados = evento.dados;
        const proposta = propostas.get(dados.proposta);
        if (!proposta) {
          avisos.push(`${onde}: a proposta ${dados.proposta} não existe até este ponto.`);
        } else if (execucoes.has(dados.id)) {
          avisos.push(`${onde}: a execução ${dados.id} já existe.`);
        } else if (proposta.estado !== "liberada") {
          avisos.push(`${onde}: a proposta ${proposta.id} não está liberada (está ${proposta.estado}).`);
        } else if (dados.acao !== proposta.acao || dados.alvo !== proposta.alvo || dados.estado !== "aplicada") {
          avisos.push(`${onde}: a execução ${dados.id} não aplica o que a proposta ${proposta.id} descreve.`);
        } else {
          const execucao: ExecucaoView = {
            id: dados.id,
            estado: "aplicada",
            aplicadaEm: dados.aplicada_em,
            desfeitaEm: null,
            efeitos: [],
          };
          execucoes.set(execucao.id, execucao);
          proposta.execucoes.push(execucao);
          proposta.estado = "executada";
        }
        break;
      }
      case "acao_desfeita": {
        const execucao = execucoes.get(evento.dados.id);
        if (!execucao) {
          avisos.push(`${onde}: a execução ${evento.dados.id} não existe até este ponto.`);
        } else if (execucao.estado !== "aplicada" || evento.dados.desfeita_em === null) {
          avisos.push(`${onde}: a execução ${execucao.id} já foi desfeita ou vem sem o instante.`);
        } else {
          execucao.estado = "desfeita";
          execucao.desfeitaEm = evento.dados.desfeita_em;
          const proposta = propostas.get(evento.dados.proposta);
          if (proposta) {
            proposta.estado = "desfeita";
          }
        }
        break;
      }
      case "efeito_verificado": {
        const execucao = execucoes.get(evento.dados.execucao);
        if (!execucao) {
          avisos.push(`${onde}: a execução ${evento.dados.execucao} não existe até este ponto.`);
        } else {
          execucao.efeitos.push({
            instante: evento.instante,
            resultado: evento.dados.resultado,
            observacao: evento.dados.observacao,
          });
        }
        break;
      }
      case "catalogo_ampliado": {
        const proposta = propostas.get(evento.dados.proposta);
        if (!proposta) {
          avisos.push(`${onde}: a proposta ${evento.dados.proposta} não existe até este ponto.`);
        } else if (!proposta.nova || proposta.estado !== "executada") {
          avisos.push(`${onde}: a proposta ${proposta.id} não é de uma ação nova aplicada.`);
        } else {
          proposta.promovida = true;
        }
        break;
      }
      case "incidente_marcado_resolvido": {
        const marcacao: MarcacaoView = {
          instante: evento.instante,
          canal: evento.dados.canal,
          usuario: evento.dados.usuario,
          motivo: evento.dados.motivo ?? null,
        };
        // Vale a primeira marca. Uma segunda fica só no histórico.
        montagem.marcacao ??= marcacao;
        break;
      }
      default:
        break;
    }
  }

  const incidentes: IncidenteView[] = [];
  for (const montagem of montagens.values()) {
    // Todo incidente que chega aqui tem abertura no log; a checagem só satisfaz os tipos.
    if (montagem.incidente) {
      incidentes.push({ ...montagem, incidente: montagem.incidente });
    }
  }
  const eventosSemAbertura = Array.from(semAbertura.values()).reduce((soma, quantos) => soma + quantos, 0);
  const incidentesSemAbertura = Array.from(semAbertura.keys());
  if (eventosSemAbertura > 0) {
    avisos.push(
      `${eventosSemAbertura} evento(s) de incidente sem abertura no log ` +
        `(${incidentesSemAbertura.slice(0, LINHAS_POR_AVISO).join(", ")}): ficam fora da fila e não contam como incidente.`,
    );
  }

  return {
    resumo: {
      janelasClassificadas,
      totalIncidentes: incidentes.length,
      chamadasLLM,
      tokens,
      eventosSemAbertura,
      incidentesSemAbertura,
    },
    incidentes,
    avisos,
  };
}
