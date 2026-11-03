// O incidente de ponta a ponta: a abertura pelo classificador, cada agente com a conversa que teve com o
// modelo (o evento `conversa_do_agente`, desde o contrato 0.8.0) e o que ele deixou no log, e as decisões
// sobre as propostas entre um agente e outro. Tudo sai dos eventos do incidente, na ordem do log; nada é
// inventado. Num log anterior ao 0.8.0, as etapas aparecem sem a conversa.

import type { AgentName } from "./design-system";
import type {
  Evento,
  EventoDeConversa,
  EventoDeLLM,
  LugarDoModelo,
  MensagemDaConversa,
  MotivoDeParada,
  TipoDeEvento,
  VereditoDaTriagem,
} from "./types";

/** Um bloco da conversa como a tela mostra, já com o papel de cada mensagem dito em palavras. */
export type ItemDaConversa =
  /** O prompt de sistema, com as skills do agente. */
  | { tipo: "sistema"; texto: string }
  /** A primeira mensagem do usuário: o pedido do orquestrador. */
  | { tipo: "pedido"; texto: string }
  /** As outras mensagens do usuário: os avisos do laço (chamada repetida, volta sem tools...). */
  | { tipo: "aviso"; texto: string }
  /** A nota que quem grava põe no lugar das mensagens do meio de uma conversa longa demais. */
  | { tipo: "omitidas"; texto: string }
  /** Texto do modelo; `final` na última mensagem da conversa. */
  | { tipo: "modelo"; texto: string; final: boolean }
  /** Uma tool que o modelo pediu, com os argumentos como ele os escreveu (e formatados, quando são JSON). */
  | { tipo: "pedido_de_tool"; id: string; nome: string; argumentos: string; formatados: string | null }
  /** O que a tool devolveu ao modelo; `nome` é o da tool pedida com o mesmo id. */
  | { tipo: "resultado_de_tool"; respostaA: string | null; nome: string | null; texto: string; formatado: string | null };

const NOTA_DE_OMITIDAS = /^\[\d+ mensagens do meio da conversa omitidas no log\]$/;

/** O texto como JSON identado, quando ele é um JSON; senão, nulo. */
export function jsonFormatado(texto: string): string | null {
  const limpo = texto.trim();
  if (!limpo.startsWith("{") && !limpo.startsWith("[")) {
    return null;
  }
  try {
    return JSON.stringify(JSON.parse(limpo), null, 2);
  } catch {
    return null;
  }
}

/** As mensagens da conversa, na ordem, como blocos da tela. */
export function itensDaConversa(mensagens: MensagemDaConversa[]): ItemDaConversa[] {
  const nomeDoPedido = new Map<string, string>();
  const itens: ItemDaConversa[] = [];
  let pedidoVisto = false;
  mensagens.forEach((mensagem, indice) => {
    const ultima = indice === mensagens.length - 1;
    switch (mensagem.papel) {
      case "system":
        itens.push({ tipo: "sistema", texto: mensagem.texto });
        break;
      case "user":
        if (NOTA_DE_OMITIDAS.test(mensagem.texto.trim())) {
          itens.push({ tipo: "omitidas", texto: mensagem.texto });
        } else if (!pedidoVisto) {
          pedidoVisto = true;
          itens.push({ tipo: "pedido", texto: mensagem.texto });
        } else {
          itens.push({ tipo: "aviso", texto: mensagem.texto });
        }
        break;
      case "assistant": {
        const pedidas = mensagem.tools_pedidas ?? [];
        if (mensagem.texto.trim().length > 0) {
          itens.push({ tipo: "modelo", texto: mensagem.texto, final: ultima && pedidas.length === 0 });
        }
        for (const pedida of pedidas) {
          nomeDoPedido.set(pedida.id, pedida.nome);
          itens.push({ tipo: "pedido_de_tool", id: pedida.id, nome: pedida.nome, argumentos: pedida.argumentos, formatados: jsonFormatado(pedida.argumentos) });
        }
        break;
      }
      case "tool": {
        const respostaA = mensagem.resposta_a ?? null;
        itens.push({
          tipo: "resultado_de_tool",
          respostaA,
          nome: respostaA ? (nomeDoPedido.get(respostaA) ?? null) : null,
          texto: mensagem.texto,
          formatado: jsonFormatado(mensagem.texto),
        });
        break;
      }
    }
  });
  return itens;
}

// Os eventos que um agente deixa no log enquanto roda: aparecem dentro da etapa dele.
const DA_ETAPA = new Set<TipoDeEvento>([
  "atacante_apontado",
  "analise_emitida",
  "recomendacao_emitida",
  "sumario_emitido",
  "acao_proposta",
  "acao_executada",
  "acao_desfeita",
  "efeito_verificado",
  "incidente_encerrado",
  "catalogo_ampliado",
  "recusa",
]);
// Os eventos entre um agente e outro: a abertura e as decisões sobre o incidente e as propostas.
const DO_FLUXO = new Set<TipoDeEvento>(["incidente_aberto", "acao_aprovada", "acao_rejeitada", "incidente_marcado_resolvido"]);

export interface EtapaDoAgente {
  tipo: "agente";
  /** O id do evento que fecha a etapa (a conversa ou, num log antigo, a conclusão). */
  id: string;
  agente: AgentName;
  tarefa: "incidente" | "sumario";
  /** A rodada do orquestrador: a decisão abre uma rodada nova, e a execução é da rodada da decisão que a liberou. */
  rodada: number;
  modelo: string | null;
  onde: LugarDoModelo | null;
  /** Por que o laço parou; nulo enquanto o agente ainda roda. */
  motivo: MotivoDeParada | null;
  veredito: VereditoDaTriagem | null;
  chamadas: number;
  tokensEntrada: number;
  tokensSaida: number;
  segundos: number;
  /** A conversa; nula num log anterior ao contrato 0.8.0. */
  conversa: ItemDaConversa[] | null;
  /** Quantos caracteres a conversa tem, somando o texto e os argumentos. */
  caracteres: number;
  /** O que o agente deixou no log nesta etapa (proposta, execução, efeito, análise...). */
  produziu: Evento[];
  /** O agente começou e ainda não terminou, no fim de um log que ainda está sendo gravado (uma simulação). */
  emAndamento: boolean;
  /**
   * O agente começou e não terminou num log que já terminou (uma execução gravada da rodada): o laço parou
   * no meio, por um erro, sem gravar a conversa nem a conclusão.
   */
  interrompida: boolean;
}

export interface PassoDoFluxo {
  tipo: "evento";
  evento: Evento;
}

export type ItemDoFluxo = EtapaDoAgente | PassoDoFluxo;

interface Corrente {
  agente: AgentName | null;
  chamadas: EventoDeLLM[];
  produziu: Evento[];
}

const vazia = (): Corrente => ({ agente: null, chamadas: [], produziu: [] });

function caracteresDa(conversa: EventoDeConversa): number {
  return conversa.dados.mensagens.reduce(
    (soma, mensagem) => soma + mensagem.texto.length + (mensagem.tools_pedidas ?? []).reduce((parcial, pedida) => parcial + pedida.argumentos.length, 0),
    0,
  );
}

/**
 * O fluxo do incidente a partir dos eventos dele, na ordem do log. Uma etapa fecha na conversa do agente
 * (ou, num log sem conversa, na conclusão dele) e leva as chamadas ao modelo e o que ele gravou desde a
 * etapa anterior; o que vem logo depois da conversa, antes de outro agente começar (o sumário gravado
 * depois da conversa dele), também fica na etapa. A abertura e as decisões ficam entre as etapas.
 */
export function fluxoDoIncidente(eventos: Evento[], { terminado = false }: { terminado?: boolean } = {}): ItemDoFluxo[] {
  const fluxo: ItemDoFluxo[] = [];
  let corrente = vazia();
  let ultima: EtapaDoAgente | null = null;
  let concluida = false;
  let rodada = 0;

  const abrirEtapa = (agente: AgentName, tarefa: "incidente" | "sumario", fechamento: string): EtapaDoAgente => {
    if (agente === "decisao" && tarefa === "incidente") {
      rodada += 1;
    }
    const chamadas = corrente.chamadas.filter((chamada) => chamada.dados.agente === agente);
    const ultimaChamada = chamadas[chamadas.length - 1];
    const etapa: EtapaDoAgente = {
      tipo: "agente",
      id: fechamento,
      agente,
      tarefa,
      rodada: Math.max(1, rodada),
      modelo: ultimaChamada?.dados.modelo ?? null,
      onde: ultimaChamada?.dados.onde ?? null,
      motivo: null,
      veredito: null,
      chamadas: chamadas.length,
      tokensEntrada: chamadas.reduce((soma, chamada) => soma + chamada.dados.tokens_entrada, 0),
      tokensSaida: chamadas.reduce((soma, chamada) => soma + chamada.dados.tokens_saida, 0),
      segundos: chamadas.reduce((soma, chamada) => soma + chamada.dados.duracao_ms, 0) / 1000,
      conversa: null,
      caracteres: 0,
      produziu: corrente.produziu,
      emAndamento: false,
      interrompida: false,
    };
    fluxo.push(etapa);
    corrente = vazia();
    return etapa;
  };

  for (const evento of eventos) {
    switch (evento.tipo) {
      case "llm_chamada":
        corrente.chamadas.push(evento);
        corrente.agente = evento.dados.agente;
        ultima = null;
        break;
      case "conversa_do_agente": {
        const dados = evento.dados;
        const etapa = abrirEtapa(dados.agente, dados.tarefa ?? "incidente", evento.id);
        etapa.modelo = dados.modelo;
        etapa.onde = dados.onde ?? etapa.onde;
        etapa.motivo = dados.motivo;
        etapa.conversa = itensDaConversa(dados.mensagens);
        etapa.caracteres = caracteresDa(evento);
        ultima = etapa;
        concluida = false;
        break;
      }
      case "agente_concluido": {
        const dados = evento.dados;
        if (ultima && ultima.agente === dados.agente && ultima.tarefa === "incidente" && !concluida) {
          // A conclusão vem logo depois da conversa: completa a etapa.
          ultima.motivo = dados.motivo;
          ultima.veredito = dados.veredito;
        } else {
          // Log anterior à conversa: a etapa fecha na conclusão.
          const etapa = abrirEtapa(dados.agente, "incidente", evento.id);
          etapa.motivo = dados.motivo;
          etapa.veredito = dados.veredito;
          ultima = etapa;
        }
        concluida = true;
        break;
      }
      default:
        if (DO_FLUXO.has(evento.tipo)) {
          fluxo.push({ tipo: "evento", evento });
        } else if (DA_ETAPA.has(evento.tipo)) {
          if (corrente.chamadas.length > 0 || !ultima) {
            corrente.produziu.push(evento);
          } else {
            ultima.produziu.push(evento);
          }
        }
        break;
    }
  }

  // Sobrou um agente sem conversa nem conclusão: num log antigo, é o sumário da triagem, que não tinha
  // conclusão própria; num log que ainda está sendo gravado, um agente em andamento; num log que já
  // terminou (`terminado`), um agente interrompido.
  if (corrente.agente) {
    const sumario = corrente.produziu.some((evento) => evento.tipo === "sumario_emitido");
    const etapa = abrirEtapa(corrente.agente, sumario ? "sumario" : "incidente", `${corrente.chamadas[corrente.chamadas.length - 1]?.id ?? "fim"}`);
    etapa.emAndamento = !sumario && !terminado;
    etapa.interrompida = !sumario && terminado;
  } else if (corrente.produziu.length > 0) {
    fluxo.push(...corrente.produziu.map((evento): PassoDoFluxo => ({ tipo: "evento", evento })));
  }
  return fluxo;
}

/** Quantas etapas do fluxo trazem a conversa: zero num log anterior ao contrato 0.8.0. */
export function etapasComConversa(fluxo: ItemDoFluxo[]): number {
  return fluxo.filter((item) => item.tipo === "agente" && item.conversa !== null).length;
}
