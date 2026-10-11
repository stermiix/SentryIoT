import type { Agente, Canal, EstadoDaProposta, ResultadoDoEfeito, TipoDeEvento } from "./types";

// Como cada valor do log aparece na tela. São Maps, e não objetos literais, para que um valor
// como "toString" ou "constructor" nunca encontre uma chave herdada do protótipo.

export const ROTULO_DO_EVENTO = new Map<TipoDeEvento, string>([
  ["janelas_classificadas", "Janelas classificadas"],
  ["incidente_aberto", "Incidente aberto"],
  ["incidente_atualizado", "Incidente atualizado"],
  ["incidente_encerrado", "Incidente encerrado"],
  ["llm_chamada", "Chamada à IA"],
  ["tool_chamada", "Chamada de tool"],
  ["recomendacao_emitida", "Recomendação emitida"],
  ["acao_proposta", "Proposta criada"],
  ["acao_aprovada", "Aprovada"],
  ["acao_rejeitada", "Rejeitada"],
  ["acao_executada", "Executada"],
  ["acao_desfeita", "Desfeita"],
  ["efeito_verificado", "Efeito verificado"],
  ["catalogo_ampliado", "Promovida ao catálogo"],
  ["recusa", "Recusada pelo servidor"],
]);

// Nome de cada agente como aparece na tela. No log vai sem acento (`AGENTES` em tipos.py).
export const NOME_DO_AGENTE = new Map<Agente, string>([
  ["triagem", "Triagem"],
  ["decisao", "Decisão"],
  ["execucao", "Execução"],
]);

export const RESULTADO_DO_EFEITO = new Map<ResultadoDoEfeito, string>([
  ["cessou", "o incidente cessou"],
  ["diminuiu", "o incidente diminuiu"],
  ["persiste", "o incidente persiste"],
]);

export const ESTADO_DA_PROPOSTA = new Map<EstadoDaProposta, string>([
  ["aguardando_aprovacao", "Aguardando aprovação"],
  ["liberada", "Liberada"],
  ["rejeitada", "Rejeitada"],
  ["executada", "Executada"],
  ["desfeita", "Desfeita"],
]);

// "pelo terminal", "pela interface": o canal por onde a pessoa decidiu.
export const PELO_CANAL = new Map<Canal, string>([
  ["terminal", "pelo terminal"],
  ["interface", "pela interface"],
]);

export function rotulo<T>(mapa: Map<T, string>, valor: T): string {
  return mapa.get(valor) ?? String(valor);
}
