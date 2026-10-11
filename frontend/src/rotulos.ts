import type { Agente, Canal, EstadoDaProposta, MotivoDeRecusa, ResultadoDoEfeito, TipoDeEvento } from "./types";

// Como cada valor do log aparece na tela. A tabela é escrita como `Record`, para que o TypeScript
// exija uma entrada para cada valor do contrato, e a busca é feita num `Map`, para que um valor
// como "toString" ou "constructor" nunca encontre uma chave herdada do protótipo.

function mapa<K extends string>(tabela: Record<K, string>): Map<K, string> {
  return new Map(Object.entries(tabela) as [K, string][]);
}

export const ROTULO_DO_EVENTO = mapa<TipoDeEvento>({
  janelas_classificadas: "Janelas classificadas",
  incidente_aberto: "Incidente aberto",
  incidente_atualizado: "Incidente atualizado",
  incidente_encerrado: "Incidente encerrado",
  incidente_marcado_resolvido: "Marcado como já resolvido",
  llm_chamada: "Chamada à IA",
  tool_chamada: "Chamada de tool",
  recomendacao_emitida: "Recomendação emitida",
  acao_proposta: "Proposta criada",
  acao_aprovada: "Aprovada",
  acao_rejeitada: "Rejeitada",
  acao_executada: "Executada",
  acao_desfeita: "Desfeita",
  efeito_verificado: "Efeito verificado",
  catalogo_ampliado: "Promovida ao catálogo",
  recusa: "Recusada pelo servidor",
});

// Nome de cada agente como aparece na tela. No log vai sem acento (`AGENTES` em tipos.py).
export const NOME_DO_AGENTE = mapa<Agente>({ triagem: "Triagem", decisao: "Decisão", execucao: "Execução" });

export const RESULTADO_DO_EFEITO = mapa<ResultadoDoEfeito>({
  cessou: "o incidente cessou",
  diminuiu: "o incidente diminuiu",
  persiste: "o incidente persiste",
});

export const ESTADO_DA_PROPOSTA = mapa<EstadoDaProposta>({
  aguardando_aprovacao: "Aguardando aprovação",
  liberada: "Liberada",
  rejeitada: "Rejeitada",
  executada: "Executada",
  desfeita: "Desfeita",
});

// "pelo terminal", "pela interface": o canal por onde a pessoa decidiu.
export const PELO_CANAL = mapa<Canal>({ terminal: "pelo terminal", interface: "pela interface" });

// Por que o servidor recusou a chamada, em palavras do sistema. A mensagem da recusa, que pode
// repetir um trecho do que o agente mandou, aparece à parte, entre aspas.
export const MOTIVO_DA_RECUSA = mapa<MotivoDeRecusa>({
  identificador_desconhecido: "identificador desconhecido",
  argumentos_invalidos: "argumentos inválidos",
  alvo_malformado: "alvo malformado",
  alvo_nao_permitido: "alvo não permitido",
  incidente_encerrado: "incidente encerrado",
  incidente_ja_resolvido: "incidente marcado como já resolvido",
  limite_de_propostas_pendentes: "limite de propostas aguardando aprovação",
  limite_de_propostas_liberadas: "limite de propostas liberadas e não executadas",
  acao_nova_incompleta: "ação nova incompleta",
  proposta_nao_liberada: "proposta não liberada",
  proposta_ja_executada: "proposta já executada",
  acao_nao_aplicada: "ação não aplicada",
  tool_fora_da_linha: "tool fora da linha do agente",
});

export function rotulo<T>(tabela: Map<T, string>, valor: T): string {
  return tabela.get(valor) ?? String(valor);
}

/** O alvo como a tela mostra: o endereço e, quando o agente escreveu com rótulo, o rótulo. */
export function alvoNaTela(alvo: string, alvoComRotulo: string | null): string {
  return alvoComRotulo === null ? alvo : `${alvo} (${alvoComRotulo})`;
}

/** Texto que veio do log (de um agente ou de uma pessoa), entre aspas: não é texto do sistema. */
export function aspas(texto: string): string {
  return `“${texto}”`;
}
