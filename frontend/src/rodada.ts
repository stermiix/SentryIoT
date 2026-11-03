// A rodada final dos experimentos, que vai junto com a interface em `public/dados/rodada-final/`
// (montada por `python -m codigo.agente.vitrine`). Sem `VITE_LOG_DE_EVENTOS`, a interface abre aqui: o
// `indice.json` traz os grupos e as execuções com as medidas, e cada execução tem o log real da rodada,
// comprimido com gzip.

import type { AgentName } from "./design-system";
import { lerLog, type LogLido } from "./log";
import type { VereditoDaTriagem } from "./types";

/** A pasta dos dados, ao lado do app (respeita o `base` do Vite). */
export const PASTA_DA_RODADA = `${import.meta.env.BASE_URL ?? "/"}dados/rodada-final/`;
export const CAMINHO_DO_INDICE = `${PASTA_DA_RODADA}indice.json`;
/** A versão do formato que `vitrine.py` grava (`VERSAO_DO_INDICE`). */
export const VERSAO_DO_INDICE = 1;

export interface Taxa {
  acertos: number;
  de: number;
}

export interface AgenteNoResumo {
  agente: AgentName;
  /** Em quantas execuções o agente rodou. */
  execucoes: number;
  chamadas: number;
  tokens_entrada: number;
  tokens_saida: number;
  llm_s: number;
  mediana_tokens: number | null;
  mediana_llm_s: number | null;
}

/** O resumo de um grupo, calculado das medidas das rodadas (`vitrine.resumir`). As taxas deixam de fora as rodadas com erro. */
export interface ResumoDoGrupo {
  execucoes: number;
  com_erro: number;
  pcaps: number;
  incidentes: number;
  repeticoes: number;
  verdadeiras: number;
  falsas: number;
  triagem_correta: Taxa;
  /** A primeira proposta aceitável pelo gabarito, nos incidentes verdadeiros. */
  acao_aceitavel: Taxa;
  atacante_certo: Taxa;
  /** A regra fixa do reprodutor (a primeira origem do incidente), para comparar com o atacante apontado. */
  regra_fixa_certa: Taxa;
  abaixo_da_confianca_minima: number;
  desfechos: Record<string, number>;
  chamadas: number;
  tokens_entrada: number;
  tokens_saida: number;
  mediana_tokens: number | null;
  mediana_agentes_s: number | null;
  mediana_deteccao_s: number | null;
  por_agente: AgenteNoResumo[];
}

/** Uma execução: um incidente, numa repetição, com as medidas da rodada e o caminho do log. */
export interface ExecucaoDaRodada {
  id: string;
  rodada: string;
  pcap: string;
  incidente: string;
  repeticao: number;
  categoria_do_pcap: string;
  categoria: string;
  /** Verdade de campo: o pcap é de ataque, o incidente tem quadro de atacante e a categoria é a do pcap. */
  verdadeiro: boolean;
  confianca: number;
  deteccao_s: number;
  desfecho: string;
  erro: string | null;
  triagem_rotulo: VereditoDaTriagem | null;
  triagem_correta: boolean;
  n_propostas: number;
  n_aceitaveis: number;
  primeira_aceitavel: boolean;
  acao_primeira: string | null;
  n_aprovadas: number;
  n_rejeitadas: number;
  n_baixo_risco: number;
  n_novas: number;
  atacante_apontado: boolean;
  atacante_certo: boolean;
  origem_da_regra_certa: boolean;
  agentes_s: number;
  chamadas: number;
  tokens_entrada: number;
  tokens_saida: number;
  llm_s: number;
  modelos: string[];
  /** Quantas conversas de agente o log traz (contrato 0.8.0). */
  conversas: number;
  avisos: string[];
  /** O log, relativo à pasta da rodada: `oficial/<rodada>.jsonl.gz`. */
  log: string;
  /** O tamanho do log sem compressão. */
  bytes: number;
}

export interface GrupoDaRodada {
  id: string;
  titulo: string;
  descricao: string;
  conjunto_gerado_em: string | null;
  resumo: ResumoDoGrupo;
  execucoes: ExecucaoDaRodada[];
}

export interface IndiceDaRodada {
  versao: number;
  configuracao: string;
  modelos: string[];
  confianca_minima_para_propor: number;
  inicial: string;
  grupos: GrupoDaRodada[];
}

/** A execução escolhida, com o grupo dela e o índice inteiro: o que as telas recebem para mostrar as medidas. */
export interface ContextoDaRodada {
  indice: IndiceDaRodada;
  grupo: GrupoDaRodada;
  execucao: ExecucaoDaRodada;
}

/** Como o orquestrador terminou o incidente, em poucas palavras (`codigo/agente/agentes.py`). */
export const DESFECHO: Record<string, string> = {
  resolvido: "resolvido",
  sem_resolucao: "sem resolução",
  incidente_encerrado: "já encerrado",
  agente_parou: "agente parou",
  sem_proposta: "sem proposta",
  sem_aprovacao: "sem aprovação",
  todas_rejeitadas: "propostas rejeitadas",
  efeito_nao_verificado: "efeito não verificado",
  erro: "erro na rodada",
};

export function rotuloDoDesfecho(desfecho: string): string {
  return DESFECHO[desfecho] ?? desfecho;
}

// O log de uma execução é sempre um arquivo da pasta de um grupo: o índice não faz a interface buscar
// outro endereço.
const CAMINHO_DE_LOG = /^[A-Za-z0-9_-]+\/[A-Za-z0-9._+-]+\.jsonl(?:\.gz)?$/;

type Buscar = typeof fetch;
const buscarPadrao: Buscar = (entrada, init) => fetch(entrada, init);

function ehObjeto(valor: unknown): valor is Record<string, unknown> {
  return typeof valor === "object" && valor !== null && !Array.isArray(valor);
}

const NUMEROS: (keyof ExecucaoDaRodada)[] = ["repeticao", "confianca", "agentes_s", "chamadas", "tokens_entrada", "tokens_saida", "n_propostas"];
const TEXTOS: (keyof ExecucaoDaRodada)[] = ["id", "rodada", "pcap", "incidente", "categoria_do_pcap", "categoria", "desfecho", "log"];
const BOOLEANOS: (keyof ExecucaoDaRodada)[] = ["verdadeiro", "triagem_correta", "primeira_aceitavel", "atacante_certo", "atacante_apontado"];

function problemaDaExecucao(valor: unknown): string | null {
  if (!ehObjeto(valor)) {
    return "execução que não é objeto";
  }
  for (const campo of TEXTOS) {
    if (typeof valor[campo] !== "string") {
      return `execução sem ${campo}`;
    }
  }
  for (const campo of NUMEROS) {
    if (typeof valor[campo] !== "number" || !Number.isFinite(valor[campo])) {
      return `${valor.id}: ${campo} não é número`;
    }
  }
  for (const campo of BOOLEANOS) {
    if (typeof valor[campo] !== "boolean") {
      return `${valor.id}: ${campo} não é verdadeiro nem falso`;
    }
  }
  if (!CAMINHO_DE_LOG.test(valor.log as string)) {
    return `${valor.id}: o log ${String(valor.log)} não é um arquivo da pasta da rodada`;
  }
  return null;
}

/** Confere o `indice.json` e o devolve tipado. Fora do formato, levanta um erro que diz o que está errado. */
export function conferirIndice(valor: unknown): IndiceDaRodada {
  const falha = (problema: string) => new Error(`O índice da rodada final está fora do formato: ${problema}.`);
  if (!ehObjeto(valor) || valor.versao !== VERSAO_DO_INDICE) {
    throw falha(`a versão precisa ser ${VERSAO_DO_INDICE}`);
  }
  if (!Array.isArray(valor.grupos) || valor.grupos.length === 0 || typeof valor.inicial !== "string") {
    throw falha("faltam os grupos ou a execução inicial");
  }
  const ids = new Set<string>();
  for (const grupo of valor.grupos as unknown[]) {
    if (!ehObjeto(grupo) || typeof grupo.id !== "string" || typeof grupo.titulo !== "string" || !ehObjeto(grupo.resumo) || !Array.isArray(grupo.execucoes)) {
      throw falha("grupo sem id, título, resumo ou execuções");
    }
    for (const execucao of grupo.execucoes as unknown[]) {
      const problema = problemaDaExecucao(execucao);
      if (problema) {
        throw falha(problema);
      }
      const id = (execucao as ExecucaoDaRodada).id;
      if (ids.has(id)) {
        throw falha(`a execução ${id} aparece duas vezes`);
      }
      ids.add(id);
    }
  }
  if (!ids.has(valor.inicial)) {
    throw falha(`a execução inicial ${valor.inicial} não está nos grupos`);
  }
  return valor as unknown as IndiceDaRodada;
}

/** Se a resposta é a página do app (o servidor devolve o index.html para um arquivo que não existe), e não um dado. */
function ehPagina(resposta: Response): boolean {
  return (resposta.headers.get("content-type") ?? "").includes("text/html");
}

/**
 * O índice da rodada final que veio no build. Nulo quando o build não tem os dados (a rodada ainda não foi
 * montada): as telas abrem vazias, como sem log. Um índice fora do formato levanta erro.
 */
export async function carregarIndice(buscar: Buscar = buscarPadrao): Promise<IndiceDaRodada | null> {
  let resposta: Response;
  try {
    resposta = await buscar(CAMINHO_DO_INDICE, { cache: "no-cache" });
  } catch {
    return null;
  }
  if (resposta.status === 404 || (resposta.ok && ehPagina(resposta))) {
    return null;
  }
  if (!resposta.ok) {
    throw new Error(`Não foi possível ler o índice da rodada final (HTTP ${resposta.status}).`);
  }
  let corpo: unknown;
  try {
    corpo = JSON.parse(await resposta.text());
  } catch {
    throw new Error("O índice da rodada final não é um JSON válido.");
  }
  return conferirIndice(corpo);
}

/**
 * O texto de um log, comprimido ou não. Os bytes mágicos do gzip (1f 8b) dizem se é preciso abrir: um
 * servidor que manda `Content-Encoding: gzip` já entrega o texto aberto, e o `.jsonl` puro também vale.
 */
export async function textoDoLog(resposta: Response): Promise<string> {
  const bytes = new Uint8Array(await resposta.arrayBuffer());
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    if (typeof DecompressionStream === "undefined") {
      throw new Error("Este navegador não abre arquivos gzip (DecompressionStream). Use um navegador atual.");
    }
    const aberto = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Response(aberto).text();
  }
  return new TextDecoder("utf-8").decode(bytes);
}

/** Busca e lê o log de uma execução, conferido linha a linha contra o contrato, como qualquer log. */
export async function carregarExecucao(execucao: ExecucaoDaRodada, buscar: Buscar = buscarPadrao): Promise<LogLido> {
  const caminho = `${PASTA_DA_RODADA}${execucao.log}`;
  const resposta = await buscar(caminho);
  if (!resposta.ok || ehPagina(resposta)) {
    throw new Error(`O log da execução ${execucao.rodada} não está no build (${caminho}). Gere os dados de novo com python -m codigo.agente.vitrine.`);
  }
  return lerLog(await textoDoLog(resposta));
}

// --- A escolha da execução ---------------------------------------------------------------

export function acharExecucao(indice: IndiceDaRodada, id: string | null | undefined): ContextoDaRodada | null {
  for (const grupo of indice.grupos) {
    const execucao = grupo.execucoes.find((item) => item.id === id);
    if (execucao) {
      return { indice, grupo, execucao };
    }
  }
  return null;
}

export type CampoDoSeletor = "grupo" | "pcap" | "incidente" | "repeticao";

export interface OpcaoDoSeletor {
  value: string;
  label: string;
}

export interface OpcoesDoSeletor {
  grupo: OpcaoDoSeletor[];
  pcap: OpcaoDoSeletor[];
  incidente: OpcaoDoSeletor[];
  repeticao: OpcaoDoSeletor[];
  /** O valor de cada campo na execução escolhida. */
  valor: Record<CampoDoSeletor, string>;
}

function unicos<T>(itens: T[], chave: (item: T) => string): T[] {
  const vistos = new Set<string>();
  return itens.filter((item) => {
    const valor = chave(item);
    if (vistos.has(valor)) {
      return false;
    }
    vistos.add(valor);
    return true;
  });
}

/** As opções de cada campo do seletor (grupo → pcap → incidente → repetição), a partir da execução escolhida. */
export function opcoesDoSeletor({ indice, grupo, execucao }: ContextoDaRodada): OpcoesDoSeletor {
  const doPcap = grupo.execucoes.filter((item) => item.pcap === execucao.pcap);
  const doIncidente = doPcap.filter((item) => item.incidente === execucao.incidente);
  return {
    grupo: indice.grupos.map((item) => ({ value: item.id, label: `${item.titulo} (${item.execucoes.length})` })),
    pcap: unicos(grupo.execucoes, (item) => item.pcap).map((item) => ({ value: item.pcap, label: `${item.pcap} · ${item.categoria_do_pcap}` })),
    incidente: unicos(doPcap, (item) => item.incidente).map((item) => ({
      value: item.incidente,
      label: `${item.incidente} · ${item.categoria}${item.verdadeiro ? "" : " · falso"}`,
    })),
    repeticao: doIncidente.map((item) => ({ value: String(item.repeticao), label: `${item.repeticao} · ${rotuloDoDesfecho(item.desfecho)}` })),
    valor: { grupo: grupo.id, pcap: execucao.pcap, incidente: execucao.incidente, repeticao: String(execucao.repeticao) },
  };
}

/**
 * A execução depois de mudar um campo do seletor. Os campos abaixo do que mudou ficam como estavam quando
 * existem na escolha nova; senão, vale a primeira opção.
 */
export function trocarNoSeletor(contexto: ContextoDaRodada, campo: CampoDoSeletor, valor: string): string {
  const { indice, execucao } = contexto;
  const grupo = campo === "grupo" ? indice.grupos.find((item) => item.id === valor) : contexto.grupo;
  if (!grupo || grupo.execucoes.length === 0) {
    return execucao.id;
  }
  const pcap = campo === "pcap" ? valor : execucao.pcap;
  const incidente = campo === "incidente" ? valor : execucao.incidente;
  const repeticao = campo === "repeticao" ? Number(valor) : execucao.repeticao;
  // Do mais específico ao mais geral: a mesma execução no grupo novo, o mesmo incidente, o mesmo pcap, o grupo.
  const candidatos: ((item: ExecucaoDaRodada) => boolean)[] = [
    (item) => item.pcap === pcap && item.incidente === incidente && item.repeticao === repeticao,
    (item) => item.pcap === pcap && item.incidente === incidente,
    (item) => item.pcap === pcap && item.repeticao === repeticao && campo !== "incidente",
    (item) => item.pcap === pcap,
    () => campo === "grupo",
  ];
  for (const criterio of candidatos) {
    const achada = grupo.execucoes.find(criterio);
    if (achada) {
      return achada.id;
    }
  }
  return execucao.id;
}

/** A execução em que a interface abre: a que o índice indica, ou a primeira. */
export function execucaoInicial(indice: IndiceDaRodada): string {
  return acharExecucao(indice, indice.inicial)?.execucao.id ?? indice.grupos[0].execucoes[0].id;
}
