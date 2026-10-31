// O acesso à simulação (`/api/simulacao`, em `codigo/api/simulacao.py`): o pcap escolhido na tela vai
// no corpo, passa pelo extrator, pelo classificador e pela política de acionamento, e cada incidente
// segue para os agentes em segundo plano. A tela acompanha o log com `consultarSimulacao`, e a pessoa
// decide o que depende dela com `decidirNaSimulacao`.

import type { AgentName } from "./design-system";
import type { Evento } from "./types";

export interface IncidenteDaSimulacao {
  id: string;
  categoria: string;
  categoria_do_modelo: string;
  janelas: number;
  confianca: number;
  distribuido: boolean;
  origens_distintas: number;
  inicio: string;
  fim: string;
  primeira_janela_de_ataque: string;
  aberto_em: string;
  atraso_de_deteccao_s: number;
  reaberturas: number;
}

export type EstadoDosAgentes = "rodando" | "parando" | "concluidos" | "interrompidos" | "sem_modelo" | "sem_incidentes";

export type SituacaoDoIncidente = "na_fila" | "em_andamento" | "concluido" | "erro" | "interrompido";

export interface IncidenteNosAgentes {
  id: string;
  situacao: SituacaoDoIncidente;
  /** Como o orquestrador terminou o incidente (`resolvido`, `sem_proposta`...). */
  desfecho: string | null;
  erro: string | null;
}

export interface AgentesDaSimulacao {
  estado: EstadoDosAgentes;
  configuracao: string;
  modelo: string;
  /** Por que os agentes não rodaram, quando o modelo não está configurado. */
  motivo: string | null;
  incidentes: IncidenteNosAgentes[];
}

export interface ResultadoDaSimulacao {
  arquivo: string;
  quadros: number;
  ignorados: number;
  janelas: number;
  /** Janelas do trecho de treino, extraídas mas não classificadas (com "só o trecho de teste"). */
  janelas_puladas: number;
  /** A última janela, quando não chega a 100 quadros, é descartada. */
  janelas_incompletas: number;
  trecho: { a_partir_da_janela: number; so_teste: boolean };
  por_categoria: Record<string, number>;
  duracao_do_pcap_s: number;
  processamento_s: number;
  modelo: string;
  ponto_de_operacao: { regra: string; limiar: number | null; seguidas: number };
  acionamento: Record<string, number>;
  incidentes: IncidenteDaSimulacao[];
  incidentes_alem_do_teto: number;
  log: string;
  /** Os cenários ao lado do log, para subir o servidor MCP com `--cenarios`. */
  cenarios: string;
  /** O log de eventos como está agora, em JSON Lines, para as telas lerem. */
  eventos: string;
  agentes: AgentesDaSimulacao;
}

/** O que a pessoa decide pela tela. Em `resolvido`, o `id` é o do incidente; nos outros, o da proposta. */
export interface DecisaoNaSimulacao {
  tipo: "aprovar" | "rejeitar" | "resolvido";
  id: string;
  motivo?: string;
}

export type TipoDeErro = "backend" | "rede";

export class ErroDaSimulacao extends Error {
  constructor(
    readonly tipo: TipoDeErro,
    mensagem: string,
    readonly status: number | null,
  ) {
    super(mensagem);
    this.name = "ErroDaSimulacao";
  }
}

type Buscar = typeof fetch;
const buscarPadrao: Buscar = (entrada, init) => fetch(entrada, init);

/** O cabeçalho que o backend exige nas rotas que gastam máquina: uma página de outro site não o manda sem licença. */
export const CABECALHO_DA_INTERFACE = { "X-SentryIoT": "interface" } as const;

/** Faz o pedido e devolve o corpo já lido. A recusa do backend vira `ErroDaSimulacao`, com a mensagem dele. */
async function pedir(caminho: string, init: RequestInit, buscar: Buscar): Promise<unknown> {
  let resposta: Response;
  try {
    resposta = await buscar(caminho, { ...init, headers: { ...init.headers, ...CABECALHO_DA_INTERFACE } });
  } catch {
    throw new ErroDaSimulacao("rede", "O backend não está no ar.", null);
  }
  const texto = await resposta.text();
  let corpo: unknown = null;
  try {
    corpo = JSON.parse(texto);
  } catch {
    corpo = null;
  }
  if (!resposta.ok) {
    const erro = ehObjeto(corpo) && typeof corpo.erro === "string" ? corpo.erro : `O backend respondeu com o status ${resposta.status}.`;
    throw new ErroDaSimulacao("backend", erro, resposta.status);
  }
  return corpo;
}

const FORA_DO_FORMATO = "O backend devolveu a simulação fora do formato esperado.";

/**
 * O arquivo vai cru no corpo, com o nome na consulta; o backend aceita um por vez. Com `soTeste`,
 * só o trecho do pcap que ficou fora do treino do modelo é classificado.
 */
export async function iniciarSimulacao(arquivo: Blob, nome: string, soTeste = false, buscar: Buscar = buscarPadrao): Promise<ResultadoDaSimulacao> {
  const consulta = `nome=${encodeURIComponent(nome)}${soTeste ? "&so_teste=1" : ""}`;
  const corpo = await pedir(`/api/simulacao?${consulta}`, { method: "POST", headers: { "Content-Type": "application/vnd.tcpdump.pcap" }, body: arquivo }, buscar);
  if (!ehResultado(corpo)) {
    throw new ErroDaSimulacao("backend", FORA_DO_FORMATO, null);
  }
  return corpo;
}

/** A simulação mais recente no backend, com o log como está agora. Nula se não houve nenhuma. */
export async function consultarSimulacao(buscar: Buscar = buscarPadrao): Promise<ResultadoDaSimulacao | null> {
  const corpo = await pedir("/api/simulacao/atual", { cache: "no-store" }, buscar);
  if (!ehObjeto(corpo) || (corpo.simulacao !== null && !ehResultado(corpo.simulacao))) {
    throw new ErroDaSimulacao("backend", FORA_DO_FORMATO, null);
  }
  return corpo.simulacao as ResultadoDaSimulacao | null;
}

export async function decidirNaSimulacao(decisao: DecisaoNaSimulacao, buscar: Buscar = buscarPadrao): Promise<void> {
  await pedir("/api/simulacao/decisao", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(decisao) }, buscar);
}

export async function pararSimulacao(buscar: Buscar = buscarPadrao): Promise<void> {
  await pedir("/api/simulacao/parar", { method: "POST" }, buscar);
}

/** Enquanto os agentes rodam, a tela acompanha o log e as decisões chegam a eles. */
export function agentesAtivos(agentes: AgentesDaSimulacao): boolean {
  return agentes.estado === "rodando" || agentes.estado === "parando";
}

/** O agente da última chamada à IA do incidente: é onde ele está agora. */
export function ultimoAgente(eventos: Evento[], incidente: string): AgentName | null {
  for (let indice = eventos.length - 1; indice >= 0; indice -= 1) {
    const evento = eventos[indice];
    if (evento.tipo === "llm_chamada" && evento.incidente === incidente) {
      return evento.dados.agente;
    }
  }
  return null;
}

/** Tamanho de arquivo em B, KB, MB ou GB, com vírgula decimal. */
export function tamanhoDoArquivo(bytes: number): string {
  const unidades = ["B", "KB", "MB", "GB"];
  let valor = bytes;
  let unidade = 0;
  while (valor >= 1024 && unidade < unidades.length - 1) {
    valor /= 1024;
    unidade += 1;
  }
  const casas = unidade === 0 || valor >= 100 ? 0 : 1;
  return `${valor.toFixed(casas).replace(".", ",")} ${unidades[unidade]}`;
}

function ehObjeto(valor: unknown): valor is Record<string, unknown> {
  return typeof valor === "object" && valor !== null && !Array.isArray(valor);
}

function ehResultado(valor: unknown): valor is ResultadoDaSimulacao {
  return (
    ehObjeto(valor) &&
    typeof valor.arquivo === "string" &&
    typeof valor.janelas === "number" &&
    ehObjeto(valor.por_categoria) &&
    Array.isArray(valor.incidentes) &&
    typeof valor.eventos === "string" &&
    ehObjeto(valor.agentes) &&
    typeof valor.agentes.estado === "string" &&
    Array.isArray(valor.agentes.incidentes)
  );
}
