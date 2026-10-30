import type { ReplayMark } from "./design-system/components/Replay";
import type { Address, FeatureRow, Incident, LogEvent, Proposal, Provider } from "./design-system/components/modelos";
import { fmtConfidence, fmtInt } from "./design-system/components/util";
import {
  EFFECT,
  EVENT,
  PROPOSAL_STATE,
  REFUSAL_REASON,
  RISK,
  STOP_REASON,
  VERDICT,
  type AgentName,
  type Channel,
  type IncidentState,
  type ProviderLocation,
} from "./design-system/components/vocab";
import { hora } from "./formato";
import { agregar, type Agregado } from "./log";
import type { Evento, EventoDeRecusa, IncidenteView, Livre, PropostaView, TipoDeEvento } from "./types";

// A ponte entre o log e o design system: o log é lido e conferido por `log.ts`, e aqui cada evento,
// incidente e proposta vira o objeto que os componentes desenham (`design-system/components/modelos.ts`).
// Nada daqui inventa dado: o que o log não traz fica vazio, e a tela diz que falta.

// --- Onde cada modelo roda ---------------------------------------------------------------

function lista(valor: string | undefined): Set<string> {
  return new Set((valor ?? "").split(",").map((nome) => nome.trim()).filter((nome) => nome.length > 0));
}
const MODELOS_LOCAIS = lista(import.meta.env.VITE_MODELOS_LOCAIS);
const MODELOS_NA_NUVEM = lista(import.meta.env.VITE_MODELOS_NA_NUVEM);

/**
 * Onde o modelo roda, pelas listas `VITE_MODELOS_LOCAIS` e `VITE_MODELOS_NA_NUVEM`. Vale para o log
 * gravado antes da versão 0.5.0 do contrato, sem o campo `onde`, e para o chat. Um modelo fora das
 * duas listas volta sem lugar: a tela não mostra "local" nem "nuvem" para ele.
 */
export function ondeRoda(modelo: string): ProviderLocation | undefined {
  if (MODELOS_LOCAIS.has(modelo)) {
    return "local";
  }
  return MODELOS_NA_NUVEM.has(modelo) ? "nuvem" : undefined;
}

/**
 * Os modelos do backend do chat como provedores do seletor. Sem lugar conhecido, o modelo entra
 * como nuvem: é o caso que pede cuidado, porque o texto pode sair da máquina.
 */
export function provedoresDoChat(modelos: string[]): Provider[] {
  return modelos.map((modelo) => {
    const local = ondeRoda(modelo) === "local";
    return { id: modelo, label: local ? "Modelo local" : "Nuvem", model: modelo, location: local ? "local" : "nuvem", status: "online" };
  });
}

// --- Eventos -----------------------------------------------------------------------------

// Um argumento de tool só aparece na linha do tempo quando é curto e tem forma de identificador
// (id, rótulo neutro, nome de ação, número). Texto livre do agente (justificativa, descrição,
// consulta) não vira texto do sistema: a linha mostra só a chave dele.
const VALOR_DE_IDENTIFICADOR = /^[A-Za-z0-9_.:@-]{1,40}$/;

function valorNaLinha(valor: unknown): string {
  if (typeof valor === "number" || typeof valor === "boolean") {
    return String(valor);
  }
  if (typeof valor === "string" && VALOR_DE_IDENTIFICADOR.test(valor)) {
    return valor;
  }
  if (Array.isArray(valor)) {
    return "[…]";
  }
  return typeof valor === "object" && valor !== null ? "{…}" : "…";
}

/** `obter_resumo(id=inc-0001, limite=5)`: a chamada de tool como a linha do tempo mostra, sem texto livre do agente. */
export function chamadaDeTool(nome: string, argumentos: Livre): string {
  const partes = Object.entries(argumentos).map(([chave, valor]) => `${chave}=${valorNaLinha(valor)}`);
  return `${nome}(${partes.join(", ")})`;
}

/** Texto que veio do log, entre aspas: não é texto do sistema. */
export function aspas(texto: string): string {
  return `“${texto}”`;
}

/** O prazo da medida, em minutos (`parametros.duracao`), ou nada quando ela não tem prazo. */
export function prazo(parametros: Livre): string | undefined {
  const duracao = parametros.duracao;
  return typeof duracao === "number" ? `${fmtInt(duracao)} min` : undefined;
}

// O formato dos ids que o servidor dá às propostas e às execuções.
const ID_DE_PROPOSTA_OU_EXECUCAO = /^(?:prop|exec)-[0-9]{1,9}$/;

/**
 * A proposta ou a execução de que a recusa fala, quando os argumentos da tool trazem um id com a
 * forma dos ids do servidor. O argumento foi escrito pelo agente: outro texto não vira id na tela.
 */
function idDaRecusa(evento: EventoDeRecusa): string | undefined {
  const citado = evento.dados.argumentos.id_proposta ?? evento.dados.argumentos.id_execucao;
  return typeof citado === "string" && ID_DE_PROPOSTA_OU_EXECUCAO.test(citado) ? citado : undefined;
}

function plural(quantidade: number, singular: string, varios: string): string {
  return `${fmtInt(quantidade)} ${quantidade === 1 ? singular : varios}`;
}

/** Um evento do log como linha da linha do tempo. `n` é a posição dele no log, a partir de 1. */
export function linhaDoEvento(evento: Evento, n: number): LogEvent {
  const base = { n, id: evento.id, at: hora(evento.instante), type: evento.tipo, incident: evento.incidente ?? undefined, text: EVENT[evento.tipo].label };
  switch (evento.tipo) {
    case "janelas_classificadas": {
      const partes = Object.entries(evento.dados.por_categoria).map(([categoria, quantidade]) => `${categoria} ${fmtInt(quantidade ?? 0)}`);
      return { ...base, text: plural(evento.dados.janelas, "janela", "janelas"), detail: partes.join(" · ") || undefined, windows: evento.dados.janelas };
    }
    case "incidente_aberto": {
      const dados = evento.dados;
      return { ...base, ref: dados.id, detail: `${dados.categoria} · modelo ${dados.categoria_do_modelo} · confiança ${fmtConfidence(dados.confianca)}` };
    }
    case "incidente_atualizado": {
      const dados = evento.dados;
      return { ...base, ref: dados.id, text: `${plural(dados.janelas, "janela", "janelas")} · ${plural(dados.origens_distintas, "origem", "origens")}` };
    }
    case "incidente_encerrado":
      return { ...base, ref: evento.dados.id, detail: plural(evento.dados.janelas, "janela", "janelas") };
    case "incidente_marcado_resolvido": {
      const dados = evento.dados;
      return { ...base, ref: dados.incidente, channel: dados.canal, user: dados.usuario, quote: dados.motivo ?? undefined };
    }
    case "llm_chamada": {
      const dados = evento.dados;
      return {
        ...base,
        agent: dados.agente,
        tokens: dados.tokens_entrada + dados.tokens_saida,
        seconds: dados.duracao_ms / 1000,
        model: dados.modelo,
        // O log diz onde a chamada rodou desde o contrato 0.5.0; antes, as listas do ambiente dizem.
        location: dados.onde ?? ondeRoda(dados.modelo),
      };
    }
    case "tool_chamada": {
      const dados = evento.dados;
      return { ...base, agent: dados.agente ?? undefined, text: chamadaDeTool(dados.nome, dados.argumentos) };
    }
    case "agente_concluido": {
      const dados = evento.dados;
      return {
        ...base,
        agent: dados.agente,
        text: `${EVENT[evento.tipo].label} · ${STOP_REASON[dados.motivo]}`,
        detail: [plural(dados.voltas, "chamada à IA", "chamadas à IA"), dados.veredito ? `veredito ${VERDICT[dados.veredito]}` : null]
          .filter(Boolean)
          .join(" · "),
      };
    }
    case "recomendacao_emitida": {
      const dados = evento.dados;
      return { ...base, agent: dados.agente, ref: dados.propostas.join(", ") || undefined, quote: dados.texto };
    }
    case "acao_proposta": {
      const dados = evento.dados;
      const duracao = prazo(dados.parametros);
      const estado = dados.risco === "alto" ? "aguardando_aprovacao" : "liberada";
      return {
        ...base,
        ref: dados.id,
        text: [dados.acao, alvoNaLinha(dados.alvo, dados.alvo_com_rotulo, dados.nova), duracao].filter(Boolean).join(" · "),
        detail: [dados.nova ? "Ação nova" : null, RISK[dados.risco].label, PROPOSAL_STATE[estado].label.toLowerCase()].filter(Boolean).join(" · "),
      };
    }
    case "acao_aprovada":
    case "acao_rejeitada": {
      const dados = evento.dados;
      return {
        ...base,
        ref: dados.proposta,
        text: `${dados.proposta} ${evento.tipo === "acao_aprovada" ? "aprovada" : "rejeitada"}`,
        channel: dados.canal,
        user: dados.usuario,
        quote: dados.motivo ?? undefined,
      };
    }
    case "acao_executada":
    case "acao_desfeita": {
      const dados = evento.dados;
      return { ...base, ref: dados.id, text: `${dados.proposta} ${evento.tipo === "acao_executada" ? "aplicada" : "desfeita"} · ${dados.acao}` };
    }
    case "efeito_verificado":
      return { ...base, ref: evento.dados.execucao, text: EFFECT[evento.dados.resultado].label, detail: evento.dados.observacao };
    case "catalogo_ampliado":
      return { ...base, ref: evento.dados.proposta, text: `${evento.dados.acao.nome} entrou no catálogo` };
    case "recusa": {
      const dados = evento.dados;
      return {
        ...base,
        agent: dados.agente ?? undefined,
        ref: idDaRecusa(evento),
        text: `${dados.tool} · ${REFUSAL_REASON[dados.motivo]}`,
        detail: aspas(dados.mensagem),
      };
    }
  }
}

/**
 * O alvo de uma proposta na linha do tempo: o rótulo neutro quando há. O alvo de uma ação nova sem
 * rótulo é texto do agente, e a linha só diz que ele existe.
 */
function alvoNaLinha(alvo: string, comRotulo: string | null, nova: boolean): string {
  if (comRotulo) {
    return comRotulo;
  }
  return nova ? "alvo descrito pelo agente" : alvo;
}

/** Todas as linhas do log, na ordem dos ids (a do replay). As que a reconstrução ignorou vêm marcadas. */
export function linhasDoLog(eventos: Evento[], ignorados: ReadonlySet<string> = new Set()): LogEvent[] {
  return eventos.map((evento, indice) => ({ ...linhaDoEvento(evento, indice + 1), ...(ignorados.has(evento.id) ? { ignored: true } : {}) }));
}

/**
 * As marcas da trilha do replay: incidentes abertos, propostas que pedem uma pessoa e decisões
 * humanas. Evento que a reconstrução ignorou não ganha marca.
 */
export function marcasDoReplay(eventos: Evento[], ignorados: ReadonlySet<string> = new Set()): ReplayMark[] {
  const marcas: ReplayMark[] = [];
  eventos.forEach((evento, indice) => {
    const n = indice + 1;
    if (ignorados.has(evento.id)) {
      return;
    }
    switch (evento.tipo) {
      case "incidente_aberto":
        marcas.push({ n, tone: "info", label: `${evento.dados.id} aberto` });
        break;
      case "acao_proposta":
        if (evento.dados.risco === "alto") {
          marcas.push({ n, tone: "attention", label: `${evento.dados.id} aguardando aprovação` });
        }
        break;
      case "acao_aprovada":
        marcas.push({ n, tone: "success", label: `${evento.dados.proposta} aprovada` });
        break;
      case "acao_rejeitada":
        marcas.push({ n, tone: "danger", label: `${evento.dados.proposta} rejeitada` });
        break;
      case "efeito_verificado":
        if (evento.dados.resultado === "cessou") {
          marcas.push({ n, tone: "success", label: EFFECT.cessou.label });
        }
        break;
      case "incidente_marcado_resolvido":
        marcas.push({ n, tone: "neutral", label: `${evento.dados.incidente} marcado como já resolvido` });
        break;
      default:
        break;
    }
  });
  return marcas;
}

// --- Incidentes e propostas --------------------------------------------------------------

/** O estado vem do classificador; a marca de "já resolvido" aparece enquanto ele vê o incidente aberto. */
export function estadoDoIncidente(view: IncidenteView): IncidentState {
  if (view.incidente.estado === "encerrado") {
    return "encerrado";
  }
  return view.marcacao ? "ja-resolvido" : "aberto";
}

export function aguardandoNo(view: IncidenteView): number {
  return view.propostas.filter((proposta) => proposta.estado === "aguardando_aprovacao").length;
}

export function incidenteDaFila(view: IncidenteView): Incident {
  const dados = view.incidente;
  return {
    id: view.id,
    state: estadoDoIncidente(view),
    category: dados.categoria,
    modelCategory: dados.categoria_do_modelo,
    confidence: dados.confianca,
    windows: dados.janelas,
    start: hora(dados.inicio),
    end: hora(dados.fim),
    sources: dados.origens_distintas,
    destinations: dados.destinos.length,
    awaiting: aguardandoNo(view),
    note: view.marcacao?.motivo ?? undefined,
  };
}

function texto(valor: unknown): string | undefined {
  return typeof valor === "string" && valor.trim() ? valor : undefined;
}

/** Como o agente descreveu a ação nova (`parametros` da proposta): o que a pessoa lê antes de aprovar. */
function acaoNova(parametros: Livre): Proposal["newAction"] {
  const passos = Array.isArray(parametros.passos) ? parametros.passos.filter((passo): passo is string => typeof passo === "string" && passo.trim().length > 0) : [];
  return {
    description: texto(parametros.descricao),
    steps: passos.length > 0 ? passos : undefined,
    expected: texto(parametros.efeito_esperado),
    undo: texto(parametros.como_desfazer),
    source: texto(parametros.fonte),
  };
}

export function propostaDaTela(proposta: PropostaView, incidente: string): Proposal {
  const decisao = proposta.decisoes[proposta.decisoes.length - 1];
  const efeitos = proposta.execucoes.flatMap((execucao) => execucao.efeitos);
  const efeito = efeitos[efeitos.length - 1];
  return {
    id: proposta.id,
    incident: incidente,
    action: proposta.acao,
    isNew: proposta.nova,
    promoted: proposta.promovida,
    // O rótulo neutro é o que o agente de decisão viu; o endereço real fica ao lado, porque a tela é
    // local. Ação nova sem rótulo tem alvo em texto livre, escrito pelo agente.
    target: proposta.alvoComRotulo
      ? { label: proposta.alvoComRotulo, address: proposta.alvo }
      : proposta.nova
        ? { label: proposta.alvo, free: true }
        : { label: proposta.alvo },
    newAction: proposta.nova ? acaoNova(proposta.parametros) : undefined,
    duration: prazo(proposta.parametros),
    risk: proposta.risco,
    state: proposta.estado,
    reasons: proposta.motivosDeRiscoAlto,
    justification: proposta.justificativa || undefined,
    decision: decisao && {
      kind: decisao.tipo === "acao_aprovada" ? "aprovada" : "rejeitada",
      channel: decisao.canal,
      user: decisao.usuario,
      at: hora(decisao.instante),
      reason: decisao.motivo ?? undefined,
    },
    executions: proposta.execucoes.map((execucao) => ({ id: execucao.id, state: execucao.estado, at: hora(execucao.desfeitaEm ?? execucao.aplicadaEm) })),
    effect: efeito && { result: efeito.resultado, at: hora(efeito.instante) },
    createdAt: hora(proposta.criadaEm),
  };
}

/** As propostas que pedem uma pessoa vêm primeiro; as outras, na ordem em que foram criadas. */
export function propostasDaTela(view: IncidenteView): Proposal[] {
  const propostas = view.propostas.map((proposta) => propostaDaTela(proposta, view.id));
  const pede = (proposta: Proposal) => (proposta.state === "aguardando_aprovacao" ? 0 : 1);
  return propostas.map((proposta, indice) => ({ proposta, indice })).sort((a, b) => pede(a.proposta) - pede(b.proposta) || a.indice - b.indice).map(({ proposta }) => proposta);
}

/** Origens ou destinos com quadros e o rótulo neutro que cada endereço recebeu no incidente. */
export function enderecosDoIncidente(view: IncidenteView, papel: "origem" | "destino"): Address[] {
  const rotuloDe = new Map<string, string>();
  for (const [rotulo, endereco] of view.rotulos) {
    if (rotulo.startsWith(`${papel}-`)) {
      rotuloDe.set(endereco, rotulo);
    }
  }
  const lista = papel === "origem" ? view.incidente.origens : view.incidente.destinos;
  return lista.map((item) => ({ address: item.endereco, label: rotuloDe.get(item.endereco) ?? item.endereco, frames: item.quadros, role: papel }));
}

export function featuresDoIncidente(view: IncidenteView): FeatureRow[] {
  return view.incidente.features_principais.map((feature) => ({ name: feature.nome, value: feature.valor, benign: feature.referencia_benigno }));
}

// --- O estado da tela num passo do replay ------------------------------------------------

export interface EstadoDaTela {
  /** Quantos eventos já foram aplicados (1 a `total`). */
  passo: number;
  total: number;
  atual: LogEvent | null;
  agregado: Agregado;
  incidentes: Incident[];
  janelas: number;
  /** Janelas que o classificador pôs numa categoria de ataque: as que virariam chamada sem agregação. */
  janelasDeAtaque: number;
  chamadas: number;
  tokens: number;
  /** Tokens somados chamada a chamada, para a linha do cartão de tokens. */
  tokensAcumulados: number[];
  aguardando: number;
}

export function estadoNoPasso(eventos: Evento[], linhas: LogEvent[], passo: number): EstadoDaTela {
  const ate = Math.max(0, Math.min(passo, eventos.length));
  const aplicados = eventos.slice(0, ate);
  const agregado = agregar(aplicados);
  let janelasDeAtaque = 0;
  let acumulado = 0;
  const tokensAcumulados: number[] = [];
  for (const evento of aplicados) {
    if (evento.tipo === "janelas_classificadas") {
      for (const [categoria, quantidade] of Object.entries(evento.dados.por_categoria)) {
        if (categoria !== "Benign") {
          janelasDeAtaque += quantidade ?? 0;
        }
      }
    }
    if (evento.tipo === "llm_chamada") {
      acumulado += evento.dados.tokens_entrada + evento.dados.tokens_saida;
      tokensAcumulados.push(acumulado);
    }
  }
  const incidentes = agregado.incidentes.map(incidenteDaFila);
  return {
    passo: ate,
    total: eventos.length,
    atual: ate > 0 ? linhas[ate - 1] : null,
    agregado,
    incidentes,
    janelas: agregado.resumo.janelasClassificadas,
    janelasDeAtaque,
    chamadas: agregado.resumo.chamadasLLM,
    tokens: agregado.resumo.tokens,
    tokensAcumulados,
    aguardando: incidentes.reduce((soma, incidente) => soma + incidente.awaiting, 0),
  };
}

// --- O detalhe de um incidente -----------------------------------------------------------

// Os eventos que entram no histórico de decisões e efeitos.
const DO_HISTORICO = new Set<TipoDeEvento>([
  "incidente_aberto",
  "incidente_encerrado",
  "incidente_marcado_resolvido",
  "recomendacao_emitida",
  "acao_proposta",
  "acao_aprovada",
  "acao_rejeitada",
  "acao_executada",
  "acao_desfeita",
  "efeito_verificado",
  "catalogo_ampliado",
  "recusa",
]);
// Quantos eventos depois do cursor o histórico mostra, esmaecidos.
export const HISTORICO_A_FRENTE = 8;
// Quantas chamadas o rastro dos agentes mostra, das mais recentes.
export const RASTRO_RESUMIDO = 7;

export interface RecomendacaoDaTela {
  id: string;
  at: string;
  agent: AgentName;
  text: string;
  propostas: string[];
  /** O modelo da última chamada à IA do mesmo agente antes da recomendação, e onde ele roda. */
  model?: string;
  location?: ProviderLocation;
}

/** As recomendações do incidente, cada uma com o modelo que o agente usava naquele ponto. */
function recomendacoesDoIncidente(view: IncidenteView): RecomendacaoDaTela[] {
  const modeloDe = new Map<AgentName, { modelo: string; onde: ProviderLocation | undefined }>();
  const recomendacoes: RecomendacaoDaTela[] = [];
  for (const evento of view.eventos) {
    if (evento.tipo === "llm_chamada") {
      modeloDe.set(evento.dados.agente, { modelo: evento.dados.modelo, onde: evento.dados.onde ?? ondeRoda(evento.dados.modelo) });
    } else if (evento.tipo === "recomendacao_emitida") {
      const ultima = modeloDe.get(evento.dados.agente);
      recomendacoes.push({
        id: evento.id,
        at: hora(evento.instante),
        agent: evento.dados.agente,
        text: evento.dados.texto,
        propostas: evento.dados.propostas,
        model: ultima?.modelo,
        location: ultima?.onde,
      });
    }
  }
  return recomendacoes;
}

export interface MarcacaoDaTela {
  at: string;
  channel: Channel;
  user: string;
  reason?: string;
}

export interface DetalheDoIncidente {
  view: IncidenteView;
  incidente: Incident;
  propostas: Proposal[];
  origens: Address[];
  destinos: Address[];
  features: FeatureRow[];
  recomendacoes: RecomendacaoDaTela[];
  /** Chamadas à IA e de tool deste incidente até o cursor. */
  rastro: LogEvent[];
  /** Decisões e efeitos, até alguns eventos depois do cursor (os de depois aparecem esmaecidos). */
  historico: LogEvent[];
  marcacao: MarcacaoDaTela | null;
  chamadas: number;
  tokens: number;
  /** Hora em que o evento de abertura chegou (o ataque começou antes: `incidente.start`). */
  abertoEm: string;
}

/**
 * O detalhe do incidente `id` no passo do estado. O histórico usa a montagem do log inteiro
 * (`final`) para mostrar o que vem logo depois do cursor; como a reconstrução é sequencial, um
 * evento aceito até o passo é aceito no log inteiro também.
 */
export function detalheDoIncidente(estado: EstadoDaTela, final: Agregado, linhas: LogEvent[], id: string): DetalheDoIncidente | null {
  const view = estado.agregado.incidentes.find((item) => item.id === id);
  if (!view) {
    return null;
  }
  const posicao = new Map(linhas.map((linha) => [linha.id, linha]));
  const linhaDe = (evento: Evento) => posicao.get(evento.id)!;
  const doLogInteiro = final.incidentes.find((item) => item.id === id) ?? view;
  return {
    view,
    incidente: incidenteDaFila(view),
    propostas: propostasDaTela(view),
    origens: enderecosDoIncidente(view, "origem"),
    destinos: enderecosDoIncidente(view, "destino"),
    features: featuresDoIncidente(view),
    recomendacoes: recomendacoesDoIncidente(view),
    rastro: view.eventos.filter((evento) => evento.tipo === "llm_chamada" || evento.tipo === "tool_chamada").map(linhaDe),
    historico: doLogInteiro.eventos
      .filter((evento) => DO_HISTORICO.has(evento.tipo))
      .map(linhaDe)
      .filter((linha) => linha.n <= estado.passo + HISTORICO_A_FRENTE),
    marcacao: view.marcacao && {
      at: hora(view.marcacao.instante),
      channel: view.marcacao.canal,
      user: view.marcacao.usuario,
      reason: view.marcacao.motivo ?? undefined,
    },
    chamadas: view.chamadasLLM,
    tokens: view.tokensEntrada + view.tokensSaida,
    abertoEm: hora(view.abertoEm),
  };
}

/** O passo em que mais propostas aguardam uma pessoa ao mesmo tempo (o primeiro, se houver empate). */
export function passoComMaisPendencias(eventos: Evento[], linhas: LogEvent[]): number {
  let melhor = eventos.length;
  let maximo = 0;
  for (let passo = 1; passo <= eventos.length; passo += 1) {
    if (eventos[passo - 1].tipo !== "acao_proposta") {
      continue;
    }
    const aguardando = estadoNoPasso(eventos, linhas, passo).aguardando;
    if (aguardando > maximo) {
      maximo = aguardando;
      melhor = passo;
    }
  }
  return melhor;
}
