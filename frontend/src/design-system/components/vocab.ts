/* The official vocabulary of the project, exactly as it appears on screen (pt-BR),
   and how each term is drawn: icon, tone (colour role) and, for categories, a print pattern.
   The values (categories, states, event types, risk reasons) are the log contract's own
   (`codigo/mcp/contrato.json`, through `listas.ts` and `types.ts`): only the drawing is decided here. */
import type { IconName } from './icons-data';
import { CATEGORIAS, CATEGORIAS_DO_MODELO, MOTIVOS_DE_RISCO_ALTO } from '../../listas';
import type {
  Agente, Canal, Categoria, CategoriaDoModelo, CodigoDeRiscoAlto, EstadoDaExecucao, EstadoDaProposta,
  MotivoDeRecusa, ResultadoDoEfeito, Risco, TipoDeEvento,
} from '../../types';

export type Tone = 'attention' | 'danger' | 'success' | 'info' | 'neutral';

/* ---------- categories ---------- */
export type Category = Categoria;
export type ModelCategory = CategoriaDoModelo;
export type AnyCategory = Category | ModelCategory;

export interface CategoryInfo { label: string; token: string; icon: IconName; pattern: string; description: string }
export const CATEGORY: Record<AnyCategory, CategoryInfo> = {
  'DDoS':       { label: 'DDoS',       token: 'cat-ddos',       icon: 'merge',               pattern: 'solid',    description: 'Negação de serviço distribuída: muitas origens.' },
  'DoS':        { label: 'DoS',        token: 'cat-dos',        icon: 'arrow-right-to-line', pattern: 'dots',     description: 'Negação de serviço de uma origem.' },
  'DDoS+DoS':   { label: 'DDoS+DoS',   token: 'cat-flood',      icon: 'waves',               pattern: 'rows',     description: 'Classe do modelo: o classificador não separa DDoS de DoS.' },
  'Mirai':      { label: 'Mirai',      token: 'cat-mirai',      icon: 'worm',                pattern: 'cross',    description: 'Botnet de dispositivos IoT.' },
  'Recon':      { label: 'Recon',      token: 'cat-recon',      icon: 'radar',               pattern: 'cols',     description: 'Reconhecimento e varredura.' },
  'Spoofing':   { label: 'Spoofing',   token: 'cat-spoofing',   icon: 'venetian-mask',       pattern: 'diag',     description: 'Falsificação de identidade (ARP, DNS).' },
  'Web':        { label: 'Web',        token: 'cat-web',        icon: 'code-xml',            pattern: 'antidiag', description: 'Ataques a aplicações web.' },
  'BruteForce': { label: 'BruteForce', token: 'cat-bruteforce', icon: 'key-round',           pattern: 'checker',  description: 'Força bruta de credenciais.' },
  'Benign':     { label: 'Benign',     token: 'cat-benign',     icon: 'circle',              pattern: 'none',     description: 'Tráfego normal.' },
};
export const INCIDENT_CATEGORIES: readonly Category[] = CATEGORIAS;
export const MODEL_CATEGORIES: readonly ModelCategory[] = CATEGORIAS_DO_MODELO;

/* ---------- states ---------- */
export interface StateInfo { label: string; tone: Tone; icon: IconName }

/** The incident as the screen shows it: the classifier's state, or the operator's "já resolvido" mark. */
export type IncidentState = 'aberto' | 'encerrado' | 'ja-resolvido';
export const INCIDENT_STATE: Record<IncidentState, StateInfo> = {
  'aberto':       { label: 'Aberto',                    tone: 'info',    icon: 'circle-dot' },
  'encerrado':    { label: 'Encerrado',                 tone: 'neutral', icon: 'archive' },
  'ja-resolvido': { label: 'Marcado como já resolvido', tone: 'neutral', icon: 'user-check' },
};

export type ProposalState = EstadoDaProposta;
export const PROPOSAL_STATE: Record<ProposalState, StateInfo> = {
  'aguardando_aprovacao': { label: 'Aguardando aprovação', tone: 'attention', icon: 'hourglass' },
  'liberada':             { label: 'Liberada',             tone: 'info',      icon: 'lock-open' },
  'rejeitada':            { label: 'Rejeitada',            tone: 'danger',    icon: 'ban' },
  'executada':            { label: 'Executada',            tone: 'success',   icon: 'check-check' },
  'desfeita':             { label: 'Desfeita',             tone: 'neutral',   icon: 'undo-2' },
};

export type ExecutionState = EstadoDaExecucao;
export const EXECUTION_STATE: Record<ExecutionState, StateInfo> = {
  'aplicada': { label: 'Aplicada', tone: 'success', icon: 'check' },
  'desfeita': { label: 'Desfeita', tone: 'neutral', icon: 'undo-2' },
};

export type EffectResult = ResultadoDoEfeito;
export const EFFECT: Record<EffectResult, StateInfo> = {
  'cessou':   { label: 'o incidente cessou',   tone: 'success',   icon: 'circle-check-big' },
  'diminuiu': { label: 'o incidente diminuiu', tone: 'info',      icon: 'trending-down' },
  'persiste': { label: 'o incidente persiste', tone: 'attention', icon: 'activity' },
};

export type Risk = Risco;
export const RISK: Record<Risk, StateInfo> = {
  'baixo': { label: 'Risco baixo', tone: 'neutral', icon: 'shield-check' },
  'alto':  { label: 'Risco alto',  tone: 'danger',  icon: 'triangle-alert' },
};

export type AgentName = Agente;
export const AGENT: Record<AgentName, { label: string; icon: IconName; role: string }> = {
  'triagem':  { label: 'Triagem',  icon: 'list-filter', role: 'Lê o incidente e confere se o alerta é coerente.' },
  'decisao':  { label: 'Decisão',  icon: 'scale',       role: 'Escolhe a mitigação e propõe ações. Só vê rótulos neutros.' },
  'execucao': { label: 'Execução', icon: 'wrench',      role: 'Aplica, verifica o efeito e pode desfazer. Sempre local.' },
};

export type Channel = Canal;
export const CHANNEL: Record<Channel, { label: string; icon: IconName }> = {
  'terminal':  { label: 'pelo terminal',  icon: 'square-terminal' },
  'interface': { label: 'pela interface', icon: 'mouse-pointer-click' },
};

export type ProviderLocation = 'local' | 'nuvem';

/* ---------- the 16 event types of the log, as the timeline draws them ---------- */
export type EventType = TipoDeEvento;

export const EVENT: Record<EventType, StateInfo> = {
  'janelas_classificadas':       { label: 'Janelas classificadas',     tone: 'neutral', icon: 'layers' },
  'incidente_aberto':            { label: 'Incidente aberto',          tone: 'info',    icon: 'flag' },
  'incidente_atualizado':        { label: 'Incidente atualizado',      tone: 'info',    icon: 'refresh-cw' },
  'incidente_encerrado':         { label: 'Incidente encerrado',       tone: 'neutral', icon: 'archive' },
  'incidente_marcado_resolvido': { label: 'Marcado como já resolvido', tone: 'neutral', icon: 'user-check' },
  'llm_chamada':                 { label: 'Chamada à IA',              tone: 'neutral', icon: 'brain-circuit' },
  'tool_chamada':                { label: 'Chamada de tool',           tone: 'neutral', icon: 'plug' },
  'recomendacao_emitida':        { label: 'Recomendação emitida',      tone: 'neutral', icon: 'message-square-quote' },
  'acao_proposta':               { label: 'Proposta criada',           tone: 'neutral', icon: 'clipboard-plus' },
  'acao_aprovada':               { label: 'Aprovada',                  tone: 'success', icon: 'badge-check' },
  'acao_rejeitada':              { label: 'Rejeitada',                 tone: 'danger',  icon: 'ban' },
  'acao_executada':              { label: 'Executada',                 tone: 'success', icon: 'check-check' },
  'acao_desfeita':               { label: 'Desfeita',                  tone: 'neutral', icon: 'undo-2' },
  'efeito_verificado':           { label: 'Efeito verificado',         tone: 'info',    icon: 'search-check' },
  'catalogo_ampliado':           { label: 'Promovida ao catálogo',     tone: 'info',    icon: 'book-plus' },
  'recusa':                      { label: 'Recusada pelo servidor',    tone: 'danger',  icon: 'shield-x' },
};
export const EVENT_TYPES = Object.keys(EVENT) as EventType[];

/* ---------- the 9 reasons a proposal is high risk (text the person reads before approving) ----------
   The sentence is the contract's (`MOTIVOS_DE_RISCO_ALTO`), never the one that came in the log. */
export type RiskReason = CodigoDeRiscoAlto;
export const RISK_REASON: Record<RiskReason, string> = MOTIVOS_DE_RISCO_ALTO;

/* ---------- why the MCP server refused a call, in the system's words ----------
   The refusal message, which may repeat what the agent sent, is shown apart, in quotes. */
export const REFUSAL_REASON: Record<MotivoDeRecusa, string> = {
  identificador_desconhecido: 'identificador desconhecido',
  argumentos_invalidos: 'argumentos inválidos',
  alvo_malformado: 'alvo malformado',
  alvo_nao_permitido: 'alvo não permitido',
  incidente_encerrado: 'incidente encerrado',
  incidente_ja_resolvido: 'incidente marcado como já resolvido',
  limite_de_propostas_pendentes: 'limite de propostas aguardando aprovação',
  limite_de_propostas_liberadas: 'limite de propostas liberadas e não executadas',
  acao_nova_incompleta: 'ação nova incompleta',
  proposta_nao_liberada: 'proposta não liberada',
  proposta_ja_executada: 'proposta já executada',
  acao_nao_aplicada: 'ação não aplicada',
  tool_fora_da_linha: 'tool fora da linha do agente',
};

export const TONE_VARS: Record<Tone, { fg: string; tint: string }> = {
  attention: { fg: 'var(--attention)', tint: 'var(--attention-tint)' },
  danger:    { fg: 'var(--danger)',    tint: 'var(--danger-tint)' },
  success:   { fg: 'var(--success)',   tint: 'var(--success-tint)' },
  info:      { fg: 'var(--info)',      tint: 'var(--info-tint)' },
  neutral:   { fg: 'var(--neutral)',   tint: 'var(--neutral-tint)' },
};
