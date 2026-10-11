// Tipos do log de eventos, escritos à mão a partir de `codigo/mcp/contrato.json` (que sai de
// `codigo/mcp/tipos.py`). Cada linha do log é um `Evento`, e o campo `tipo` diz o formato de
// `dados`: a união abaixo é discriminada por ele. A conferência em tempo de execução, que dá
// garantia a estes tipos, fica em `contrato.ts`.
//
// Duas coisas daqui ainda não estão no contrato e chegam em outro PR do MCP: o evento
// `incidente_marcado_resolvido` e a categoria `DDoS+DoS` do modelo. A interface já as aceita, e
// funciona igual com um log que não tem nenhuma das duas.

export type Categoria =
  | "DDoS"
  | "DoS"
  | "DDoS+DoS"
  | "Mirai"
  | "Recon"
  | "Spoofing"
  | "Web"
  | "BruteForce"
  | "Benign";
export type Agente = "triagem" | "decisao" | "execucao";
export type Canal = "terminal" | "interface";
export type Risco = "baixo" | "alto";
export type EstadoDoIncidente = "aberto" | "encerrado";
export type EstadoDaProposta = "aguardando_aprovacao" | "liberada" | "rejeitada" | "executada" | "desfeita";
export type EstadoDaExecucao = "aplicada" | "desfeita";
export type ResultadoDoEfeito = "cessou" | "diminuiu" | "persiste";
export type CodigoDeRiscoAlto =
  | "acao_sempre_de_risco_alto"
  | "acao_nova"
  | "prazo_acima_do_limite"
  | "alvo_fora_do_incidente"
  | "alvo_e_destino_do_incidente"
  | "alvo_protegido"
  | "orcamento_de_risco_baixo_esgotado";
export type MotivoDeRecusa =
  | "identificador_desconhecido"
  | "argumentos_invalidos"
  | "alvo_malformado"
  | "alvo_nao_permitido"
  | "incidente_encerrado"
  | "limite_de_propostas_pendentes"
  | "acao_nova_incompleta"
  | "proposta_nao_liberada"
  | "proposta_ja_executada"
  | "acao_nao_aplicada"
  | "tool_fora_da_linha";

/** Objeto livre do contrato (`argumentos`, `resultado`, `parametros`). */
export type Livre = Record<string, unknown>;

// --- O que vai em `dados`, por tipo de evento ----------------------------------------------

export interface LoteDeJanelas {
  janelas: number;
  por_categoria: Partial<Record<Categoria, number>>;
}

export interface EnderecoContado {
  endereco: string;
  quadros: number;
}

export interface FeaturePrincipal {
  nome: string;
  valor: number;
  referencia_benigno: number;
}

export interface Incidente {
  id: string;
  estado: EstadoDoIncidente;
  categoria: Categoria;
  categoria_do_modelo: Categoria;
  confianca: number;
  inicio: string;
  fim: string;
  janelas: number;
  origens_distintas: number;
  distribuido: boolean;
  origens: EnderecoContado[];
  destinos: EnderecoContado[];
  features_principais: FeaturePrincipal[];
}

export interface ChamadaDeLLM {
  agente: Agente;
  modelo: string;
  tokens_entrada: number;
  tokens_saida: number;
  duracao_ms: number;
}

export interface ChamadaDeTool {
  agente: Agente | null;
  nome: string;
  argumentos: Livre;
  resultado: Livre;
  duracao_ms: number;
}

export interface Recomendacao {
  agente: Agente;
  texto: string;
  propostas: string[];
}

export interface MotivoDeRiscoAlto {
  codigo: CodigoDeRiscoAlto;
  descricao: string;
}

export interface Proposta {
  id: string;
  incidente: string;
  acao: string;
  alvo: string;
  parametros: Livre;
  justificativa: string;
  nova: boolean;
  risco: Risco;
  motivos_de_risco_alto: MotivoDeRiscoAlto[];
  exige_aprovacao: boolean;
  estado: EstadoDaProposta;
}

export interface Decisao {
  proposta: string;
  canal: Canal;
  motivo: string | null;
}

export interface Execucao {
  id: string;
  proposta: string;
  incidente: string;
  acao: string;
  alvo: string;
  parametros: Livre;
  estado: EstadoDaExecucao;
  aplicada_em: string;
  desfeita_em: string | null;
}

export interface Efeito {
  execucao: string;
  incidente: string;
  resultado: ResultadoDoEfeito;
  observacao: string;
}

export interface ParametroDeAcao {
  nome: string;
  descricao: string;
  obrigatorio: boolean;
}

export interface AcaoDoCatalogo {
  nome: string;
  descricao: string;
  alvo: string;
  parametros: ParametroDeAcao[];
  regra: string;
  origem: "base" | "promovida";
  passos: string[];
  efeito_esperado: string | null;
  como_desfazer: string;
  fonte: string | null;
}

export interface Promocao {
  proposta: string;
  acao: AcaoDoCatalogo;
}

export interface Recusa {
  agente: Agente | null;
  tool: string;
  argumentos: Livre;
  motivo: MotivoDeRecusa;
  mensagem: string;
}

/** A pessoa marcou o incidente como já resolvido (evento que ainda vai entrar no contrato). */
export interface MarcacaoDeResolvido {
  incidente: string;
  canal: Canal;
  usuario: string;
  motivo?: string | null;
}

// --- Os eventos ----------------------------------------------------------------------------

interface Linha<T extends string, D> {
  id: string;
  instante: string;
  tipo: T;
  incidente: string | null;
  dados: D;
}

export type EventoDeJanelas = Linha<"janelas_classificadas", LoteDeJanelas>;
export type EventoDeIncidente = Linha<"incidente_aberto" | "incidente_atualizado" | "incidente_encerrado", Incidente>;
export type EventoDeLLM = Linha<"llm_chamada", ChamadaDeLLM>;
export type EventoDeTool = Linha<"tool_chamada", ChamadaDeTool>;
export type EventoDeRecomendacao = Linha<"recomendacao_emitida", Recomendacao>;
export type EventoDeProposta = Linha<"acao_proposta", Proposta>;
export type EventoDeDecisao = Linha<"acao_aprovada" | "acao_rejeitada", Decisao>;
export type EventoDeExecucao = Linha<"acao_executada" | "acao_desfeita", Execucao>;
export type EventoDeEfeito = Linha<"efeito_verificado", Efeito>;
export type EventoDeCatalogo = Linha<"catalogo_ampliado", Promocao>;
export type EventoDeRecusa = Linha<"recusa", Recusa>;
export type EventoDeMarcacao = Linha<"incidente_marcado_resolvido", MarcacaoDeResolvido>;

export type Evento =
  | EventoDeJanelas
  | EventoDeIncidente
  | EventoDeLLM
  | EventoDeTool
  | EventoDeRecomendacao
  | EventoDeProposta
  | EventoDeDecisao
  | EventoDeExecucao
  | EventoDeEfeito
  | EventoDeCatalogo
  | EventoDeRecusa
  | EventoDeMarcacao;
export type TipoDeEvento = Evento["tipo"];

// --- O que a interface monta a partir dos eventos ------------------------------------------

export interface ExecucaoView {
  id: string;
  estado: EstadoDaExecucao;
  aplicadaEm: string;
  desfeitaEm: string | null;
  efeitos: { instante: string; resultado: ResultadoDoEfeito; observacao: string }[];
}

export interface DecisaoView {
  tipo: EventoDeDecisao["tipo"];
  instante: string;
  canal: Canal;
  motivo: string | null;
}

/** Estado de uma proposta depois dos eventos lidos, como o `reconstruir` de `codigo/mcp/acoes.py`. */
export interface PropostaView {
  id: string;
  acao: string;
  alvo: string;
  justificativa: string;
  nova: boolean;
  risco: Risco;
  exigeAprovacao: boolean;
  motivosDeRiscoAlto: MotivoDeRiscoAlto[];
  estado: EstadoDaProposta;
  criadaEm: string;
  decisoes: DecisaoView[];
  execucoes: ExecucaoView[];
  promovida: boolean;
}

export interface MarcacaoView {
  instante: string;
  canal: Canal;
  usuario: string;
  motivo: string | null;
}

export interface IncidenteView {
  id: string;
  incidente: Incidente;
  abertoEm: string;
  eventos: Evento[];
  chamadasLLM: number;
  tokensEntrada: number;
  tokensSaida: number;
  recomendacoes: EventoDeRecomendacao[];
  propostas: PropostaView[];
  marcacao: MarcacaoView | null;
}

export interface ResumoGeral {
  janelasClassificadas: number;
  totalIncidentes: number;
  chamadasLLM: number;
  tokens: number;
  /** Eventos que citam um incidente sem `incidente_aberto` no log: ficam fora da fila. */
  eventosSemAbertura: number;
  incidentesSemAbertura: string[];
}
