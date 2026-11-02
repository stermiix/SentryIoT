import type {
  AGENTES,
  CANAIS,
  CATEGORIAS,
  CATEGORIAS_DO_MODELO,
  CODIGOS_DE_RISCO_ALTO,
  ESTADOS_DA_EXECUCAO,
  ESTADOS_DA_PROPOSTA,
  ESTADOS_DO_INCIDENTE,
  LUGARES_DO_MODELO,
  MOTIVOS_DE_PARADA,
  MOTIVOS_DE_RECUSA,
  ORIGENS_DE_ACAO,
  PROTOCOLOS_DE_TRANSPORTE,
  RESULTADOS_DO_EFEITO,
  RISCOS,
  VEREDITOS_DA_TRIAGEM,
} from "./listas";

// Tipos do log de eventos, escritos a partir de `codigo/mcp/contrato.json` (contrato 0.7.0, que
// sai de `codigo/mcp/tipos.py`). Cada linha do log é um `Evento`, e o campo `tipo` diz o formato de
// `dados`: a união abaixo é discriminada por ele. Os valores fixos vêm de `listas.ts`, que um teste
// confere contra o `contrato.json`, e a conferência em tempo de execução fica em `contrato.ts`.

export type Categoria = (typeof CATEGORIAS)[number];
export type CategoriaDoModelo = (typeof CATEGORIAS_DO_MODELO)[number];
export type Agente = (typeof AGENTES)[number];
export type Canal = (typeof CANAIS)[number];
export type Risco = (typeof RISCOS)[number];
export type EstadoDoIncidente = (typeof ESTADOS_DO_INCIDENTE)[number];
export type EstadoDaProposta = (typeof ESTADOS_DA_PROPOSTA)[number];
export type EstadoDaExecucao = (typeof ESTADOS_DA_EXECUCAO)[number];
export type ResultadoDoEfeito = (typeof RESULTADOS_DO_EFEITO)[number];
export type CodigoDeRiscoAlto = (typeof CODIGOS_DE_RISCO_ALTO)[number];
export type MotivoDeRecusa = (typeof MOTIVOS_DE_RECUSA)[number];
export type LugarDoModelo = (typeof LUGARES_DO_MODELO)[number];
export type MotivoDeParada = (typeof MOTIVOS_DE_PARADA)[number];
export type VereditoDaTriagem = (typeof VEREDITOS_DA_TRIAGEM)[number];

/** Objeto livre do contrato (`argumentos`, `resultado`, `parametros`). */
export type Livre = Record<string, unknown>;

// --- O que vai em `dados`, por tipo de evento ----------------------------------------------

export interface LoteDeJanelas {
  janelas: number;
  por_categoria: Partial<Record<CategoriaDoModelo, number>>;
}

export interface EnderecoContado {
  endereco: string;
  quadros: number;
}

export interface PortaContada {
  destino: string;
  porta: number;
  protocolo: (typeof PROTOCOLOS_DE_TRANSPORTE)[number];
  quadros: number;
}

export interface FeaturePrincipal {
  nome: string;
  valor: number;
  referencia_benigno: number;
}

/** Porta a que um candidato a atacante mais mandou quadros, em qualquer destino. */
export interface PortaDoCandidato {
  porta: number;
  protocolo: (typeof PROTOCOLOS_DE_TRANSPORTE)[number];
  quadros: number;
}

/** Uma origem que pode ser o atacante, com as medidas que a separam do tráfego normal. */
export interface CandidatoAAtacante {
  endereco: string;
  janelas: number;
  /** Parcela das janelas benignas, fora de incidente, em que o endereço aparece como origem (0 a 1). */
  no_trafego_normal: number;
  quadros_enviados: number;
  quadros_recebidos: number;
  conexoes_abertas: number;
  conexoes_recebidas: number;
  destinos: EnderecoContado[];
  /** O contrato dá uma lista vazia como padrão: o campo pode faltar. */
  portas?: PortaDoCandidato[];
}

export interface Incidente {
  id: string;
  estado: EstadoDoIncidente;
  categoria: Categoria;
  categoria_do_modelo: CategoriaDoModelo;
  confianca: number;
  inicio: string;
  fim: string;
  janelas: number;
  origens_distintas: number;
  distribuido: boolean;
  origens: EnderecoContado[];
  destinos: EnderecoContado[];
  features_principais: FeaturePrincipal[];
  /** Ausente nos logs gravados antes da versão 0.4.0 do contrato. */
  portas?: PortaContada[];
  /** O que o classificador disse de cada janela do incidente. Ausente antes da versão 0.6.0. */
  janelas_por_categoria?: Partial<Record<CategoriaDoModelo, number>>;
  /** Até cinco origens que se destacam do tráfego normal. Ausente antes da versão 0.6.0. */
  candidatos?: CandidatoAAtacante[];
}

/** A pessoa que opera a rede marcou o incidente como já resolvido. */
export interface MarcaDeResolvido {
  incidente: string;
  canal: Canal;
  usuario: string;
  motivo: string | null;
}

export interface ChamadaDeLLM {
  agente: Agente;
  modelo: string;
  tokens_entrada: number;
  tokens_saida: number;
  duracao_ms: number;
  /** O finish_reason do provedor. Ausente nos logs gravados antes da versão 0.5.0 do contrato. */
  motivo_termino?: string | null;
  /** Onde o modelo rodou. Ausente nos logs gravados antes da versão 0.5.0 do contrato. */
  onde?: LugarDoModelo | null;
}

/** Como terminou o laço de um agente num incidente. */
export interface ConclusaoDoAgente {
  agente: Agente;
  motivo: MotivoDeParada;
  voltas: number;
  tokens_entrada: number;
  tokens_saida: number;
  /** Só na triagem, quando a resposta traz o rótulo. */
  veredito: VereditoDaTriagem | null;
}

/** O atacante que a triagem apontou entre os candidatos e as origens do incidente. */
export interface AtacanteApontado {
  endereco: string;
  justificativa: string;
}

/** A resposta final da triagem, com o rótulo lido dela. */
export interface AnaliseDaTriagem {
  agente: "triagem";
  texto: string;
  veredito: VereditoDaTriagem | null;
}

/** O sumário do incidente, escrito pela triagem a partir do log no fim do orquestrador. */
export interface Sumario {
  agente: "triagem";
  texto: string;
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
  /** O alvo com o rótulo neutro (origem-1, admin@destino-1), quando o agente o escreveu assim. */
  alvo_com_rotulo: string | null;
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
  usuario: string;
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
  origem: (typeof ORIGENS_DE_ACAO)[number];
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
export type EventoDeMarca = Linha<"incidente_marcado_resolvido", MarcaDeResolvido>;
export type EventoDeLLM = Linha<"llm_chamada", ChamadaDeLLM>;
export type EventoDeTool = Linha<"tool_chamada", ChamadaDeTool>;
export type EventoDeConclusao = Linha<"agente_concluido", ConclusaoDoAgente>;
export type EventoDeAtacante = Linha<"atacante_apontado", AtacanteApontado>;
export type EventoDeAnalise = Linha<"analise_emitida", AnaliseDaTriagem>;
export type EventoDeRecomendacao = Linha<"recomendacao_emitida", Recomendacao>;
export type EventoDeSumario = Linha<"sumario_emitido", Sumario>;
export type EventoDeProposta = Linha<"acao_proposta", Proposta>;
export type EventoDeDecisao = Linha<"acao_aprovada" | "acao_rejeitada", Decisao>;
export type EventoDeExecucao = Linha<"acao_executada" | "acao_desfeita", Execucao>;
export type EventoDeEfeito = Linha<"efeito_verificado", Efeito>;
export type EventoDeCatalogo = Linha<"catalogo_ampliado", Promocao>;
export type EventoDeRecusa = Linha<"recusa", Recusa>;

export type Evento =
  | EventoDeJanelas
  | EventoDeIncidente
  | EventoDeMarca
  | EventoDeLLM
  | EventoDeTool
  | EventoDeConclusao
  | EventoDeAtacante
  | EventoDeAnalise
  | EventoDeRecomendacao
  | EventoDeSumario
  | EventoDeProposta
  | EventoDeDecisao
  | EventoDeExecucao
  | EventoDeEfeito
  | EventoDeCatalogo
  | EventoDeRecusa;
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
  usuario: string;
  motivo: string | null;
}

/** Estado de uma proposta depois dos eventos lidos, com as regras do `reconstruir` de `codigo/mcp/acoes.py`. */
export interface PropostaView {
  id: string;
  acao: string;
  alvo: string;
  alvoComRotulo: string | null;
  /** Os parâmetros da ação, como vieram na proposta (o prazo em minutos fica em `duracao`). */
  parametros: Livre;
  justificativa: string;
  nova: boolean;
  risco: Risco;
  exigeAprovacao: boolean;
  /** Só os códigos: a frase mostrada é a do contrato (`MOTIVOS_DE_RISCO_ALTO`), e não a do log. */
  motivosDeRiscoAlto: CodigoDeRiscoAlto[];
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

/** A análise que a triagem escreveu no incidente. */
export interface AnaliseView {
  id: string;
  instante: string;
  texto: string;
  veredito: VereditoDaTriagem | null;
}

/** O atacante que a triagem apontou no incidente. */
export interface AtacanteView {
  id: string;
  instante: string;
  endereco: string;
  justificativa: string;
}

/** O sumário que a triagem escreveu no fim do incidente. */
export interface SumarioView {
  id: string;
  instante: string;
  texto: string;
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
  /** A última análise da triagem (desde o contrato 0.6.0). */
  analise: AnaliseView | null;
  /** O último atacante que a triagem apontou: vale o último (desde o contrato 0.6.0). */
  atacante: AtacanteView | null;
  /** O último sumário do incidente (desde o contrato 0.6.0). */
  sumario: SumarioView | null;
  /**
   * O veredito da última conclusão da triagem. Num log anterior ao contrato 0.6.0, que não tem a
   * análise, é o único lugar em que o veredito aparece.
   */
  vereditoDaConclusao: VereditoDaTriagem | null;
  /** O endereço de cada rótulo neutro do incidente (origem-1, destino-1), na ordem em que apareceram. */
  rotulos: ReadonlyMap<string, string>;
}

export interface ResumoGeral {
  janelasClassificadas: number;
  totalIncidentes: number;
  chamadasLLM: number;
  tokens: number;
  /** Eventos que citam um incidente que não estava aberto naquele ponto do log: ficam fora da fila. */
  eventosSemAbertura: number;
  incidentesSemAbertura: string[];
}
