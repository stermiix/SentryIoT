// O acesso à simulação (`POST /api/simulacao`, em `codigo/api/simulacao.py`): o pcap escolhido na
// tela vai no corpo, passa pelo extrator, pelo classificador e pela política de acionamento, e
// volta com o log de eventos e o pedido que iria ao modelo da triagem. Nenhum modelo é chamado.

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

export interface MensagemDoPedido {
  role: string;
  content: string;
}

export interface ToolDoPedido {
  type: string;
  function: { name: string; description: string };
}

export interface PedidoAoModelo {
  model: string;
  messages: MensagemDoPedido[];
  tools: ToolDoPedido[];
  [parametro: string]: unknown;
}

export interface ParaOLlm {
  /** Sempre falso: a simulação para na porta do modelo. */
  enviado: false;
  motivo: string;
  agente: "triagem";
  onde_roda: string;
  incidente: string;
  pedido: PedidoAoModelo;
  primeira_leitura: { tool: string; resultado: Record<string, unknown> };
  visao_da_fronteira: { tool: string; resultado: Record<string, unknown> };
}

export interface ResultadoDaSimulacao {
  arquivo: string;
  quadros: number;
  ignorados: number;
  janelas: number;
  por_categoria: Record<string, number>;
  duracao_do_pcap_s: number;
  processamento_s: number;
  modelo: string;
  ponto_de_operacao: { regra: string; limiar: number | null; seguidas: number };
  acionamento: Record<string, number>;
  incidentes: IncidenteDaSimulacao[];
  incidentes_alem_do_teto: number;
  log: string;
  /** O log de eventos gravado, em JSON Lines, para as outras telas lerem. */
  eventos: string;
  para_o_llm: ParaOLlm | null;
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

/** O arquivo vai cru no corpo, com o nome na consulta; o backend aceita um por vez. */
export async function iniciarSimulacao(arquivo: Blob, nome: string, buscar: Buscar = buscarPadrao): Promise<ResultadoDaSimulacao> {
  let resposta: Response;
  try {
    resposta = await buscar(`/api/simulacao?nome=${encodeURIComponent(nome)}`, {
      method: "POST",
      headers: { "Content-Type": "application/vnd.tcpdump.pcap" },
      body: arquivo,
    });
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
  if (!ehResultado(corpo)) {
    throw new ErroDaSimulacao("backend", "O backend devolveu a simulação fora do formato esperado.", resposta.status);
  }
  return corpo;
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

/** Os parâmetros de geração do pedido: tudo o que não é modelo, mensagens, tools nem stream. */
export function parametrosDoPedido(pedido: PedidoAoModelo): [string, string][] {
  return Object.entries(pedido)
    .filter(([chave]) => !["model", "messages", "tools", "stream"].includes(chave))
    .map(([chave, valor]) => [chave, typeof valor === "object" ? JSON.stringify(valor) : String(valor)]);
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
    (valor.para_o_llm === null || (ehObjeto(valor.para_o_llm) && valor.para_o_llm.enviado === false && ehObjeto(valor.para_o_llm.pedido)))
  );
}
