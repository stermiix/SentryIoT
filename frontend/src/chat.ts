// O acesso à API do chat com o modelo (`/api/chat` e `/api/modelos`, servidas pelo backend em
// `codigo/api/`). Os componentes não chamam `fetch` diretamente: tudo passa por aqui, e os testes
// trocam o `fetch`.

export type Papel = "usuario" | "assistente";

export interface MensagemDoChat {
  papel: Papel;
  conteudo: string;
}

export interface PedidoDeChat {
  /** Vazio usa o modelo padrão do backend. */
  modelo: string;
  sistema: string;
  mensagens: MensagemDoChat[];
}

export interface RespostaDoChat {
  conteudo: string;
  modelo: string;
  /** Nulos quando o provedor não informa o uso. */
  tokens_entrada: number | null;
  tokens_saida: number | null;
  tempo_ms: number;
}

export interface ListaDeModelos {
  modelos: string[];
  padrao: string;
}

/** Uma mensagem como fica na conversa da tela: a do modelo guarda junto o que a API devolveu. */
export type MensagemDaConversa = { papel: "usuario"; conteudo: string } | ({ papel: "assistente" } & RespostaDoChat);

export type TipoDeErro = "backend" | "rede";

/** `backend`: o backend respondeu com erro (400, 502, 503…). `rede`: não houve resposta. */
export class ErroDoChat extends Error {
  constructor(
    readonly tipo: TipoDeErro,
    mensagem: string,
    readonly status: number | null,
  ) {
    super(mensagem);
    this.name = "ErroDoChat";
  }
}

const SEM_BACKEND = "O backend do chat não está no ar.";

type Buscar = typeof fetch;
const buscarPadrao: Buscar = (entrada, init) => fetch(entrada, init);

/**
 * A conversa com a nova mensagem da pessoa no fim, e o pedido correspondente para a API: só papel
 * e conteúdo de cada mensagem, com o modelo escolhido e o prompt de sistema vazio.
 */
export function montarPedido(mensagens: MensagemDaConversa[], texto: string, modelo: string): { historico: MensagemDaConversa[]; pedido: PedidoDeChat } {
  const historico: MensagemDaConversa[] = [...mensagens, { papel: "usuario", conteudo: texto.trim() }];
  return {
    historico,
    pedido: { modelo, sistema: "", mensagens: historico.map(({ papel, conteudo }) => ({ papel, conteudo })) },
  };
}

export async function enviarChat(pedido: PedidoDeChat, buscar: Buscar = buscarPadrao): Promise<RespostaDoChat> {
  const corpo = await pedir("/api/chat", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(pedido) }, buscar);
  if (!ehRespostaDoChat(corpo)) {
    throw new ErroDoChat("backend", "O backend devolveu uma resposta fora do formato esperado.", 200);
  }
  return corpo;
}

export async function listarModelos(buscar: Buscar = buscarPadrao): Promise<ListaDeModelos> {
  const corpo = await pedir("/api/modelos", { method: "GET" }, buscar);
  if (!ehListaDeModelos(corpo)) {
    throw new ErroDoChat("backend", "O backend devolveu a lista de modelos fora do formato esperado.", 200);
  }
  return corpo;
}

/** Uma chamada à API: falha de rede vira erro de rede; status de erro vira erro de backend com a mensagem dele. */
async function pedir(caminho: string, init: RequestInit, buscar: Buscar): Promise<unknown> {
  let resposta: Response;
  try {
    resposta = await buscar(caminho, init);
  } catch {
    throw new ErroDoChat("rede", SEM_BACKEND, null);
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
    throw new ErroDoChat("backend", erro, resposta.status);
  }
  return corpo;
}

function ehObjeto(valor: unknown): valor is Record<string, unknown> {
  return typeof valor === "object" && valor !== null && !Array.isArray(valor);
}

function ehInteiroOuNulo(valor: unknown): valor is number | null {
  return valor === null || (typeof valor === "number" && Number.isInteger(valor));
}

function ehRespostaDoChat(valor: unknown): valor is RespostaDoChat {
  return (
    ehObjeto(valor) &&
    typeof valor.conteudo === "string" &&
    typeof valor.modelo === "string" &&
    ehInteiroOuNulo(valor.tokens_entrada) &&
    ehInteiroOuNulo(valor.tokens_saida) &&
    typeof valor.tempo_ms === "number"
  );
}

function ehListaDeModelos(valor: unknown): valor is ListaDeModelos {
  return ehObjeto(valor) && Array.isArray(valor.modelos) && valor.modelos.every((m) => typeof m === "string") && typeof valor.padrao === "string";
}
