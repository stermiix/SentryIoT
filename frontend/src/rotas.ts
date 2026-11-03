// A tela vem da âncora da página (`#/incidentes/inc-0001`), e não do caminho: o app é estático, e o
// backend devolve o mesmo index.html para qualquer caminho.

export type Tela =
  | "rodada"
  | "visao-geral"
  | "incidente"
  | "ao-vivo"
  | "simulacao"
  | "isolado-integrado"
  | "custo-latencia"
  | "qualidade"
  | "chat"
  | "relatorio"
  | "componentes"
  | "entrar";

export interface Rota {
  tela: Tela;
  /** O incidente do detalhe ou do relatório; nulo abre o da execução escolhida ou o primeiro da fila. */
  incidente: string | null;
  /** No detalhe do incidente, a aba da conversa dos agentes (`#/incidentes/inc-0001/conversa`). */
  aba?: "conversa";
}

// O trecho da âncora de cada tela. O detalhe e o relatório levam o id do incidente depois.
const TRECHO: Record<Tela, string> = {
  rodada: "rodada-final",
  "visao-geral": "visao-geral",
  incidente: "incidentes",
  "ao-vivo": "ao-vivo",
  simulacao: "simulacao",
  "isolado-integrado": "isolado-integrado",
  "custo-latencia": "custo-latencia",
  qualidade: "qualidade-do-modelo",
  chat: "chat",
  relatorio: "relatorio",
  componentes: "componentes",
  entrar: "entrar",
};
const POR_TRECHO = new Map(Object.entries(TRECHO).map(([tela, trecho]) => [trecho, tela as Tela]));
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * `#/incidentes/inc-0001` → detalhe do inc-0001, e `#/incidentes/inc-0001/conversa` → a conversa dos agentes
 * dele. Âncora vazia ou desconhecida abre a visão geral; `#chat` ainda abre o chat.
 */
export function lerRota(ancora: string): Rota {
  const [trecho = "", id = "", aba = ""] = ancora.replace(/^#\/?/, "").split("/");
  const tela = POR_TRECHO.get(trecho) ?? "visao-geral";
  const incidente = (tela === "incidente" || tela === "relatorio") && ID.test(id) ? id : null;
  return tela === "incidente" && incidente && aba === "conversa" ? { tela, incidente, aba } : { tela, incidente };
}

export function ancoraDa(rota: Rota): string {
  const id = rota.incidente && (rota.tela === "incidente" || rota.tela === "relatorio") ? `/${rota.incidente}` : "";
  const aba = id && rota.tela === "incidente" && rota.aba === "conversa" ? "/conversa" : "";
  return `#/${TRECHO[rota.tela]}${id}${aba}`;
}
