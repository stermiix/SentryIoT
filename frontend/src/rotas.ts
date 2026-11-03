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
  /**
   * A execução da rodada final que as telas mostram (`?execucao=oficial/Recon-PortScan-inc-0003-local-r1`).
   * Cada pcap numera os incidentes do `inc-0001`: sem a execução, um recarregamento abriria o mesmo número
   * de outro log.
   */
  execucao?: string;
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
// O id de uma execução do índice: `<grupo>/<rodada>`.
const EXECUCAO = /^[A-Za-z0-9_-]{1,40}\/[A-Za-z0-9._+-]{1,200}$/;

/**
 * `#/incidentes/inc-0001` → detalhe do inc-0001, e `#/incidentes/inc-0001/conversa` → a conversa dos agentes
 * dele. Âncora vazia ou desconhecida abre a visão geral; `#chat` ainda abre o chat.
 */
export function lerRota(ancora: string): Rota {
  const [caminho = "", consulta = ""] = ancora.replace(/^#\/?/, "").split("?");
  const [trecho = "", id = "", aba = ""] = caminho.split("/");
  const tela = POR_TRECHO.get(trecho) ?? "visao-geral";
  const incidente = (tela === "incidente" || tela === "relatorio") && ID.test(id) ? id : null;
  const rota: Rota = tela === "incidente" && incidente && aba === "conversa" ? { tela, incidente, aba } : { tela, incidente };
  const execucao = new URLSearchParams(consulta).get("execucao");
  return execucao && EXECUCAO.test(execucao) ? { ...rota, execucao } : rota;
}

export function ancoraDa(rota: Rota): string {
  const id = rota.incidente && (rota.tela === "incidente" || rota.tela === "relatorio") ? `/${rota.incidente}` : "";
  const aba = id && rota.tela === "incidente" && rota.aba === "conversa" ? "/conversa" : "";
  const execucao = rota.execucao && EXECUCAO.test(rota.execucao) ? `?execucao=${encodeURIComponent(rota.execucao)}` : "";
  return `#/${TRECHO[rota.tela]}${id}${aba}${execucao}`;
}

/** As telas em que o incidente da rota é de um log: trocar de execução troca o incidente também. */
export function temIncidente(rota: Rota): boolean {
  return rota.tela === "incidente" || rota.tela === "relatorio";
}
