// O que a pessoa decide pela interface: aprovar ou rejeitar uma proposta, marcar um incidente como já
// resolvido e entrar com usuário e senha.
//
// As decisões chegam ao backend enquanto os agentes rodam numa simulação (`ligarSimulacao`). Fora
// disso, num log só de leitura, elas são tomadas pelo terminal (`python -m codigo.mcp.aprovar`), e a
// operação devolve o comando. As telas chamam sempre `operacao`, e nunca `fetch`.

import { decidirNaSimulacao, ErroDaSimulacao, type DecisaoNaSimulacao } from "./simulacao";

export type TipoDeErroDaOperacao = "indisponivel" | "recusada" | "rede";

export class ErroDaOperacao extends Error {
  constructor(
    readonly tipo: TipoDeErroDaOperacao,
    mensagem: string,
    /** O comando de terminal que faz a mesma coisa, quando houver. */
    readonly comando: string | null = null,
  ) {
    super(mensagem);
    this.name = "ErroDaOperacao";
  }
}

export interface Operacao {
  /** Se as decisões pela interface chegam ao servidor. Falso: os botões abrem o diálogo, que explica. */
  readonly gravaDecisoes: boolean;
  /** Se existe login. Falso: a tela de entrada explica e oferece o replay. */
  readonly temLogin: boolean;
  aprovar(proposta: string): Promise<void>;
  rejeitar(proposta: string, motivo: string): Promise<void>;
  marcarResolvido(incidente: string, motivo: string): Promise<void>;
  entrar(usuario: string, senha: string): Promise<void>;
}

/** O motivo entre aspas duplas, pronto para colar no terminal (sem o que o shell interpretaria). */
function comMotivo(motivo: string): string {
  const limpo = motivo.trim().replace(/["\\$`!]/g, "");
  return limpo ? ` --motivo "${limpo}"` : "";
}

const SEM_ROTA = "A interface ainda não grava decisões: o log é só leitura. Para decidir agora, use o terminal.";

/** Sem agentes rodando: nada chega ao servidor, e cada erro traz o comando equivalente do terminal. */
export const operacaoPeloTerminal: Operacao = {
  gravaDecisoes: false,
  temLogin: false,
  async aprovar(proposta) {
    throw new ErroDaOperacao("indisponivel", SEM_ROTA, `python -m codigo.mcp.aprovar ${proposta}`);
  },
  async rejeitar(proposta, motivo) {
    throw new ErroDaOperacao("indisponivel", SEM_ROTA, `python -m codigo.mcp.aprovar ${proposta} --rejeitar${comMotivo(motivo)}`);
  },
  async marcarResolvido(incidente, motivo) {
    throw new ErroDaOperacao("indisponivel", SEM_ROTA, `python -m codigo.mcp.aprovar --resolvido ${incidente}${comMotivo(motivo)}`);
  },
  async entrar() {
    throw new ErroDaOperacao(
      "indisponivel",
      "O SentryIoT ainda não tem login. A interface roda na máquina da equipe ou atrás da rede da equipe (Tailscale), sem usuário e senha.",
    );
  },
};

async function decidir(decisao: DecisaoNaSimulacao): Promise<void> {
  try {
    await decidirNaSimulacao(decisao);
  } catch (falha) {
    const pelaRede = falha instanceof ErroDaSimulacao && falha.tipo === "rede";
    throw new ErroDaOperacao(pelaRede ? "rede" : "recusada", falha instanceof Error ? falha.message : "Falha inesperada ao gravar a decisão.");
  }
}

/** Com agentes rodando numa simulação: a decisão vai ao log dela, com o canal da interface. */
export const operacaoNaSimulacao: Operacao = {
  gravaDecisoes: true,
  temLogin: false,
  aprovar: (proposta) => decidir({ tipo: "aprovar", id: proposta }),
  rejeitar: (proposta, motivo) => decidir({ tipo: "rejeitar", id: proposta, motivo }),
  marcarResolvido: (incidente, motivo) => decidir({ tipo: "resolvido", id: incidente, motivo }),
  entrar: operacaoPeloTerminal.entrar,
};

let atual: Operacao = operacaoPeloTerminal;

/** O app chama com verdadeiro enquanto os agentes de uma simulação rodam. */
export function ligarSimulacao(ativa: boolean): void {
  atual = ativa ? operacaoNaSimulacao : operacaoPeloTerminal;
}

export const operacao: Operacao = {
  get gravaDecisoes() {
    return atual.gravaDecisoes;
  },
  get temLogin() {
    return atual.temLogin;
  },
  aprovar: (proposta) => atual.aprovar(proposta),
  rejeitar: (proposta, motivo) => atual.rejeitar(proposta, motivo),
  marcarResolvido: (incidente, motivo) => atual.marcarResolvido(incidente, motivo),
  entrar: (usuario, senha) => atual.entrar(usuario, senha),
};
