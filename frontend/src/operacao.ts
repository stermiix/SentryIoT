// O que a pessoa decide pela interface: aprovar ou rejeitar uma proposta, marcar um incidente como já
// resolvido e entrar com usuário e senha. O backend ainda não tem rotas para isso: hoje as decisões
// são tomadas pelo terminal (`python -m codigo.mcp.aprovar`), e a interface só lê o log.
//
// As telas chamam sempre `operacao`, e nunca `fetch`. Para ligar a interface ao servidor, basta
// escrever uma `Operacao` que chame as rotas novas e trocar a constante `operacao` no fim do arquivo:
// as telas, os diálogos de confirmação e as mensagens de erro já estão prontos.

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

/** A operação de hoje: nada chega ao servidor, e cada erro traz o comando equivalente do terminal. */
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

export const operacao: Operacao = operacaoPeloTerminal;
