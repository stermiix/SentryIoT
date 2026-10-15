import { describe, expect, it } from "vitest";
import { ErroDaOperacao, operacao, operacaoPeloTerminal } from "./operacao";

// Enquanto o backend não tem rotas de decisão, cada operação falha com o comando de terminal que faz
// a mesma coisa. Os diálogos mostram esse comando.

async function falha(promessa: Promise<void>): Promise<ErroDaOperacao> {
  try {
    await promessa;
  } catch (erro) {
    expect(erro).toBeInstanceOf(ErroDaOperacao);
    return erro as ErroDaOperacao;
  }
  throw new Error("a operação deveria ter falhado");
}

describe("operações pela interface, hoje", () => {
  it("a interface usa a operação pelo terminal, que não grava decisões e não tem login", () => {
    expect(operacao).toBe(operacaoPeloTerminal);
    expect(operacao.gravaDecisoes).toBe(false);
    expect(operacao.temLogin).toBe(false);
  });

  it("aprovar, rejeitar e marcar como já resolvido devolvem o comando equivalente", async () => {
    expect((await falha(operacao.aprovar("prop-0003"))).comando).toBe("python -m codigo.mcp.aprovar prop-0003");
    expect((await falha(operacao.rejeitar("prop-0002", "o dispositivo não pode parar"))).comando).toBe(
      'python -m codigo.mcp.aprovar prop-0002 --rejeitar --motivo "o dispositivo não pode parar"',
    );
    expect((await falha(operacao.marcarResolvido("inc-0002", ""))).comando).toBe("python -m codigo.mcp.aprovar --resolvido inc-0002");
  });

  it("o motivo vai para o comando sem aspas, barras, cifrão, crase nem exclamação", async () => {
    const erro = await falha(operacao.rejeitar("prop-0002", 'a "b" $(c) `d` \\e caiu!agora'));
    expect(erro.comando).toBe('python -m codigo.mcp.aprovar prop-0002 --rejeitar --motivo "a b (c) d e caiuagora"');
  });

  it("entrar explica que ainda não há login", async () => {
    const erro = await falha(operacao.entrar("operador", "x"));
    expect(erro.tipo).toBe("indisponivel");
    expect(erro.message).toContain("ainda não tem login");
  });
});
