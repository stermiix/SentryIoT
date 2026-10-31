import { afterEach, describe, expect, it, vi } from "vitest";
import { ErroDaOperacao, ligarSimulacao, operacao } from "./operacao";

// Sem agentes rodando, cada decisão falha com o comando de terminal que faz a mesma coisa, e os
// diálogos mostram esse comando. Com uma simulação em andamento, ela vai ao backend.

async function falha(promessa: Promise<void>): Promise<ErroDaOperacao> {
  try {
    await promessa;
  } catch (erro) {
    expect(erro).toBeInstanceOf(ErroDaOperacao);
    return erro as ErroDaOperacao;
  }
  throw new Error("a operação deveria ter falhado");
}

describe("sem agentes rodando", () => {
  it("a interface não grava decisões e não tem login", () => {
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

describe("com agentes rodando numa simulação", () => {
  afterEach(() => {
    ligarSimulacao(false);
    vi.unstubAllGlobals();
  });

  function backendQueResponde(status: number, corpo: unknown) {
    const buscar = vi.fn(async (_url: string, _init?: RequestInit) => new Response(JSON.stringify(corpo), { status }));
    vi.stubGlobal("fetch", buscar);
    return buscar;
  }
  const corpoDa = (buscar: ReturnType<typeof backendQueResponde>) => JSON.parse(String(buscar.mock.calls[0][1]?.body));

  it("aprovar, rejeitar e marcar como já resolvido vão ao backend", async () => {
    ligarSimulacao(true);
    expect(operacao.gravaDecisoes).toBe(true);

    const aprova = backendQueResponde(200, { ok: true });
    await operacao.aprovar("prop-0001");
    expect(corpoDa(aprova)).toEqual({ tipo: "aprovar", id: "prop-0001" });

    const rejeita = backendQueResponde(200, { ok: true });
    await operacao.rejeitar("prop-0002", "não pode parar");
    expect(corpoDa(rejeita)).toEqual({ tipo: "rejeitar", id: "prop-0002", motivo: "não pode parar" });

    const resolve = backendQueResponde(200, { ok: true });
    await operacao.marcarResolvido("inc-0001", "bloqueei no roteador");
    expect(corpoDa(resolve)).toEqual({ tipo: "resolvido", id: "inc-0001", motivo: "bloqueei no roteador" });
  });

  it("a recusa do backend chega ao diálogo com a mensagem, sem comando de terminal", async () => {
    ligarSimulacao(true);
    backendQueResponde(409, { erro: "Não existe proposta com o identificador prop-0009." });

    const erro = await falha(operacao.aprovar("prop-0009"));

    expect(erro.tipo).toBe("recusada");
    expect(erro.message).toContain("prop-0009");
    expect(erro.comando).toBeNull();
  });

  it("quando os agentes terminam, a decisão volta para o terminal", async () => {
    ligarSimulacao(true);
    ligarSimulacao(false);

    expect(operacao.gravaDecisoes).toBe(false);
    expect((await falha(operacao.aprovar("prop-0003"))).comando).toBe("python -m codigo.mcp.aprovar prop-0003");
  });
});
