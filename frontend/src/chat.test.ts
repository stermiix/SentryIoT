import { describe, expect, it } from "vitest";
import { ErroDoChat, enviarChat, listarModelos, listarPrompts, montarPedido, textoDaSkill, type MensagemDaConversa, type Prompt } from "./chat";

// O acesso à API do chat com o modelo, com `fetch` simulado. A tela do chat é testada em
// `telas.test.tsx`.

type Chamada = { url: string; init: RequestInit };

function fetchQueResponde(status: number, corpo: unknown, chamadas: Chamada[] = []): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    chamadas.push({ url: String(url), init: init ?? {} });
    const texto = typeof corpo === "string" ? corpo : JSON.stringify(corpo);
    return new Response(texto, { status, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
}

const PEDIDO = { modelo: "", sistema: "", mensagens: [{ papel: "usuario" as const, conteudo: "Oi" }] };

describe("acesso à API do chat", () => {
  it("manda o pedido em JSON para /api/chat e devolve a resposta", async () => {
    const chamadas: Chamada[] = [];
    const resposta = { conteudo: "Olá.", modelo: "m-1", tokens_entrada: 12, tokens_saida: 3, tempo_ms: 950 };

    const recebida = await enviarChat(PEDIDO, fetchQueResponde(200, resposta, chamadas));

    expect(recebida).toEqual(resposta);
    expect(chamadas).toHaveLength(1);
    expect(chamadas[0].url).toBe("/api/chat");
    expect(chamadas[0].init.method).toBe("POST");
    expect(JSON.parse(String(chamadas[0].init.body))).toEqual(PEDIDO);
  });

  it("erro do provedor (502) vira erro de backend com a mensagem do backend", async () => {
    const promessa = enviarChat(PEDIDO, fetchQueResponde(502, { erro: "o provedor recusou", codigo: 429 }));

    await expect(promessa).rejects.toMatchObject({ tipo: "backend", status: 502, message: "o provedor recusou" });
    await expect(promessa).rejects.toBeInstanceOf(ErroDoChat);
  });

  it("backend sem configuração (503) diz o que falta no .env", async () => {
    const corpo = { erro: "o backend está sem configuração do provedor: faltam LLM_API_KEY", faltando: ["LLM_API_KEY"] };

    await expect(enviarChat(PEDIDO, fetchQueResponde(503, corpo))).rejects.toMatchObject({
      tipo: "backend",
      status: 503,
      message: expect.stringContaining("LLM_API_KEY"),
    });
  });

  it("resposta de erro que não é JSON vira erro de backend com o status", async () => {
    await expect(enviarChat(PEDIDO, fetchQueResponde(500, "<html>erro</html>"))).rejects.toMatchObject({
      tipo: "backend",
      status: 500,
      message: expect.stringContaining("500"),
    });
  });

  it("backend fora do ar vira erro de rede", async () => {
    const semRede = (async () => {
      throw new TypeError("Failed to fetch");
    }) as typeof fetch;

    await expect(enviarChat(PEDIDO, semRede)).rejects.toMatchObject({ tipo: "rede", status: null, message: "O backend do chat não está no ar." });
  });
});

describe("lista de modelos", () => {
  it("lê /api/modelos e devolve a lista e o padrão", async () => {
    const chamadas: Chamada[] = [];
    const lista = await listarModelos(fetchQueResponde(200, { modelos: ["m-1", "m-2"], padrao: "m-1" }, chamadas));

    expect(lista).toEqual({ modelos: ["m-1", "m-2"], padrao: "m-1" });
    expect(chamadas[0].url).toBe("/api/modelos");
  });

  it("falha do backend vira erro de backend; backend fora do ar vira erro de rede", async () => {
    await expect(listarModelos(fetchQueResponde(500, "<html>"))).rejects.toMatchObject({ tipo: "backend", status: 500 });
    const semRede = (async () => {
      throw new TypeError("Failed to fetch");
    }) as typeof fetch;
    await expect(listarModelos(semRede)).rejects.toMatchObject({ tipo: "rede" });
  });

  it("resposta fora do formato vira erro de backend", async () => {
    await expect(listarModelos(fetchQueResponde(200, { modelos: "m-1" }))).rejects.toMatchObject({ tipo: "backend" });
  });
});

const PROMPTS: Prompt[] = [
  { nome: "analise-por-categoria", titulo: "Análise por categoria de ataque", texto: "# Análise\n\ncorpo" },
  { nome: "triagem-do-alerta", titulo: "Triagem do alerta", texto: "# Triagem\n\ncorpo" },
];

describe("lista de prompts", () => {
  it("lê /api/prompts e devolve as skills", async () => {
    const chamadas: Chamada[] = [];
    const lista = await listarPrompts(fetchQueResponde(200, { prompts: PROMPTS }, chamadas));

    expect(lista).toEqual(PROMPTS);
    expect(chamadas[0].url).toBe("/api/prompts");
  });

  it("resposta fora do formato vira erro de backend", async () => {
    await expect(listarPrompts(fetchQueResponde(200, { prompts: [{ nome: "x" }] }))).rejects.toMatchObject({ tipo: "backend" });
  });

  it("carregar uma skill troca o prompt de sistema pelo texto dela, e um nome desconhecido mantém o atual", () => {
    expect(textoDaSkill(PROMPTS, "triagem-do-alerta", "o que estava")).toBe("# Triagem\n\ncorpo");
    expect(textoDaSkill(PROMPTS, "nao-existe", "o que estava")).toBe("o que estava");
    expect(textoDaSkill(PROMPTS, "", "o que estava")).toBe("o que estava");
  });
});

describe("montagem do pedido a partir da conversa", () => {
  it("acrescenta a mensagem da pessoa e manda o modelo, o prompt de sistema e só papel e conteúdo de cada mensagem", () => {
    const anterior: MensagemDaConversa[] = [
      { papel: "usuario", conteudo: "Oi" },
      { papel: "assistente", conteudo: "Olá.", modelo: "m", tokens_entrada: 1, tokens_saida: 1, tempo_ms: 5 },
    ];

    const { historico, pedido } = montarPedido(anterior, "  Tudo bem?  ", "m-2", "Seja breve.");

    expect(historico).toEqual([...anterior, { papel: "usuario", conteudo: "Tudo bem?" }]);
    expect(pedido).toEqual({
      modelo: "m-2",
      sistema: "Seja breve.",
      mensagens: [
        { papel: "usuario", conteudo: "Oi" },
        { papel: "assistente", conteudo: "Olá." },
        { papel: "usuario", conteudo: "Tudo bem?" },
      ],
    });
  });

  it("não muda a conversa recebida", () => {
    const anterior: MensagemDaConversa[] = [{ papel: "usuario", conteudo: "Oi" }];
    montarPedido(anterior, "Mais", "m", "");
    expect(anterior).toHaveLength(1);
  });
});
