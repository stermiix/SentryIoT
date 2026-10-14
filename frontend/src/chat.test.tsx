import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import textoDoExemplo from "../public/dados/incidente_flood.jsonl?raw";
import { Pagina, telaDaAncora } from "./App";
import { ErroDoChat, enviarChat, listarModelos, listarPrompts, montarPedido, textoDaSkill, type MensagemDaConversa, type Prompt } from "./chat";
import { TelaDoChat } from "./components/ChatDoModelo";
import { recorte, textoDe } from "./html-de-teste";
import { lerLog } from "./log";

// O chat com o modelo: o acesso à API com `fetch` simulado, a tela desenhada no Node em cada
// estado, e a página escolhendo a tela pela âncora.

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

const CONVERSA: MensagemDaConversa[] = [
  { papel: "usuario", conteudo: "O que é um port scan?" },
  { papel: "assistente", conteudo: "Uma varredura de portas.", modelo: "qwen3.8-27c", tokens_entrada: 67, tokens_saida: 191, tempo_ms: 9334 },
];

function tela(props: Partial<Parameters<typeof TelaDoChat>[0]> = {}): string {
  return renderToString(
    <TelaDoChat
      modelos={["m-1", "m-2"]}
      modelo="m-1"
      onModelo={() => {}}
      sistema=""
      onSistema={() => {}}
      prompts={PROMPTS}
      onCarregarPrompt={() => {}}
      mensagens={[]}
      texto=""
      enviando={false}
      erro={null}
      erroDeCarga={null}
      onTexto={() => {}}
      onEnviar={() => {}}
      onLimpar={() => {}}
      {...props}
    />,
  );
}

describe("tela do chat", () => {
  it("começa vazia, com a caixa de envio e o botão de limpar", () => {
    const html = tela();
    expect(textoDe(recorte(html, "chat-conversa"))).toContain("Nenhuma mensagem ainda");
    expect(html).toContain('class="chat-entrada"');
    expect(textoDe(html)).toContain("Limpar conversa");
    expect(textoDe(html)).toContain("Enviar");
  });

  it("o seletor lista os modelos permitidos com o padrão selecionado", () => {
    const seletor = recorte(tela(), "chat-modelo");
    expect(seletor).toMatch(/<option[^>]*selected[^>]*value="m-1"|<option[^>]*value="m-1"[^>]*selected/);
    expect(seletor).toContain('value="m-2"');
    expect(seletor).not.toMatch(/<select[^>]*disabled/);
  });

  it("mostra o prompt de sistema numa caixa editável e o seletor de skills com uma opção por prompt", () => {
    const html = tela({ sistema: "Seja breve." });
    expect(recorte(html, "chat-sistema")).toMatch(/<textarea[^>]*>Seja breve\.<\/textarea>/);
    const seletor = recorte(html, "chat-skill");
    expect(textoDe(seletor)).toContain("Carregar skill");
    expect(seletor).toContain('value="analise-por-categoria"');
    expect(textoDe(seletor)).toContain("Triagem do alerta");
    expect(seletor).not.toMatch(/<select[^>]*disabled/);
  });

  it("sem prompts, o seletor de skills fica desabilitado e a caixa continua editável", () => {
    const html = tela({ prompts: [] });
    expect(recorte(html, "chat-skill")).toMatch(/<select[^>]*disabled/);
    expect(recorte(html, "chat-sistema")).not.toMatch(/<textarea[^>]*disabled/);
  });

  it("falha ao carregar modelos ou skills vai numa faixa própria, separada do erro de envio", () => {
    const html = tela({ erroDeCarga: "O backend do chat não está no ar.", erro: "o provedor recusou" });
    const faixas = html.match(/class="error-banner[" ]/g) ?? [];
    expect(faixas).toHaveLength(2);
    expect(textoDe(recorte(html, "error-banner chat-carga"))).toContain("Não foi possível carregar os modelos e as skills.");
    expect(textoDe(recorte(html, "error-banner chat-carga"))).toContain("O backend do chat não está no ar.");
  });

  it("com erro de limite (400), a faixa mostra a mensagem e o texto digitado continua na caixa", () => {
    const html = tela({ erro: "o campo conteudo passa de 8000 caracteres", texto: "rascunho longo", mensagens: CONVERSA });
    expect(textoDe(recorte(html, "error-banner"))).toContain("o campo conteudo passa de 8000 caracteres");
    expect(recorte(html, "chat-entrada")).toContain("rascunho longo");
    expect(textoDe(recorte(html, "chat-conversa"))).toContain("Uma varredura de portas.");
  });

  it("sem lista de modelos, o seletor fica desabilitado e mostra o modelo atual, se houver", () => {
    expect(recorte(tela({ modelos: [], modelo: "" }), "chat-modelo")).toMatch(/<select[^>]*disabled/);
    const comPadrao = recorte(tela({ modelos: [], modelo: "m-1" }), "chat-modelo");
    expect(comPadrao).toMatch(/<select[^>]*disabled/);
    expect(comPadrao).toContain('value="m-1"');
  });

  it("mostra a conversa e, sob a resposta, o modelo, os tokens e o tempo", () => {
    const conversa = textoDe(recorte(tela({ mensagens: CONVERSA }), "chat-conversa"));
    expect(conversa).toContain("O que é um port scan?");
    expect(conversa).toContain("Uma varredura de portas.");
    expect(conversa).toContain("qwen3.8-27c");
    expect(conversa).toContain("67 tokens de entrada");
    expect(conversa).toContain("191 de saída");
    expect(conversa).toContain("9,3 s");
  });

  it("sem tokens informados, a linha diz que o provedor não informou", () => {
    const resposta: MensagemDaConversa = { papel: "assistente", conteudo: "ok", modelo: "m", tokens_entrada: null, tokens_saida: null, tempo_ms: 100 };
    expect(textoDe(recorte(tela({ mensagens: [resposta] }), "chat-conversa"))).toContain("tokens não informados");
  });

  it("resposta vazia avisa em vez de mostrar nada", () => {
    const resposta: MensagemDaConversa = { papel: "assistente", conteudo: "", modelo: "m", tokens_entrada: 1, tokens_saida: 0, tempo_ms: 100 };
    expect(textoDe(recorte(tela({ mensagens: [resposta] }), "chat-conversa"))).toContain("O modelo não devolveu texto");
  });

  it("enquanto espera, desabilita a entrada e avisa", () => {
    const html = tela({ mensagens: CONVERSA.slice(0, 1), enviando: true });
    expect(textoDe(recorte(html, "chat-conversa"))).toContain("Aguardando o modelo…");
    expect(recorte(html, "chat-entrada")).toMatch(/<textarea[^>]*disabled/);
    expect(recorte(html, "chat-entrada")).toMatch(/<button[^>]*disabled[^>]*>Enviar/);
  });

  it.each([
    ["backend fora do ar", "O backend do chat não está no ar."],
    ["erro do provedor (502)", "o provedor recusou"],
    ["backend sem configuração (503)", "o backend está sem configuração do provedor: faltam LLM_API_KEY"],
  ])("mostra o erro de %s numa faixa, no padrão das existentes", (_caso, mensagem) => {
    const html = tela({ erro: mensagem });
    expect(textoDe(recorte(html, "error-banner"))).toContain(mensagem);
  });
});

describe("tela pela âncora", () => {
  it("#chat abre o chat e qualquer outra âncora abre a visão geral", () => {
    expect(telaDaAncora("#chat")).toBe("chat");
    expect(telaDaAncora("#incidentes")).toBe("incidentes");
    expect(telaDaAncora("")).toBe("incidentes");
  });

  const { eventos } = lerLog(textoDoExemplo);
  function pagina(telaAtual: "incidentes" | "chat"): string {
    return renderToString(
      <Pagina tela={telaAtual} eventos={eventos} avisos={[]} passo={eventos.length} onMudarPasso={() => {}} selecionadoId={null} onSelecionar={() => {}} carregando={false} erro={null} />,
    );
  }

  it("na tela do chat, a barra lateral marca o chat, o caminho muda e a pílula não diz REPLAY", () => {
    const html = pagina("chat");
    expect(html).toContain('class="chat-conversa');
    expect(textoDe(recorte(html, "breadcrumb"))).toContain("Chat com o modelo");
    expect(recorte(html, "navigation")).toMatch(/class="nav-item active" href="#chat"/);
    expect(textoDe(recorte(html, "topbar-actions"))).not.toContain("REPLAY");
    expect(html).not.toContain('class="metricas"');
  });

  it("na visão geral, o chat não aparece e o item do chat está na barra lateral sem destaque", () => {
    const html = pagina("incidentes");
    expect(html).not.toContain('class="chat-conversa');
    expect(recorte(html, "navigation")).toMatch(/class="nav-item" href="#chat"/);
    expect(textoDe(recorte(html, "topbar-actions"))).toContain("REPLAY");
  });
});
