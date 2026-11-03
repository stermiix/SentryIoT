import { describe, expect, it } from "vitest";
import textoDoExemplo from "../../codigo/mcp/exemplos/incidente_flood.jsonl?raw";
import { etapasComConversa, fluxoDoIncidente, itensDaConversa, jsonFormatado, type EtapaDoAgente, type ItemDoFluxo } from "./conversa";
import { AVISO_DE_TESTE, comConversas } from "./conversa-de-teste";
import { agregar, lerLog } from "./log";
import type { MensagemDaConversa } from "./types";

function fluxo(texto: string, incidente: string): ItemDoFluxo[] {
  const lido = lerLog(texto);
  expect(lido.avisos).toEqual([]);
  const view = agregar(lido.eventos).incidentes.find((item) => item.id === incidente)!;
  return fluxoDoIncidente(view.eventos);
}

const etapas = (itens: ItemDoFluxo[]) => itens.filter((item): item is EtapaDoAgente => item.tipo === "agente");
const resumo = (itens: ItemDoFluxo[]) =>
  itens.map((item) => (item.tipo === "agente" ? `${item.agente}${item.tarefa === "sumario" ? ":sumario" : `:${item.rodada}`}` : item.evento.tipo));

describe("a conversa de um agente, mensagem a mensagem", () => {
  const mensagens: MensagemDaConversa[] = [
    { papel: "system", texto: "# Skill", tools_pedidas: [] },
    { papel: "user", texto: "Abriu o incidente inc-0001.", tools_pedidas: [] },
    {
      papel: "assistant",
      texto: "Vou ler o incidente.",
      tools_pedidas: [
        { id: "c1", nome: "obter_incidente", argumentos: '{"id":"inc-0001"}' },
        { id: "c2", nome: "obter_janelas", argumentos: "{id: inc-0001" },
      ],
    },
    { papel: "tool", texto: '{"id":"inc-0001","janelas":3}', resposta_a: "c1" },
    { papel: "tool", texto: "Chamada repetida, não executada.", resposta_a: "c2" },
    { papel: "user", texto: "[12 mensagens do meio da conversa omitidas no log]" },
    { papel: "user", texto: AVISO_DE_TESTE },
    { papel: "assistant", texto: "Rótulo da triagem: coerente", tools_pedidas: [] },
  ];

  it("diz o papel de cada mensagem: o primeiro user é o pedido, os outros são avisos do laço", () => {
    expect(itensDaConversa(mensagens).map((item) => item.tipo)).toEqual([
      "sistema", "pedido", "modelo", "pedido_de_tool", "pedido_de_tool", "resultado_de_tool", "resultado_de_tool", "omitidas", "aviso", "modelo",
    ]);
  });

  it("liga cada resultado à tool pedida e formata o JSON, mas mostra cru o que não é JSON", () => {
    const itens = itensDaConversa(mensagens);
    expect(itens[3]).toEqual({ tipo: "pedido_de_tool", id: "c1", nome: "obter_incidente", argumentos: '{"id":"inc-0001"}', formatados: '{\n  "id": "inc-0001"\n}' });
    expect(itens[4]).toMatchObject({ tipo: "pedido_de_tool", nome: "obter_janelas", formatados: null });
    expect(itens[5]).toMatchObject({ tipo: "resultado_de_tool", respostaA: "c1", nome: "obter_incidente", formatado: '{\n  "id": "inc-0001",\n  "janelas": 3\n}' });
    expect(itens[6]).toMatchObject({ tipo: "resultado_de_tool", respostaA: "c2", nome: "obter_janelas", formatado: null });
  });

  it("só a última mensagem, sem tools, é a resposta final", () => {
    const modelo = itensDaConversa(mensagens).filter((item) => item.tipo === "modelo");
    expect(modelo.map((item) => item.tipo === "modelo" && item.final)).toEqual([false, true]);
  });

  it("formata só objeto e lista de JSON", () => {
    expect(jsonFormatado("[1,2]")).toBe("[\n  1,\n  2\n]");
    expect(jsonFormatado("42")).toBeNull();
    expect(jsonFormatado("texto")).toBeNull();
  });
});

describe("o incidente de ponta a ponta", () => {
  it("com a conversa no log, cada agente vira uma etapa com a conversa, na ordem das rodadas, e as decisões ficam entre elas", () => {
    const itens = fluxo(comConversas(textoDoExemplo), "inc-0001");
    expect(resumo(itens)).toEqual([
      "incidente_aberto", "triagem:1", "decisao:1", "execucao:1", "decisao:2", "execucao:2", "acao_rejeitada", "acao_aprovada", "execucao:2", "triagem:sumario",
    ]);
    expect(etapasComConversa(itens)).toBe(6);
    const [triagem, decisao] = etapas(itens);
    expect(triagem.conversa?.map((item) => item.tipo)).toEqual(["sistema", "pedido", "pedido_de_tool", "resultado_de_tool", "aviso", "modelo"]);
    expect([triagem.modelo, triagem.onde, triagem.motivo, triagem.veredito]).toEqual(["qwen3.8-27c", "local", "resposta_final", "coerente"]);
    // As chamadas ao modelo da etapa: os tokens e o tempo são os dos llm_chamada do agente.
    expect(triagem.chamadas).toBe(2);
    expect(triagem.tokensEntrada).toBeGreaterThan(0);
    // O que o agente deixou no log fica na etapa dele.
    expect(triagem.produziu.map((evento) => evento.tipo)).toEqual(["analise_emitida"]);
    expect(decisao.produziu.map((evento) => evento.tipo)).toEqual(["acao_proposta", "recomendacao_emitida"]);
    const execucao = etapas(itens)[2];
    expect(execucao.produziu.map((evento) => evento.tipo)).toEqual(["acao_executada", "efeito_verificado"]);
    // O sumário, sem conclusão própria, leva o que veio depois dele.
    const sumario = etapas(itens)[etapas(itens).length - 1];
    expect(sumario.produziu.map((evento) => evento.tipo)).toEqual(["sumario_emitido", "catalogo_ampliado"]);
  });

  it("num log anterior à conversa, as etapas fecham na conclusão, sem conversa", () => {
    const itens = fluxo(textoDoExemplo, "inc-0001");
    expect(etapasComConversa(itens)).toBe(0);
    expect(resumo(itens)).toEqual([
      "incidente_aberto", "triagem:1", "decisao:1", "execucao:1", "decisao:2", "execucao:2", "acao_rejeitada", "acao_aprovada", "execucao:2", "triagem:sumario",
    ]);
    expect(etapas(itens).every((etapa) => etapa.conversa === null && !etapa.emAndamento)).toBe(true);
  });

  it("o incidente marcado como já resolvido mostra a marca no fluxo, antes dos agentes", () => {
    expect(resumo(fluxo(comConversas(textoDoExemplo), "inc-0002"))).toEqual(["incidente_aberto", "incidente_marcado_resolvido", "triagem:1", "decisao:1", "triagem:sumario"]);
  });

  it("num log que já terminou (execução gravada), o agente sem conclusão foi interrompido, e não está em andamento", () => {
    const linhas = comConversas(textoDoExemplo).trim().split("\n");
    const corte = linhas.findIndex((linha) => linha.includes('"tipo":"llm_chamada"') && linha.includes('"agente":"decisao"'));
    const lido = lerLog(linhas.slice(0, corte + 1).join("\n"));
    const view = agregar(lido.eventos).incidentes.find((item) => item.id === "inc-0001")!;
    const ultima = etapas(fluxoDoIncidente(view.eventos, { terminado: true })).pop()!;
    expect([ultima.agente, ultima.interrompida, ultima.emAndamento]).toEqual(["decisao", true, false]);
    // O sumário de um log antigo, sem conclusão própria, não é interrupção.
    const antigo = agregar(lerLog(textoDoExemplo).eventos).incidentes.find((item) => item.id === "inc-0001")!;
    expect(etapas(fluxoDoIncidente(antigo.eventos, { terminado: true })).some((etapa) => etapa.interrompida)).toBe(false);
  });

  it("um agente que começou e não terminou fica em andamento, no fim", () => {
    const linhas = comConversas(textoDoExemplo).trim().split("\n");
    // Corta o log logo depois da primeira chamada da decisão do inc-0001.
    const corte = linhas.findIndex((linha) => linha.includes('"tipo":"llm_chamada"') && linha.includes('"agente":"decisao"'));
    const itens = fluxo(linhas.slice(0, corte + 1).join("\n"), "inc-0001");
    const ultima = etapas(itens)[etapas(itens).length - 1];
    expect([ultima.agente, ultima.emAndamento, ultima.interrompida, ultima.motivo]).toEqual(["decisao", true, false, null]);
  });
});
