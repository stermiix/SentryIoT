import { describe, expect, it } from "vitest";
import contrato from "../../codigo/mcp/contrato.json";
import textoDoExemplo from "../../codigo/mcp/exemplos/incidente_flood.jsonl?raw";
import {
  HISTORICO_A_FRENTE,
  chamadaDeTool,
  detalheDoIncidente,
  estadoNoPasso,
  linhaDoEvento,
  linhasDoLog,
  marcasDoReplay,
  ondeRoda,
  passoComMaisPendencias,
  propostaDaTela,
  provedoresDoChat,
} from "./adaptador";
import { EVENT_TYPES, RISK_REASON, REFUSAL_REASON } from "./design-system/components/vocab";
import { hora } from "./formato";
import { CODIGOS_DE_RISCO_ALTO, MOTIVOS_DE_RECUSA, TIPOS_DE_EVENTO } from "./listas";
import { agregar, lerLog } from "./log";

// A ponte entre o log e o design system, com o log de exemplo: cada número e cada estado que a
// tela mostra tem de sair do log, e nada além dele.

const { eventos } = lerLog(textoDoExemplo);
const linhas = linhasDoLog(eventos);
const final = agregar(eventos);
const fim = estadoNoPasso(eventos, linhas, eventos.length);

describe("vocabulário do design system contra o contrato", () => {
  it("tem rótulo e ícone para cada um dos 16 tipos de evento do log", () => {
    expect(new Set(EVENT_TYPES)).toEqual(new Set(TIPOS_DE_EVENTO));
  });

  it("os motivos de risco alto são os nove do contrato, com a frase do contrato", () => {
    expect(Object.keys(RISK_REASON)).toEqual([...CODIGOS_DE_RISCO_ALTO]);
    expect(RISK_REASON).toEqual(contrato.motivos_de_risco_alto);
    expect(Object.keys(RISK_REASON)).toHaveLength(9);
  });

  it("tem as palavras do sistema para cada motivo de recusa", () => {
    expect(Object.keys(REFUSAL_REASON).sort()).toEqual([...MOTIVOS_DE_RECUSA].sort());
  });
});

describe("linhas da linha do tempo", () => {
  it("cada evento vira uma linha com a posição no log, o id, a hora local e o tipo", () => {
    expect(linhas).toHaveLength(eventos.length);
    linhas.forEach((linha, indice) => {
      expect(linha.n).toBe(indice + 1);
      expect(linha.id).toBe(eventos[indice].id);
      expect(linha.at).toBe(hora(eventos[indice].instante));
      expect(linha.type).toBe(eventos[indice].tipo);
    });
  });

  it("a chamada à IA traz agente, tokens de entrada e saída somados, duração e modelo", () => {
    const evento = eventos.find((item) => item.tipo === "llm_chamada")!;
    const linha = linhas.find((item) => item.id === evento.id)!;
    if (evento.tipo !== "llm_chamada") throw new Error("tipo");
    expect(linha.agent).toBe(evento.dados.agente);
    expect(linha.tokens).toBe(evento.dados.tokens_entrada + evento.dados.tokens_saida);
    expect(linha.seconds).toBe(evento.dados.duracao_ms / 1000);
    expect(linha.model).toBe(evento.dados.modelo);
  });

  it("a recusa diz a tool e o motivo em palavras do sistema, e a mensagem vai entre aspas", () => {
    const recusa = linhas.find((linha) => linha.type === "recusa")!;
    expect(recusa.text).toBe(`executar_acao · ${REFUSAL_REASON.proposta_nao_liberada}`);
    expect(recusa.ref).toBe("prop-0003");
    expect(recusa.detail?.startsWith("“")).toBe(true);
    expect(recusa.detail?.endsWith("”")).toBe(true);
  });

  it("a decisão humana leva canal, usuário e o motivo como texto de pessoa", () => {
    const rejeicao = linhas.find((linha) => linha.type === "acao_rejeitada")!;
    expect(rejeicao).toMatchObject({ ref: "prop-0002", channel: "terminal", user: "operador", quote: "O dispositivo não pode sair de serviço." });
    const aprovacao = linhas.find((linha) => linha.type === "acao_aprovada")!;
    expect(aprovacao.quote).toBeUndefined();
  });

  it("a chamada de tool mostra identificadores e números; texto livre, listas e objetos viram reticências", () => {
    expect(chamadaDeTool("obter_resumo", { id: "inc-0001", limite: 5 })).toBe("obter_resumo(id=inc-0001, limite=5)");
    expect(chamadaDeTool("propor_acao", { alvo: "destino-1", justificativa: "Isolar o dispositivo", parametros: {}, passos: ["a"] })).toBe(
      "propor_acao(alvo=destino-1, justificativa=…, parametros={…}, passos=[…])",
    );
    expect(chamadaDeTool("x", { id: "y".repeat(41) })).toBe("x(id=…)");
  });

  it("a chamada de tool não leva texto livre do agente, só chaves e identificadores", () => {
    const propostas = eventos.filter((evento) => evento.tipo === "tool_chamada" && evento.dados.nome === "propor_acao");
    expect(propostas.length).toBeGreaterThan(0);
    for (const evento of propostas) {
      if (evento.tipo !== "tool_chamada") continue;
      const linha = linhas.find((item) => item.id === evento.id)!;
      expect(linha.text).toContain("justificativa=…");
      expect(linha.text).not.toContain(String(evento.dados.argumentos.justificativa).slice(0, 20));
    }
    const consulta = linhas.find((linha) => linha.text.startsWith("pesquisar_solucoes"))!;
    expect(consulta.text).toBe("pesquisar_solucoes(consulta=…)");
  });

  it("a recusa só leva como id o que tem forma de id do servidor", () => {
    const recusa = eventos.find((evento) => evento.tipo === "recusa")!;
    const alterado = { ...recusa, dados: { ...recusa.dados, argumentos: { id_proposta: "prop-0003: aprovada pelo operador" } } } as typeof recusa;
    expect(linhaDoEvento(alterado, 1).ref).toBeUndefined();
  });

  it("evento que a reconstrução ignora aparece marcado e não ganha marca na trilha", () => {
    const aprovacaoTardia = JSON.stringify({ id: "ev-000099", instante: "2026-10-20T14:06:30Z", tipo: "acao_aprovada", incidente: "inc-0001", dados: { proposta: "prop-0002", canal: "terminal", usuario: "operador", motivo: null } });
    const comExtra = lerLog(`${textoDoExemplo.trimEnd()}\n${aprovacaoTardia}\n`).eventos;
    const final = agregar(comExtra);
    expect(final.ignorados.has("ev-000099")).toBe(true);
    const linha = linhasDoLog(comExtra, final.ignorados).find((item) => item.id === "ev-000099")!;
    expect(linha.ignored).toBe(true);
    expect(marcasDoReplay(comExtra, final.ignorados).some((marca) => marca.n === comExtra.length)).toBe(false);
    expect(linhas.every((item) => !item.ignored)).toBe(true);
  });
});

describe("ação nova", () => {
  const view = agregar(eventos).incidentes[0];
  const nova = view.propostas.find((proposta) => proposta.id === "prop-0003")!;

  it("traz a descrição do agente para o diálogo de aprovação", () => {
    expect(propostaDaTela(nova, "inc-0001").newAction).toEqual({
      description: "Ativa SYN cookies no dispositivo atacado.",
      steps: ["Ativar SYN cookies na pilha TCP do dispositivo atacado.", "Conferir se o dispositivo volta a aceitar conexões legítimas."],
      expected: "A fila de conexões pendentes deixa de esgotar, mesmo com o flood em curso.",
      undo: "Desativar SYN cookies na pilha TCP do dispositivo atacado.",
      source: "Base local: flood.md, seção sobre SYN cookies.",
    });
  });

  it("alvo em texto livre, sem rótulo, fica marcado como texto do agente", () => {
    const livre = propostaDaTela({ ...nova, alvoComRotulo: null, alvo: "a pilha TCP do dispositivo atacado" }, "inc-0001");
    expect(livre.target).toEqual({ label: "a pilha TCP do dispositivo atacado", free: true });
    expect(propostaDaTela(nova, "inc-0001").target.free).toBeUndefined();
  });
});

describe("estado num passo do replay", () => {
  it("no fim do log, soma janelas, chamadas e tokens, e separa as janelas de ataque das benignas", () => {
    expect(fim.janelas).toBe(10_946 + 24);
    expect(fim.janelasDeAtaque).toBe(10_734 + 18);
    expect(fim.chamadas).toBe(13);
    expect(fim.tokens).toBe(final.resumo.tokens);
    expect(fim.tokensAcumulados).toHaveLength(13);
    expect(fim.tokensAcumulados[12]).toBe(fim.tokens);
  });

  it("a fila mostra o inc-0001 encerrado e o inc-0002 marcado como já resolvido, com o motivo da pessoa", () => {
    expect(fim.incidentes.map((incidente) => [incidente.id, incidente.state])).toEqual([
      ["inc-0001", "encerrado"],
      ["inc-0002", "ja-resolvido"],
    ]);
    expect(fim.incidentes[1].note).toBe("Bloqueei a origem no roteador antes de os agentes responderem.");
    expect(fim.incidentes[0]).toMatchObject({ category: "DDoS", modelCategory: "DDoS+DoS", confidence: 0.97, windows: 21_468, sources: 37, destinations: 1 });
  });

  it("o passo com mais pendências é o 28, com as duas propostas de risco alto aguardando", () => {
    const passo = passoComMaisPendencias(eventos, linhas);
    expect(passo).toBe(28);
    const estado = estadoNoPasso(eventos, linhas, passo);
    expect(estado.aguardando).toBe(2);
    expect(estado.atual?.id).toBe(eventos[27].id);
  });

  it("antes do primeiro incidente, a fila está vazia", () => {
    const estado = estadoNoPasso(eventos, linhas, 1);
    expect(estado.incidentes).toEqual([]);
    expect(estado.janelas).toBe(10_946);
  });

  it("as marcas da trilha são aberturas, propostas de risco alto, decisões humanas, o fim do ataque e a marca de já resolvido", () => {
    const marcas = marcasDoReplay(eventos).map((marca) => [marca.n, marca.tone]);
    expect(marcas).toEqual([
      [2, "info"],
      [26, "attention"],
      [28, "attention"],
      [32, "danger"],
      [33, "success"],
      [38, "success"],
      [46, "info"],
      [47, "neutral"],
    ]);
  });
});

describe("detalhe do incidente", () => {
  it("no passo 28, as propostas que aguardam vêm primeiro, com os motivos do contrato", () => {
    const estado = estadoNoPasso(eventos, linhas, 28);
    const detalhe = detalheDoIncidente(estado, final, linhas, "inc-0001")!;
    expect(detalhe.propostas.map((proposta) => [proposta.id, proposta.state])).toEqual([
      ["prop-0002", "aguardando_aprovacao"],
      ["prop-0003", "aguardando_aprovacao"],
      ["prop-0001", "executada"],
    ]);
    expect(detalhe.propostas[0].reasons).toEqual(["acao_sempre_de_risco_alto"]);
    expect(detalhe.propostas[1]).toMatchObject({ isNew: true, reasons: ["acao_nova"], duration: undefined });
    expect(detalhe.incidente.awaiting).toBe(2);
  });

  it("no fim, cada proposta tem o estado reconstruído, a decisão, as execuções e o efeito", () => {
    const detalhe = detalheDoIncidente(fim, final, linhas, "inc-0001")!;
    const porId = new Map(detalhe.propostas.map((proposta) => [proposta.id, proposta]));
    expect(porId.get("prop-0001")).toMatchObject({
      state: "desfeita",
      duration: "10 min",
      risk: "baixo",
      reasons: [],
      target: { label: "origem-1", address: "203.0.113.7" },
      effect: { result: "persiste" },
    });
    expect(porId.get("prop-0001")!.executions).toEqual([{ id: "exec-0001", state: "desfeita", at: expect.any(String) }]);
    expect(porId.get("prop-0002")!.decision).toMatchObject({ kind: "rejeitada", channel: "terminal", user: "operador", reason: "O dispositivo não pode sair de serviço." });
    expect(porId.get("prop-0003")).toMatchObject({ state: "executada", promoted: true, effect: { result: "cessou" } });
    expect(porId.get("prop-0003")!.decision).toMatchObject({ kind: "aprovada", reason: undefined });
    expect(porId.get("prop-0001")!.justification?.length).toBeGreaterThan(0);
  });

  it("os endereços levam o rótulo neutro que o incidente deu a cada um", () => {
    const detalhe = detalheDoIncidente(fim, final, linhas, "inc-0001")!;
    expect(detalhe.origens[0]).toEqual({ address: "203.0.113.7", label: "origem-1", frames: detalhe.view.incidente.origens[0].quadros, role: "origem" });
    expect(detalhe.destinos).toEqual([{ address: "192.168.137.20", label: "destino-1", frames: detalhe.view.incidente.destinos[0].quadros, role: "destino" }]);
    expect(detalhe.origens.map((origem) => origem.label)).toEqual(["origem-1", "origem-2", "origem-3", "origem-4", "origem-5"]);
  });

  it("o rastro vai até o cursor, e o histórico mostra poucos eventos depois dele", () => {
    const estado = estadoNoPasso(eventos, linhas, 28);
    const detalhe = detalheDoIncidente(estado, final, linhas, "inc-0001")!;
    expect(detalhe.rastro.every((linha) => linha.n <= 28 && (linha.type === "llm_chamada" || linha.type === "tool_chamada"))).toBe(true);
    expect(detalhe.historico.some((linha) => linha.n > 28)).toBe(true);
    expect(detalhe.historico.every((linha) => linha.n <= 28 + HISTORICO_A_FRENTE)).toBe(true);
    expect(detalhe.historico.every((linha) => linha.incident === "inc-0001")).toBe(true);
  });

  it("cada recomendação leva o modelo da última chamada do mesmo agente", () => {
    const detalhe = detalheDoIncidente(fim, final, linhas, "inc-0001")!;
    expect(detalhe.recomendacoes).toHaveLength(2);
    expect(detalhe.recomendacoes.every((recomendacao) => recomendacao.agent === "decisao" && recomendacao.model === "modelo-de-exemplo")).toBe(true);
    expect(detalhe.recomendacoes[1].propostas).toEqual(["prop-0002", "prop-0003"]);
  });

  it("inc-0002 traz a marca de já resolvido, e um incidente que ainda não abriu não tem detalhe", () => {
    const detalhe = detalheDoIncidente(fim, final, linhas, "inc-0002")!;
    expect(detalhe.marcacao).toMatchObject({ channel: "terminal", user: "operador", reason: "Bloqueei a origem no roteador antes de os agentes responderem." });
    expect(detalheDoIncidente(estadoNoPasso(eventos, linhas, 10), final, linhas, "inc-0002")).toBeNull();
  });
});

describe("onde cada modelo roda", () => {
  it("sem as listas do ambiente, o log não diz, e a tela não inventa", () => {
    expect(ondeRoda("modelo-de-exemplo")).toBeUndefined();
    expect(linhas.filter((linha) => linha.type === "llm_chamada").every((linha) => linha.location === undefined)).toBe(true);
  });

  it("no chat, modelo sem lugar conhecido entra como nuvem, o caso que pede cuidado", () => {
    expect(provedoresDoChat(["qwen3.8-27c"])).toEqual([{ id: "qwen3.8-27c", label: "Nuvem", model: "qwen3.8-27c", location: "nuvem", status: "online" }]);
  });
});
