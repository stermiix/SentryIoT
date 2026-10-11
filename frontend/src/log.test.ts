import { describe, expect, it } from "vitest";
import textoDoExemplo from "../public/dados/incidente_flood.jsonl?raw";
import { agregar, lerLog } from "./log";

// Os casos adversariais da revisão da interface, montados a partir do log de exemplo. Os valores
// esperados saem do próprio log, para que os testes continuem valendo quando ele for regenerado.

type Bruto = { id: string; instante: string; tipo: string; incidente: string | null; dados: Record<string, unknown> };

const base: Bruto[] = textoDoExemplo
  .split("\n")
  .filter((linha) => linha.trim().length > 0)
  .map((linha) => JSON.parse(linha) as Bruto);

function texto(eventos: (Bruto | string)[]): string {
  return eventos.map((evento) => (typeof evento === "string" ? evento : JSON.stringify(evento))).join("\n") + "\n";
}

function copia(tipo: string, ordem = 0): Bruto {
  const achados = base.filter((evento) => evento.tipo === tipo);
  if (!achados[ordem]) {
    throw new Error(`o log de exemplo não tem o evento ${tipo} de número ${ordem + 1}`);
  }
  return structuredClone(achados[ordem]);
}

/** O log de exemplo com alguns eventos trocados pelas cópias alteradas, no mesmo lugar (mesmo id). */
function trocando(...trocados: Bruto[]): Bruto[] {
  const porId = new Map(trocados.map((evento) => [evento.id, evento]));
  return base.map((evento) => porId.get(evento.id) ?? evento);
}

function proximoId(deslocamento = 1): string {
  return `ev-${String(base.length + deslocamento).padStart(6, "0")}`;
}

function ler(eventos: (Bruto | string)[]) {
  const lido = lerLog(texto(eventos));
  return { ...lido, ...agregar(lido.eventos), avisosDaLeitura: lido.avisos };
}

const somaDe = (tipo: string, conta: (dados: Record<string, unknown>) => number) =>
  base.filter((evento) => evento.tipo === tipo).reduce((soma, evento) => soma + conta(evento.dados), 0);
const ESPERADO = {
  janelas: somaDe("janelas_classificadas", (dados) => dados.janelas as number),
  chamadas: base.filter((evento) => evento.tipo === "llm_chamada").length,
  tokens: somaDe("llm_chamada", (dados) => (dados.tokens_entrada as number) + (dados.tokens_saida as number)),
  incidentes: new Set(base.filter((evento) => evento.tipo === "incidente_aberto").map((evento) => evento.incidente)).size,
};

describe("log de exemplo", () => {
  it("é lido inteiro, sem aviso nenhum", () => {
    const resultado = ler(base);
    expect(resultado.avisosDaLeitura).toEqual([]);
    expect(resultado.avisos).toEqual([]);
    expect(resultado.eventos).toHaveLength(base.length);
  });

  it("soma janelas, incidentes, chamadas e tokens", () => {
    const { resumo } = ler(base);
    expect(resumo.janelasClassificadas).toBe(ESPERADO.janelas);
    expect(resumo.totalIncidentes).toBe(ESPERADO.incidentes);
    expect(resumo.chamadasLLM).toBe(ESPERADO.chamadas);
    expect(resumo.tokens).toBe(ESPERADO.tokens);
    expect(resumo.eventosSemAbertura).toBe(0);
  });

  it("deixa o incidente no estado do último evento de incidente", () => {
    const deIncidente = base.filter((evento) => evento.tipo.startsWith("incidente_"));
    const ultimo = deIncidente[deIncidente.length - 1];
    const { incidentes } = ler(base);
    expect(incidentes[0].incidente.estado).toBe(ultimo.dados.estado);
  });
});

describe("duplicados e ordem (C4, C5)", () => {
  it("descarta evento com id repetido e avisa as linhas", () => {
    const resultado = ler([...base, ...base.slice(2)]);
    expect(resultado.eventos).toHaveLength(base.length);
    expect(resultado.resumo.chamadasLLM).toBe(ESPERADO.chamadas);
    expect(resultado.resumo.tokens).toBe(ESPERADO.tokens);
    expect(resultado.avisosDaLeitura.join(" ")).toMatch(new RegExp(`id de evento repetido.*${base.length + 1}`));
  });

  it("usa a ordem dos ids, e não a do arquivo", () => {
    const encerrado = copia("incidente_encerrado");
    const resultado = ler([base[0], encerrado, copia("incidente_aberto")]);
    expect(resultado.incidentes[0].incidente.estado).toBe("encerrado");
    expect(resultado.avisosDaLeitura.join(" ")).toContain("não estão em ordem");
  });

  it("chega ao mesmo resultado com o arquivo de trás para a frente", () => {
    const resultado = ler([...base].reverse());
    expect(resultado.avisos).toEqual([]);
    expect(resultado.resumo).toEqual(ler(base).resumo);
    expect(resultado.incidentes[0].propostas).toEqual(ler(base).incidentes[0].propostas);
  });

  it("recusa estado de incidente que vem com outro incidente no evento", () => {
    const trocado = copia("incidente_aberto");
    trocado.id = proximoId();
    trocado.incidente = "inc-0002";
    const resultado = ler([...base, trocado]);
    expect(resultado.incidentes.map((view) => view.id)).toEqual([base.find((e) => e.tipo === "incidente_aberto")!.incidente]);
    expect(resultado.avisosDaLeitura.join(" ")).toContain(`${base.length + 1} (incidente_aberto com dados.id diferente`);
  });
});

describe("incidente sem abertura (S1)", () => {
  it("não entra na fila nem conta como incidente, e é contado à parte", () => {
    const fantasma = copia("llm_chamada");
    fantasma.id = proximoId();
    fantasma.incidente = "inc-9999";
    const resultado = ler([...base, fantasma]);
    expect(resultado.resumo.totalIncidentes).toBe(ESPERADO.incidentes);
    expect(resultado.incidentes.map((view) => view.id)).not.toContain("inc-9999");
    expect(resultado.resumo.eventosSemAbertura).toBe(1);
    expect(resultado.resumo.incidentesSemAbertura).toEqual(["inc-9999"]);
    expect(resultado.avisos.join(" ")).toContain("inc-9999");
  });
});

describe("linhas fora do contrato (C1, C8)", () => {
  it("descarta o incidente sem features e avisa o número da linha", () => {
    const semFeatures = copia("incidente_aberto");
    delete semFeatures.dados.features_principais;
    const resultado = ler([base[0], semFeatures]);
    expect(resultado.incidentes).toEqual([]);
    expect(resultado.avisosDaLeitura.join(" ")).toContain("2 (incidente_aberto com dados.features_principais fora do contrato)");
  });

  it("descarta janelas sem dados, linha null e linha que é uma lista", () => {
    const semDados = copia("janelas_classificadas");
    delete (semDados as Partial<Bruto>).dados;
    const resultado = ler([...trocando(semDados), "null", "[]"]);
    expect(resultado.eventos).toHaveLength(base.length - 1);
    const aviso = resultado.avisosDaLeitura.join(" ");
    expect(aviso).toContain(`${base.indexOf(base.find((e) => e.id === semDados.id)!) + 1} (janelas_classificadas com dados`);
    expect(aviso).toContain(`${base.length + 1} (não é um objeto JSON)`);
    expect(aviso).toContain(`${base.length + 2} (não é um objeto JSON)`);
  });

  it("não deixa texto virar NaN nos contadores", () => {
    const comTexto = copia("janelas_classificadas");
    const janelasDoLote = comTexto.dados.janelas as number;
    comTexto.dados.janelas = "abc";
    const { resumo } = ler(trocando(comTexto));
    expect(resumo.janelasClassificadas).toBe(ESPERADO.janelas - janelasDoLote);
    expect(Number.isNaN(resumo.janelasClassificadas)).toBe(false);
  });

  it("descarta tokens infinitos e instante sem fuso", () => {
    const infinito = copia("llm_chamada");
    infinito.dados.tokens_entrada = 1e308;
    const semFuso = copia("llm_chamada", 1);
    semFuso.instante = "2026-10-20T14:03:43";
    const resultado = ler(trocando(infinito, semFuso));
    expect(resultado.resumo.chamadasLLM).toBe(ESPERADO.chamadas - 2);
    expect(resultado.avisosDaLeitura.join(" ")).toContain("llm_chamada com instante fora do contrato");
  });

  it("descarta toString e constructor nos campos com valores fixos", () => {
    const efeito = copia("efeito_verificado");
    efeito.dados.resultado = "toString";
    const recusa = copia("recusa");
    recusa.tipo = "constructor";
    const chamada = copia("llm_chamada");
    chamada.dados.agente = "constructor";
    const resultado = ler(trocando(efeito, recusa, chamada));
    expect(resultado.eventos).toHaveLength(base.length - 3);
    const aviso = resultado.avisosDaLeitura.join(" ");
    expect(aviso).toContain("efeito_verificado com dados.resultado fora do contrato");
    expect(aviso).toContain("tipo de evento desconhecido");
    expect(aviso).toContain("llm_chamada com dados.agente fora do contrato");
  });

  it("não repete na mensagem o valor que veio no log", () => {
    const recusa = copia("recusa");
    recusa.dados.mensagem = "linha 1\u001b[2Jlinha 2";
    const resultado = ler(trocando(recusa));
    expect(resultado.avisosDaLeitura.join(" ")).not.toContain("\u001b");
    expect(resultado.avisosDaLeitura.join(" ")).toContain("recusa com dados.mensagem fora do contrato");
  });
});

describe("última linha", () => {
  it("ignora a última linha sem quebra de linha no fim, que pode estar sendo gravada", () => {
    const cortada = JSON.stringify(copia("llm_chamada")).slice(0, 40);
    const lido = lerLog(texto(base) + cortada);
    expect(lido.eventos).toHaveLength(base.length);
    expect(lido.avisos.join(" ")).toContain(`A linha ${base.length + 1} não termina em quebra de linha`);
  });

  it("descarta uma linha cortada no meio do arquivo", () => {
    const cortada = JSON.stringify(copia("llm_chamada")).slice(0, 40);
    const lido = lerLog(texto([...base, cortada]));
    expect(lido.eventos).toHaveLength(base.length);
    expect(lido.avisos.join(" ")).toContain(`${base.length + 1} (não é um JSON válido)`);
  });

  it("aceita fim de linha CRLF", () => {
    const lido = lerLog(texto(base).replace(/\n/g, "\r\n"));
    expect(lido.avisos).toEqual([]);
    expect(lido.eventos).toHaveLength(base.length);
  });
});

describe("estado das propostas (C2)", () => {
  const { incidentes, avisos } = ler(base);
  const propostas = new Map(incidentes.flatMap((view) => view.propostas).map((proposta) => [proposta.id, proposta]));

  it("tem uma proposta para cada acao_proposta, com risco e aprovação", () => {
    expect(avisos).toEqual([]);
    for (const evento of base.filter((e) => e.tipo === "acao_proposta")) {
      const proposta = propostas.get(evento.dados.id as string)!;
      expect(proposta.acao).toBe(evento.dados.acao);
      expect(proposta.risco).toBe(evento.dados.risco);
      expect(proposta.exigeAprovacao).toBe(evento.dados.exige_aprovacao);
      expect(proposta.motivosDeRiscoAlto).toEqual(evento.dados.motivos_de_risco_alto);
    }
  });

  it("liga decisões, execuções, efeitos e promoção à proposta certa", () => {
    for (const evento of base.filter((e) => e.tipo === "acao_rejeitada")) {
      const proposta = propostas.get(evento.dados.proposta as string)!;
      expect(proposta.estado).toBe("rejeitada");
      expect(proposta.decisoes[0]).toMatchObject({ tipo: "acao_rejeitada", canal: evento.dados.canal });
    }
    const desfeitas = new Set(base.filter((e) => e.tipo === "acao_desfeita").map((e) => e.dados.id));
    for (const evento of base.filter((e) => e.tipo === "acao_executada")) {
      const proposta = propostas.get(evento.dados.proposta as string)!;
      const execucao = proposta.execucoes.find((item) => item.id === evento.dados.id)!;
      expect(execucao).toBeDefined();
      expect(proposta.estado).toBe(desfeitas.has(evento.dados.id) ? "desfeita" : "executada");
      const efeitos = base.filter((e) => e.tipo === "efeito_verificado" && e.dados.execucao === evento.dados.id);
      expect(execucao.efeitos.map((efeito) => efeito.resultado)).toEqual(efeitos.map((e) => e.dados.resultado));
    }
    for (const evento of base.filter((e) => e.tipo === "catalogo_ampliado")) {
      expect(propostas.get(evento.dados.proposta as string)!.promovida).toBe(true);
    }
  });

  it("avisa decisão sobre proposta que não existe, sem mudar nenhum estado", () => {
    const aprovacao = copia("acao_aprovada");
    aprovacao.id = proximoId();
    aprovacao.dados.proposta = "prop-9999";
    const resultado = ler([...base, aprovacao]);
    expect(resultado.avisos.join(" ")).toContain("a proposta prop-9999 não existe");
    expect(resultado.incidentes[0].propostas).toEqual(incidentes[0].propostas);
  });

  it("deixa aguardando aprovação a proposta de risco alto gravada como liberada", () => {
    const forjada = copia("acao_proposta", 1);
    forjada.id = proximoId();
    forjada.dados = { ...forjada.dados, id: "prop-0099", estado: "liberada" };
    const resultado = ler([...base, forjada]);
    const proposta = resultado.incidentes[0].propostas.find((item) => item.id === "prop-0099")!;
    expect(forjada.dados.risco).toBe("alto");
    expect(proposta.estado).toBe("aguardando_aprovacao");
    expect(resultado.avisos.join(" ")).toContain("prop-0099 não confere com o próprio risco");
  });
});

describe("eventos que ainda vão entrar no contrato", () => {
  it("mostra a marca de já resolvido e aceita a categoria DDoS+DoS", () => {
    const aberto = copia("incidente_aberto");
    aberto.dados.categoria_do_modelo = "DDoS+DoS";
    const marcacao: Bruto = {
      id: proximoId(),
      instante: base[base.length - 1].instante,
      tipo: "incidente_marcado_resolvido",
      incidente: aberto.incidente,
      dados: { incidente: aberto.incidente, canal: "interface", usuario: "operador" },
    };
    const resultado = ler([...trocando(aberto), marcacao]);
    expect(resultado.avisos).toEqual([]);
    expect(resultado.avisosDaLeitura).toEqual([]);
    const view = resultado.incidentes[0];
    expect(view.marcacao).toEqual({ instante: marcacao.instante, canal: "interface", usuario: "operador", motivo: null });
    expect(view.eventos.some((evento) => evento.tipo === "incidente_atualizado")).toBe(
      base.some((evento) => evento.tipo === "incidente_atualizado"),
    );
  });

  it("recusa a marca com canal fora da lista ou com outro incidente", () => {
    const marcacao = (canal: string, incidente: string): Bruto => ({
      id: proximoId(),
      instante: base[base.length - 1].instante,
      tipo: "incidente_marcado_resolvido",
      incidente: base[1].incidente,
      dados: { incidente, canal, usuario: "operador", motivo: "Bloqueado no firewall." },
    });
    const outroCanal = ler([...base, marcacao("email", base[1].incidente!)]);
    expect(outroCanal.avisosDaLeitura.join(" ")).toContain("incidente_marcado_resolvido com dados.canal fora do contrato");
    const outroIncidente = ler([...base, marcacao("terminal", "inc-0002")]);
    expect(outroIncidente.avisosDaLeitura.join(" ")).toContain("dados.incidente diferente do campo incidente");
  });

  it("funciona com o log atual, que não tem nenhum dos dois", () => {
    expect(base.some((evento) => evento.tipo === "incidente_marcado_resolvido")).toBe(false);
    expect(ler(base).incidentes[0].marcacao).toBeNull();
  });
});

describe("replay passo a passo", () => {
  it("só mostra o incidente depois do evento de abertura", () => {
    const { eventos } = lerLog(texto(base));
    const abertura = eventos.findIndex((evento) => evento.tipo === "incidente_aberto");
    expect(agregar(eventos.slice(0, abertura)).incidentes).toEqual([]);
    expect(agregar(eventos.slice(0, abertura + 1)).incidentes).toHaveLength(1);
    expect(agregar(eventos.slice(0, abertura + 1)).incidentes[0].incidente.estado).toBe("aberto");
  });
});
