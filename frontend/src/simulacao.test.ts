import { describe, expect, it } from "vitest";
import { agentesAtivos, consultarSimulacao, decidirNaSimulacao, ErroDaSimulacao, iniciarSimulacao, pararSimulacao, tamanhoDoArquivo, ultimoAgente } from "./simulacao";
import type { Evento } from "./types";

// O acesso à simulação, com `fetch` simulado. A tela é testada em `telas.test.tsx`.

type Chamada = { url: string; init: RequestInit };

function fetchQueResponde(status: number, corpo: unknown, chamadas: Chamada[] = []): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    chamadas.push({ url: String(url), init: init ?? {} });
    return new Response(typeof corpo === "string" ? corpo : JSON.stringify(corpo), { status, headers: { "Content-Type": "application/json" } });
  }) as typeof fetch;
}

const RESULTADO = {
  arquivo: "a.pcap", quadros: 700, ignorados: 0, janelas: 7, por_categoria: { Benign: 2, "DDoS+DoS": 5 },
  duracao_do_pcap_s: 7, processamento_s: 0.1, modelo: "rf.joblib", ponto_de_operacao: { regra: "argmax", limiar: null, seguidas: 3 },
  acionamento: { fecha_apos: 10 }, incidentes: [], incidentes_alem_do_teto: 0, log: "dados/eventos/simulacoes/x/eventos.jsonl",
  cenarios: "dados/eventos/simulacoes/x/eventos.cenarios.json", janelas_puladas: 0, janelas_incompletas: 1,
  trecho: { a_partir_da_janela: 0, so_teste: false }, eventos: "",
  agentes: { estado: "rodando", configuracao: "local", modelo: "qwen", motivo: null, incidentes: [] },
};

describe("acesso à simulação", () => {
  it("manda o pcap cru no corpo, com o nome na consulta, e devolve o resultado", async () => {
    const chamadas: Chamada[] = [];
    const pcap = new Blob([new Uint8Array([1, 2, 3])]);

    const recebido = await iniciarSimulacao(pcap, "meu ataque.pcap", true, fetchQueResponde(200, RESULTADO, chamadas));

    expect(recebido).toEqual(RESULTADO);
    expect(chamadas[0].url).toBe("/api/simulacao?nome=meu%20ataque.pcap&so_teste=1");
    expect(new Headers(chamadas[0].init.headers).get("X-SentryIoT")).toBe("interface");
    expect(chamadas[0].init.method).toBe("POST");
    expect(chamadas[0].init.body).toBe(pcap);
    expect(new Headers(chamadas[0].init.headers).get("Content-Type")).toBe("application/vnd.tcpdump.pcap");
  });

  it("erro do backend vira ErroDaSimulacao com a mensagem dele", async () => {
    const falha = iniciarSimulacao(new Blob([]), "a.pcapng", false, fetchQueResponde(400, { erro: "a entrada está em pcapng" }));

    await expect(falha).rejects.toThrow(ErroDaSimulacao);
    await expect(falha).rejects.toMatchObject({ tipo: "backend", status: 400, message: "a entrada está em pcapng" });
  });

  it("sem backend, o erro é de rede", async () => {
    const semRede = (async () => {
      throw new TypeError("Failed to fetch");
    }) as typeof fetch;

    await expect(iniciarSimulacao(new Blob([]), "a.pcap", false, semRede)).rejects.toMatchObject({ tipo: "rede", status: null });
  });

  it("recusa resposta fora do formato, e uma sem o estado dos agentes", async () => {
    await expect(iniciarSimulacao(new Blob([]), "a.pcap", false, fetchQueResponde(200, { arquivo: 1 }))).rejects.toThrow("fora do formato");
    const semAgentes = { ...RESULTADO, agentes: undefined };
    await expect(iniciarSimulacao(new Blob([]), "a.pcap", false, fetchQueResponde(200, semAgentes))).rejects.toThrow("fora do formato");
  });

  it("consulta a simulação atual com o cabeçalho da interface, e devolve nulo quando não há nenhuma", async () => {
    const chamadas: Chamada[] = [];
    expect(await consultarSimulacao(fetchQueResponde(200, { simulacao: RESULTADO }, chamadas))).toEqual(RESULTADO);
    expect(chamadas[0].url).toBe("/api/simulacao/atual");
    expect(new Headers(chamadas[0].init.headers).get("X-SentryIoT")).toBe("interface");
    expect(chamadas[0].init.cache).toBe("no-store");
    expect(await consultarSimulacao(fetchQueResponde(200, { simulacao: null }))).toBeNull();
  });

  it("manda a decisão da pessoa e devolve a recusa do servidor com a mensagem dele", async () => {
    const chamadas: Chamada[] = [];
    await decidirNaSimulacao({ tipo: "rejeitar", id: "prop-0002", motivo: "não pode parar" }, fetchQueResponde(200, { ok: true }, chamadas));
    expect(chamadas[0].url).toBe("/api/simulacao/decisao");
    expect(chamadas[0].init.method).toBe("POST");
    expect(JSON.parse(String(chamadas[0].init.body))).toEqual({ tipo: "rejeitar", id: "prop-0002", motivo: "não pode parar" });
    await expect(decidirNaSimulacao({ tipo: "aprovar", id: "prop-0009" }, fetchQueResponde(409, { erro: "Não existe proposta." }))).rejects.toThrow("Não existe proposta.");
  });

  it("pede para os agentes pararem", async () => {
    const chamadas: Chamada[] = [];
    await pararSimulacao(fetchQueResponde(200, { ok: true }, chamadas));
    expect(chamadas[0].url).toBe("/api/simulacao/parar");
    expect(chamadas[0].init.method).toBe("POST");
  });

  it("os agentes estão ativos enquanto rodam ou param, e só aí a tela acompanha o log", () => {
    const com = (estado: string) => ({ ...RESULTADO.agentes, estado }) as Parameters<typeof agentesAtivos>[0];
    expect(agentesAtivos(com("rodando"))).toBe(true);
    expect(agentesAtivos(com("parando"))).toBe(true);
    for (const estado of ["concluidos", "interrompidos", "sem_modelo", "sem_incidentes"]) {
      expect(agentesAtivos(com(estado)), estado).toBe(false);
    }
  });

  it("o último agente de um incidente vem da última chamada à IA dele", () => {
    const chamada = (incidente: string, agente: string) => ({ tipo: "llm_chamada", incidente, dados: { agente } }) as unknown as Evento;
    const eventos = [chamada("inc-0001", "triagem"), chamada("inc-0001", "decisao"), chamada("inc-0002", "execucao")];
    expect(ultimoAgente(eventos, "inc-0001")).toBe("decisao");
    expect(ultimoAgente(eventos, "inc-0003")).toBeNull();
  });

  it("mostra o tamanho do arquivo", () => {
    expect(tamanhoDoArquivo(512)).toBe("512 B");
    expect(tamanhoDoArquivo(1536)).toBe("1,5 KB");
    expect(tamanhoDoArquivo(1024 * 1024 * 250)).toBe("250 MB");
  });
});
