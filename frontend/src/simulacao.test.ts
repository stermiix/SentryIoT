import { describe, expect, it } from "vitest";
import { ErroDaSimulacao, iniciarSimulacao, parametrosDoPedido, tamanhoDoArquivo, type PedidoAoModelo } from "./simulacao";

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
  eventos: "", para_o_llm: null,
};

describe("acesso à simulação", () => {
  it("manda o pcap cru no corpo, com o nome na consulta, e devolve o resultado", async () => {
    const chamadas: Chamada[] = [];
    const pcap = new Blob([new Uint8Array([1, 2, 3])]);

    const recebido = await iniciarSimulacao(pcap, "meu ataque.pcap", fetchQueResponde(200, RESULTADO, chamadas));

    expect(recebido).toEqual(RESULTADO);
    expect(chamadas[0].url).toBe("/api/simulacao?nome=meu%20ataque.pcap");
    expect(chamadas[0].init.method).toBe("POST");
    expect(chamadas[0].init.body).toBe(pcap);
    expect(new Headers(chamadas[0].init.headers).get("Content-Type")).toBe("application/vnd.tcpdump.pcap");
  });

  it("erro do backend vira ErroDaSimulacao com a mensagem dele", async () => {
    const falha = iniciarSimulacao(new Blob([]), "a.pcapng", fetchQueResponde(400, { erro: "a entrada está em pcapng" }));

    await expect(falha).rejects.toThrow(ErroDaSimulacao);
    await expect(falha).rejects.toMatchObject({ tipo: "backend", status: 400, message: "a entrada está em pcapng" });
  });

  it("sem backend, o erro é de rede", async () => {
    const semRede = (async () => {
      throw new TypeError("Failed to fetch");
    }) as typeof fetch;

    await expect(iniciarSimulacao(new Blob([]), "a.pcap", semRede)).rejects.toMatchObject({ tipo: "rede", status: null });
  });

  it("recusa resposta fora do formato, e uma que diga que o pedido foi enviado", async () => {
    await expect(iniciarSimulacao(new Blob([]), "a.pcap", fetchQueResponde(200, { arquivo: "a.pcap" }))).rejects.toThrow("fora do formato");
    const enviado = { ...RESULTADO, para_o_llm: { enviado: true, pedido: {} } };
    await expect(iniciarSimulacao(new Blob([]), "a.pcap", fetchQueResponde(200, enviado))).rejects.toThrow("fora do formato");
  });

  it("mostra o tamanho do arquivo e os parâmetros do pedido", () => {
    expect(tamanhoDoArquivo(512)).toBe("512 B");
    expect(tamanhoDoArquivo(7 * 1024 * 1024 + 300 * 1024)).toBe("7,3 MB");
    expect(tamanhoDoArquivo(192 * 1024 * 1024)).toBe("192 MB");
    const pedido: PedidoAoModelo = { model: "m", messages: [], tools: [], stream: false, temperature: 0, chat_template_kwargs: { enable_thinking: false } };
    expect(parametrosDoPedido(pedido)).toEqual([["temperature", "0"], ["chat_template_kwargs", '{"enable_thinking":false}']]);
  });
});
