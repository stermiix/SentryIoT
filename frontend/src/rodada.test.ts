import { describe, expect, it } from "vitest";
import textoDoExemplo from "../../codigo/mcp/exemplos/incidente_flood.jsonl?raw";
import {
  CAMINHO_DO_INDICE,
  PASTA_DA_RODADA,
  acharExecucao,
  carregarExecucao,
  carregarIndice,
  conferirIndice,
  execucaoInicial,
  opcoesDoSeletor,
  textoDoLog,
  trocarNoSeletor,
  CargaMaisRecente,
  ancoraCorrigida,
  navegacaoNaFonte,
  rotaNaExecucao,
} from "./rodada";
import type { Rota } from "./rotas";
import { indiceDeTeste } from "./rodada-de-teste";

/** O texto em gzip, pela API do navegador (a mesma que a interface usa para abrir). */
async function gzip(texto: string): Promise<ArrayBuffer> {
  const fluxo = new Blob([texto]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Response(fluxo).arrayBuffer();
}

function resposta(corpo: BodyInit | null, status = 200, tipo = "application/json"): Response {
  return new Response(corpo, { status, headers: { "content-type": tipo } });
}

describe("índice da rodada final", () => {
  it("aceita o formato da vitrine e recusa o que foge dele, dizendo o quê", () => {
    expect(conferirIndice(indiceDeTeste()).grupos).toHaveLength(2);
    expect(() => conferirIndice({ ...indiceDeTeste(), versao: 2 })).toThrow("a versão precisa ser 1");
    expect(() => conferirIndice({ ...indiceDeTeste(), inicial: "outra" })).toThrow("a execução inicial outra não está nos grupos");
    const comLogDeFora = indiceDeTeste();
    comLogDeFora.grupos[0].execucoes[0].log = "https://outro.site/log.jsonl";
    expect(() => conferirIndice(comLogDeFora)).toThrow("não é um arquivo da pasta da rodada");
    const repetida = indiceDeTeste();
    repetida.grupos[1].execucoes[0].id = repetida.grupos[0].execucoes[0].id;
    expect(() => conferirIndice(repetida)).toThrow("aparece duas vezes");
    const semNumero = indiceDeTeste() as unknown as { grupos: { execucoes: Record<string, unknown>[] }[] };
    semNumero.grupos[0].execucoes[0].tokens_entrada = "muitos";
    expect(() => conferirIndice(semNumero)).toThrow("tokens_entrada não é número");
  });

  it("é buscado ao lado do app; sem os dados no build (404 ou a página do app), não há rodada, sem erro", async () => {
    const pedidos: string[] = [];
    const indice = await carregarIndice(async (entrada) => {
      pedidos.push(String(entrada));
      return resposta(JSON.stringify(indiceDeTeste()));
    });
    expect(pedidos).toEqual([CAMINHO_DO_INDICE]);
    expect(CAMINHO_DO_INDICE).toBe("/dados/rodada-final/indice.json");
    expect(indice?.inicial).toBe("oficial/DDoS-UDP_Flood-inc-0002-local-r1");
    expect(await carregarIndice(async () => resposta("não achei", 404, "text/plain"))).toBeNull();
    expect(await carregarIndice(async () => resposta("<!doctype html>", 200, "text/html; charset=utf-8"))).toBeNull();
    expect(await carregarIndice(async () => Promise.reject(new TypeError("rede")))).toBeNull();
    await expect(carregarIndice(async () => resposta("{", 200))).rejects.toThrow("não é um JSON válido");
    await expect(carregarIndice(async () => resposta("", 500, "text/plain"))).rejects.toThrow("HTTP 500");
  });
});

describe("log de uma execução", () => {
  it("abre o gzip pelos bytes mágicos, e aceita o texto já aberto pelo servidor ou o .jsonl puro", async () => {
    const comprimido = await gzip(textoDoExemplo);
    expect(Array.from(new Uint8Array(comprimido).slice(0, 2))).toEqual([0x1f, 0x8b]);
    expect(await textoDoLog(resposta(comprimido, 200, "application/gzip"))).toBe(textoDoExemplo);
    // O servidor que manda Content-Encoding: gzip entrega o texto aberto, com o mesmo nome de arquivo.
    expect(await textoDoLog(resposta(textoDoExemplo, 200, "application/gzip"))).toBe(textoDoExemplo);
    expect(await textoDoLog(resposta(textoDoExemplo, 200, "application/x-ndjson"))).toBe(textoDoExemplo);
  });

  it("é lido e conferido como qualquer log; arquivo ausente vira erro que diz como gerar", async () => {
    const execucao = indiceDeTeste().grupos[0].execucoes[0];
    const comprimido = await gzip(textoDoExemplo);
    const pedidos: string[] = [];
    const lido = await carregarExecucao(execucao, async (entrada) => {
      pedidos.push(String(entrada));
      return resposta(comprimido, 200, "application/gzip");
    });
    expect(pedidos).toEqual([`${PASTA_DA_RODADA}oficial/DDoS-UDP_Flood-inc-0001-local-r1.jsonl.gz`]);
    expect(lido.avisos).toEqual([]);
    expect(lido.eventos).toHaveLength(68);
    await expect(carregarExecucao(execucao, async () => resposta("<!doctype html>", 200, "text/html"))).rejects.toThrow("python -m codigo.agente.vitrine");
  });
});

describe("seletor de execução: grupo → pcap → incidente → repetição", () => {
  const indice = indiceDeTeste();
  const contexto = (id: string) => acharExecucao(indice, id)!;

  it("abre na execução que o índice indica", () => {
    expect(execucaoInicial(indice)).toBe("oficial/DDoS-UDP_Flood-inc-0002-local-r1");
    expect(execucaoInicial({ ...indice, inicial: "nenhuma" })).toBe("oficial/DDoS-UDP_Flood-inc-0001-local-r1");
  });

  it("as opções de cada campo saem da execução escolhida", () => {
    const opcoes = opcoesDoSeletor(contexto("oficial/DDoS-UDP_Flood-inc-0001-local-r1"));
    expect(opcoes.valor).toEqual({ grupo: "oficial", pcap: "DDoS-UDP_Flood.pcap", incidente: "inc-0001", repeticao: "1" });
    expect(opcoes.grupo.map((opcao) => opcao.label)).toEqual(["Rodada oficial (CICIoT2023) (6)", "Kali Linux, rede isolada (1)"]);
    expect(opcoes.pcap.map((opcao) => opcao.label)).toEqual(["DDoS-UDP_Flood.pcap · DDoS", "Recon-PortScan.pcap · Recon", "BenignTraffic2.pcap · Benign"]);
    expect(opcoes.incidente.map((opcao) => opcao.label)).toEqual(["inc-0001 · DDoS", "inc-0002 · DDoS"]);
    expect(opcoes.repeticao.map((opcao) => opcao.label)).toEqual(["1 · resolvido", "2 · sem proposta"]);
    // O incidente falso diz isso no rótulo.
    expect(opcoesDoSeletor(contexto("oficial/BenignTraffic2-inc-0001-local-r2")).incidente.map((opcao) => opcao.label)).toEqual(["inc-0001 · DDoS · falso"]);
  });

  it("trocar um campo mantém os de baixo quando existem, e senão pega o primeiro", () => {
    const daqui = contexto("oficial/DDoS-UDP_Flood-inc-0002-local-r2");
    expect(trocarNoSeletor(daqui, "repeticao", "1")).toBe("oficial/DDoS-UDP_Flood-inc-0002-local-r1");
    expect(trocarNoSeletor(daqui, "incidente", "inc-0001")).toBe("oficial/DDoS-UDP_Flood-inc-0001-local-r2");
    // O Recon-PortScan não tem inc-0002 nem a repetição 2: fica a primeira execução dele.
    expect(trocarNoSeletor(daqui, "pcap", "Recon-PortScan.pcap")).toBe("oficial/Recon-PortScan-inc-0001-local-r1");
    expect(trocarNoSeletor(daqui, "grupo", "kali")).toBe("kali/kali-nmap-inc-0001-local-r1");
    expect(trocarNoSeletor(daqui, "grupo", "nao-existe")).toBe(daqui.execucao.id);
  });
});

describe("a execução na âncora", () => {
  const indice = indiceDeTeste();
  const recon = acharExecucao(indice, "oficial/Recon-PortScan-inc-0001-local-r1")!;
  const conversa: Rota = { tela: "incidente", incidente: "inc-0003", aba: "conversa" };

  it("numa execução, a tela de um incidente passa ao incidente dela; as outras telas ficam", () => {
    expect(rotaNaExecucao(conversa, recon)).toEqual({ tela: "incidente", incidente: "inc-0001", aba: "conversa", execucao: recon.execucao.id });
    expect(rotaNaExecucao({ tela: "custo-latencia", incidente: null }, recon)).toEqual({ tela: "custo-latencia", incidente: null, execucao: recon.execucao.id });
    // Sem execução (a simulação, o log da variável), a âncora larga a execução e o incidente.
    expect(rotaNaExecucao({ ...conversa, execucao: recon.execucao.id }, null)).toEqual({ tela: "incidente", incidente: null });
    expect(rotaNaExecucao({ tela: "visao-geral", incidente: null, execucao: recon.execucao.id }, null)).toEqual({ tela: "visao-geral", incidente: null, execucao: undefined });
  });

  it("a âncora que traz uma execução do índice fica como está, e um recarregamento abre essa execução", () => {
    expect(ancoraCorrigida(indice, { ...conversa, execucao: recon.execucao.id }, null)).toBeNull();
  });

  it("sem execução na âncora, vale a carregada ou a inicial, e o incidente de outro log não passa", () => {
    // Primeira vez: a inicial, e o inc-0003 da âncora vira o incidente dela.
    expect(ancoraCorrigida(indice, conversa, null)).toEqual({ tela: "incidente", incidente: "inc-0002", aba: "conversa", execucao: indice.inicial });
    // Entrada do histórico da simulação, de volta à rodada: a carregada, no incidente dela.
    expect(ancoraCorrigida(indice, conversa, recon.execucao.id)).toEqual({ tela: "incidente", incidente: "inc-0001", aba: "conversa", execucao: recon.execucao.id });
    // Execução que o índice não tem (dados gerados de novo).
    expect(ancoraCorrigida(indice, { tela: "visao-geral", incidente: null, execucao: "oficial/outra" }, null)).toEqual({ tela: "visao-geral", incidente: null, execucao: indice.inicial });
  });

  it("a navegação das telas leva a execução da âncora na rodada, e não a leva na simulação nem no log da variável", () => {
    const daAncora: Rota = { tela: "visao-geral", incidente: null, execucao: recon.execucao.id };
    const nova: Rota = { tela: "incidente", incidente: "inc-0002" };
    expect(navegacaoNaFonte(nova, daAncora, { modoRodada: true, simulando: false }).execucao).toBe(recon.execucao.id);
    expect(navegacaoNaFonte({ ...nova, execucao: "kali/kali-nmap-inc-0001-local-r1" }, daAncora, { modoRodada: true, simulando: false }).execucao).toBe("kali/kali-nmap-inc-0001-local-r1");
    expect(navegacaoNaFonte(nova, daAncora, { modoRodada: true, simulando: true }).execucao).toBeUndefined();
    expect(navegacaoNaFonte(nova, daAncora, { modoRodada: false, simulando: false }).execucao).toBeUndefined();
  });
});

describe("carga da execução: a mais recente vence", () => {
  function adiada<T>() {
    let resolver!: (valor: T) => void;
    let rejeitar!: (erro: Error) => void;
    const promessa = new Promise<T>((ok, falha) => {
      resolver = ok;
      rejeitar = falha;
    });
    return { promessa, resolver, rejeitar };
  }

  it("a escolha nova vence a que estava a caminho, mesmo que esta chegue depois", async () => {
    const carga = new CargaMaisRecente<string>();
    const b = adiada<string>();
    const c = adiada<string>();
    const deB = carga.carregar(() => b.promessa);
    const deC = carga.carregar(() => c.promessa);
    c.resolver("C");
    b.resolver("B");
    expect(await deC).toEqual({ tipo: "ok", valor: "C" });
    expect(await deB).toEqual({ tipo: "superada" });
  });

  it("voltar à execução já carregada cancela a que estava a caminho", async () => {
    const carga = new CargaMaisRecente<string>();
    const b = adiada<string>();
    const deB = carga.carregar(() => b.promessa);
    carga.cancelar();
    b.resolver("B");
    expect(await deB).toEqual({ tipo: "superada" });
  });

  it("a falha volta como erro, e repetir a escolha tenta de novo", async () => {
    const carga = new CargaMaisRecente<string>();
    expect(await carga.carregar(async () => Promise.reject(new Error("HTTP 404")))).toEqual({ tipo: "erro", erro: new Error("HTTP 404") });
    expect(await carga.carregar(async () => "B")).toEqual({ tipo: "ok", valor: "B" });
    // A falha de uma carga superada não aparece.
    const b = adiada<string>();
    const deB = carga.carregar(() => b.promessa);
    void carga.carregar(async () => "C");
    b.rejeitar(new Error("tarde"));
    expect(await deB).toEqual({ tipo: "superada" });
  });
});
