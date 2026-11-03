import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import textoDoExemplo from "../../codigo/mcp/exemplos/incidente_flood.jsonl?raw";
import codigoDoAprovador from "../../codigo/agente/aprovador.py?raw";
import { APROVADOR_AUTOMATICO } from "./adaptador";
import { Pagina, type PropsDaPagina } from "./App";
import { AVISO_DE_TESTE, PROMPT_DE_TESTE, comConversas } from "./conversa-de-teste";
import { fmtInt } from "./design-system/components/util";
import { recorte, textoDe } from "./html-de-teste";
import { lerLog } from "./log";
import { acharExecucao, type IndiceDaRodada } from "./rodada";
import { indiceDeTeste } from "./rodada-de-teste";
import type { Rota } from "./rotas";
import type { ResultadoDaSimulacao } from "./simulacao";
import { montarReplay } from "./telas/replay";

// As telas no modo da rodada final, com o índice de teste e o log de exemplo do stub (com e sem a conversa
// dos agentes, que o exemplo não traz e `conversa-de-teste.ts` acrescenta).

const nada = () => undefined;
const COM_CONVERSAS = comConversas(textoDoExemplo);
const EXECUCAO = "oficial/DDoS-UDP_Flood-inc-0001-local-r1";
const texto = (html: string) => textoDe(html).replace(/\s+/g, " ");

function replayDe(log: string, passo?: number) {
  const { eventos, avisos } = lerLog(log);
  return montarReplay(eventos, avisos, passo ?? eventos.length, { irPara: nada, tocando: false, alternar: nada });
}

function naRodada(rota: Rota, { log = COM_CONVERSAS, indice = indiceDeTeste() as IndiceDaRodada | null, execucao = EXECUCAO, ...extras }: Partial<PropsDaPagina> & { log?: string; execucao?: string } = {}): string {
  const rodada = indice ? acharExecucao(indice, execucao) : null;
  return renderToString(
    <Pagina rota={rota} replay={replayDe(log)} navegar={nada} modelo={{ online: false }} modoRodada indice={indice} rodada={rodada} {...extras} />,
  );
}

/** O log de exemplo com o lugar do modelo em cada chamada, como desde o contrato 0.5.0. */
const COM_LUGAR = COM_CONVERSAS.split("\n")
  .map((linha) => (linha.includes('"tipo":"llm_chamada"') ? linha.replace('"onde":null', '"onde":"local"') : linha))
  .join("\n");
/** O log de exemplo com as decisões do inc-0001 tomadas pelo aprovador automático, como nos experimentos. */
const COM_APROVADOR = COM_CONVERSAS.replace(/"usuario":"operador"/g, `"usuario":"${APROVADOR_AUTOMATICO}"`);

describe("modo da rodada final: navegação e barra da fonte", () => {
  it("a navegação mostra a rodada final e tira o que ficou fora da versão final", () => {
    const html = texto(naRodada({ tela: "visao-geral", incidente: null }));
    expect(html).toContain("Rodada final");
    for (const fora of ["Ao vivo", "Componentes", "Entrar"]) {
      expect(recorte(naRodada({ tela: "visao-geral", incidente: null }), "sx-sidebar")).not.toContain(fora);
    }
    // O modo do replay não oferece mais o ao vivo.
    expect(html).not.toContain("Planejad");
  });

  it("a barra diz a execução, com o seletor de grupo, pcap, incidente e repetição, e as medidas", () => {
    const barra = recorte(naRodada({ tela: "visao-geral", incidente: null }), "app-fonte");
    const html = texto(barra);
    expect(html).toContain("Rodada final · execução gravada");
    expect(html).toContain("Modelo local qwen3.8-27c nos três agentes · aprovação automática por regra fixa · efeito simulado");
    for (const rotulo of ["Grupo", "Captura (pcap)", "Incidente", "Repetição"]) {
      expect(html).toContain(rotulo);
    }
    expect(barra).toContain("Kali Linux, rede isolada (1)");
    expect(barra).toContain("Recon-PortScan.pcap · Recon");
    expect(barra).toContain("2 · sem proposta");
    expect(html).toContain("triagem certa");
    expect(html).toContain("primeira ação aceitável");
    expect(html).toContain("atacante certo");
    expect(html).toContain(`resolvido · ${fmtInt(52_900)} tokens`);
    expect(html).toContain("Nesta execução, os agentes trataram só o inc-0001");
    // A nuvem não aparece como o caso da rodada.
    expect(html).not.toContain("nuvem");
  });

  it("a fila da visão geral destaca o incidente que os agentes trataram", () => {
    const html = naRodada({ tela: "visao-geral", incidente: null });
    expect(texto(html)).toContain("em destaque, o que os agentes trataram (inc-0001)");
    expect(html).toContain("is-selected");
  });

  it("sem os dados no build, a barra diz como gerá-los, e a tela da rodada também", () => {
    const visao = texto(naRodada({ tela: "visao-geral", incidente: null }, { indice: null, log: "" }));
    expect(visao).toContain("Os dados da rodada final não estão neste build.");
    expect(visao).toContain("python -m codigo.agente.vitrine");
    expect(texto(naRodada({ tela: "rodada", incidente: null }, { indice: null, log: "" }))).toContain("Os dados da rodada final não estão neste build");
  });

  it("com o log de uma simulação, a barra diz isso e oferece voltar, menos com os agentes rodando", () => {
    const simulacao = { arquivo: "Recon-PortScan.pcap", agentes: { estado: "concluidos" } } as unknown as ResultadoDaSimulacao;
    const parada = recorte(naRodada({ tela: "visao-geral", incidente: null }, { simulacao, voltar: nada }), "app-fonte");
    expect(texto(parada)).toContain("SimulaçãoRecon-PortScan.pcapAs telas mostram o log desta simulação.");
    expect(texto(parada)).toContain("Voltar à rodada final");
    expect(parada).not.toContain("disabled");
    const rodando = recorte(naRodada({ tela: "visao-geral", incidente: null }, { simulacao: { ...simulacao, agentes: { estado: "rodando" } } as ResultadoDaSimulacao }), "app-fonte");
    expect(rodando).toContain("disabled");
    expect(rodando).toContain("pare-os na tela Simulação");
  });
});

describe("tela Rodada final", () => {
  it("mostra cada grupo com o resumo das medidas e a tabela das execuções, com a aberta marcada", () => {
    const html = naRodada({ tela: "rodada", incidente: null });
    const textoDaTela = texto(html);
    expect(textoDaTela).toContain("Rodada oficial (CICIoT2023)");
    expect(textoDaTela).toContain("Kali Linux, rede isolada");
    expect(textoDaTela).toContain("6 execuções · 3 pcaps · 4 incidentes · 1 repetição");
    for (const rotulo of ["Triagem certa", "Primeira ação aceitável", "Atacante certo", "Abaixo de 0,6", "Tokens por execução", "Tempo dos agentes"]) {
      expect(textoDaTela).toContain(rotulo);
    }
    expect(textoDaTela).toContain("aprovador automático, com regra fixa conferida no gabarito");
    expect(textoDaTela).toContain("os agentes só recomendam");
    expect(html.match(/app-linha-atual/g)).toHaveLength(1);
    expect(textoDaTela).toContain("inc-0001 · repetição 1 · aberta");
    expect(html).toContain("sx-rowlink");
    expect(textoDaTela).toContain("BenignTraffic2.pcap");
    expect(textoDaTela).toContain("falso · pcap Benign");
  });
});

describe("detalhe do incidente numa execução da rodada", () => {
  it("diz que é só leitura, com a aprovação automática e o efeito simulado, e mostra o que a rodada mediu", () => {
    const html = naRodada({ tela: "incidente", incidente: "inc-0001" });
    const textoDaTela = texto(html);
    expect(textoDaTela).toContain("Execução gravada da rodada final, só leitura.");
    expect(textoDaTela).toContain("aprovador automático dos experimentos");
    expect(textoDaTela).toContain("a verificação do efeito é simulada");
    const medidas = texto(recorte(html, "sx-kv body-sm app-medidas"));
    expect(medidas).toContain("Verdade de campoataque de DDoS");
    expect(medidas).toContain("coerente · certa");
    expect(medidas).toContain("bloquear_ip · aceitável pelo gabarito");
    expect(medidas).toContain("certo · a regra fixa erra");
    // Só leitura: nenhum botão de decidir, e o "Já resolvido" desligado, dizendo por quê.
    expect(textoDaTela).not.toContain("Aprovar");
    expect(html).toContain("Execução gravada da rodada final: só leitura");
  });

  it("sem incidente na rota, abre o que os agentes trataram na execução", () => {
    const execucao = "oficial/DDoS-UDP_Flood-inc-0002-local-r1";
    expect(texto(naRodada({ tela: "incidente", incidente: null }, { execucao }))).toContain("Incidentes / inc-0002");
  });

  it("a decisão do aprovador automático é texto do sistema, e não de pessoa", () => {
    const html = naRodada({ tela: "incidente", incidente: "inc-0001" }, { log: COM_APROVADOR });
    expect(texto(html)).toContain("Regra do aprovador automático, não uma pessoa: O dispositivo não pode sair de serviço.");
    expect(html).not.toContain("Texto de pessoa · aprovador-automatico");
    expect(texto(html)).toContain("prop-0002 rejeitada pelo aprovador automático");
  });

  it("o nome do aprovador automático é o do código", () => {
    expect(codigoDoAprovador).toContain(`USUARIO = "${APROVADOR_AUTOMATICO}"`);
  });
});

describe("conversa dos agentes", () => {
  const conversa = (incidente = "inc-0001", extras: Partial<PropsDaPagina> & { log?: string; execucao?: string } = {}) =>
    naRodada({ tela: "incidente", incidente, aba: "conversa" }, extras);

  it("é uma aba do incidente, com o número de conversas", () => {
    const abas = texto(recorte(conversa(), "sx-tabs"));
    expect(abas).toContain("Detalhe");
    expect(abas).toContain("Conversa dos agentes6");
  });

  it("mostra cada agente na ordem, com o papel de cada mensagem, e as decisões entre eles", () => {
    const html = conversa();
    const textoDaTela = texto(html);
    const ordem = ["Triagemlocal", "Decisãolocal · qwen3.8-27cRodada 1", "Execuçãolocal · qwen3.8-27cRodada 1", "Decisãolocal · qwen3.8-27cRodada 2", "Execuçãolocal · qwen3.8-27cRodada 2", "Execuçãolocal · qwen3.8-27cRodada 2", "TriagemSumário do incidente"];
    let desde = 0;
    for (const titulo of ordem) {
      const achado = textoDaTela.indexOf(titulo, desde);
      expect(achado, titulo).toBeGreaterThan(-1);
      desde = achado + titulo.length;
    }
    for (const rotulo of ["Prompt de sistema, com as skills do agente", "Pedido do orquestrador", "Pede a tool obter_resumo", "Resultado de obter_resumo", "Aviso do laço ao modelo", "Resposta final"]) {
      expect(textoDaTela).toContain(rotulo);
    }
    expect(textoDaTela).toContain(AVISO_DE_TESTE);
    expect(textoDaTela).toContain("Abriu o incidente inc-0001. Faça a decisao.");
    // Os argumentos e o resultado curto aparecem formatados; o argumento é do modelo, na borda tracejada.
    expect(html).toContain("app-bruto code app-bruto--modelo");
    expect(textoDaTela).toContain('"limite": 5');
    expect(textoDaTela).toContain('"janelas": 40');
    // A resposta final é texto de agente, na voz dele, com o modelo.
    expect(html).toContain("sx-voice--agent");
    expect(textoDaTela).toContain("Resposta final da triagem sobre inc-0001.");
    expect(textoDaTela).toContain("Escrito por IA (qwen3.8-27c)");
    // O que cada agente deixou no log, e as decisões entre as etapas.
    expect(textoDaTela).toContain("No log, nesta etapa");
    expect(textoDaTela).toContain("prop-0002 rejeitada");
    expect(textoDaTela).toContain("parou por resposta final");
  });

  it("o prompt de sistema começa recolhido, com o tamanho, e o texto só aparece aberto", () => {
    const html = conversa();
    expect(texto(html)).toContain(`${PROMPT_DE_TESTE.length + " (triagem)".length} caracteres`);
    expect(texto(html)).not.toContain("Leia o incidente e responda no formato pedido.");
  });

  it("ao lado, o que a rodada mediu na execução", () => {
    const textoDaTela = texto(conversa());
    expect(textoDaTela).toContain("O que a rodada mediu nesta execução");
    expect(textoDaTela).toContain("aceitável pelo gabarito");
  });

  it("num incidente que os agentes não trataram nesta execução, oferece abrir a execução dele", () => {
    const textoDaTela = texto(conversa("inc-0002", { log: textoDoExemplo.split("\n").filter((linha) => !linha.includes('"incidente":"inc-0002"') || linha.includes("incidente_aberto")).join("\n") }));
    expect(textoDaTela).toContain("Os agentes não trataram este incidente neste log");
    expect(textoDaTela).toContain("nesta, os agentes trataram o inc-0001");
    expect(textoDaTela).toContain("Abrir a execução do inc-0002");
  });

  it("num log anterior ao contrato 0.8.0, as etapas aparecem sem as mensagens, e a tela diz por quê", () => {
    const textoDaTela = texto(conversa("inc-0001", { log: textoDoExemplo }));
    expect(textoDaTela).toContain("Este log não traz a conversa dos agentes.");
    expect(textoDaTela).toContain("O log não traz a conversa deste agente");
    expect(textoDaTela).not.toContain("Pedido do orquestrador");
  });
});

describe("telas do artigo e relatório com a rodada", () => {
  it("Tela 4: tudo no modelo local, custo de nuvem zero, e o grupo da rodada por agente", () => {
    const textoDaTela = texto(naRodada({ tela: "custo-latencia", incidente: null }, { log: COM_LUGAR }));
    expect(textoDaTela).toContain("Onde o modelo rodou");
    expect(textoDaTela).toContain("15chamadas no modelo local");
    expect(textoDaTela).toContain("Na nuvemnenhuma chamada");
    expect(textoDaTela).toContain("Custo de nuvemUS$ 0,00");
    expect(textoDaTela).toContain("Os experimentos rodam só no modelo local");
    expect(textoDaTela).toContain("Rodada oficial (CICIoT2023): por agente");
    expect(textoDaTela).toContain("nenhuma foi à nuvem, e o custo de nuvem é US$ 0,00");
  });

  it("Tela 3: a legenda diz que a execução é da rodada, com aprovação automática e efeito simulado", () => {
    const textoDaTela = texto(naRodada({ tela: "isolado-integrado", incidente: null }));
    expect(textoDaTela).toContain("Execução DDoS-UDP_Flood-inc-0001-local-r1 da rodada final");
    expect(textoDaTela).toContain("efeito da ação simulado");
  });

  it("relatório: as decisões do aprovador automático não são decisões humanas, e o efeito é simulado", () => {
    const textoDaTela = texto(naRodada({ tela: "relatorio", incidente: "inc-0001" }, { log: COM_APROVADOR }));
    expect(textoDaTela).toContain("Decisões do aprovador automático");
    expect(textoDaTela).not.toContain("Decisões humanas");
    expect(textoDaTela).toContain("pelo aprovador automático dos experimentos, por regra fixa conferida no gabarito, e não por uma pessoa");
    expect(textoDaTela).toContain("a verificação do efeito é simulada");
  });
});

describe("simulação no modo da rodada", () => {
  const resultado = (estado: string) =>
    ({
      arquivo: "Recon-PortScan.pcap", quadros: 10, ignorados: 0, janelas: 1, janelas_puladas: 0, janelas_incompletas: 0,
      trecho: { a_partir_da_janela: 0, so_teste: true }, por_categoria: {}, duracao_do_pcap_s: 1, processamento_s: 0.1, modelo: "m",
      ponto_de_operacao: { regra: "argmax", limiar: null, seguidas: 4 }, acionamento: {}, incidentes: [], incidentes_alem_do_teto: 0,
      log: "x.jsonl", cenarios: "x.cenarios.json", eventos: "",
      agentes: { estado, configuracao: "local", modelo: "qwen3.8-27c", motivo: null, incidentes: [] },
    }) as ResultadoDaSimulacao;

  it("com uma simulação nas telas, oferece voltar à rodada final quando os agentes pararam", () => {
    const html = naRodada({ tela: "simulacao", incidente: null }, { simulacao: resultado("concluidos"), voltar: nada });
    expect(texto(html)).toContain("Voltar à rodada final");
    const rodando = naRodada({ tela: "simulacao", incidente: null }, { simulacao: resultado("rodando"), voltar: nada });
    expect(recorte(rodando, "sx-pagehead")).toContain("disabled");
  });

  it("a última simulação do backend, fora das telas, pode voltar a elas", () => {
    const textoDaTela = texto(naRodada({ tela: "simulacao", incidente: null }, { ultimaSimulacao: resultado("concluidos") }));
    expect(textoDaTela).toContain("A última simulação está fora das telas");
    expect(textoDaTela).toContain("Abrir esta simulação nas telas");
    expect(textoDaTela).toContain("mostram a rodada final");
  });
});
