import type { ReactElement } from "react";
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import textoDoExemplo from "../../codigo/mcp/exemplos/incidente_flood.jsonl?raw";
import { Pagina } from "./App";
import type { MensagemDaConversa, Prompt } from "./chat";
import { CLASSES, MATRIZ, medir } from "./dados/qualidade";
import { fmtInt, fmtPct } from "./design-system/components/util";
import { textoDe } from "./html-de-teste";
import { MOTIVOS_DE_RISCO_ALTO } from "./listas";
import { agregar, lerLog } from "./log";
import type { Rota, Tela } from "./rotas";
import type { ResultadoDaSimulacao } from "./simulacao";
import { TelaDoChat } from "./telas/Chat";
import { TelaComponentes } from "./telas/Componentes";
import { TelaEntrar } from "./telas/Entrar";
import { montarReplay } from "./telas/replay";

// As telas desenhadas no Node com o log de exemplo, em passos escolhidos do replay. O texto que a
// banca vê tem de sair do log, e o que veio de agente ou de pessoa tem de aparecer como tal.

const lido = lerLog(textoDoExemplo);
const AVISOS = [...lido.avisos, ...agregar(lido.eventos).avisos];
const nada = () => undefined;

function replayNo(passo: number, texto = textoDoExemplo) {
  const { eventos, avisos } = lerLog(texto);
  return montarReplay(eventos, avisos, passo, { irPara: nada, tocando: false, alternar: nada });
}

function pagina(tela: Tela, passo = lido.eventos.length, incidente: string | null = null, texto = textoDoExemplo): string {
  const rota: Rota = { tela, incidente };
  return renderToString(<Pagina rota={rota} replay={replayNo(passo, texto)} navegar={nada} modelo={{ nome: "modelo-de-exemplo", online: true }} />);
}

const texto = (html: string) => textoDe(html).replace(/\s+/g, " ");
// O HTML sem os blocos de voz (texto de agente e de pessoa) nem as citações entre aspas do servidor.
const semVozes = (html: string) =>
  html.replace(/<figure class="sx-voice[\s\S]*?<\/figure>/g, "").replace(/<div class="sx-rsec__body voice-agent">[\s\S]*?<\/div>/g, "");

describe("o log de exemplo", () => {
  it("é lido sem avisos", () => {
    expect(AVISOS).toEqual([]);
  });
});

describe("visão geral", () => {
  it("no fim do log, abre com o funil do argumento, os três números e a fila", () => {
    const html = texto(pagina("visao-geral"));
    expect(html).toContain("Visão geral");
    expect(html).toContain(`${fmtInt(10_970)}janelas classificadas`);
    expect(html).toContain(`Sem agregação, cada janela de ataque seria uma chamada: ${fmtInt(10_752)} chamadas à IA`);
    expect(html).toContain("Por incidente: inc-0001, 11 chamadas · inc-0002, 2 chamadas (marcado como já resolvido).");
    expect(html).toContain("inc-0001");
    expect(html).toContain("Marcado como já resolvido");
    expect(html).toContain("evento 60 de 60");
  });

  it("antes do primeiro incidente, a fila diz por que está vazia", () => {
    expect(texto(pagina("visao-geral", 1))).toContain("Nenhum incidente até aqui");
  });

  it("no passo 31, o cartão e a barra lateral pedem uma pessoa", () => {
    const html = pagina("visao-geral", 31);
    expect(html).toContain("sx-metric--attention");
    expect(html).toContain("sx-nav__count is-attention");
    expect(texto(html)).toContain("Propostas de risco alto esperam uma pessoa.");
  });
});

describe("detalhe do incidente", () => {
  it("no passo 31, as duas propostas aguardam com os motivos do contrato, sem botões: é um ponto passado", () => {
    const html = texto(pagina("incidente", 31, "inc-0001"));
    expect(html).toContain("2 propostas de risco alto aguardam aprovação");
    expect(html).toContain("Este é um ponto passado do replay");
    expect(html).toContain(MOTIVOS_DE_RISCO_ALTO.acao_sempre_de_risco_alto);
    expect(html).toContain(MOTIVOS_DE_RISCO_ALTO.acao_nova);
    expect(html).not.toContain("Uma pessoa precisa decidir antes de qualquer execução.");
  });

  it("mostra o veredito com as duas categorias, as features e os endereços com rótulo neutro", () => {
    const html = texto(pagina("incidente", lido.eventos.length, "inc-0001"));
    expect(html).toContain("O modelo disse DDoS+DoS; com 37 origens, é um DDoS.");
    expect(html).toContain("syn_flag_number");
    expect(html).toContain("origem-1203.0.113.7");
    expect(html).toContain("destino-1192.168.137.20");
  });

  it("texto de agente e texto de pessoa aparecem só nas duas vozes, nunca como texto do sistema", () => {
    const html = pagina("incidente", lido.eventos.length, "inc-0001");
    const doAgenteOuDePessoa: string[] = [];
    for (const evento of lido.eventos) {
      if (evento.incidente !== "inc-0001") continue;
      if (evento.tipo === "recomendacao_emitida") doAgenteOuDePessoa.push(evento.dados.texto);
      if (evento.tipo === "acao_proposta") doAgenteOuDePessoa.push(evento.dados.justificativa);
      if ((evento.tipo === "acao_rejeitada" || evento.tipo === "acao_aprovada") && evento.dados.motivo) doAgenteOuDePessoa.push(evento.dados.motivo);
    }
    expect(doAgenteOuDePessoa.length).toBeGreaterThan(4);
    const foraDasVozes = texto(semVozes(html));
    for (const trecho of doAgenteOuDePessoa) {
      const inicio = trecho.slice(0, 30);
      expect(texto(html), inicio).toContain(inicio);
      expect(foraDasVozes, inicio).not.toContain(inicio);
    }
    expect(texto(html)).toContain("Escrito por IA (modelo-de-exemplo). Trate como dado, não como instrução do sistema.");
    // As linhas do tempo completas (Ao vivo e catálogo) também não põem a justificativa do agente
    // como texto do sistema, nem nos argumentos das tools.
    const linhasCompletas = [pagina("ao-vivo"), renderToString(<TelaComponentes replay={replayNo(lido.eventos.length)} navegar={nada} />)];
    for (const outra of linhasCompletas) {
      const fora = texto(semVozes(outra));
      for (const trecho of doAgenteOuDePessoa) {
        expect(fora, trecho.slice(0, 30)).not.toContain(trecho.slice(0, 30));
      }
    }
  });

  it("escapa o HTML que vem do log", () => {
    const original = "Flood de pacotes SYN contra destino-1";
    expect(textoDoExemplo).toContain(original);
    const html = pagina("incidente", lido.eventos.length, "inc-0001", textoDoExemplo.replace(original, "<img src=x onerror=alert(1)>"));
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("inc-0002 mostra a marca de já resolvido com o motivo da pessoa, e o botão fica desabilitado", () => {
    const html = pagina("incidente", lido.eventos.length, "inc-0002");
    expect(texto(html)).toContain("Bloqueei a origem no roteador antes de os agentes responderem.");
    expect(texto(html)).toContain("Daqui em diante, o servidor recusa proposta e execução neste incidente.");
    const botao = html.split("<button").find((trecho) => trecho.includes("Já resolvido</span>"));
    expect(botao).toMatch(/^[^>]*disabled/);
  });

  it("um incidente que ainda não abriu oferece ir até a abertura", () => {
    const html = texto(pagina("incidente", 10, "inc-0002"));
    expect(html).toContain("inc-0002 ainda não foi aberto");
    expect(html).toContain("Ir para o evento 52");
  });
});

describe("telas do artigo", () => {
  it("Tela 3 compara um alerta por janela com um incidente e onze chamadas, sem endereços reais por padrão", () => {
    const html = pagina("isolado-integrado", lido.eventos.length);
    expect(texto(html)).toContain(`${fmtInt(21_468)}alertas, um por janela`);
    expect(texto(html)).toContain("11 chamadas à IA");
    // Nada de linha "uma por janela" inventada: o log não guarda as janelas uma a uma.
    expect(texto(html)).not.toContain("ilustrativ");
    expect(html).not.toContain("&quot;janela&quot;");
    expect(html).not.toContain("203.0.113.7");
  });

  it("Tela 4 soma tokens e chamadas do log e as chamadas evitadas", () => {
    const html = texto(pagina("custo-latencia", lido.eventos.length));
    expect(html).toContain(fmtInt(agregar(lido.eventos).resumo.tokens));
    expect(html).toContain(fmtInt(10_752 - 13));
    expect(html).toContain("O log não diz onde cada modelo roda.");
  });

  it("Tela 5 mostra a matriz real do ponto de operação", () => {
    const qualidade = medir(CLASSES, MATRIZ);
    const html = texto(pagina("qualidade"));
    expect(html).toContain(fmtPct(qualidade.f1Macro, 1));
    expect(html).toContain(fmtInt(MATRIZ[0][0]));
    expect(html).toContain("regerado_janela_100_ponto.csv");
    expect(html).not.toContain("ilustrativ");
  });

  it("Tela 6 fica vazia até o teste rodar, com os três desfechos em zero e o selo de planejada", () => {
    const html = texto(pagina("seguranca-mcp"));
    expect(html).toContain("Os testes ainda não rodaram");
    expect(html).toContain("Planejada");
    expect(html).toContain("Agente resistiu0");
    expect(html).not.toContain("ilustrativ");
    expect(html).not.toContain("inc-0001");
  });
});

describe("ao vivo e relatório", () => {
  it("sem log ao vivo configurado, a tela é a planejada e fica vazia: não usa o log do replay", () => {
    const html = texto(pagina("ao-vivo"));
    expect(html).toContain("Planejada");
    expect(html).toContain("Nada aguarda você");
    expect(html).toContain("Nenhum incidente aberto");
    expect(html).toContain("Nenhum evento ainda");
    expect(html).not.toContain("inc-0001");
    expect(html).not.toContain("Provedores de IA");
  });

  it("o relatório sai do log: capa, fatos, ações, recomendações e decisões humanas", () => {
    const html = texto(pagina("relatorio", lido.eventos.length, "inc-0001"));
    expect(html).toContain("SNT-2026-INC0001");
    expect(html).toContain("inc-0001 · DDoS contra destino-1");
    expect(html).toContain("Fatos do log");
    expect(html).toContain("prop-0002 isolar_dispositivo rejeitada pelo terminal, por operador");
    expect(html).toContain("O dispositivo não pode sair de serviço.");
    expect(html).toContain("prop-0003 ativar_syn_cookies aprovada pelo terminal");
    expect(html).toContain("Gerado pelo agente · Decisão");
    expect(html).toContain("Planejada");
  });
});

describe("chat com o modelo", () => {
  const PROMPTS: Prompt[] = [
    { nome: "triagem-do-alerta", titulo: "Triagem do alerta", texto: "# Triagem" },
    { nome: "execucao-da-acao", titulo: "Execução da ação", texto: "# Execução" },
  ];
  const CONVERSA: MensagemDaConversa[] = [
    { papel: "usuario", conteudo: "O que é um port scan?" },
    { papel: "assistente", conteudo: "Uma varredura de portas.", modelo: "qwen3.8-27c", tokens_entrada: 67, tokens_saida: 191, tempo_ms: 9334 },
  ];
  function chat(props: Partial<Parameters<typeof TelaDoChat>[0]> = {}): string {
    return renderToString(
      <TelaDoChat
        modelos={["m-1", "m-2"]}
        modelo="m-1"
        onModelo={nada}
        sistema=""
        onSistema={nada}
        prompts={PROMPTS}
        skill=""
        onCarregarPrompt={nada}
        mensagens={[]}
        texto=""
        enviando={false}
        erro={null}
        erroDeCarga={null}
        onTexto={nada}
        onEnviar={nada}
        onLimpar={nada}
        {...props}
      />,
    );
  }

  it("começa vazio, com as skills para carregar", () => {
    const html = texto(chat());
    expect(html).toContain("Nenhuma mensagem ainda");
    expect(html).toContain("Triagem do alerta");
    expect(html).toContain("Execução da ação");
  });

  it("mostra a conversa nas duas vozes, com modelo, tokens e tempo sob a resposta", () => {
    const html = chat({ mensagens: CONVERSA });
    expect(html).toContain("sx-msg--user");
    expect(html).toContain("sx-msg--assistant");
    expect(texto(html)).toContain("258 tokens · 9,3 s");
    expect(texto(html)).toContain("Uma varredura de portas.");
  });

  it("sem tokens informados, diz isso; resposta vazia avisa em vez de mostrar nada", () => {
    const semUso: MensagemDaConversa[] = [{ papel: "assistente", conteudo: "", modelo: "m", tokens_entrada: null, tokens_saida: null, tempo_ms: 800 }];
    const html = texto(chat({ mensagens: semUso }));
    expect(html).toContain("tokens não informados");
    expect(html).toContain("O modelo não devolveu texto.");
  });

  it("o erro de envio e o erro de carga aparecem separados, e o texto fica na caixa", () => {
    const html = chat({ erro: "o campo sistema passa de 20000 caracteres", erroDeCarga: "O backend do chat não está no ar.", texto: "Minha pergunta" });
    expect(texto(html)).toContain("Não foi possível obter a resposta.");
    expect(texto(html)).toContain("Não foi possível carregar os modelos e as skills.");
    expect(html).toContain("Minha pergunta");
  });

  it("enquanto espera a resposta, a caixa fica desabilitada e o chat avisa", () => {
    const html = chat({ enviando: true, mensagens: [CONVERSA[0]] });
    expect(html).toContain('aria-label="Aguardando o modelo"');
    expect(html).toMatch(/<textarea[^>]*disabled/);
  });

  it("sem lista de modelos, o seletor fica sem opção", () => {
    expect(texto(chat({ modelos: [], modelo: "" }))).toContain("Nenhum modelo");
  });

  it("a página do chat abre dentro da moldura, sem o controle do replay", () => {
    const html = pagina("chat");
    expect(texto(html)).toContain("Chat com o modelo");
    expect(html).not.toContain("Controle do replay");
  });
});

describe("sem log de eventos", () => {
  const vazia = (tela: Tela) => pagina(tela, 0, null, "");

  it("a visão geral abre em zero, sem fios no funil, sem contagem na barra e sem o replay no pé", () => {
    const html = vazia("visao-geral");
    expect(texto(html)).toContain("Nenhuma janela classificada ainda.");
    expect(texto(html)).toContain("Nenhum log de eventos carregado.");
    expect(html).not.toContain("sx-funnel__win");
    expect(html).not.toContain("sx-nav__count");
    expect(html).not.toContain("sx-replay");
  });

  it("nenhuma tela mostra número, incidente ou texto do log de exemplo", () => {
    const telas: Tela[] = ["visao-geral", "incidente", "ao-vivo", "isolado-integrado", "custo-latencia", "seguranca-mcp", "relatorio", "componentes"];
    for (const tela of telas) {
      const html = texto(vazia(tela));
      for (const trecho of ["inc-0001", "inc-0002", fmtInt(10_970), fmtInt(25_514), "ilustrativ", "log de exemplo"]) {
        expect(html, `${tela}: ${trecho}`).not.toContain(trecho);
      }
    }
  });

  it("o detalhe, a Tela 3, a Tela 4 e o relatório dizem que nenhum log foi carregado", () => {
    expect(texto(vazia("incidente"))).toContain("Nenhum log de eventos carregado.");
    expect(texto(vazia("isolado-integrado"))).toContain("Nenhum log de eventos carregado.");
    expect(texto(vazia("custo-latencia"))).toContain("Nenhum log carregado.");
    expect(texto(vazia("relatorio"))).toContain("nenhum log foi carregado");
  });
});

describe("outras telas", () => {
  it("a entrada explica o acesso e oferece o replay", () => {
    const html = texto(renderToString(<TelaEntrar navegar={nada} />));
    expect(html).toContain("Abrir o replay");
    expect(html).toContain("Acesso restrito");
    expect(html).toContain("O replay funciona sem internet");
  });

  it("o catálogo desenha todos os componentes com o log de exemplo", () => {
    const html: string = renderToString((<TelaComponentes replay={replayNo(lido.eventos.length)} navegar={nada} />) as ReactElement);
    const classes = ["sx-logo", "sx-backdrop", "sx-btn", "sx-iconbtn", "sx-cat", "sx-status", "sx-risk", "sx-agent", "sx-channel", "sx-target", "sx-sidebar", "sx-mode", "sx-seg", "sx-tabs", "sx-panel", "sx-field", "sx-funnel", "sx-metric", "sx-conf", "sx-verdict", "sx-queue", "sx-features", "sx-addr", "sx-timeline", "sx-prop", "sx-voice", "sx-alert", "sx-empty", "sx-skel", "sx-tip", "sx-dialog", "sx-chart", "sx-bars", "sx-cm", "sx-msg", "sx-prompt", "sx-msel", "sx-providers", "sx-rpage", "sx-rfacts", "sx-kbd"];
    for (const classe of classes) {
      expect(html, classe).toMatch(new RegExp(`class="[^"]*\\b${classe}\\b`));
    }
  });

  it("toda tela da moldura desenha no primeiro, num do meio e no último passo sem lançar erro", () => {
    const telas: Tela[] = ["visao-geral", "incidente", "ao-vivo", "isolado-integrado", "custo-latencia", "qualidade", "seguranca-mcp", "relatorio", "componentes"];
    for (const tela of telas) {
      for (const passo of [1, 31, lido.eventos.length]) {
        expect(() => pagina(tela, passo), `${tela} no passo ${passo}`).not.toThrow();
      }
    }
  });
});

describe("simulação", () => {
  const RESULTADO: ResultadoDaSimulacao = {
    arquivo: "Recon-PingSweep.pcap",
    quadros: 22943,
    ignorados: 12,
    janelas: 227,
    por_categoria: { Benign: 130, Recon: 96, "DDoS+DoS": 1 },
    duracao_do_pcap_s: 9000,
    processamento_s: 0.18,
    modelo: "rf_regerado_janela_100.joblib",
    ponto_de_operacao: { regra: "argmax", limiar: null, seguidas: 3 },
    acionamento: { fecha_apos: 10, silencio_s: 60, reagrupa_s: 300, teto: 20 },
    incidentes: [],
    incidentes_alem_do_teto: 0,
    log: "dados/eventos/simulacoes/x/eventos.jsonl",
    cenarios: "dados/eventos/simulacoes/x/eventos.cenarios.json",
    janelas_puladas: 159,
    janelas_incompletas: 1,
    trecho: { a_partir_da_janela: 159, so_teste: true },
    eventos: textoDoExemplo,
    para_o_llm: {
      enviado: false,
      motivo: "A simulação para na porta do modelo.",
      agente: "triagem",
      onde_roda: "modelo local",
      incidente: "inc-0001",
      pedido: {
        model: "qwen-teste",
        messages: [
          { role: "system", content: "# Triagem do alerta" },
          { role: "user", content: "Abriu o incidente inc-0001 (evento incidente_aberto)." },
        ],
        tools: [
          { type: "function", function: { name: "obter_incidente", description: "" } },
          { type: "function", function: { name: "obter_janelas", description: "" } },
        ],
        stream: false,
        temperature: 0,
      },
      primeira_leitura: { tool: "obter_incidente", resultado: { id: "inc-0001", origens: [{ endereco: "203.0.113.7", quadros: 10 }] } },
      visao_da_fronteira: { tool: "obter_resumo", resultado: { id: "inc-0001", origens: [{ rotulo: "origem-1", quadros: 10 }] } },
    },
  };

  function simulacao(resultado: ResultadoDaSimulacao | null): string {
    const rota: Rota = { tela: "simulacao", incidente: null };
    return renderToString(
      <Pagina rota={rota} replay={replayNo(lido.eventos.length)} navegar={nada} modelo={{ nome: "m", online: true }} simulacao={resultado} aoSimular={nada} />,
    );
  }

  it("sem simulação, oferece anexar o pcap e iniciar, com o botão desabilitado até haver arquivo", () => {
    const html = simulacao(null);
    const textoDaTela = texto(html);

    expect(textoDaTela).toContain("Simulação com um pcap");
    expect(textoDaTela).toContain("Anexar pcap");
    expect(textoDaTela).toContain("Nenhuma simulação ainda");
    const botao = html.split("<button").find((trecho) => trecho.split("</button>")[0].includes("Iniciar simulação"));
    expect(botao?.split(">")[0]).toContain("disabled");
  });

  it("com o resultado, mostra o fluxo até a porta do modelo e o pedido à triagem como não enviado", () => {
    const textoDaTela = texto(simulacao(RESULTADO));

    expect(textoDaTela).toContain("Do Recon-PingSweep.pcap até a porta do modelo");
    expect(textoDaTela).toContain("227 janelas de 100 quadros, das quais 159 do trecho de treino ficaram de fora");
    expect(textoDaTela).not.toContain("inclui o trecho do pcap usado no treino");
    expect(textoDaTela).toContain("pedido de inc-0001 montado, não enviado");
    expect(textoDaTela).toContain("Não enviado");
    expect(textoDaTela).toContain("qwen-teste");
    expect(textoDaTela).toContain("obter_incidente, obter_janelas");
    expect(textoDaTela).toContain("temperature");
    expect(textoDaTela).toContain("inc-0001");
  });

  it("o bloco da fronteira traz só rótulos neutros, e o endereço fica no bloco do modelo local", () => {
    const textoDaTela = texto(simulacao(RESULTADO));
    const [local, fronteira] = textoDaTela.split("O que chegaria à fronteira");

    expect(local).toContain("203.0.113.7");
    expect(fronteira).toContain("origem-1");
    expect(fronteira).not.toContain("203.0.113.7");
  });

  it("avisa quando a simulação inclui o trecho de treino do modelo", () => {
    const comTreino = { ...RESULTADO, janelas_puladas: 0, trecho: { a_partir_da_janela: 0, so_teste: false } };

    expect(texto(simulacao(comTreino))).toContain("inclui o trecho do pcap usado no treino do modelo");
  });

  it("a barra lateral leva à simulação", () => {
    expect(texto(pagina("visao-geral"))).toContain("Simulação");
  });
});
