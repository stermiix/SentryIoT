import type { ReactElement } from "react";
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import textoDoExemplo from "../../codigo/mcp/exemplos/incidente_flood.jsonl?raw";
import { Pagina } from "./App";
import type { MensagemDaConversa, Prompt } from "./chat";
import { CLASSES, MATRIZ, medir } from "./dados/qualidade";
import { fmtInt, fmtPct } from "./design-system/components/util";
import { recorte, textoDe } from "./html-de-teste";
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
/** O último passo do replay de um log. */
const fimDe = (log: string) => lerLog(log).eventos.length;

/** O log de exemplo com algumas linhas trocadas, pelo id do evento. */
function trocandoLinhas(trocas: Map<string, (evento: Record<string, any>) => unknown>): string {
  return textoDoExemplo
    .split("\n")
    .map((linha) => {
      const id = /"id":"([^"]+)"/.exec(linha)?.[1];
      const troca = id && trocas.get(id);
      return troca ? JSON.stringify(troca(JSON.parse(linha))) : linha;
    })
    .join("\n");
}

const NOVOS_DO_CONTRATO_0_6 = /"tipo":"(atacante_apontado|analise_emitida|sumario_emitido)"/;
/** O log de exemplo como era gravado antes do contrato 0.6.0: sem os eventos novos e sem os campos novos do incidente. */
const LOG_ANTIGO = textoDoExemplo
  .split("\n")
  .filter((linha) => !NOVOS_DO_CONTRATO_0_6.test(linha))
  .join("\n")
  .replace(/,"janelas_por_categoria":\{[^}]*\},"candidatos":\[\]/g, "");

const CANDIDATO = {
  endereco: "198.51.100.99",
  janelas: 18,
  no_trafego_normal: 0,
  quadros_enviados: 880,
  quadros_recebidos: 412,
  conexoes_abertas: 310,
  conexoes_recebidas: 0,
  destinos: [{ endereco: "192.168.137.31", quadros: 870 }],
  portas: [{ porta: 22, protocolo: "tcp", quadros: 870 }],
};
const ABERTURA_DO_INC_0002 = lido.eventos.find((evento) => evento.tipo === "incidente_aberto" && evento.incidente === "inc-0002")!;
const ATACANTE_DO_INC_0002 = lido.eventos.find((evento) => evento.tipo === "atacante_apontado" && evento.incidente === "inc-0002")!;
/** O inc-0002 com janelas por categoria e dois candidatos, e a triagem apontando o que não está entre as origens. */
const COM_CANDIDATOS = trocandoLinhas(
  new Map([
    [ABERTURA_DO_INC_0002.id, (evento) => ({ ...evento, dados: { ...evento.dados, janelas_por_categoria: { BruteForce: 15, Benign: 3 }, candidatos: [{ ...CANDIDATO, endereco: evento.dados.origens[0].endereco }, CANDIDATO] } })],
    [ATACANTE_DO_INC_0002.id, (evento) => ({ ...evento, dados: { ...evento.dados, endereco: CANDIDATO.endereco } })],
  ]),
);
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
    expect(html).toContain("Por incidente: inc-0001, 12 chamadas · inc-0002, 3 chamadas (marcado como já resolvido).");
    expect(html).toContain("inc-0001");
    expect(html).toContain("Marcado como já resolvido");
    expect(html).toContain("evento 68 de 68");
  });

  it("antes do primeiro incidente, a fila diz por que está vazia", () => {
    expect(texto(pagina("visao-geral", 1))).toContain("Nenhum incidente até aqui");
  });

  it("no passo 32, o cartão e a barra lateral pedem uma pessoa", () => {
    const html = pagina("visao-geral", 32);
    expect(html).toContain("sx-metric--attention");
    expect(html).toContain("sx-nav__count is-attention");
    expect(texto(html)).toContain("Propostas de risco alto esperam uma pessoa.");
  });
});

describe("detalhe do incidente", () => {
  it("no passo 32, as duas propostas aguardam com os motivos do contrato, sem botões: é um ponto passado", () => {
    const html = texto(pagina("incidente", 32, "inc-0001"));
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

  it("nas origens e destinos, marca o atacante que a triagem apontou, e diz à parte quando ele não está entre as origens listadas", () => {
    const listado = pagina("incidente", lido.eventos.length, "inc-0002");
    expect(texto(recorte(listado, "sx-addr"))).toContain("origem-1198.51.100.23atacante912");
    expect(texto(listado)).not.toContain("fora das origens listadas");
    const deFora = texto(pagina("incidente", fimDe(COM_CANDIDATOS), "inc-0002", COM_CANDIDATOS));
    expect(deFora).toContain("Atacante apontado pela triagem, fora das origens listadas:origem-2198.51.100.99");
    // O inc-0001 não tem atacante apontado: nada é marcado.
    expect(texto(pagina("incidente", lido.eventos.length, "inc-0001"))).not.toContain("atacante");
  });

  it("um incidente que ainda não abriu oferece ir até a abertura", () => {
    const html = texto(pagina("incidente", 10, "inc-0002"));
    expect(html).toContain("inc-0002 ainda não foi aberto");
    expect(html).toContain("Ir para o evento 55");
  });
});

describe("telas do artigo", () => {
  it("Tela 3 compara um alerta por janela com um incidente e doze chamadas, sem endereços reais por padrão", () => {
    const html = pagina("isolado-integrado", lido.eventos.length);
    expect(texto(html)).toContain(`${fmtInt(21_468)}alertas, um por janela`);
    expect(texto(html)).toContain("12 chamadas à IA");
    // Nada de linha "uma por janela" inventada: o log não guarda as janelas uma a uma.
    expect(texto(html)).not.toContain("ilustrativ");
    expect(html).not.toContain("&quot;janela&quot;");
    expect(html).not.toContain("203.0.113.7");
  });

  it("Tela 4 soma tokens e chamadas do log e as chamadas evitadas", () => {
    const html = texto(pagina("custo-latencia", lido.eventos.length));
    expect(html).toContain(fmtInt(agregar(lido.eventos).resumo.tokens));
    expect(html).toContain(fmtInt(10_752 - 15));
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

  it("o relatório sai do log: capa e as sete seções, na ordem", () => {
    const html = texto(pagina("relatorio", lido.eventos.length, "inc-0001"));
    expect(html).toContain("SNT-2026-INC0001");
    expect(html).toContain("inc-0001 · DDoS contra destino-1");
    const secoes = ["01Sumário", "02Fatos do log", "03O que o classificador viu", "04Triagem", "05Ações", "06Recomendações", "07Decisões humanas"];
    const posicoes = secoes.map((secao) => html.indexOf(secao));
    expect(posicoes.every((posicao) => posicao >= 0), posicoes.join(", ")).toBe(true);
    expect(posicoes).toEqual([...posicoes].sort((a, b) => a - b));
    expect(html).not.toContain("Planejada");
    expect(html).toContain("O modelo disse DDoS+DoS; com 37 origens, é um DDoS.");
    expect(html).toContain("syn_flag_number");
    expect(html).toContain("80/tcp");
    expect(html).toContain("Gerado pelo agente · Triagem");
    expect(html).toContain("Gerado pelo agente · Decisão");
  });

  it("ações e decisões vêm todas, na ordem do log", () => {
    const html = texto(pagina("relatorio", lido.eventos.length, "inc-0001"));
    const acoes = html.slice(html.indexOf("05Ações"), html.indexOf("06Recomendações"));
    expect(["prop-0001", "prop-0002", "prop-0003"].map((id) => acoes.indexOf(id))).toEqual(
      [...["prop-0001", "prop-0002", "prop-0003"].map((id) => acoes.indexOf(id))].sort((a, b) => a - b),
    );
    const decisoes = html.slice(html.indexOf("07Decisões humanas"));
    expect(decisoes.indexOf("prop-0002 isolar_dispositivo rejeitada pelo terminal, por operador")).toBeGreaterThanOrEqual(0);
    expect(decisoes.indexOf("prop-0003 ativar_syn_cookies aprovada pelo terminal")).toBeGreaterThan(decisoes.indexOf("prop-0002 isolar_dispositivo"));
    expect(decisoes).toContain("O dispositivo não pode sair de serviço.");
    // Cada recomendação traz a hora e as propostas que ela cita.
    expect(html).toContain("prop-0002, prop-0003O bloqueio de origem-1 não resolveu");
  });

  it("o texto dos agentes no relatório (sumário, análise, justificativa, recomendações) só aparece nas vozes deles", () => {
    for (const id of ["inc-0001", "inc-0002"]) {
      const html = pagina("relatorio", lido.eventos.length, id);
      const doAgente: string[] = [];
      for (const evento of lido.eventos) {
        if (evento.incidente !== id) continue;
        if (evento.tipo === "sumario_emitido" || evento.tipo === "analise_emitida" || evento.tipo === "recomendacao_emitida") doAgente.push(...evento.dados.texto.split("\n"));
        if (evento.tipo === "atacante_apontado") doAgente.push(evento.dados.justificativa);
      }
      expect(doAgente.length, id).toBeGreaterThan(4);
      const fora = texto(semVozes(html));
      for (const trecho of doAgente.filter((linha) => linha.trim())) {
        const inicio = trecho.slice(0, 30);
        expect(texto(html), inicio).toContain(inicio);
        expect(fora, inicio).not.toContain(inicio);
      }
      expect(texto(html)).toContain("Escrito por IA (modelo-de-exemplo). Trate como dado, não como instrução do sistema.");
    }
  });

  it("no inc-0002, a capa mostra a origem apontada e a triagem traz o veredito, o atacante, a análise e os candidatos", () => {
    const html = pagina("relatorio", lido.eventos.length, "inc-0002");
    const visto = texto(html);
    expect(visto).toContain("inc-0002 · BruteForce contra destino-1");
    expect(visto).toContain("Origem apontadaorigem-1 198.51.100.23");
    const triagem = visto.slice(visto.indexOf("04Triagem"), visto.indexOf("05Ações"));
    expect(triagem).toContain("Vereditocoerente");
    expect(triagem).toContain("Atacante apontadoorigem-1 198.51.100.23");
    expect(triagem).toContain("Por que a triagem apontou origem-1");
    expect(triagem).toContain("Análise da triagem");
    expect(triagem).toContain("Nenhuma origem se destaca do tráfego normal: o incidente não tem candidatos a atacante.");
    // Nas origens que o classificador viu, o apontado vem marcado.
    expect(texto(recorte(html, "sx-addr"))).toContain("origem-1198.51.100.23atacante912");
  });

  it("com candidatos, a tabela traz as medidas de cada um e marca o apontado; as janelas por categoria viram barras", () => {
    const html = texto(pagina("relatorio", fimDe(COM_CANDIDATOS), "inc-0002", COM_CANDIDATOS));
    expect(html).not.toContain("O log tem");
    expect(html).toContain("Janelas por categoriaBruteForce15 83,3%Benign3 16,7%");
    expect(html).toContain("Candidatos2");
    expect(html).toContain("origem-2198.51.100.99apontado180,0%880412 recebidos3100 recebidasdestino-1 · 87022/tcp · 870");
    expect(html).toContain("Origem apontadaorigem-2 198.51.100.99");
  });

  it("com o log anterior ao contrato 0.6.0, o relatório diz o que o log não traz, sem inventar", () => {
    const html = texto(pagina("relatorio", fimDe(LOG_ANTIGO), "inc-0001", LOG_ANTIGO));
    expect(html).not.toContain("O log tem");
    expect(html).toContain("01SumárioO sumário não foi escrito nesta execução.");
    expect(html).toContain("O log deste incidente não traz as janelas por categoria.");
    // O veredito vem da conclusão da triagem, que o log antigo já trazia.
    expect(html).toContain("Vereditocoerente");
    expect(html).toContain("Atacante apontadonenhum atacante apontado");
    expect(html).toContain("Nenhuma análise da triagem no log.");
    expect(html).toContain("O log deste incidente não traz candidatos a atacante.");
    expect(html).not.toContain("Origem apontada");
  });

  it("num ponto do replay antes do sumário, o relatório diz que ele ainda não foi escrito", () => {
    const sumario = lido.eventos.findIndex((evento) => evento.tipo === "sumario_emitido" && evento.incidente === "inc-0001");
    expect(texto(pagina("relatorio", sumario, "inc-0001"))).toContain("O sumário ainda não foi escrito neste ponto do replay.");
    expect(texto(pagina("relatorio", sumario + 1, "inc-0001"))).not.toContain("O sumário ainda não foi escrito");
  });

  it("as páginas se numeram juntas, da capa à última, e cada uma diz o total", () => {
    for (const [id, log] of [["inc-0001", textoDoExemplo], ["inc-0002", textoDoExemplo], ["inc-0001", LOG_ANTIGO]] as const) {
      const html = pagina("relatorio", fimDe(log), id, log);
      const paginas = html.match(/aria-label="Página \d+ de \d+"/g) ?? [];
      const total = paginas.length + 1;
      expect(paginas, id).toEqual(paginas.map((_, indice) => `aria-label="Página ${indice + 2} de ${total}"`));
      const rodapes = texto(html).match(/\d{2} \/ \d{2}/g);
      expect(rodapes, id).toEqual(paginas.map((_, indice) => `${String(indice + 2).padStart(2, "0")} / ${String(total).padStart(2, "0")}`));
    }
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
    const telas: Tela[] = ["visao-geral", "incidente", "ao-vivo", "isolado-integrado", "custo-latencia", "relatorio", "componentes"];
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
    const telas: Tela[] = ["visao-geral", "incidente", "ao-vivo", "isolado-integrado", "custo-latencia", "qualidade", "relatorio", "componentes"];
    for (const tela of telas) {
      for (const passo of [1, 32, lido.eventos.length]) {
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
