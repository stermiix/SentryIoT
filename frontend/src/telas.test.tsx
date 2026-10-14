import type { ReactElement, ReactNode } from "react";
import { renderToString } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import textoDoExemplo from "../public/dados/incidente_flood.jsonl?raw";
import { Pagina } from "./App";
import ControleDoReplay from "./components/ControleDoReplay";
import DetalheDoIncidente from "./components/DetalheDoIncidente";
import FilaDeIncidentes from "./components/FilaDeIncidentes";
import LimiteDeErro from "./components/LimiteDeErro";
import ResumoMetricas from "./components/ResumoMetricas";
import { recorte, textoDe } from "./html-de-teste";
import { MOTIVOS_DE_RISCO_ALTO } from "./listas";
import { agregar, lerLog } from "./log";
import { ESTADO_DA_PROPOSTA, rotulo } from "./rotulos";
import type { Evento, IncidenteView } from "./types";

// As telas desenhadas no Node, com react-dom/server, a partir do log de exemplo e de variações
// dele. Cada conferência recorta o painel de que fala antes de procurar o texto.

const { eventos: base } = lerLog(textoDoExemplo);
type Bruto = Record<string, any>;

function reler(eventos: Bruto[]): Evento[] {
  const lido = lerLog(eventos.map((evento) => JSON.stringify(evento)).join("\n") + "\n");
  expect(lido.avisos).toEqual([]);
  return lido.eventos;
}

/** O log de exemplo com alguns eventos alterados por `alterar`. */
function variacao(alterar: (evento: Bruto) => void): Evento[] {
  return reler(
    base.map((evento) => {
      const copia = structuredClone(evento) as Bruto;
      alterar(copia);
      return copia;
    }),
  );
}

function detalhe(view: IncidenteView): string {
  return renderToString(<DetalheDoIncidente incidente={view} />);
}

function fila(eventos: Evento[]): string {
  const { resumo, incidentes } = agregar(eventos);
  return renderToString(<FilaDeIncidentes resumo={resumo} incidentes={incidentes} selecionadoId={null} onSelecionar={() => {}} />);
}

const final = agregar(base);
const doFlood = final.incidentes.find((view) => view.propostas.length > 0)!;
const marcado = final.incidentes.find((view) => view.marcacao !== null)!;

// O id que cada linha do histórico precisa mostrar: o da proposta ou da execução de que ela fala.
function idEsperado(evento: Evento): string | null {
  switch (evento.tipo) {
    case "acao_proposta":
    case "acao_executada":
    case "acao_desfeita":
      return evento.dados.id;
    case "acao_aprovada":
    case "acao_rejeitada":
    case "catalogo_ampliado":
      return evento.dados.proposta;
    case "efeito_verificado":
      return evento.dados.execucao;
    case "recusa": {
      const citado = evento.dados.argumentos.id_proposta ?? evento.dados.argumentos.id_execucao;
      return typeof citado === "string" ? citado : evento.id;
    }
    case "incidente_marcado_resolvido":
      return evento.dados.incidente;
    default:
      return null;
  }
}

describe("histórico de decisões e ações", () => {
  it("cada linha mostra o id da proposta ou da execução de que fala, na ordem do log", () => {
    for (const view of final.incidentes) {
      const linhas = recorte(detalhe(view), "action-list").split("<li").slice(1);
      const esperados = view.eventos.map(idEsperado).filter((id): id is string => id !== null);
      expect(linhas.map((linha) => /class="event-id">([^<]+)</.exec(linha)![1])).toEqual(esperados);
    }
  });

  it("cada linha mostra a hora do evento", () => {
    const linhas = recorte(detalhe(doFlood), "action-list").split("<li").slice(1);
    const historico = doFlood.eventos.filter((evento) => idEsperado(evento) !== null);
    linhas.forEach((linha, indice) => expect(linha).toContain(`dateTime="${historico[indice].instante}"`));
  });

  it("texto de pessoa ou de agente vai entre aspas", () => {
    const html = textoDe(recorte(detalhe(doFlood), "action-list"));
    for (const evento of doFlood.eventos) {
      if (evento.tipo === "acao_rejeitada" && evento.dados.motivo) {
        expect(html).toContain(`por ${evento.dados.usuario}: “${evento.dados.motivo}”`);
      }
      if (evento.tipo === "recusa") {
        expect(html).toContain(`“${evento.dados.mensagem}”`);
      }
    }
  });
});

describe("rastro dos agentes", () => {
  it("mostra a hora de cada um dos sete primeiros eventos", () => {
    const rastro = recorte(detalhe(doFlood), "timeline");
    const eventos = doFlood.eventos.filter((evento) => evento.tipo === "tool_chamada" || evento.tipo === "llm_chamada").slice(0, 7);
    for (const evento of eventos) {
      expect(rastro).toContain(`dateTime="${evento.instante}"`);
    }
  });
});

describe("propostas de ação", () => {
  it("cada cartão mostra o estado reconstruído da proposta", () => {
    const cartoes = recorte(detalhe(doFlood), "proposal-list").split('<li class="proposal"').slice(1);
    expect(cartoes).toHaveLength(doFlood.propostas.length);
    doFlood.propostas.forEach((proposta, indice) => {
      expect(cartoes[indice]).toContain(`class="event-id">${proposta.id}</code>`);
      expect(cartoes[indice]).toContain(`proposal-${proposta.estado}">${rotulo(ESTADO_DA_PROPOSTA, proposta.estado)}</span>`);
    });
    // O exemplo tem propostas em estados diferentes: um estado fixo na tela não passa.
    expect(new Set(doFlood.propostas.map((proposta) => proposta.estado)).size).toBeGreaterThan(1);
  });

  it("mostra o alvo com o rótulo, a aprovação e a frase do contrato para cada motivo de risco alto", () => {
    const html = textoDe(recorte(detalhe(doFlood), "proposal-list"));
    for (const proposta of doFlood.propostas) {
      if (proposta.alvoComRotulo) {
        expect(html).toContain(`em ${proposta.alvo} (${proposta.alvoComRotulo})`);
      }
      for (const codigo of proposta.motivosDeRiscoAlto) {
        expect(html).toContain(MOTIVOS_DE_RISCO_ALTO[codigo]);
      }
      expect(html).toContain(`Justificativa do agente: “${proposta.justificativa}”`);
    }
    expect(html).toContain("Exige aprovação humana");
    expect(html).toContain("Sem aprovação humana");
  });

  it("mostra o motivo de risco alto alvo_na_rede_local e a recusa de incidente já resolvido", () => {
    const flood = base.find((evento) => evento.tipo === "incidente_aberto")!;
    const ultimo = base[base.length - 1];
    const proposta = {
      id: "ev-900001",
      instante: ultimo.instante,
      tipo: "acao_proposta",
      incidente: flood.incidente,
      dados: {
        id: "prop-0900",
        incidente: flood.incidente,
        acao: "bloquear_ip",
        alvo: "192.168.137.42",
        alvo_com_rotulo: null,
        parametros: { duracao: 10 },
        justificativa: "Origem dentro da rede local.",
        nova: false,
        risco: "alto",
        motivos_de_risco_alto: [{ codigo: "alvo_na_rede_local", descricao: MOTIVOS_DE_RISCO_ALTO.alvo_na_rede_local }],
        exige_aprovacao: true,
        estado: "aguardando_aprovacao",
      },
    };
    const recusa = {
      id: "ev-900002",
      instante: ultimo.instante,
      tipo: "recusa",
      incidente: marcado.id,
      dados: {
        agente: "decisao",
        tool: "propor_acao",
        argumentos: { id: marcado.id },
        motivo: "incidente_ja_resolvido",
        mensagem: "O incidente foi marcado como já resolvido.",
      },
    };
    const eventos = reler([...base, proposta, recusa]);
    const { incidentes, avisos } = agregar(eventos);
    expect(avisos).toEqual([]);
    const htmlDoFlood = textoDe(detalhe(incidentes.find((view) => view.id === flood.incidente)!));
    expect(htmlDoFlood).toContain(MOTIVOS_DE_RISCO_ALTO.alvo_na_rede_local);
    const htmlDoMarcado = textoDe(recorte(detalhe(incidentes.find((view) => view.id === marcado.id)!), "action-list"));
    expect(htmlDoMarcado).toContain("propor_acao · incidente marcado como já resolvido · “O incidente foi marcado como já resolvido.”");
  });
});

describe("recomendação", () => {
  it("lista, no próprio painel, as propostas ligadas a cada recomendação", () => {
    const painel = recorte(detalhe(doFlood), "panel recommendation-panel");
    const citadas = doFlood.recomendacoes.flatMap((evento) => evento.dados.propostas);
    expect(citadas.length).toBeGreaterThan(0);
    for (const id of citadas) {
      expect(painel).toContain(`class="event-id">${id}</code>`);
    }
  });

  it("dá o nome do agente que emitiu a recomendação", () => {
    const eventos = variacao((evento) => {
      if (evento.tipo === "recomendacao_emitida") {
        evento.dados.agente = "triagem";
      }
    });
    const view = agregar(eventos).incidentes.find((item) => item.id === doFlood.id)!;
    const painel = textoDe(recorte(detalhe(view), "panel recommendation-panel"));
    expect(painel).toContain("Agente de triagem");
    expect(painel).not.toContain("Agente de decisão");
  });

  it("escapa HTML vindo do log e mantém a quebra de linha", () => {
    const eventos = variacao((evento) => {
      if (evento.tipo === "recomendacao_emitida") {
        evento.dados.texto = "<b>negrito</b>\nsegunda linha <script>alert(2)</script>";
      }
      if (evento.tipo === "recusa") {
        evento.dados.tool = '"><script>alert(1)</script>';
        evento.dados.mensagem = "<img src=x onerror=alert(1)> javascript:alert(1)";
      }
    });
    const html = agregar(eventos).incidentes.map(detalhe).join("");
    expect(html).not.toMatch(/<(script|img|b)[\s>]/i);
    expect(html).toContain("&lt;script&gt;alert(2)&lt;/script&gt;");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    // A quebra de linha chega ao HTML; o CSS (white-space: pre-line) a mostra.
    expect(html).toContain("&lt;/b&gt;\nsegunda linha");
  });
});

describe("marca de já resolvido e categoria do modelo", () => {
  const marca = base.find((evento) => evento.tipo === "incidente_marcado_resolvido")!;

  it("aparece no detalhe, com canal, usuário e motivo entre aspas", () => {
    if (marca.tipo !== "incidente_marcado_resolvido") {
      throw new Error("o exemplo precisa de uma marca de já resolvido");
    }
    const aviso = textoDe(recorte(detalhe(marcado), "resolved-notice"));
    expect(aviso).toContain("Marcado como já resolvido");
    expect(aviso).toContain(marca.dados.canal === "terminal" ? "pelo terminal" : "pela interface");
    expect(aviso).toContain(`por ${marca.dados.usuario}`);
    if (marca.dados.motivo) {
      expect(aviso).toContain(`“${marca.dados.motivo}”`);
    }
  });

  it("na fila, o incidente marcado aparece como já resolvido, e o encerrado como encerrado", () => {
    expect(fila(base)).toContain('state-resolved"><span></span>Já resolvido');
    const aberto = base.find((evento) => evento.tipo === "incidente_aberto" && evento.incidente === marcado.id)!;
    const encerramento = {
      id: "ev-900003",
      instante: base[base.length - 1].instante,
      tipo: "incidente_encerrado",
      incidente: marcado.id,
      dados: { ...structuredClone(aberto.dados), estado: "encerrado" },
    };
    const html = fila(reler([...base, encerramento]));
    expect(html).not.toContain("Já resolvido");
    expect(html.match(/state-closed/g)).toHaveLength(final.incidentes.length);
  });

  it("mostra a categoria do modelo e a categoria do incidente", () => {
    for (const view of final.incidentes) {
      const html = detalhe(view);
      expect(html).toContain(`Saída do modelo: <strong>${view.incidente.categoria_do_modelo}</strong>`);
      expect(html).toContain(`attack-category">${view.incidente.categoria}</strong>`);
    }
  });
});

describe("página no passo do replay", () => {
  function pagina(passo: number): string {
    return renderToString(
      <Pagina
        eventos={base}
        avisos={[]}
        passo={passo}
        onMudarPasso={() => {}}
        selecionadoId={null}
        onSelecionar={() => {}}
        carregando={false}
        erro={null}
      />,
    );
  }

  it("mostra a fila e os contadores até o evento do passo", () => {
    const segundaAbertura = base.findIndex((evento, indice) => evento.tipo === "incidente_aberto" && indice > 1);
    for (const passo of [segundaAbertura, base.length]) {
      const html = pagina(passo);
      const ate = agregar(base.slice(0, passo));
      expect(textoDe(recorte(html, "replay-position"))).toContain(`Evento ${passo} de ${base.length}`);
      expect(recorte(html, "nav-count")).toContain(`>${ate.incidentes.length}<`);
      expect(html.match(/class="incident-select"/g)).toHaveLength(ate.incidentes.length);
      expect(textoDe(recorte(html, "metricas"))).toContain(ate.resumo.janelasClassificadas.toLocaleString("pt-BR"));
    }
    expect(agregar(base.slice(0, segundaAbertura)).incidentes.length).toBeLessThan(final.incidentes.length);
  });

  it("antes do primeiro evento, não há incidente", () => {
    expect(pagina(0)).toContain("Nenhum incidente aberto até este ponto do replay.");
  });

  it("mostra os avisos do log", () => {
    const html = renderToString(
      <Pagina eventos={base} avisos={["Aviso de teste."]} passo={base.length} onMudarPasso={() => {}} selecionadoId={null} onSelecionar={() => {}} carregando={false} erro={null} />,
    );
    expect(textoDe(recorte(html, "warning-banner"))).toContain("Aviso de teste.");
  });
});

describe("controle do replay", () => {
  // O componente não tem estado: chamado como função, ele devolve os elementos, e o clique de cada
  // botão pode ser chamado direto, sem navegador.
  function botoes(passo: number, onMudar: (passo: number) => void) {
    const encontrados: ReactElement<{ onClick: () => void; "aria-disabled": boolean; children: ReactNode }>[] = [];
    const visitar = (no: ReactNode) => {
      if (Array.isArray(no)) {
        no.forEach(visitar);
      } else if (no && typeof no === "object" && "props" in no) {
        const elemento = no as ReactElement<{ children?: ReactNode }>;
        if (elemento.type === "button") {
          encontrados.push(elemento as (typeof encontrados)[number]);
        }
        visitar(elemento.props.children);
      }
    };
    visitar(ControleDoReplay({ eventos: base, passo, onMudar }));
    return new Map(encontrados.map((botao) => [String(botao.props.children), botao]));
  }

  it("cada botão leva ao passo certo", () => {
    const meio = Math.floor(base.length / 2);
    const esperado = new Map([
      ["Início", 0],
      ["◀ Anterior", meio - 1],
      ["Próximo ▶", meio + 1],
      ["Fim", base.length],
    ]);
    for (const [texto, destino] of esperado) {
      const onMudar = vi.fn();
      botoes(meio, onMudar).get(texto)!.props.onClick();
      expect(onMudar, texto).toHaveBeenCalledWith(destino);
    }
  });

  it("nas pontas, o botão fica inativo sem perder o foco e o clique não faz nada", () => {
    for (const [passo, inativos] of [
      [0, ["Início", "◀ Anterior"]],
      [base.length, ["Próximo ▶", "Fim"]],
    ] as const) {
      const onMudar = vi.fn();
      const mapa = botoes(passo, onMudar);
      for (const texto of inativos) {
        expect(mapa.get(texto)!.props["aria-disabled"]).toBe(true);
        mapa.get(texto)!.props.onClick();
      }
      expect(onMudar).not.toHaveBeenCalled();
    }
    expect(renderToString(ControleDoReplay({ eventos: base, passo: 0, onMudar: () => {} }))).not.toContain("disabled=\"\"");
  });
});

describe("error boundary", () => {
  it("desenha de novo quando muda o incidente ou o passo", () => {
    const limite = new LimiteDeErro({ parte: "a fila", chave: "b", children: null });
    limite.state = { erro: new Error("falhou") };
    const setState = vi.spyOn(limite, "setState").mockImplementation(() => {});
    limite.componentDidUpdate({ parte: "a fila", chave: "b", children: null });
    expect(setState).not.toHaveBeenCalled();
    limite.componentDidUpdate({ parte: "a fila", chave: "a", children: null });
    expect(setState).toHaveBeenCalledWith({ erro: null });
  });

  it("mostra a parte que falhou, no lugar dela", () => {
    const limite = new LimiteDeErro({ parte: "a fila de incidentes", chave: "a", children: null });
    limite.state = LimiteDeErro.getDerivedStateFromError(new Error("falhou ao desenhar"));
    expect(textoDe(renderToString(limite.render() as ReactElement))).toContain("Não foi possível mostrar a fila de incidentes.falhou ao desenhar");
  });
});

describe("resumo", () => {
  it("o incidente marcado como já resolvido não conta como em acompanhamento", () => {
    const html = textoDe(renderToString(<ResumoMetricas resumo={final.resumo} incidentes={final.incidentes} />));
    const emAcompanhamento = final.incidentes.filter((view) => view.incidente.estado === "aberto" && !view.marcacao).length;
    expect(html).toContain(`${emAcompanhamento} em acompanhamento`);
    expect(final.incidentes.some((view) => view.incidente.estado === "aberto" && view.marcacao)).toBe(true);
  });
});
