import { Fragment, useEffect, useLayoutEffect, useRef, useState, type ReactElement, type ReactNode } from "react";
import { detalheDoIncidente, type DetalheDoIncidente } from "../adaptador";
import { instanteEmMs } from "../contrato";
import {
  ASSETS,
  AddressList,
  Button,
  CATEGORY,
  CategoryBars,
  ClassifierVerdict,
  EVENT,
  EmptyState,
  FeatureTable,
  Icon,
  PageHeader,
  ReportCover,
  ReportFacts,
  ReportPage,
  ReportSection,
  RiskBadge,
  StatusBadge,
  VERDICT,
  VoiceQuote,
  cx,
  fmtConfidence,
  fmtInt,
  fmtPct,
  type AgentName,
} from "../design-system";
import { paginar, paginarSemMedida, type SecaoMedida, type Trecho } from "../paginacao";
import { AVISO_DO_EFEITO } from "./comum";
import { incidenteEscolhido } from "./Incidente";
import type { PropsDaTela } from "./replay";

// No Node, onde os testes desenham a tela, não há como medir: o relatório sai no plano sem medida.
// No navegador, o efeito de layout mede as seções antes de a página aparecer.
const NO_NAVEGADOR = typeof window !== "undefined";
const useEfeitoDeLayout = NO_NAVEGADOR ? useLayoutEffect : useEffect;

/** A data do instante no fuso de quem abre a página, como `2026-10-20` (o mesmo fuso das horas). */
function dataIso(instante: string): string {
  const ms = instanteEmMs(instante);
  if (!Number.isFinite(ms)) {
    return instante.slice(0, 10);
  }
  const data = new Date(ms);
  const dois = (valor: number) => String(valor).padStart(2, "0");
  return `${data.getFullYear()}-${dois(data.getMonth() + 1)}-${dois(data.getDate())}`;
}

// O ponto entre um endereço e os quadros dele: a linha pode quebrar antes do ponto, e o número não
// se separa dele.
const SEPARADOR = " ·\u00a0";

/** Uma seção do relatório: o cabeçalho numerado e as peças, que não se cortam entre páginas. */
interface Secao {
  n: string;
  titulo: string;
  voz?: "system" | "agent";
  agente?: AgentName;
  /** As peças são blocos (tabelas, listas, citações), com um intervalo entre eles. */
  blocos?: boolean;
  /** No plano sem medida, a seção abre uma página. */
  novaPagina?: boolean;
  /** Cada peça desenha um elemento só: é por ele que a página escondida mede a peça. */
  pecas: ReactElement[];
}

/**
 * O texto de um agente em linhas, cada uma uma peça, para que um texto longo continue na página
 * seguinte. As linhas de um parágrafo ficam juntas; a linha em branco separa os parágrafos. `antes`
 * vai no começo da primeira linha.
 */
function linhasDoTexto(texto: string, chave: string, antes?: ReactNode, classeDaPrimeira?: string): ReactElement[] {
  const linhas = texto.split("\n").map((linha) => linha.trim());
  const pecas: ReactElement[] = [];
  linhas.forEach((linha, indice) => {
    if (!linha) {
      return;
    }
    const primeira = pecas.length === 0;
    pecas.push(
      <p key={`${chave}-${indice}`} className={cx(Boolean(linhas[indice + 1]) && "app-linha", primeira && classeDaPrimeira) || undefined}>
        {primeira && antes}
        {linha}
      </p>,
    );
  });
  return pecas;
}

/** O texto de um agente dentro de uma citação: as quebras de linha ficam, e as linhas em branco somem. */
function comQuebras(texto: string): ReactNode {
  const linhas = texto.split("\n").map((linha) => linha.trim()).filter(Boolean);
  return linhas.map((linha, indice) => (
    <Fragment key={indice}>
      {indice > 0 && <br />}
      {linha}
    </Fragment>
  ));
}

/** Um bloco com um rótulo em cima: uma peça só. */
function Bloco({ rotulo, children }: { rotulo: string; children: ReactNode }) {
  return (
    <div className="sx-stack sx-stack--sm">
      <span className="sx-eyebrow eyebrow">{rotulo}</span>
      {children}
    </div>
  );
}

/** O endereço com o rótulo neutro em cima, quebrando onde precisar: um IPv6 não é cortado no papel. */
function Endereco({ rotulo, endereco }: { rotulo?: string; endereco: string }) {
  return (
    <span className="app-empilhado">
      {rotulo && rotulo !== endereco && <span className="data">{rotulo}</span>}
      <span className="data-sm sx-muted app-quebra">{endereco}</span>
    </span>
  );
}

function secoesDoRelatorio(detalhe: DetalheDoIncidente, sumarioAdiante: boolean, efeitoSimulado: boolean): Secao[] {
  const { incidente, atacante } = detalhe;
  const marcaDoAtacante = atacante ? { address: atacante.address, label: "atacante", icon: EVENT.atacante_apontado.icon } : undefined;

  const sumario: Secao = detalhe.sumario
    ? { n: "01", titulo: "Sumário", voz: "agent", agente: "triagem", pecas: linhasDoTexto(detalhe.sumario.text, "sumario") }
    : {
        n: "01",
        titulo: "Sumário",
        pecas: [<p key="sem">{sumarioAdiante ? "O sumário ainda não foi escrito neste ponto do replay." : "O sumário não foi escrito nesta execução."}</p>],
      };

  const fatos: Secao = {
    n: "02",
    titulo: "Fatos do log",
    pecas: [
      <ReportFacts
        key="fatos"
        items={[
          { label: "Janelas", value: fmtInt(incidente.windows) },
          { label: "Período", value: `${incidente.start}–${incidente.end}` },
          { label: "Confiança", value: fmtConfidence(incidente.confidence) },
          { label: "Origens", value: fmtInt(incidente.sources) },
          { label: "Chamadas à IA", value: fmtInt(detalhe.chamadas) },
          { label: "Tokens", value: fmtInt(detalhe.tokens) },
        ]}
      />,
    ],
  };

  const classificador: Secao = {
    n: "03",
    titulo: "O que o classificador viu",
    blocos: true,
    novaPagina: true,
    pecas: [
      <ClassifierVerdict key="veredito" model={incidente.modelCategory} category={incidente.category} sources={incidente.sources} confidence={incidente.confidence} />,
      <Bloco key="janelas" rotulo="Janelas por categoria">
        {detalhe.janelasPorCategoria.length > 0 ? (
          <CategoryBars data={detalhe.janelasPorCategoria} showShare ariaLabel="Janelas do incidente por categoria do modelo" />
        ) : (
          <p>O log deste incidente não traz as janelas por categoria.</p>
        )}
      </Bloco>,
      <Bloco key="features" rotulo="Features que mais pesaram, contra o tráfego benigno">
        {detalhe.features.length > 0 ? <FeatureTable rows={detalhe.features} /> : <p>O log não trouxe features para este incidente.</p>}
      </Bloco>,
      <AddressList key="origens" title="Origens" items={detalhe.origens} total={incidente.sources} mark={marcaDoAtacante} />,
      <AddressList key="destinos" title="Destinos" items={detalhe.destinos} total={incidente.destinations} />,
      <Bloco key="portas" rotulo="Portas mais atacadas">
        {detalhe.portas && detalhe.portas.length > 0 ? (
          <table className="sx-rtable">
            <thead>
              <tr>
                <th>Porta</th>
                <th>Destino</th>
                <th className="app-num">Quadros</th>
              </tr>
            </thead>
            <tbody>
              {detalhe.portas.map((porta) => (
                <tr key={`${porta.destination.address}-${porta.port}-${porta.protocol}`}>
                  <td className="data">
                    {porta.port}/{porta.protocol}
                  </td>
                  <td>
                    <Endereco rotulo={porta.destination.label} endereco={porta.destination.address} />
                  </td>
                  <td className="data app-num">{fmtInt(porta.frames)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>{detalhe.portas ? "Nenhuma porta de TCP ou de UDP no incidente." : "O log deste incidente não traz as portas."}</p>
        )}
      </Bloco>,
    ],
  };

  const triagem: Secao = {
    n: "04",
    titulo: "Triagem",
    blocos: true,
    novaPagina: true,
    pecas: [
      <ReportFacts
        key="fatos"
        items={[
          { label: "Veredito", value: detalhe.veredito ? VERDICT[detalhe.veredito] : "não informado" },
          {
            label: "Atacante apontado",
            value: atacante ? (
              <>
                {atacante.label} <span className="data-sm sx-muted app-quebra">{atacante.address}</span>
              </>
            ) : (
              "nenhum atacante apontado"
            ),
          },
          { label: "Candidatos", value: detalhe.candidatos ? fmtInt(detalhe.candidatos.length) : "não informado" },
        ]}
      />,
      ...(atacante
        ? [
            <Bloco key="justificativa" rotulo={`Por que a triagem apontou ${atacante.label}`}>
              <VoiceQuote voice="agent" agent="triagem" author={atacante.model} refId={atacante.id} at={atacante.at}>
                {atacante.justification}
              </VoiceQuote>
            </Bloco>,
          ]
        : []),
      detalhe.analise ? (
        <Bloco key="analise" rotulo="Análise da triagem">
          <VoiceQuote voice="agent" agent="triagem" author={detalhe.analise.model} refId={detalhe.analise.id} at={detalhe.analise.at}>
            {comQuebras(detalhe.analise.text)}
          </VoiceQuote>
        </Bloco>
      ) : (
        <p key="analise">Nenhuma análise da triagem no log.</p>
      ),
      <Bloco key="candidatos" rotulo="Candidatos a atacante">
        {detalhe.candidatos && detalhe.candidatos.length > 0 ? (
          <table className="sx-rtable">
            <thead>
              <tr>
                <th className="app-coluna-candidato">Candidato</th>
                <th className="app-num">Janelas</th>
                <th className="app-num">Tráfego normal</th>
                <th className="app-num">Quadros enviados</th>
                <th className="app-num">Conexões abertas</th>
                <th>Destinos e portas</th>
              </tr>
            </thead>
            <tbody>
              {detalhe.candidatos.map((candidato, indice) => (
                <tr key={`${candidato.address}-${indice}`}>
                  <td>
                    <span className="app-empilhado">
                      <Endereco rotulo={candidato.label} endereco={candidato.address} />
                      {candidato.pointed && (
                        <span className="data-sm app-gelo app-linha-com-icone">
                          <Icon name={EVENT.atacante_apontado.icon} size={12} />
                          apontado
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="data app-num">{fmtInt(candidato.windows)}</td>
                  <td className="data app-num">{fmtPct(candidato.normalShare, 1)}</td>
                  <td className="app-num">
                    <span className="app-empilhado">
                      <span className="data">{fmtInt(candidato.framesSent)}</span>
                      <span className="data-sm sx-muted">{fmtInt(candidato.framesReceived)} recebidos</span>
                    </span>
                  </td>
                  <td className="app-num">
                    <span className="app-empilhado">
                      <span className="data">{fmtInt(candidato.connectionsOpened)}</span>
                      <span className="data-sm sx-muted">{fmtInt(candidato.connectionsReceived)} recebidas</span>
                    </span>
                  </td>
                  <td>
                    <span className="app-empilhado data-sm">
                      {candidato.destinations.map((destino) => (
                        <span key={destino.address}>
                          <span className="app-quebra">{destino.label ?? destino.address}</span>
                          {SEPARADOR}
                          {fmtInt(destino.frames)}
                        </span>
                      ))}
                      {candidato.ports.map((porta) => (
                        <span key={`${porta.port}/${porta.protocol}`} className="sx-muted">
                          {porta.port}/{porta.protocol}
                          {SEPARADOR}
                          {fmtInt(porta.frames)}
                        </span>
                      ))}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>
            {detalhe.candidatos
              ? "Nenhuma origem se destaca do tráfego normal: o incidente não tem candidatos a atacante."
              : "O log deste incidente não traz candidatos a atacante."}
          </p>
        )}
      </Bloco>,
    ],
  };

  const acoes: Secao = {
    n: "05",
    titulo: "Ações",
    novaPagina: true,
    pecas: [
      detalhe.propostasNaOrdem.length > 0 ? (
        <table key="acoes" className="sx-rtable">
          <thead>
            <tr>
              <th>Id</th>
              <th>Ação</th>
              <th>Risco</th>
              <th>Resultado</th>
            </tr>
          </thead>
          <tbody>
            {detalhe.propostasNaOrdem.map((proposta) => (
              <tr key={proposta.id}>
                <td className="data-sm sx-muted">{proposta.id}</td>
                <td>
                  <span className="data">{proposta.action}</span> <span className="data-sm sx-muted">{proposta.target.free ? "alvo descrito pelo agente" : proposta.target.label}</span>
                </td>
                <td>
                  <RiskBadge level={proposta.risk} size="sm" />
                </td>
                <td>
                  <span className="sx-row app-celula">
                    <StatusBadge kind="proposal" value={proposta.state} size="sm" />
                    {proposta.effect && <StatusBadge kind="effect" value={proposta.effect.result} size="sm" />}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p key="acoes">Nenhuma ação foi proposta.</p>
      ),
      ...(efeitoSimulado ? [<p key="ressalva-do-efeito" className="body-sm sx-muted">{AVISO_DO_EFEITO}</p>] : []),
    ],
  };

  // O selo da seção diz o agente só quando todas as recomendações são do mesmo.
  const agentes = Array.from(new Set(detalhe.recomendacoes.map((recomendacao) => recomendacao.agent)));
  const recomendacoes: Secao =
    detalhe.recomendacoes.length > 0
      ? {
          n: "06",
          titulo: "Recomendações",
          voz: "agent",
          agente: agentes.length === 1 ? agentes[0] : undefined,
          pecas: detalhe.recomendacoes.flatMap((recomendacao, indice) =>
            linhasDoTexto(
              recomendacao.text,
              recomendacao.id,
              <span className="data-sm sx-muted app-hora">
                {recomendacao.at}
                {recomendacao.propostas.length > 0 && ` · ${recomendacao.propostas.join(", ")}`}
              </span>,
              indice > 0 ? "app-novo-texto" : undefined,
            ),
          ),
        }
      : { n: "06", titulo: "Recomendações", pecas: [<p key="sem">Nenhuma recomendação no log.</p>] };

  const marcacao = detalhe.marcacao;
  const decisoes: Secao = {
    n: "07",
    titulo: "Decisões humanas",
    blocos: true,
    pecas: [
      ...detalhe.decididas.map((proposta) => {
        const decisao = proposta.decision!;
        return (
          <div key={proposta.id} className="sx-stack sx-stack--sm">
            <p className="body app-nota">
              <span className="data">{proposta.id}</span> <span className="data">{proposta.action}</span> {decisao.kind}{" "}
              {decisao.channel === "terminal" ? "pelo terminal" : "pela interface"}, por {decisao.user}, às {decisao.at}
              {decisao.reason ? ":" : ", sem motivo escrito."}
            </p>
            {decisao.reason && (
              <VoiceQuote voice="person" author={decisao.user} channel={decisao.channel} refId={proposta.id} at={decisao.at}>
                {decisao.reason}
              </VoiceQuote>
            )}
          </div>
        );
      }),
      ...(marcacao
        ? [
            marcacao.reason ? (
              <VoiceQuote key="marcacao" voice="person" author={marcacao.user} channel={marcacao.channel} refId={incidente.id} at={marcacao.at}>
                {marcacao.reason}
              </VoiceQuote>
            ) : (
              <p key="marcacao" className="body">
                <span className="data">{incidente.id}</span> marcado como já resolvido por {marcacao.user}, às {marcacao.at}, sem motivo escrito.
              </p>
            ),
          ]
        : []),
    ],
  };
  if (decisoes.pecas.length === 0) {
    decisoes.pecas.push(<p key="sem" className="body">Nenhuma decisão humana neste incidente.</p>);
  }
  return [sumario, fatos, classificador, triagem, acoes, recomendacoes, decisoes];
}

/** As seções medidas na página escondida, ou null quando não dá para medir (nada desenhado ainda). */
function medir(raiz: HTMLElement, secoes: Secao[]): { secoes: SecaoMedida[]; altura: number; intervalo: number } | null {
  const corpo = raiz.querySelector<HTMLElement>(".sx-rpage__body");
  if (!corpo || corpo.children.length !== secoes.length) {
    return null;
  }
  const estilo = getComputedStyle(corpo);
  // Um pixel de folga para os arredondamentos: a página corta o que passa da borda.
  const altura = Math.floor(corpo.clientHeight - parseFloat(estilo.paddingTop) - parseFloat(estilo.paddingBottom)) - 1;
  const medidas: SecaoMedida[] = [];
  for (const [indice, secao] of Array.from(corpo.children).entries()) {
    const caixa = secao.getBoundingClientRect();
    const pecas = Array.from(secao.querySelector(":scope > .sx-rsec__body")?.children ?? []).map((peca) => {
      const medida = peca.getBoundingClientRect();
      return { topo: medida.top - caixa.top, fundo: medida.bottom - caixa.top };
    });
    if (pecas.length !== secoes[indice].pecas.length || caixa.height <= 0) {
      return null;
    }
    medidas.push({ altura: caixa.height, pecas });
  }
  return altura > 0 ? { secoes: medidas, altura, intervalo: parseFloat(estilo.rowGap) || 0 } : null;
}

function SecaoDoRelatorio({ secao, de, ate }: { secao: Secao; de: number; ate: number }) {
  return (
    <ReportSection
      n={secao.n}
      title={de > 0 ? `${secao.titulo} (continuação)` : secao.titulo}
      voice={secao.voz}
      agent={secao.agente}
      className={secao.blocos ? "app-blocos" : undefined}
    >
      {secao.pecas.slice(de, ate)}
    </ReportSection>
  );
}

/**
 * As páginas internas do relatório. O conteúdo varia (o texto de um agente vai até 2.000
 * caracteres), e a página A4 corta o que passa da borda: por isso cada seção é medida numa página
 * escondida, com as mesmas fontes e larguras, e as páginas quebram entre as peças. A medida se
 * refaz a cada desenho e quando uma fonte termina de carregar. A capa é a página 1.
 */
function PaginasDoRelatorio({ secoes, titulo, data }: { secoes: Secao[]; titulo: string; data: string }) {
  const medida = useRef<HTMLDivElement>(null);
  const [plano, setPlano] = useState<Trecho[][] | null>(null);
  const [, setFontes] = useState(0);
  useEffect(() => {
    const fontes = document.fonts;
    if (!fontes) {
      return;
    }
    let viva = true;
    const medirDeNovo = () => viva && setFontes((vez) => vez + 1);
    fontes.addEventListener("loadingdone", medirDeNovo);
    void fontes.ready.then(medirDeNovo);
    return () => {
      viva = false;
      fontes.removeEventListener("loadingdone", medirDeNovo);
    };
  }, []);
  useEfeitoDeLayout(() => {
    const medidas = medida.current && medir(medida.current, secoes);
    const novo = medidas ? paginar(medidas.secoes, medidas.altura, medidas.intervalo) : null;
    setPlano((atual) => (JSON.stringify(atual) === JSON.stringify(novo) ? atual : novo));
  });

  const paginas = plano ?? paginarSemMedida(secoes);
  const total = paginas.length + 1;
  return (
    <>
      {paginas.map((trechos, indice) => (
        <ReportPage key={indice} logoSrc={ASSETS.mark128} docTitle={titulo} date={data} page={indice + 2} pages={total}>
          {trechos.map(({ secao, de, ate }) => (
            <SecaoDoRelatorio key={`${secao}-${de}`} secao={secoes[secao]} de={de} ate={ate} />
          ))}
        </ReportPage>
      ))}
      {NO_NAVEGADOR && (
        <div ref={medida} className="app-relatorio-medida" aria-hidden="true">
          <ReportPage logoSrc={ASSETS.mark128} docTitle={titulo} date={data} page={2} pages={total}>
            {secoes.map((secao, indice) => (
              <SecaoDoRelatorio key={indice} secao={secao} de={0} ate={secao.pecas.length} />
            ))}
          </ReportPage>
        </div>
      )}
    </>
  );
}

/**
 * O relatório do incidente em A4: capa, sumário, fatos do log, o que o classificador viu, a
 * triagem, ações, recomendações e decisões humanas, tudo tirado do log até o cursor. O texto dos
 * agentes (sumário, análise, justificativa do atacante, recomendações) aparece na voz deles.
 */
export function TelaRelatorio(props: PropsDaTela & { incidente: string | null; efeitoSimulado?: boolean }) {
  const { replay } = props;
  const id = incidenteEscolhido(props, props.incidente);
  const detalhe = id ? detalheDoIncidente(replay.estado, replay.final, replay.linhas, id) : null;
  const cabecalho = (
    <PageHeader
      eyebrow={id ? `Relatórios / ${id}` : "Relatórios"}
      title="Relatório de incidente"
      meta={
        <span className="body-sm sx-muted">
          {replay.estado.total === 0 ? "Nenhum log de eventos carregado." : `Gerado do log até o evento ${replay.estado.passo} de ${replay.estado.total}. Imprima em A4, sem margens.`}
        </span>
      }
      actions={
        <>
          {detalhe && (
            <Button variant="ghost" icon="arrow-left-right" onClick={() => props.navegar({ tela: "incidente", incidente: detalhe.incidente.id })}>
              Abrir o incidente
            </Button>
          )}
          <Button variant="primary" icon="printer" disabled={!detalhe} onClick={() => window.print()}>
            Imprimir
          </Button>
        </>
      }
    />
  );
  if (!detalhe) {
    return (
      <>
        {cabecalho}
        <EmptyState icon="file-text" title="Nenhum incidente para relatar">
          {replay.estado.total === 0 ? "O relatório sai do log de eventos, e nenhum log foi carregado." : "Avance o replay até um incidente aberto, ou escolha um na fila."}
        </EmptyState>
      </>
    );
  }

  const { incidente, view, atacante } = detalhe;
  const destino = detalhe.destinos[0];
  const data = dataIso(view.incidente.inicio);
  // O sumário sai no fim do orquestrador: num ponto do replay anterior a ele, ainda não foi escrito.
  const sumarioAdiante = !detalhe.sumario && Boolean(replay.final.incidentes.find((item) => item.id === incidente.id)?.sumario);
  return (
    <>
      {cabecalho}
      <div className="app-relatorio">
        <ReportCover
          logoSrc={ASSETS.mark128}
          heroSrc={ASSETS.mark}
          eyebrow="Resposta autônoma a intrusão"
          title={
            <>
              {incidente.id} · {incidente.category ?? incidente.modelCategory}
              {destino ? ` contra ${destino.label}` : ""}
            </>
          }
          meta={[
            { icon: "flag", label: "Incidente", value: incidente.id },
            {
              icon: CATEGORY[incidente.category ?? incidente.modelCategory].icon,
              label: "Categoria",
              value: (
                <>
                  {incidente.category ?? incidente.modelCategory} <span className="body sx-muted">· modelo {incidente.modelCategory} · {fmtPct(incidente.confidence)}</span>
                </>
              ),
            },
            { icon: "file-text", label: "ID do relatório", value: `SNT-${data.slice(0, 4)}-${incidente.id.replace(/[^A-Za-z0-9]/g, "").toUpperCase()}` },
            {
              icon: "target",
              label: "Alvo",
              value: destino ? (
                <>
                  {destino.label} <span className="data sx-muted">{destino.address}</span>
                </>
              ) : (
                "sem destino no log"
              ),
            },
            ...(atacante
              ? [
                  {
                    icon: EVENT.atacante_apontado.icon,
                    label: "Origem apontada",
                    value: (
                      <>
                        {atacante.label} <span className="data sx-muted app-quebra">{atacante.address}</span>
                      </>
                    ),
                  },
                ]
              : []),
          ]}
          date={data}
          mode="Modo replay"
        />
        <PaginasDoRelatorio secoes={secoesDoRelatorio(detalhe, sumarioAdiante, props.efeitoSimulado ?? false)} titulo={`Relatório de incidente · ${incidente.id}`} data={data} />
      </div>
    </>
  );
}
