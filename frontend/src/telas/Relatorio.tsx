import { detalheDoIncidente } from "../adaptador";
import { instanteEmMs } from "../contrato";
import {
  ASSETS,
  Button,
  CATEGORY,
  EmptyState,
  PageHeader,
  ReportCover,
  ReportFacts,
  ReportPage,
  ReportSection,
  RiskBadge,
  StatusBadge,
  VoiceQuote,
  fmtConfidence,
  fmtInt,
  fmtPct,
} from "../design-system";
import { Planejada } from "./comum";
import { incidenteEscolhido } from "./Incidente";
import type { PropsDaTela } from "./replay";

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

/**
 * O relatório do incidente em A4: capa, fatos do log, ações, recomendações e decisões humanas, tudo
 * tirado do log até o cursor. O sumário escrito pela IA no fim do incidente é planejado: o lugar
 * dele está na primeira página, e o texto entra quando o agente passar a escrevê-lo no log.
 */
export function TelaRelatorio(props: PropsDaTela & { incidente: string | null }) {
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

  const { incidente, view } = detalhe;
  const destino = detalhe.destinos[0];
  const data = dataIso(view.incidente.inicio);
  const titulo = `Relatório de incidente · ${incidente.id}`;
  const decisoes = detalhe.propostas.filter((proposta) => proposta.decision);
  // O selo da seção diz o agente só quando todas as recomendações são do mesmo.
  const agentes = Array.from(new Set(detalhe.recomendacoes.map((recomendacao) => recomendacao.agent)));
  const paginas = 3;
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
          ]}
          date={data}
          mode="Modo replay"
        />
        <ReportPage logoSrc={ASSETS.mark128} docTitle={titulo} date={data} page={2} pages={paginas}>
          <ReportSection n="01" title="Sumário">
            <p className="app-planejado">
              <Planejada />O agente de triagem escreve este sumário a partir do log quando o incidente termina. Enquanto isso não existe, o relatório traz só os fatos do log e
              os textos que os agentes e as pessoas já escreveram.
            </p>
          </ReportSection>
          <ReportSection n="02" title="Fatos do log">
            <ReportFacts
              items={[
                { label: "Janelas", value: fmtInt(incidente.windows) },
                { label: "Período", value: `${incidente.start}–${incidente.end}` },
                { label: "Confiança", value: fmtConfidence(incidente.confidence) },
                { label: "Origens", value: fmtInt(incidente.sources) },
                { label: "Chamadas à IA", value: fmtInt(detalhe.chamadas) },
                { label: "Tokens", value: fmtInt(detalhe.tokens) },
              ]}
            />
          </ReportSection>
          <ReportSection n="03" title="Ações">
            {detalhe.propostas.length > 0 ? (
              <table className="sx-rtable">
                <thead>
                  <tr>
                    <th>Id</th>
                    <th>Ação</th>
                    <th>Risco</th>
                    <th>Resultado</th>
                  </tr>
                </thead>
                <tbody>
                  {detalhe.propostas.map((proposta) => (
                    <tr key={proposta.id}>
                      <td className="data-sm sx-muted">{proposta.id}</td>
                      <td>
                        <span className="data">{proposta.action}</span> <span className="data-sm sx-muted">{proposta.target.free ? "alvo descrito pelo agente" : proposta.target.label}</span>
                      </td>
                      <td><RiskBadge level={proposta.risk} size="sm" /></td>
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
              <p>Nenhuma ação foi proposta.</p>
            )}
          </ReportSection>
        </ReportPage>
        <ReportPage logoSrc={ASSETS.mark128} docTitle={titulo} date={data} page={3} pages={paginas}>
          <ReportSection n="04" title="Recomendações" voice="agent" agent={agentes.length === 1 ? agentes[0] : undefined}>
            {detalhe.recomendacoes.length > 0 ? (
              detalhe.recomendacoes.map((recomendacao) => (
                <p key={recomendacao.id}>
                  <span className="data-sm sx-muted app-hora">{recomendacao.at}</span> {recomendacao.text}
                </p>
              ))
            ) : (
              <p>Nenhuma recomendação no log.</p>
            )}
          </ReportSection>
          <ReportSection n="05" title="Decisões humanas">
            <div className="sx-stack sx-stack--sm">
              {decisoes.map((proposta) => {
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
              })}
              {detalhe.marcacao &&
                (detalhe.marcacao.reason ? (
                  <VoiceQuote voice="person" author={detalhe.marcacao.user} channel={detalhe.marcacao.channel} refId={incidente.id} at={detalhe.marcacao.at}>
                    {detalhe.marcacao.reason}
                  </VoiceQuote>
                ) : (
                  <p className="body">
                    <span className="data">{incidente.id}</span> marcado como já resolvido por {detalhe.marcacao.user}, às {detalhe.marcacao.at}, sem motivo escrito.
                  </p>
                ))}
              {decisoes.length === 0 && !detalhe.marcacao && <p className="body">Nenhuma decisão humana neste incidente.</p>}
            </div>
          </ReportSection>
        </ReportPage>
      </div>
    </>
  );
}
