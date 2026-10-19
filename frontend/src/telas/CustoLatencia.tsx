import {
  AGENT,
  AgentBadge,
  AreaChart,
  EmptyState,
  Icon,
  MetricCard,
  PageHeader,
  Panel,
  fmtDuration,
  fmtInt,
  fmtPct,
  ratioDown,
  type AgentName,
  type LogEvent,
  type ProviderLocation,
} from "../design-system";
import type { PropsDaTela } from "./replay";

interface Soma {
  chamadas: number;
  tokens: number;
  /** Latência média, em segundos. */
  latencia: number;
}

function somar(chamadas: LogEvent[]): Soma {
  const tokens = chamadas.reduce((soma, chamada) => soma + (chamada.tokens ?? 0), 0);
  const segundos = chamadas.reduce((soma, chamada) => soma + (chamada.seconds ?? 0), 0);
  return { chamadas: chamadas.length, tokens, latencia: chamadas.length > 0 ? segundos / chamadas.length : 0 };
}

function ondeRodaram(chamadas: LogEvent[]): string {
  const lugares = Array.from(new Set(chamadas.map((chamada) => chamada.location ?? "não informado")));
  return lugares.length > 0 ? lugares.join(" e ") : "sem chamadas";
}

/** Tela 4: tokens, latência e chamadas por agente, calculados das chamadas à IA do log até o cursor. */
export function TelaCustoLatencia({ replay }: PropsDaTela) {
  const { estado } = replay;
  const semLog = estado.total === 0;
  const chamadas = replay.linhas.filter((linha) => linha.type === "llm_chamada" && linha.n <= estado.passo);
  const todas = somar(chamadas);
  const porLugar = (lugar: ProviderLocation) => somar(chamadas.filter((chamada) => chamada.location === lugar));
  const local = porLugar("local");
  const nuvem = porLugar("nuvem");
  const agentes = (Object.keys(AGENT) as AgentName[]).map((agente) => {
    const doAgente = chamadas.filter((chamada) => chamada.agent === agente);
    return { agente, onde: ondeRodaram(doAgente), ...somar(doAgente) };
  });
  const evitadas = Math.max(0, estado.janelasDeAtaque - todas.chamadas);
  const comparacao = [
    { rotulo: "Tokens", local: local.tokens, nuvem: nuvem.tokens, formato: (valor: number) => fmtInt(valor) },
    { rotulo: "Latência média", local: local.latencia, nuvem: nuvem.latencia, formato: (valor: number) => fmtDuration(valor) },
    { rotulo: "Chamadas", local: local.chamadas, nuvem: nuvem.chamadas, formato: (valor: number) => fmtInt(valor) },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Telas do artigo · Tela 4"
        title="Custo e latência"
        meta={
          <span className="body-sm sx-muted">
            Tokens, tempo de resposta e chamadas à IA por agente, {semLog ? "tirados do log de eventos. Nenhum log carregado." : `até o evento ${estado.passo} de ${estado.total} do log.`}
          </span>
        }
      />
      <div className="sx-grid app-custo">
        <MetricCard
          className="sx-span-3"
          label="Tokens no log"
          value={todas.tokens}
          icon="coins"
          context={todas.chamadas > 0 ? `${fmtInt(todas.chamadas)} chamadas · ${fmtInt(todas.tokens / todas.chamadas)} por chamada` : "Nenhuma chamada à IA ainda."}
        />
        <MetricCard className="sx-span-3" label="Latência média" value={todas.chamadas > 0 ? fmtDuration(todas.latencia) : "–"} icon="timer" context="tempo de resposta de cada chamada à IA" />
        <MetricCard className="sx-span-3" label="Chamadas à IA" value={todas.chamadas} icon="brain-circuit" context={`${fmtInt(estado.incidentes.length)} ${estado.incidentes.length === 1 ? "incidente" : "incidentes"} no log até aqui`} />
        <MetricCard
          className="sx-span-3"
          label="Chamadas evitadas"
          value={evitadas}
          icon="trending-down"
          delta={todas.chamadas > 0 ? { text: `${fmtInt(ratioDown(estado.janelasDeAtaque, todas.chamadas))}× menos`, tone: "success" } : undefined}
          context="Uma chamada por janela de ataque, sem agregação."
        />
        <Panel className="sx-span-8 app-preencher" eyebrow="Por chamada" title="Tokens e latência ao longo do log">
          {chamadas.length > 1 ? (
            <AreaChart
              ariaLabel="Tokens e latência de cada chamada à IA ao longo do log"
              labels={chamadas.map((chamada) => chamada.at)}
              series={[
                { name: "Tokens", values: chamadas.map((chamada) => chamada.tokens ?? 0) },
                { name: "Latência (ms)", values: chamadas.map((chamada) => Math.round((chamada.seconds ?? 0) * 1000)) },
              ]}
              height="fill"
            />
          ) : (
            <EmptyState icon="chart-area" title={semLog ? "Nenhuma chamada à IA" : "Poucas chamadas para o gráfico"}>
              {semLog ? "O gráfico sai das chamadas à IA do log de eventos, e nenhum log foi carregado." : "Avance o replay: o gráfico aparece a partir da segunda chamada à IA."}
            </EmptyState>
          )}
        </Panel>
        <Panel className="sx-span-4 app-preencher" eyebrow="Onde roda" title="Local × nuvem">
          {local.chamadas > 0 && nuvem.chamadas > 0 ? (
            <div className="sx-stack sx-stack--sm">
              {comparacao.map((medida) => {
                const maior = Math.max(medida.local, medida.nuvem) || 1;
                return (
                  <div key={medida.rotulo} className="sx-stack app-medida">
                    <span className="sx-eyebrow eyebrow">{medida.rotulo}</span>
                    <div className="sx-compare">
                      <span className="body-sm">Local</span>
                      <span className="sx-compare__bar"><span style={{ width: `${(medida.local / maior) * 100}%` }} /></span>
                      <span className="data">{medida.formato(medida.local)}</span>
                      <span className="body-sm">Nuvem</span>
                      <span className="sx-compare__bar is-cloud"><span style={{ width: `${(medida.nuvem / maior) * 100}%` }} /></span>
                      <span className="data">{medida.formato(medida.nuvem)}</span>
                    </div>
                  </div>
                );
              })}
              <span className="body-sm sx-muted app-linha-com-icone"><Icon name="eye-off" size={14} />A nuvem só recebe rótulos neutros.</span>
            </div>
          ) : (
            <EmptyState icon="cloud-off" title="Sem chamadas dos dois lados">
              O log não diz onde cada modelo roda. Liste os modelos em VITE_MODELOS_LOCAIS e VITE_MODELOS_NA_NUVEM para comparar local e nuvem.
            </EmptyState>
          )}
        </Panel>
        <Panel className="sx-span-12" eyebrow="Por agente" title="Quem gastou o quê" flush>
          <div className="sx-tablewrap">
            <table className="sx-table">
              <thead>
                <tr>
                  <th scope="col">Agente</th>
                  <th scope="col">Onde</th>
                  <th scope="col" className="is-num">Chamadas</th>
                  <th scope="col" className="is-num">Tokens</th>
                  <th scope="col" className="is-num">Latência média</th>
                  <th scope="col" className="is-num">Parte dos tokens</th>
                </tr>
              </thead>
              <tbody>
                {agentes.map((linha) => (
                  <tr key={linha.agente}>
                    <td><AgentBadge agent={linha.agente} /></td>
                    <td className="data">{linha.onde}</td>
                    <td className="is-num data">{fmtInt(linha.chamadas)}</td>
                    <td className="is-num data">{fmtInt(linha.tokens)}</td>
                    <td className="is-num data">{linha.chamadas > 0 ? fmtDuration(linha.latencia) : "–"}</td>
                    <td className="is-num data">{todas.tokens > 0 ? fmtPct(linha.tokens / todas.tokens) : "–"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </>
  );
}
