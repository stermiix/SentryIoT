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
} from "../design-system";
import type { ContextoDaRodada } from "../rodada";
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

function modelosDe(chamadas: LogEvent[]): string {
  return Array.from(new Set(chamadas.map((chamada) => chamada.model).filter((modelo): modelo is string => Boolean(modelo)))).join(", ");
}

/** O grupo da rodada final da execução aberta, por agente: as medianas por execução, das medidas do grupo inteiro. */
function NaRodada({ rodada }: { rodada: ContextoDaRodada }) {
  const { grupo, indice } = rodada;
  const { resumo } = grupo;
  // Tudo na mesma base, a das execuções sem erro (as de `por_agente`): a parte de cada agente e o total.
  const tokens = resumo.por_agente.reduce((soma, linha) => soma + linha.tokens_entrada + linha.tokens_saida, 0);
  const chamadas = resumo.por_agente.reduce((soma, linha) => soma + linha.chamadas, 0);
  return (
    <Panel
      className="sx-span-12"
      eyebrow={`Rodada final · ${fmtInt(resumo.execucoes - resumo.com_erro)} ${resumo.execucoes - resumo.com_erro === 1 ? "execução" : "execuções"} sem erro`}
      title={`${grupo.titulo}: por agente`}
      flush
      footer={
        <span className="body-sm sx-muted">
          As {fmtInt(chamadas)} chamadas dessas execuções rodaram no modelo local ({indice.modelos.join(", ")}): nenhuma foi à nuvem, e o custo de nuvem é US$ 0,00. A
          mediana é por execução em que o agente rodou, contada na coluna Execuções; o agente de execução só roda depois de uma proposta liberada.
        </span>
      }
    >
      <div className="sx-tablewrap">
        <table className="sx-table">
          <thead>
            <tr>
              <th scope="col">Agente</th>
              <th scope="col" className="is-num">Execuções</th>
              <th scope="col" className="is-num">Chamadas</th>
              <th scope="col" className="is-num">Tokens (mediana)</th>
              <th scope="col" className="is-num">Tempo de modelo (mediana)</th>
              <th scope="col" className="is-num">Parte dos tokens</th>
            </tr>
          </thead>
          <tbody>
            {resumo.por_agente.map((linha) => (
              <tr key={linha.agente}>
                <td><AgentBadge agent={linha.agente} location="local" /></td>
                <td className="is-num data">{fmtInt(linha.execucoes)}</td>
                <td className="is-num data">{fmtInt(linha.chamadas)}</td>
                <td className="is-num data">{linha.mediana_tokens === null ? "–" : fmtInt(linha.mediana_tokens)}</td>
                <td className="is-num data">{linha.mediana_llm_s === null ? "–" : fmtDuration(linha.mediana_llm_s)}</td>
                <td className="is-num data">{tokens > 0 ? fmtPct((linha.tokens_entrada + linha.tokens_saida) / tokens) : "–"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

/** Onde as chamadas à IA rodaram, até o cursor. Só local: o número, o modelo e o custo de nuvem zero. Local e nuvem: a comparação. */
function OndeRodou({ chamadas, semLog }: { chamadas: LogEvent[]; semLog: boolean }) {
  const local = somar(chamadas.filter((chamada) => chamada.location === "local"));
  const nuvem = somar(chamadas.filter((chamada) => chamada.location === "nuvem"));
  const semLugar = chamadas.filter((chamada) => !chamada.location).length;
  const comparacao = [
    { rotulo: "Tokens", local: local.tokens, nuvem: nuvem.tokens, formato: (valor: number) => fmtInt(valor) },
    { rotulo: "Latência média", local: local.latencia, nuvem: nuvem.latencia, formato: (valor: number) => fmtDuration(valor) },
    { rotulo: "Chamadas", local: local.chamadas, nuvem: nuvem.chamadas, formato: (valor: number) => fmtInt(valor) },
  ];
  if (chamadas.length === 0) {
    return (
      <EmptyState icon="cpu" title="Nenhuma chamada à IA">
        {semLog ? "O lugar de cada chamada sai do log de eventos, e nenhum log foi carregado." : "Avance o replay até a primeira chamada à IA."}
      </EmptyState>
    );
  }
  const notaSemLugar =
    semLugar > 0 ? (
      <p className="body-sm sx-muted app-nota">
        {fmtInt(semLugar)} {semLugar === 1 ? "chamada não diz" : "chamadas não dizem"} onde rodou: o log é anterior ao contrato 0.5.0.
      </p>
    ) : null;
  if (local.chamadas > 0 && nuvem.chamadas > 0) {
    return (
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
        {notaSemLugar}
      </div>
    );
  }
  if (local.chamadas === 0 && nuvem.chamadas === 0) {
    return (
      <EmptyState icon="cloud-off" title="Sem o lugar das chamadas">
        O log não diz onde cada modelo roda. Ele é anterior ao contrato 0.5.0: liste os modelos em VITE_MODELOS_LOCAIS e VITE_MODELOS_NA_NUVEM para a tela saber.
      </EmptyState>
    );
  }
  const lugar = local.chamadas > 0 ? "local" : "nuvem";
  const doLugar = chamadas.filter((chamada) => chamada.location === lugar);
  return (
    <div className="sx-stack sx-stack--sm">
      <div className="sx-row app-base">
        <span className="sx-bignum display-lg">{fmtInt(doLugar.length)}</span>
        <span className="body-lg sx-muted">{doLugar.length === 1 ? "chamada" : "chamadas"} no modelo {lugar === "local" ? "local" : "da nuvem"}</span>
      </div>
      <dl className="sx-kv body">
        <dt>Modelo</dt>
        <dd className="data">{modelosDe(doLugar) || "não informado"}</dd>
        <dt>{lugar === "nuvem" ? "No modelo local" : "Na nuvem"}</dt>
        <dd>nenhuma chamada</dd>
        {lugar !== "nuvem" && (
          <>
            <dt>Custo de nuvem</dt>
            <dd className="data">US$ 0,00</dd>
          </>
        )}
      </dl>
      {lugar === "local" && <p className="body-sm sx-muted app-nota">Os experimentos rodam só no modelo local. O código aceita as configurações com a decisão na nuvem, que não foram avaliadas.</p>}
      {notaSemLugar}
    </div>
  );
}

/** Tela 4: tokens, latência e chamadas por agente, calculados das chamadas à IA do log até o cursor. */
export function TelaCustoLatencia({ replay, rodada = null }: PropsDaTela) {
  const { estado } = replay;
  const semLog = estado.total === 0;
  const chamadas = replay.linhas.filter((linha) => linha.type === "llm_chamada" && linha.n <= estado.passo);
  const todas = somar(chamadas);
  const agentes = (Object.keys(AGENT) as AgentName[]).map((agente) => {
    const doAgente = chamadas.filter((chamada) => chamada.agent === agente);
    return { agente, onde: ondeRodaram(doAgente), ...somar(doAgente) };
  });
  const evitadas = Math.max(0, estado.janelasDeAtaque - todas.chamadas);

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
        <Panel className="sx-span-4 app-preencher" eyebrow="Local × nuvem" title="Onde o modelo rodou">
          <OndeRodou chamadas={chamadas} semLog={semLog} />
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
        {rodada && <NaRodada rodada={rodada} />}
      </div>
    </>
  );
}
