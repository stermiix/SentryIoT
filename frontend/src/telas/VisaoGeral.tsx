import { AggregationFunnel, EmptyState, IncidentQueue, MetricCard, ModeIndicator, PageHeader, Panel, Segmented, fmtInt } from "../design-system";
import { AvisosDoLog } from "./comum";
import type { PropsDaTela } from "./replay";

const AO_VIVO_CONFIGURADO = Boolean(import.meta.env.VITE_LOG_AO_VIVO);

function contagem(quantidade: number, singular: string, varios: string): string | null {
  return quantidade > 0 ? `${fmtInt(quantidade)} ${quantidade === 1 ? singular : varios}` : null;
}

/** Visão geral: o funil do argumento (janelas → incidentes → chamadas à IA), três números e a fila. */
export function TelaVisaoGeral({ replay, navegar }: PropsDaTela) {
  const { estado } = replay;
  const views = estado.agregado.incidentes;
  const porEstado = (valor: string) => estado.incidentes.filter((incidente) => incidente.state === valor).length;
  const resumoDosIncidentes = [
    contagem(porEstado("aberto"), "aberto", "abertos"),
    contagem(porEstado("encerrado"), "encerrado", "encerrados"),
    contagem(porEstado("ja-resolvido"), "marcado como já resolvido", "marcados como já resolvidos"),
  ].filter(Boolean);
  const porIncidente = views.map(
    (view) => `${view.id}, ${fmtInt(view.chamadasLLM)} ${view.chamadasLLM === 1 ? "chamada" : "chamadas"}${view.marcacao ? " (marcado como já resolvido)" : ""}`,
  );

  return (
    <>
      <PageHeader
        eyebrow="SentryIoT · log de exemplo"
        title="Visão geral"
        actions={
          <>
            <ModeIndicator mode="replay" position={estado.passo} total={estado.total} at={estado.atual?.at} />
            <Segmented
              label="Modo"
              value="replay"
              onChange={(valor) => valor === "ao-vivo" && navegar({ tela: "ao-vivo", incidente: null })}
              options={[
                { value: "replay", label: "Replay", icon: "history" },
                { value: "ao-vivo", label: "Ao vivo", icon: "radio", disabled: !AO_VIVO_CONFIGURADO, hint: AO_VIVO_CONFIGURADO ? undefined : "Planejado" },
              ]}
            />
          </>
        }
      />
      <AvisosDoLog avisos={replay.avisos} />
      <div className="sx-grid">
        <AggregationFunnel
          className="sx-span-12"
          windows={estado.janelas}
          counterfactual={estado.janelasDeAtaque}
          incidents={estado.incidentes.length}
          aiCalls={estado.chamadas}
          scope={`até o evento ${estado.passo} de ${estado.total}`}
          footnote={porIncidente.length > 0 ? `Por incidente: ${porIncidente.join(" · ")}.` : undefined}
        />
        <MetricCard
          className="sx-span-4"
          label="Aguardando aprovação"
          value={estado.aguardando}
          icon="hourglass"
          tone={estado.aguardando > 0 ? "attention" : "default"}
          context={estado.aguardando > 0 ? "Propostas de risco alto esperam uma pessoa." : "Nenhuma decisão pendente."}
        />
        <MetricCard
          className="sx-span-4"
          label="Incidentes"
          value={estado.incidentes.length}
          icon="shield-alert"
          context={resumoDosIncidentes.length > 0 ? resumoDosIncidentes.join(" · ") : "Nenhum incidente ainda."}
        />
        <MetricCard
          className="sx-span-4"
          label="Tokens"
          value={estado.tokens}
          icon="coins"
          spark={estado.tokensAcumulados.length > 1 ? estado.tokensAcumulados : undefined}
          context={
            estado.chamadas > 0
              ? `${fmtInt(estado.chamadas)} ${estado.chamadas === 1 ? "chamada" : "chamadas"} à IA · ${fmtInt(estado.tokens / estado.chamadas)} por chamada`
              : "Nenhuma chamada à IA ainda."
          }
        />
        <Panel
          className="sx-span-12"
          eyebrow="Fila"
          title="Incidentes"
          flush
          actions={<span className="data-sm sx-muted">{estado.incidentes.length} no log até aqui</span>}
        >
          <IncidentQueue
            incidents={estado.incidentes}
            onSelect={(id) => navegar({ tela: "incidente", incidente: id })}
            empty={
              <EmptyState icon="shield-check" title="Nenhum incidente até aqui">
                As janelas classificadas até este evento não viraram incidente. Avance o replay para ver o primeiro.
              </EmptyState>
            }
          />
          {estado.agregado.resumo.eventosSemAbertura > 0 && (
            <p className="body-sm sx-muted app-nota">
              {estado.agregado.resumo.eventosSemAbertura} evento(s) citam incidente que não estava aberto naquele ponto do log e ficam fora da fila.
            </p>
          )}
        </Panel>
      </div>
    </>
  );
}
