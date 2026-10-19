import { useState } from "react";
import { detalheDoIncidente } from "../adaptador";
import { Button, ClassifierVerdict, EmptyState, PageHeader, Panel, RiskBadge, Segmented, StatusBadge, TargetLabel, fmtInt } from "../design-system";
import { incidenteEscolhido } from "./Incidente";
import type { PropsDaTela } from "./replay";

/**
 * Tela 3: o mesmo incidente sem agentes (um alerta por janela) e com agentes (um incidente, poucas
 * chamadas à IA, propostas e efeitos). Os dois lados saem do log: o isolado conta as janelas do
 * incidente, que seriam um alerta cada.
 */
export function TelaIsoladoIntegrado(props: PropsDaTela & { incidente?: string | null }) {
  const [enderecos, setEnderecos] = useState("rotulos");
  const id = incidenteEscolhido(props, props.incidente ?? null);
  const detalhe = id ? detalheDoIncidente(props.replay.estado, props.replay.final, props.replay.linhas, id) : null;
  const cabecalho = (
    <PageHeader
      eyebrow="Telas do artigo · Tela 3"
      title="Isolado × integrado"
      meta={<span className="body-sm sx-muted">O mesmo incidente: a saída crua do classificador e a resposta com agentes.</span>}
      actions={
        <>
          <Segmented
            label="Endereços na figura"
            value={enderecos}
            onChange={setEnderecos}
            options={[
              { value: "rotulos", label: "Rótulos neutros", icon: "eye-off" },
              { value: "ips", label: "Com IPs", icon: "eye" },
            ]}
          />
          <Button variant="secondary" icon="printer" onClick={() => window.print()}>
            Imprimir a figura
          </Button>
        </>
      }
    />
  );
  if (!detalhe) {
    return (
      <>
        {cabecalho}
        {props.replay.estado.total === 0 ? (
          <EmptyState icon="inbox" title="Nenhum incidente no log">Nenhum log de eventos carregado.</EmptyState>
        ) : (
          <EmptyState icon="flag" title="Nenhum incidente neste ponto do replay">Avance o replay até o primeiro incidente aberto.</EmptyState>
        )}
      </>
    );
  }

  const { incidente } = detalhe;
  const comIps = enderecos === "ips";

  return (
    <>
      {cabecalho}
      <div className="sx-split">
        <Panel eyebrow="Sem agentes" title="Classificador isolado">
          <div className="sx-stack sx-stack--sm">
            <div className="sx-row app-base">
              <span className="sx-bignum display-lg">{fmtInt(incidente.windows)}</span>
              <span className="body-lg sx-muted">alertas, um por janela</span>
            </div>
            <dl className="sx-kv body">
              <dt>Ação tomada</dt>
              <dd>nenhuma</dd>
              <dt>Quem decide</dt>
              <dd>o operador, alerta por alerta</dd>
              <dt>Contexto</dt>
              <dd>nenhum: cada janela chega sozinha</dd>
            </dl>
          </div>
        </Panel>
        <Panel eyebrow="Com agentes" title="Resposta integrada">
          <div className="sx-stack sx-stack--sm">
            <div className="sx-row app-base">
              <span>
                <span className="sx-bignum display-lg">1</span> <span className="body-lg sx-muted">incidente</span>
              </span>
              <span>
                <span className="sx-bignum display-lg app-gelo">{fmtInt(detalhe.chamadas)}</span>{" "}
                <span className="body-lg sx-muted">{detalhe.chamadas === 1 ? "chamada" : "chamadas"} à IA</span>
              </span>
            </div>
            <ClassifierVerdict model={incidente.modelCategory} category={incidente.category} sources={incidente.sources} confidence={incidente.confidence} />
            {detalhe.propostas.length > 0 ? (
              <ul className="sx-plist">
                {detalhe.propostas.map((proposta) => (
                  <li key={proposta.id} className="sx-plist__row">
                    <span className="sx-plist__what">
                      <span className="data">{proposta.action}</span>
                      <TargetLabel label={proposta.target.label} address={comIps ? proposta.target.address : undefined} free={proposta.target.free} />
                      <RiskBadge level={proposta.risk} size="sm" />
                    </span>
                    <span className="sx-plist__res">
                      <StatusBadge kind="proposal" value={proposta.state} size="sm" />
                      {proposta.effect && <StatusBadge kind="effect" value={proposta.effect.result} size="sm" />}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="body sx-muted app-nota">Nenhuma proposta até este ponto do replay.</p>
            )}
          </div>
        </Panel>
      </div>
      <p className="sx-caption body-sm">
        Figura: à esquerda, o classificador isolado, com um alerta por janela; à direita, o mesmo tráfego agregado em um incidente e tratado por três agentes. Contagens,
        veredito e propostas do log, {id}, até o evento {props.replay.estado.passo} de {props.replay.estado.total}.
      </p>
    </>
  );
}
