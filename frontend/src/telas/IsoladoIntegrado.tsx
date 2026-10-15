import { useState } from "react";
import { detalheDoIncidente } from "../adaptador";
import { Button, ClassifierVerdict, EmptyState, PageHeader, Panel, RiskBadge, Segmented, StatusBadge, TargetLabel, fmtInt } from "../design-system";
import { Planejada } from "./comum";
import { incidenteEscolhido } from "./Incidente";
import type { PropsDaTela } from "./replay";

// Quantas linhas do formato "uma por janela" a figura mostra antes de resumir o resto.
const LINHAS_DE_EXEMPLO = 6;

/**
 * Tela 3: o mesmo incidente sem agentes (um alerta por janela) e com agentes (um incidente, poucas
 * chamadas à IA, propostas e efeitos). O lado integrado sai do log; o lado isolado mostra o formato
 * de saída do classificador, com os valores do incidente.
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
        <EmptyState icon="flag" title="Nenhum incidente neste ponto do replay">Avance o replay até o primeiro incidente aberto.</EmptyState>
      </>
    );
  }

  const { incidente } = detalhe;
  const comIps = enderecos === "ips";
  const origem = detalhe.origens[0];
  const rate = detalhe.features.find((feature) => feature.name === "Rate");
  const linhas = Array.from({ length: Math.min(LINHAS_DE_EXEMPLO, incidente.windows) }, (_, i) => {
    const campos: Record<string, unknown> = { janela: i + 1, previsto: incidente.modelCategory, confianca: incidente.confidence };
    if (rate) {
      campos.Rate = rate.value;
    }
    if (comIps && origem) {
      campos.origem = origem.address;
    }
    return JSON.stringify(campos);
  });
  const resto = incidente.windows - linhas.length;

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
            <pre className="sx-code code">
              {linhas.join("\n")}
              {resto > 0 && (
                <>
                  {"\n"}
                  <b>… mais {fmtInt(resto)} linhas</b>
                </>
              )}
            </pre>
            <p className="body-sm sx-muted app-nota">
              <Planejada>Valores ilustrativos</Planejada> As linhas mostram o formato da saída do classificador, uma por janela, com a categoria e a confiança do incidente; o log não
              guarda as janelas uma a uma.
            </p>
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
        Figura: à esquerda, a saída do classificador isolado (uma linha por janela, no formato ilustrado); à direita, o mesmo tráfego agregado em um incidente e tratado por
        três agentes. Contagens, veredito e propostas do log de exemplo, {id}, até o evento {props.replay.estado.passo} de {props.replay.estado.total}.
      </p>
    </>
  );
}
