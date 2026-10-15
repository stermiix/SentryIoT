import type { ReactNode } from "react";
import { Button, EmptyState, Icon, MetricCard, PageHeader, Panel, cx, type IconName, type Tone } from "../design-system";
import { Planejada } from "./comum";

// Tela 6 (planejada): o teste de tool poisoning. Os testes ainda não rodaram, e a tela fica vazia,
// com os três desfechos possíveis zerados. Para ligar: preencher `TESTES` com os resultados lidos
// de um arquivo de experimento; cada teste vira um painel com o conteúdo injetado e o que aconteceu.

type Desfecho = "resistiu" | "recusada" | "caiu";

const DESFECHO: Record<Desfecho, { label: string; tone: Tone; icon: IconName; contexto: string }> = {
  resistiu: { label: "Agente resistiu", tone: "success", icon: "shield-check", contexto: "instrução injetada ignorada" },
  recusada: { label: "Recusada pelo servidor", tone: "info", icon: "shield-x", contexto: "o MCP barrou antes do agente" },
  caiu: { label: "Agente caiu", tone: "danger", icon: "shield-off", contexto: "contido pela aprovação humana" },
};

function SeloDoDesfecho({ desfecho }: { desfecho: Desfecho }) {
  const info = DESFECHO[desfecho];
  return (
    <span className={cx("sx-status", "sx-status--emphasis", `sx-tone--${info.tone}`)}>
      <Icon name={info.icon} size={15} strokeWidth={1.9} />
      {info.label}
    </span>
  );
}

interface Teste {
  id: string;
  nome: string;
  onde: string;
  injetado: string;
  aconteceu: ReactNode;
  desfecho: Desfecho;
}

// Os resultados do teste de tool poisoning. Vazio até o teste rodar: a tela mostra só a estrutura.
const TESTES: Teste[] = [];

export function TelaSegurancaMcp() {
  const quantos = (desfecho: Desfecho) => TESTES.filter((teste) => teste.desfecho === desfecho).length;
  return (
    <>
      <PageHeader
        eyebrow="Telas do artigo · Tela 6"
        title="Segurança do MCP"
        meta={
          <>
            <Planejada />
            <span className="body-sm sx-muted">Teste de tool poisoning: o que foi injetado e se o agente caiu.</span>
          </>
        }
        actions={
          <Button variant="primary" icon="flask-conical" disabled title="Planejado: os testes ainda não rodam pela interface">
            Rodar os testes
          </Button>
        }
      />
      <div className="sx-grid">
        {(Object.keys(DESFECHO) as Desfecho[]).map((desfecho) => (
          <MetricCard key={desfecho} className="sx-span-4" label={DESFECHO[desfecho].label} value={quantos(desfecho)} icon={DESFECHO[desfecho].icon} context={DESFECHO[desfecho].contexto} />
        ))}
        {TESTES.length === 0 && (
          <Panel className="sx-span-12" eyebrow="Testes" title="Resultados">
            <EmptyState icon="flask-conical" title="Os testes ainda não rodaram">
              Cada teste aparece aqui com o conteúdo injetado, onde ele entrou e o que o agente e o servidor fizeram.
            </EmptyState>
          </Panel>
        )}
        {TESTES.map((teste) => (
          <Panel key={teste.id} className="sx-span-12" eyebrow={`${teste.id} · ${teste.onde}`} title={teste.nome} actions={<SeloDoDesfecho desfecho={teste.desfecho} />}>
            <div className="sx-split">
              <div className="sx-stack sx-stack--sm">
                <span className="sx-eyebrow eyebrow">Conteúdo injetado · não confiável</span>
                <pre className="sx-code sx-untrusted code">{teste.injetado}</pre>
              </div>
              <div className="sx-stack sx-stack--sm">
                <span className="sx-eyebrow eyebrow">O que aconteceu</span>
                {teste.aconteceu}
              </div>
            </div>
          </Panel>
        ))}
      </div>
    </>
  );
}
