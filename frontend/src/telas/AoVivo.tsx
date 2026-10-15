import { useEffect, useMemo, useState } from "react";
import { detalheDoIncidente, estadoNoPasso, linhasDoLog, propostasDaTela } from "../adaptador";
import {
  AGENT,
  Alert,
  AgentBadge,
  Button,
  CategoryBadge,
  ClassifierVerdict,
  EmptyState,
  EVENT,
  EventTimeline,
  ModeIndicator,
  PageHeader,
  Panel,
  ProposalCard,
  Skeleton,
  StatusBadge,
  fmtInt,
  type AgentName,
} from "../design-system";
import { agregar, conferirResposta, lerLog } from "../log";
import type { Evento } from "../types";
import { AvisosDoLog, DialogoDeDecisao, Planejada, type PedidoDeDecisao } from "./comum";

const FONTE = import.meta.env.VITE_LOG_AO_VIVO ?? "";
// De quanto em quanto tempo o log que está sendo gravado é lido de novo.
const INTERVALO_MS = 3000;
// Quantos eventos recentes a tela mostra.
const RECENTES = 8;

interface LogAoVivo {
  eventos: Evento[];
  avisos: string[];
  erro: string | null;
}

/**
 * Lê o log que está sendo gravado a cada poucos segundos. A última linha sem quebra de linha é
 * ignorada: pode estar no meio da gravação. Sem `fonte`, não lê nada.
 */
export function useLogAoVivo(fonte: string): LogAoVivo {
  const [estado, setEstado] = useState<LogAoVivo>({ eventos: [], avisos: [], erro: null });
  useEffect(() => {
    if (!fonte) {
      return;
    }
    let ativo = true;
    // Uma leitura por vez: numa rede lenta, uma resposta antiga não volta a tela para um log mais velho.
    let lendo = false;
    const ler = async () => {
      if (lendo) {
        return;
      }
      lendo = true;
      try {
        const resposta = await fetch(fonte, { cache: "no-store" });
        conferirResposta(resposta, fonte, "VITE_LOG_AO_VIVO");
        const lido = lerLog(await resposta.text(), { ignorarUltimaIncompleta: true });
        if (ativo) {
          setEstado({ eventos: lido.eventos, avisos: [...lido.avisos, ...agregar(lido.eventos).avisos], erro: null });
        }
      } catch (falha) {
        if (ativo) {
          setEstado((atual) => ({ ...atual, erro: falha instanceof Error ? falha.message : "falha ao ler o log ao vivo." }));
        }
      } finally {
        lendo = false;
      }
    };
    void ler();
    const relogio = window.setInterval(() => void ler(), INTERVALO_MS);
    return () => {
      ativo = false;
      window.clearInterval(relogio);
    };
  }, [fonte]);
  return estado;
}

/**
 * Modo ao vivo: o incidente aparece assim que o classificador o abre, antes dos agentes, e as
 * decisões pendentes ficam à esquerda. Com `VITE_LOG_AO_VIVO`, lê o log que está sendo gravado;
 * sem ele, a tela é a planejada e fica vazia. Não usa o log do replay.
 */
export function TelaAoVivo() {
  const aoVivo = useLogAoVivo(FONTE);
  const [decisao, setDecisao] = useState<PedidoDeDecisao | null>(null);
  const eventos = aoVivo.eventos;
  const final = useMemo(() => agregar(eventos), [eventos]);
  const linhas = useMemo(() => linhasDoLog(eventos, final.ignorados), [eventos, final]);
  const passo = eventos.length;
  const estado = useMemo(() => estadoNoPasso(eventos, linhas, passo), [eventos, linhas, passo]);

  const pendentes = estado.agregado.incidentes.flatMap((view) => propostasDaTela(view).filter((proposta) => proposta.state === "aguardando_aprovacao"));
  const abertos = estado.agregado.incidentes.filter((view) => view.incidente.estado === "aberto" && !view.marcacao);
  const ultimo = abertos[abertos.length - 1] ?? estado.agregado.incidentes[estado.agregado.incidentes.length - 1];
  const detalhe = ultimo ? detalheDoIncidente(estado, final, linhas, ultimo.id) : null;
  const recentes = linhas.slice(Math.max(0, passo - RECENTES), passo).reverse();
  const atual = estado.atual;

  const dock = (
    <div className="sx-replay app-dock-ao-vivo">
      <span className="sx-row">
        <ModeIndicator mode="ao-vivo" at={atual?.at} />
        <span className="body-sm sx-muted">{FONTE ? "Recebendo eventos do log em tempo real" : "Planejado: nenhum log ao vivo configurado"}</span>
      </span>
      <span className="sx-row data-sm sx-muted">{atual ? `último: ${atual.id} · ${EVENT[atual.type].label}` : "nenhum evento ainda"}</span>
    </div>
  );

  const agentes = (Object.keys(AGENT) as AgentName[]).map((agente) => {
    const doAgente = detalhe ? detalhe.rastro.filter((linha) => linha.agent === agente) : [];
    const chamadas = doAgente.filter((linha) => linha.type === "llm_chamada");
    return { agente, chamadas, ultima: doAgente[doAgente.length - 1] };
  });

  return (
    <>
      <PageHeader
        eyebrow="Operação"
        title="Ao vivo"
        meta={
          <>
            {!FONTE && <Planejada />}
            <span className="body-sm sx-muted">O incidente aparece assim que o classificador o abre, antes dos agentes.</span>
          </>
        }
        actions={<ModeIndicator mode="ao-vivo" at={atual?.at} />}
      />
      <AvisosDoLog avisos={aoVivo.avisos} />
      {FONTE && aoVivo.erro && (
        <Alert tone="danger" title="O log ao vivo não pôde ser lido">
          {aoVivo.erro} A tela segue com a última leitura.
        </Alert>
      )}
      <div className="sx-grid">
        <Panel
          className="sx-span-7"
          eyebrow="Requer você"
          title="Decisões pendentes"
          tone={pendentes.length > 0 ? "attention" : "default"}
          actions={pendentes.length > 0 ? <StatusBadge kind="proposal" value="aguardando_aprovacao" /> : undefined}
        >
          {pendentes.length > 0 ? (
            <div className="sx-stack sx-stack--sm">
              {pendentes.map((proposta) => (
                <ProposalCard key={proposta.id} proposal={proposta} onApprove={() => setDecisao({ tipo: "approve", proposta })} onReject={() => setDecisao({ tipo: "reject", proposta })} />
              ))}
            </div>
          ) : (
            <EmptyState icon="check-check" title="Nada aguarda você">As propostas de risco alto aparecem aqui assim que o agente de decisão as cria.</EmptyState>
          )}
        </Panel>
        <div className="sx-span-5 sx-stack">
          {detalhe ? (
            <Panel eyebrow={`Aberto às ${detalhe.abertoEm}`} title={detalhe.incidente.id} actions={<StatusBadge kind="incident" value={detalhe.incidente.state} />}>
              <div className="sx-stack sx-stack--sm">
                <ClassifierVerdict
                  model={detalhe.incidente.modelCategory}
                  category={detalhe.incidente.category}
                  sources={detalhe.incidente.sources}
                  confidence={detalhe.incidente.confidence}
                />
                <hr className="sx-divider" />
                <div className="sx-eyebrow eyebrow">Agentes</div>
                {agentes.map(({ agente, chamadas, ultima }) => (
                  <div key={agente} className="sx-row">
                    <AgentBadge agent={agente} location={chamadas.length > 0 ? chamadas[chamadas.length - 1].location : undefined} />
                    <span className="body-sm sx-muted">
                      {ultima ? `${fmtInt(chamadas.length)} ${chamadas.length === 1 ? "chamada" : "chamadas"} à IA · último: ${EVENT[ultima.type].label}` : "ainda não agiu"}
                    </span>
                  </div>
                ))}
                {agentes.every(({ ultima }) => !ultima) && <Skeleton lines={2} label="Aguardando os agentes" />}
                <Button
                  variant="secondary"
                  icon="user-check"
                  block
                  disabled={detalhe.incidente.state !== "aberto"}
                  onClick={() =>
                    setDecisao({
                      tipo: "resolve",
                      incidente: detalhe.incidente.id,
                      resumo: [
                        { label: "Categoria", value: detalhe.incidente.category ? <CategoryBadge category={detalhe.incidente.category} /> : <CategoryBadge category={detalhe.incidente.modelCategory} model /> },
                        { label: "Estado", value: <StatusBadge kind="incident" value={detalhe.incidente.state} /> },
                      ],
                    })
                  }
                >
                  Marcar como já resolvido
                </Button>
              </div>
            </Panel>
          ) : (
            <Panel eyebrow="Incidente" title="Nenhum aberto">
              <EmptyState icon="shield-check" title="Nenhum incidente aberto">O classificador ainda não abriu incidente.</EmptyState>
            </Panel>
          )}
        </div>
        <Panel className="sx-span-12" eyebrow="Chegando agora" title="Eventos">
          {recentes.length > 0 ? <EventTimeline events={recentes} cursor={passo} /> : <EmptyState icon="inbox" title="Nenhum evento ainda">Os eventos aparecem aqui conforme o log é gravado.</EmptyState>}
        </Panel>
      </div>
      <DialogoDeDecisao pedido={decisao} aoFechar={() => setDecisao(null)} />
      {/* Esta tela não usa o controle do replay: o dock dela, preso ao pé, diz de onde vêm os eventos. */}
      <div className="sx-app__dock">{dock}</div>
    </>
  );
}
