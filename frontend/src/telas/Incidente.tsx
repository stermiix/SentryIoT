import { useState } from "react";
import { detalheDoIncidente, RASTRO_RESUMIDO, type DetalheDoIncidente } from "../adaptador";
import {
  AddressList,
  Alert,
  Button,
  CategoryBadge,
  ClassifierVerdict,
  EmptyState,
  EVENT,
  EventTimeline,
  FeatureTable,
  Icon,
  ModeIndicator,
  PageHeader,
  Panel,
  ProposalCard,
  PROPOSAL_STATE,
  StatusBadge,
  Tabs,
  TargetLabel,
  VoiceQuote,
  fmtInt,
} from "../design-system";
import { fluxoDoIncidente, etapasComConversa } from "../conversa";
import { AVISO_DO_EFEITO, AvisosDoLog, DialogoDeDecisao, type PedidoDeDecisao } from "./comum";
import { ConversaDosAgentes } from "./Conversa";
import { MedidasDaExecucao } from "./Medidas";
import type { PropsDaTela } from "./replay";

/**
 * O incidente da rota; sem ele, o que os agentes trataram na execução da rodada final escolhida, ou o
 * primeiro da fila (no passo atual ou, se nenhum abriu ainda, no log inteiro).
 */
export function incidenteEscolhido(props: PropsDaTela, pedido: string | null): string | null {
  const { estado, final } = props.replay;
  const daExecucao = props.rodada?.execucao.incidente;
  const daRodada = daExecucao && final.incidentes.some((item) => item.id === daExecucao) ? daExecucao : null;
  return pedido ?? daRodada ?? estado.agregado.incidentes[0]?.id ?? final.incidentes[0]?.id ?? null;
}

/** O que a tela diz de uma execução gravada da rodada final, ao lado do efeito e das decisões. */
export const AVISO_DA_RODADA =
  "As propostas de risco alto foram decididas pelo aprovador automático dos experimentos, por uma regra fixa conferida no gabarito, e não por uma pessoa.";

function Recomendacoes({ detalhe }: { detalhe: DetalheDoIncidente }) {
  const porId = new Map(detalhe.propostas.map((proposta) => [proposta.id, proposta]));
  if (detalhe.recomendacoes.length === 0) {
    return <EmptyState icon="message-square-quote" title="Nenhuma recomendação ainda">O agente de decisão ainda não respondeu neste ponto do replay.</EmptyState>;
  }
  return (
    <div className="sx-stack sx-stack--sm">
      {[...detalhe.recomendacoes].reverse().map((recomendacao) => (
        <div key={recomendacao.id} className="sx-stack app-recomendacao">
          <VoiceQuote
            voice="agent"
            agent={recomendacao.agent}
            author={recomendacao.model && (recomendacao.location ? `${recomendacao.model} · ${recomendacao.location}` : recomendacao.model)}
            refId={recomendacao.id}
            at={recomendacao.at}
          >
            {recomendacao.text}
          </VoiceQuote>
          {recomendacao.propostas.length > 0 && (
            <ul className="app-ligadas" aria-label="Propostas ligadas à recomendação">
              {recomendacao.propostas.map((id, indice) => {
                const proposta = porId.get(id);
                return (
                  <li key={`${id}-${indice}`}>
                    <span className="data-sm">{id}</span>
                    {proposta ? (
                      <>
                        <span className="data-sm sx-muted">{proposta.action}</span>
                        <StatusBadge kind="proposal" value={proposta.state} size="sm" />
                      </>
                    ) : (
                      <span className="body-sm sx-muted">proposta não encontrada neste incidente</span>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

export interface PropsDoIncidente extends PropsDaTela {
  incidente: string | null;
  /** A aba da conversa dos agentes, em vez do detalhe. */
  aba?: "conversa";
  efeitoSimulado?: boolean;
  /** O log já terminou: uma execução gravada da rodada ou uma simulação cujos agentes pararam. */
  logTerminado?: boolean;
}

/** Detalhe do incidente no passo do replay: veredito, features, propostas, endereços, agentes e histórico; e a conversa dos agentes, numa aba. */
export function TelaIncidente({ replay, navegar, rodada = null, escolherExecucao, incidente: pedido, aba, efeitoSimulado = false, logTerminado = false }: PropsDoIncidente) {
  const [decisao, setDecisao] = useState<PedidoDeDecisao | null>(null);
  const [rastroCompleto, setRastroCompleto] = useState(false);
  const id = incidenteEscolhido({ replay, navegar, rodada }, pedido);
  const { estado } = replay;
  const detalhe = id ? detalheDoIncidente(estado, replay.final, replay.linhas, id) : null;

  if (!id) {
    return (
      <>
        <PageHeader eyebrow="Operação" title="Incidentes" />
        <AvisosDoLog avisos={replay.avisos} />
        <EmptyState icon={estado.total === 0 ? "inbox" : "shield-check"} title="Nenhum incidente no log">
          {estado.total === 0 ? "Nenhum log de eventos carregado." : "O classificador não agregou nenhuma janela em incidente neste log."}
        </EmptyState>
      </>
    );
  }
  if (!detalhe) {
    const abertura = replay.linhas.find((linha) => linha.type === "incidente_aberto" && linha.ref === id);
    return (
      <EmptyState
        icon="flag"
        title={abertura ? `${id} ainda não foi aberto` : `${id} não está no log`}
        action={abertura ? <Button variant="secondary" onClick={() => replay.irPara(abertura.n)}>Ir para o evento {abertura.n}</Button> : undefined}
      >
        {abertura ? "Neste ponto do replay o classificador ainda não agregou as janelas em um incidente." : "Este incidente não aparece no log."}
      </EmptyState>
    );
  }

  const { incidente, atacante } = detalhe;
  const rastro = rastroCompleto ? detalhe.rastro : detalhe.rastro.slice(-RASTRO_RESUMIDO);
  // Antes do fim do replay, a tela mostra um estado passado: o que vem depois no log já foi
  // decidido, e a interface não oferece decidir de novo. Uma execução gravada da rodada final é só
  // leitura: ninguém trata aquele incidente agora.
  const noFim = estado.passo === estado.total;
  const decide = noFim && !rodada;
  const podeMarcar = decide && incidente.state === "aberto";
  const motivoSemMarcar = rodada
    ? "Execução gravada da rodada final: só leitura"
    : !noFim
      ? "Volte ao fim do replay para decidir"
      : "Só um incidente aberto e sem a marca pode ser marcado";
  const medida = rodada && rodada.execucao.incidente === id ? { execucao: rodada.execucao, minima: rodada.indice.confianca_minima_para_propor } : null;
  const doLogInteiro = replay.final.incidentes.find((item) => item.id === id);
  const conversas = doLogInteiro ? etapasComConversa(fluxoDoIncidente(doLogInteiro.eventos)) : 0;
  return (
    <>
      <PageHeader
        eyebrow={`Incidentes / ${id}`}
        title={<>{id} · {incidente.category ?? incidente.modelCategory}</>}
        meta={
          <>
            <StatusBadge kind="incident" value={incidente.state} />
            <span className="data-sm sx-muted">
              {incidente.start}–{incidente.end} · {fmtInt(incidente.windows)} janelas · {fmtInt(incidente.sources)} {incidente.sources === 1 ? "origem" : "origens"} ·{" "}
              {fmtInt(incidente.destinations)} {incidente.destinations === 1 ? "destino listado" : "destinos listados"} · {fmtInt(detalhe.chamadas)} chamadas à IA · {fmtInt(detalhe.tokens)} tokens
            </span>
          </>
        }
        actions={
          <>
            <ModeIndicator mode="replay" position={estado.passo} total={estado.total} at={estado.atual?.at} />
            <Button
              variant="secondary"
              icon="user-check"
              disabled={!podeMarcar}
              title={podeMarcar ? undefined : motivoSemMarcar}
              onClick={() =>
                setDecisao({
                  tipo: "resolve",
                  incidente: id,
                  resumo: [
                    { label: "Categoria", value: incidente.category ? <CategoryBadge category={incidente.category} /> : <CategoryBadge category={incidente.modelCategory} model /> },
                    { label: "Estado", value: <StatusBadge kind="incident" value={incidente.state} /> },
                  ],
                })
              }
            >
              Já resolvido
            </Button>
            <Button variant="ghost" icon="file-output" onClick={() => navegar({ tela: "relatorio", incidente: id })}>
              Gerar relatório
            </Button>
          </>
        }
      />
      <AvisosDoLog avisos={replay.avisos} />
      {efeitoSimulado && !rodada && <Alert title="Incidente de uma simulação com pcap.">{AVISO_DO_EFEITO}</Alert>}
      {rodada && (
        <Alert title="Execução gravada da rodada final, só leitura.">
          {AVISO_DA_RODADA} {AVISO_DO_EFEITO}
        </Alert>
      )}
      <Tabs
        label="Seções do incidente"
        value={aba === "conversa" ? "conversa" : "detalhe"}
        onChange={(valor) => navegar({ tela: "incidente", incidente: id, ...(valor === "conversa" ? { aba: "conversa" as const } : {}) })}
        tabs={[
          { id: "detalhe", label: "Detalhe" },
          { id: "conversa", label: "Conversa dos agentes", count: conversas > 0 ? conversas : undefined },
        ]}
      />
      {aba === "conversa" ? (
        <ConversaDosAgentes replay={replay} incidente={id} rodada={rodada} escolherExecucao={escolherExecucao} logTerminado={logTerminado || Boolean(rodada)} />
      ) : (
        <>
          {incidente.awaiting > 0 && (
            <Alert tone="attention" title={`${incidente.awaiting} ${incidente.awaiting === 1 ? "proposta de risco alto aguarda" : "propostas de risco alto aguardam"} aprovação`}>
              {rodada
                ? "Nada é executado antes da aprovação. Nesta execução da rodada, quem aprova ou rejeita é o aprovador automático, pela regra fixa do gabarito, e não uma pessoa."
                : "Nada é executado antes de uma pessoa aprovar, pelo terminal ou pela interface."}
              {!noFim && " Este é um ponto passado do replay: as decisões dele estão adiante no log."}
              {noFim && rodada && " A execução gravada terminou assim: ninguém decide mais."}
            </Alert>
          )}
          <div className="sx-grid">
            <div className="sx-span-8 sx-stack">
              <Panel eyebrow="Classificador" title="Veredito">
                <ClassifierVerdict model={incidente.modelCategory} category={incidente.category} sources={incidente.sources} confidence={incidente.confidence} />
              </Panel>
              <Panel eyebrow="Features" title="Contra a referência benigna" flush>
                {detalhe.features.length > 0 ? (
                  <FeatureTable rows={detalhe.features} />
                ) : (
                  <EmptyState icon="layers" title="Sem features em destaque">O log não trouxe features para este incidente.</EmptyState>
                )}
              </Panel>
              <Panel
                eyebrow={`Propostas · ${detalhe.propostas.length}`}
                title="Ações propostas"
                actions={incidente.awaiting > 0 ? <span className="data-sm sx-muted">{PROPOSAL_STATE.aguardando_aprovacao.label.toLowerCase()} primeiro</span> : undefined}
              >
                {detalhe.propostas.length === 0 ? (
                  <EmptyState icon="clipboard-plus" title="Nenhuma proposta ainda">
                    O agente de decisão ainda não propôs ação neste ponto do replay.
                  </EmptyState>
                ) : (
                  <div className="sx-stack sx-stack--sm">
                    {detalhe.propostas.map((proposta) => (
                      <ProposalCard
                        key={proposta.id}
                        proposal={proposta}
                        onApprove={decide ? () => setDecisao({ tipo: "approve", proposta }) : undefined}
                        onReject={decide ? () => setDecisao({ tipo: "reject", proposta }) : undefined}
                      />
                    ))}
                  </div>
                )}
              </Panel>
            </div>
            <div className="sx-span-4 sx-stack">
              {medida && (
                <Panel eyebrow="Rodada final" title="O que a rodada mediu">
                  <MedidasDaExecucao execucao={medida.execucao} minima={medida.minima} />
                </Panel>
              )}
              {detalhe.marcacao && (
                <Panel eyebrow="Operador" title="Marcado como já resolvido">
                  <div className="sx-stack sx-stack--sm">
                    {detalhe.marcacao.reason ? (
                      <VoiceQuote voice="person" author={detalhe.marcacao.user} channel={detalhe.marcacao.channel} refId={id} at={detalhe.marcacao.at}>
                        {detalhe.marcacao.reason}
                      </VoiceQuote>
                    ) : (
                      <p className="body sx-muted app-nota">
                        Às {detalhe.marcacao.at}, por {detalhe.marcacao.user}, sem motivo escrito.
                      </p>
                    )}
                    <p className="body-sm sx-muted app-nota">Daqui em diante, o servidor recusa proposta e execução neste incidente.</p>
                  </div>
                </Panel>
              )}
              <Panel eyebrow="Endereços" title="Origens e destinos">
                <div className="sx-stack sx-stack--sm">
                  <AddressList
                    title="Origens"
                    items={detalhe.origens}
                    total={incidente.sources}
                    mark={atacante ? { address: atacante.address, label: "atacante", icon: EVENT.atacante_apontado.icon } : undefined}
                  />
                  {/* A triagem pode apontar um candidato que não está entre as origens com mais quadros. */}
                  {atacante && !atacante.listed && (
                    <p className="body-sm sx-muted app-nota sx-row">
                      <span className="app-linha-com-icone">
                        <Icon name={EVENT.atacante_apontado.icon} size={14} />
                        Atacante apontado pela triagem, fora das origens listadas:
                      </span>
                      <TargetLabel label={atacante.label} address={atacante.address} />
                    </p>
                  )}
                  <hr className="sx-divider" />
                  <AddressList title="Destinos" items={detalhe.destinos} total={incidente.destinations} />
                </div>
              </Panel>
              <Panel
                eyebrow="Agentes"
                title="Rastro dos agentes"
                actions={
                  detalhe.rastro.length > RASTRO_RESUMIDO ? (
                    <Button variant="ghost" size="sm" onClick={() => setRastroCompleto((agora) => !agora)}>
                      {rastroCompleto ? "Só os últimos" : `Ver os ${detalhe.rastro.length}`}
                    </Button>
                  ) : undefined
                }
              >
                {rastro.length > 0 ? (
                  <EventTimeline events={rastro} density="compact" cursor={estado.passo} onSelect={replay.irPara} />
                ) : (
                  <EmptyState icon="bot" title="Os agentes ainda não agiram">A primeira chamada à IA aparece aqui.</EmptyState>
                )}
              </Panel>
              <Panel eyebrow="Decisão" title="Recomendações">
                <Recomendacoes detalhe={detalhe} />
              </Panel>
            </div>
            <Panel className="sx-span-12" eyebrow="Histórico" title="Decisões e efeitos" actions={<span className="data-sm sx-muted">esmaecidos: depois do cursor</span>}>
              <EventTimeline events={detalhe.historico} cursor={estado.passo} onSelect={replay.irPara} />
            </Panel>
          </div>
        </>
      )}
      <DialogoDeDecisao pedido={decisao} aoFechar={() => setDecisao(null)} />
    </>
  );
}
