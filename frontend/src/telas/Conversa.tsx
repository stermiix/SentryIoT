import { useState, type ReactNode } from "react";
import { fluxoDoIncidente, etapasComConversa, type EtapaDoAgente, type ItemDaConversa, type ItemDoFluxo } from "../conversa";
import {
  AGENT,
  AgentBadge,
  Alert,
  Button,
  EmptyState,
  EventTimeline,
  Icon,
  Panel,
  STOP_REASON,
  VERDICT,
  VoiceQuote,
  cx,
  fmtDuration,
  fmtInt,
  type IconName,
  type LogEvent,
} from "../design-system";
import type { ContextoDaRodada } from "../rodada";
import { MedidasDaExecucao } from "./Medidas";
import type { Replay } from "./replay";

// A aba "Conversa dos agentes" do detalhe do incidente: o incidente de ponta a ponta, do classificador ao
// efeito, com o que cada agente recebeu e respondeu (contrato 0.8.0).

// Até este tamanho, o resultado de uma tool já abre aberto; acima, fica recolhido.
const RESULTADO_CURTO = 400;

/** Um bloco que abre e fecha; o conteúdo só é desenhado aberto (o prompt de sistema passa de 18 mil caracteres). */
function Recolhivel({ resumo, aberto: inicial = false, children }: { resumo: ReactNode; aberto?: boolean; children: () => ReactNode }) {
  const [aberto, setAberto] = useState(inicial);
  return (
    <details className="app-recolhivel" open={aberto} onToggle={(evento) => setAberto(evento.currentTarget.open)}>
      <summary className="app-recolhivel__resumo">
        <Icon name="chevron-right" size={16} className="app-recolhivel__seta" />
        {resumo}
      </summary>
      {aberto && <div className="app-recolhivel__corpo">{children()}</div>}
    </details>
  );
}

function Bruto({ texto, doModelo = false }: { texto: string; doModelo?: boolean }) {
  return <pre className={cx("app-bruto code", doModelo && "app-bruto--modelo")}>{texto}</pre>;
}

const caracteres = (texto: string) => `${fmtInt(Array.from(texto).length)} ${Array.from(texto).length === 1 ? "caractere" : "caracteres"}`;

function Rotulo({ icone, children, extra }: { icone: IconName; children: ReactNode; extra?: ReactNode }) {
  return (
    <div className="app-msg__rotulo">
      <Icon name={icone} size={15} />
      <span className="sx-eyebrow eyebrow">{children}</span>
      {extra && <span className="data-sm sx-muted">{extra}</span>}
    </div>
  );
}

/** Uma mensagem da conversa, com o papel dela dito em palavras. */
function Mensagem({ item, etapa }: { item: ItemDaConversa; etapa: EtapaDoAgente }) {
  switch (item.tipo) {
    case "sistema":
      return (
        <li className="app-msg">
          <Recolhivel
            resumo={
              <>
                <span className="sx-eyebrow eyebrow">Prompt de sistema, com as skills do agente</span>
                <span className="data-sm sx-muted">{caracteres(item.texto)}</span>
              </>
            }
          >
            {() => <Bruto texto={item.texto} />}
          </Recolhivel>
        </li>
      );
    case "pedido":
      return (
        <li className="app-msg">
          <Rotulo icone="route">Pedido do orquestrador</Rotulo>
          <Bruto texto={item.texto} />
        </li>
      );
    case "aviso":
      return (
        <li className="app-msg">
          <Rotulo icone="repeat">Aviso do laço ao modelo</Rotulo>
          <Bruto texto={item.texto} />
        </li>
      );
    case "omitidas":
      return (
        <li className="app-msg">
          <Rotulo icone="ellipsis">Nota de quem gravou o log</Rotulo>
          <Bruto texto={item.texto} />
        </li>
      );
    case "modelo":
      return (
        <li className="app-msg">
          <Rotulo icone="brain-circuit">{item.final ? "Resposta final" : "Texto do modelo, antes das tools"}</Rotulo>
          <VoiceQuote voice="agent" agent={etapa.agente} author={etapa.modelo ?? undefined} className="app-com-quebras">
            {item.texto}
          </VoiceQuote>
        </li>
      );
    case "pedido_de_tool":
      return (
        <li className="app-msg">
          <Rotulo icone="plug" extra={item.id}>
            Pede a tool <span className="app-nome-da-tool">{item.nome}</span>
          </Rotulo>
          <Bruto texto={item.formatados ?? item.argumentos} doModelo />
          {item.formatados === null && <span className="body-sm sx-muted">Os argumentos não são um JSON válido: aparecem como o modelo os escreveu.</span>}
        </li>
      );
    case "resultado_de_tool":
      return (
        <li className="app-msg">
          <Recolhivel
            aberto={item.texto.length <= RESULTADO_CURTO}
            resumo={
              <>
                <span className="sx-eyebrow eyebrow">
                  Resultado {item.nome ? <>de <span className="app-nome-da-tool">{item.nome}</span></> : "de tool"}
                </span>
                <span className="data-sm sx-muted">{caracteres(item.texto)}</span>
              </>
            }
          >
            {() => <Bruto texto={item.formatado ?? item.texto} />}
          </Recolhivel>
        </li>
      );
  }
}

/** O que vem ao lado do selo do agente: a rodada do orquestrador ou o sumário. A triagem roda uma vez. */
function tituloDaEtapa(etapa: EtapaDoAgente): string | null {
  if (etapa.tarefa === "sumario") {
    return "Sumário do incidente";
  }
  return etapa.agente === "triagem" ? null : `Rodada ${etapa.rodada}`;
}

function resumoDaEtapa(etapa: EtapaDoAgente): string {
  const partes = [
    `${fmtInt(etapa.chamadas)} ${etapa.chamadas === 1 ? "chamada" : "chamadas"} à IA`,
    `${fmtInt(etapa.tokensEntrada)} tokens de entrada e ${fmtInt(etapa.tokensSaida)} de saída`,
    fmtDuration(etapa.segundos),
  ];
  if (etapa.motivo) {
    partes.push(`parou por ${STOP_REASON[etapa.motivo]}`);
  }
  if (etapa.veredito) {
    partes.push(`veredito ${VERDICT[etapa.veredito]}`);
  }
  return partes.join(" · ");
}

function Etapa({ etapa, numero, linhas, replay, futura }: { etapa: EtapaDoAgente; numero: number; linhas: Map<string, LogEvent>; replay: Replay; futura: boolean }) {
  const produziu = etapa.produziu.map((evento) => linhas.get(evento.id)).filter((linha): linha is LogEvent => Boolean(linha));
  return (
    <li className={cx("app-etapa", futura && "is-futura")}>
      <header className="app-etapa__cabeca">
        <span className="app-etapa__numero data-sm" aria-hidden="true">
          {numero}
        </span>
        <span className="app-etapa__titulos">
          <span className="app-etapa__titulo">
            <AgentBadge agent={etapa.agente} location={etapa.onde ?? undefined} model={etapa.modelo ?? undefined} />
            {tituloDaEtapa(etapa) && <span className="title-3">{tituloDaEtapa(etapa)}</span>}
          </span>
          <span className="data-sm sx-muted">{resumoDaEtapa(etapa)}</span>
        </span>
      </header>
      {etapa.emAndamento && <p className="body-sm sx-muted app-nota">O agente ainda está rodando neste ponto do log: a conversa vai ao log quando ele termina.</p>}
      {etapa.conversa ? (
        <ol className="app-msgs" aria-label={`Conversa da ${AGENT[etapa.agente].label.toLowerCase()}`}>
          {etapa.conversa.map((item, indice) => (
            <Mensagem key={indice} item={item} etapa={etapa} />
          ))}
        </ol>
      ) : (
        !etapa.emAndamento && <p className="body-sm sx-muted app-nota">O log não traz a conversa deste agente: foi gravado antes do contrato 0.8.0.</p>
      )}
      {produziu.length > 0 && (
        <div className="app-etapa__log">
          <span className="sx-eyebrow eyebrow">No log, nesta etapa</span>
          <EventTimeline events={produziu} density="compact" cursor={replay.estado.passo} onSelect={replay.irPara} />
        </div>
      )}
    </li>
  );
}

/** Os eventos entre as etapas (abertura, aprovações, rejeições, marca de já resolvido), em sequência. */
function Passos({ eventos, replay }: { eventos: LogEvent[]; replay: Replay }) {
  return (
    <li className="app-entre-etapas">
      <EventTimeline events={eventos} cursor={replay.estado.passo} onSelect={replay.irPara} />
    </li>
  );
}

/** A execução da rodada em que este incidente foi tratado, quando ela existe: para abrir de lá. */
function execucaoDoIncidente(rodada: ContextoDaRodada, incidente: string): string | null {
  const { grupo, execucao } = rodada;
  const doIncidente = grupo.execucoes.filter((item) => item.pcap === execucao.pcap && item.incidente === incidente);
  return (doIncidente.find((item) => item.repeticao === execucao.repeticao) ?? doIncidente[0])?.id ?? null;
}

export interface PropsDaConversa {
  replay: Replay;
  incidente: string;
  rodada?: ContextoDaRodada | null;
  escolherExecucao?: (id: string) => void;
}

/** O incidente de ponta a ponta: a abertura, cada agente com a conversa e o que deixou no log, e as decisões. */
export function ConversaDosAgentes({ replay, incidente, rodada = null, escolherExecucao }: PropsDaConversa) {
  const view = replay.final.incidentes.find((item) => item.id === incidente);
  const fluxo: ItemDoFluxo[] = view ? fluxoDoIncidente(view.eventos) : [];
  const linhas = new Map(replay.linhas.map((linha) => [linha.id, linha]));
  const etapas = fluxo.filter((item): item is EtapaDoAgente => item.tipo === "agente");
  const medida = rodada && rodada.execucao.incidente === incidente ? rodada.execucao : null;
  const outra = rodada && !medida ? execucaoDoIncidente(rodada, incidente) : null;

  // Os eventos entre as etapas vão juntos numa linha do tempo; cada etapa é um bloco.
  const blocos: ReactNode[] = [];
  let pendentes: LogEvent[] = [];
  let numero = 0;
  const fecharPassos = () => {
    if (pendentes.length > 0) {
      blocos.push(<Passos key={`passos-${pendentes[0].id}`} eventos={pendentes} replay={replay} />);
      pendentes = [];
    }
  };
  for (const item of fluxo) {
    if (item.tipo === "evento") {
      const linha = linhas.get(item.evento.id);
      if (linha) {
        pendentes.push(linha);
      }
      continue;
    }
    fecharPassos();
    numero += 1;
    const fim = linhas.get(item.id)?.n ?? 0;
    blocos.push(<Etapa key={item.id} etapa={item} numero={numero} linhas={linhas} replay={replay} futura={fim > replay.estado.passo} />);
  }
  fecharPassos();

  return (
    <div className="sx-stack">
      {medida && (
        <Panel eyebrow="Rodada final" title="O que a rodada mediu nesta execução">
          <MedidasDaExecucao execucao={medida} />
        </Panel>
      )}
      <Panel
        eyebrow="Ponta a ponta"
        title="Do classificador ao efeito"
        actions={etapas.length > 0 ? <span className="data-sm sx-muted">esmaecidas: depois do cursor do replay</span> : undefined}
      >
        {etapas.length === 0 ? (
          <EmptyState
            icon="bot"
            title="Os agentes não trataram este incidente neste log"
            action={
              outra && escolherExecucao ? (
                <Button variant="secondary" icon="history" onClick={() => escolherExecucao(outra)}>
                  Abrir a execução do {incidente}
                </Button>
              ) : undefined
            }
          >
            {rodada
              ? `Na rodada, cada execução trata um incidente: nesta, os agentes trataram o ${rodada.execucao.incidente}, e o ${incidente} aparece como o classificador o abriu.`
              : "O classificador abriu o incidente, mas nenhum agente rodou nele."}
          </EmptyState>
        ) : (
          <div className="sx-stack sx-stack--sm">
            <p className="body-sm sx-muted app-nota">
              Cada etapa mostra o que o agente recebeu (o prompt de sistema com as skills e o pedido do orquestrador), cada tool que ele pediu e o que ela devolveu,
              os avisos do laço e a resposta final, na ordem. Os argumentos das tools, escritos pelo modelo, ficam na borda tracejada. Entre as etapas ficam as
              decisões sobre as propostas.
            </p>
            {etapasComConversa(fluxo) === 0 && (
              <Alert title="Este log não traz a conversa dos agentes.">
                Ele foi gravado antes do contrato 0.8.0: as etapas mostram as chamadas à IA e o que cada agente deixou no log, sem as mensagens.
              </Alert>
            )}
            <ol className="app-ponta">{blocos}</ol>
          </div>
        )}
      </Panel>
    </div>
  );
}
