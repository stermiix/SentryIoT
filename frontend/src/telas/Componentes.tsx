import { useState, type ReactNode } from "react";
import { detalheDoIncidente, estadoNoPasso, passoComMaisPendencias, provedoresDoChat } from "../adaptador";
import {
  AGENT,
  ASSETS,
  AddressList,
  AgentBadge,
  AggregationFunnel,
  Alert,
  AreaChart,
  Button,
  CATEGORY,
  CategoryBadge,
  CategoryBars,
  ChannelTag,
  ChatMessage,
  ClassifierVerdict,
  ConfidenceMeter,
  ConfirmDialog,
  ConfusionMatrix,
  EFFECT,
  EVENT,
  EVENT_TYPES,
  EmptyState,
  EventTimeline,
  FeatureTable,
  GlassBackdrop,
  INCIDENT_CATEGORIES,
  INCIDENT_STATE,
  Icon,
  IconButton,
  IncidentQueue,
  Kbd,
  Logo,
  MODEL_CATEGORIES,
  MetricCard,
  ModeIndicator,
  ModelSelect,
  PROPOSAL_STATE,
  PageHeader,
  Panel,
  PromptBox,
  ProposalCard,
  ProviderBar,
  ReportFacts,
  ReportPage,
  ReportSection,
  RiskBadge,
  Segmented,
  Select,
  Sidebar,
  Skeleton,
  StatusBadge,
  Tabs,
  TargetLabel,
  TextField,
  Tooltip,
  VoiceQuote,
  cx,
  fmtInt,
  type AgentName,
  type EffectResult,
  type IconName,
  type IncidentState,
  type ProposalState,
} from "../design-system";
import { CLASSES, MATRIZ } from "../dados/qualidade";
import type { PropsDaTela } from "./replay";

// O catálogo do design system dentro do app: cada componente em seus estados. Os blocos que mostram
// dados usam o log carregado e, sem log, ficam vazios; os outros mostram o componente com valores
// de amostra. Serve para conferir o visual e escolher o componente certo antes de montar uma tela.

function Linha({ rotulo, children, cinza }: { rotulo: string; children?: ReactNode; cinza?: boolean }) {
  return (
    <div className="sx-demo__row">
      <span className="sx-demo__label sx-eyebrow eyebrow">{rotulo}</span>
      <div className={cx("sx-demo__items", cinza && "sx-demo--gray")}>{children}</div>
    </div>
  );
}

function Grupo({ titulo, componentes, children }: { titulo: string; componentes: string; children: ReactNode }) {
  return (
    <Panel eyebrow={componentes} title={titulo}>
      <div className="sx-stack sx-stack--sm">{children}</div>
    </Panel>
  );
}

// Os diálogos do catálogo dizem o mesmo que os das telas: hoje a interface não grava decisões.
const NOTA_DO_LOG = "A interface ainda não grava decisões: confirmar mostra o comando do terminal que faz a mesma coisa.";

export function TelaComponentes({ replay }: PropsDaTela) {
  const [segmento, setSegmento] = useState("replay");
  const [aba, setAba] = useState("propostas");
  const [ativo, setAtivo] = useState("incidente");
  const [rascunho, setRascunho] = useState("O alerta é coerente com as features?");
  const { eventos, linhas, final } = replay;
  const passoPendente = passoComMaisPendencias(eventos, linhas);
  const pendente = estadoNoPasso(eventos, linhas, passoPendente);
  const fim = estadoNoPasso(eventos, linhas, eventos.length);
  const primeiro = fim.incidentes[0]?.id;
  const noFim = primeiro ? detalheDoIncidente(fim, final, linhas, primeiro) : null;
  const comPendencia = primeiro ? detalheDoIncidente(pendente, final, linhas, primeiro) : null;
  const aguardando = comPendencia?.propostas.find((proposta) => proposta.state === "aguardando_aprovacao");
  const chamadas = linhas.filter((linha) => linha.type === "llm_chamada");
  const modelos = Array.from(new Set(chamadas.map((chamada) => chamada.model ?? ""))).filter(Boolean);
  const provedores = provedoresDoChat(modelos.length > 0 ? modelos : ["modelo"]);
  const [modelo, setModelo] = useState(provedores[0]?.id ?? "");
  const recomendacao = noFim?.recomendacoes[0];
  const rejeitada = noFim?.propostas.find((proposta) => proposta.decision?.reason);

  return (
    <>
      <PageHeader
        eyebrow="Equipe · design system"
        title="Componentes"
        meta={
          <span className="body-sm sx-muted">
            Cada componente do design system. Os blocos de dados usam o log carregado e, sem log, ficam vazios. As regras de uso estão em src/design-system/README.md e
            COMPONENTES.md.
          </span>
        }
      />
      <div className="sx-stack">
        <Grupo titulo="Marca" componentes="Logo · GlassBackdrop · Icon · Kbd">
          <Linha rotulo="Tamanhos">
            <Logo src={ASSETS.mark64} size="sm" />
            <Logo src={ASSETS.mark128} size="md" />
            <Logo src={ASSETS.mark128} size="lg" />
          </Linha>
          <Linha rotulo="Grande">
            <Logo src={ASSETS.mark512} size="xl" />
          </Linha>
          <Linha rotulo="Só a marca">
            <Logo src={ASSETS.mark128} size="lg" wordmark={false} />
            <Logo src={ASSETS.mark128} size="md" descriptor={false} />
          </Linha>
          <div className="sx-demo-stage app-palco">
            <GlassBackdrop src={ASSETS.mark} variant="login" />
            <div className="sx-demo-stage__text">
              <span className="sx-accent-bar" />
              <span className="sx-wide eyebrow-wide">Resposta autônoma a intrusão</span>
              <span className="display-lg">Detecta. Responde.</span>
            </div>
          </div>
          {(
            [
              { rotulo: "Categorias", itens: (Object.keys(CATEGORY) as (keyof typeof CATEGORY)[]).map((k) => ({ icone: CATEGORY[k].icon, nome: CATEGORY[k].label, cor: `var(--${CATEGORY[k].token})` })) },
              { rotulo: "Agentes", itens: (Object.keys(AGENT) as AgentName[]).map((k) => ({ icone: AGENT[k].icon, nome: AGENT[k].label })) },
              { rotulo: `Eventos (${EVENT_TYPES.length})`, itens: EVENT_TYPES.map((t) => ({ icone: EVENT[t].icon, nome: EVENT[t].label })) },
            ] as { rotulo: string; itens: { icone: IconName; nome: string; cor?: string }[] }[]
          ).map((grupo) => (
            <Linha key={grupo.rotulo} rotulo={grupo.rotulo}>
              {grupo.itens.map((item) => (
                <span key={grupo.rotulo + item.nome} className="sx-demo__glyph" title={item.nome}>
                  <Icon name={item.icone} size={22} style={item.cor ? { color: item.cor } : undefined} />
                  <span className="data-sm">{item.nome}</span>
                </span>
              ))}
            </Linha>
          ))}
          <Linha rotulo="Teclas">
            <Kbd>←</Kbd>
            <Kbd>→</Kbd>
            <Kbd>Home</Kbd>
            <Kbd>End</Kbd>
            <Kbd>Espaço</Kbd>
            <Kbd>Esc</Kbd>
          </Linha>
        </Grupo>

        <Grupo titulo="Ações" componentes="Button · IconButton">
          <Linha rotulo="Variantes">
            <Button variant="primary" icon="file-output">Gerar relatório</Button>
            <Button variant="secondary" icon="user-check">Já resolvido</Button>
            <Button variant="ghost" iconRight="arrow-right">Histórico</Button>
            <Button variant="danger" icon="ban">Rejeitar</Button>
            <Button variant="danger" icon="undo-2">Desfazer</Button>
          </Linha>
          <Linha rotulo="Só no modal">
            <Button variant="confirm" icon="badge-check">Aprovar e executar</Button>
            <Button variant="danger-solid" icon="ban">Rejeitar</Button>
          </Linha>
          <Linha rotulo="Estados e tamanhos">
            <Button variant="secondary" size="sm">Pequeno 32</Button>
            <Button variant="secondary" disabled>Desabilitado</Button>
            <Button variant="primary" loading>Entrando</Button>
            <Button variant="primary" size="lg" iconRight="arrow-right">Grande 48</Button>
          </Linha>
          <Linha rotulo="Só ícone">
            <IconButton icon="chevron-left" label="Anterior" size="sm" />
            <IconButton icon="download" label="Baixar" />
            <IconButton icon="play" label="Reproduzir" variant="primary" />
            <IconButton icon="send-horizontal" label="Enviar" variant="primary" size="lg" />
            <IconButton icon="panel-left-close" label="Recolher" variant="ghost" size="sm" />
            <IconButton icon="pause" label="Pausar" pressed />
            <IconButton icon="chevron-last" label="Fim" disabled />
          </Linha>
        </Grupo>

        <Grupo titulo="Selos" componentes="CategoryBadge · StatusBadge · RiskBadge · AgentBadge · ChannelTag · TargetLabel">
          <Linha rotulo="Incidente (8)">{INCIDENT_CATEGORIES.map((c) => <CategoryBadge key={c} category={c} />)}</Linha>
          <Linha rotulo="Modelo (7)">{MODEL_CATEGORIES.map((c) => <CategoryBadge key={c} category={c} model />)}</Linha>
          <Linha rotulo="Escala de cinza" cinza>{INCIDENT_CATEGORIES.map((c) => <CategoryBadge key={c} category={c} />)}</Linha>
          <Linha rotulo="Incidente">{(Object.keys(INCIDENT_STATE) as IncidentState[]).map((v) => <StatusBadge key={v} kind="incident" value={v} />)}</Linha>
          <Linha rotulo="Proposta">{(Object.keys(PROPOSAL_STATE) as ProposalState[]).map((v) => <StatusBadge key={v} kind="proposal" value={v} />)}</Linha>
          <Linha rotulo="Execução e efeito">
            <StatusBadge kind="execution" value="aplicada" />
            <StatusBadge kind="execution" value="desfeita" />
            {(Object.keys(EFFECT) as EffectResult[]).map((v) => <StatusBadge key={v} kind="effect" value={v} />)}
          </Linha>
          <Linha rotulo="Risco">
            <RiskBadge level="baixo" />
            <RiskBadge level="alto" />
            <RiskBadge level="alto" size="sm" />
          </Linha>
          <Linha rotulo="Agentes">
            <AgentBadge agent="triagem" />
            <AgentBadge agent="decisao" location="nuvem" model={modelos[0]} />
            <AgentBadge agent="execucao" location="local" />
          </Linha>
          <Linha rotulo="Canal e alvo">
            <ChannelTag channel="terminal" user="operador" at="14:05:16" />
            <ChannelTag channel="interface" />
            {noFim?.origens[0] && <TargetLabel label={noFim.origens[0].label} address={noFim.origens[0].address} />}
            <TargetLabel label="destino-1" />
          </Linha>
        </Grupo>

        <Grupo titulo="Navegação e superfícies" componentes="Sidebar · PageHeader · ModeIndicator · Segmented · Tabs · Panel">
          <div className="sx-demo sx-demo--row app-demo-barra">
            <Sidebar
              logoSrc={ASSETS.mark128}
              activeId={ativo}
              onNavigate={setAtivo}
              onToggle={() => undefined}
              sections={[
                { label: "Operação", items: [{ id: "visao-geral", label: "Visão geral", icon: "layout-dashboard" }, { id: "incidente", label: "Incidentes", icon: "shield-alert", count: 2, attention: true }, { id: "ao-vivo", label: "Ao vivo", icon: "radio", planned: true }] },
                { label: "Equipe", items: [{ id: "chat", label: "Chat com o modelo", icon: "messages-square" }] },
              ]}
            />
            <Sidebar logoSrc={ASSETS.mark128} activeId={ativo} onNavigate={setAtivo} collapsed onToggle={() => undefined} sections={[{ label: "Operação", items: [{ id: "visao-geral", label: "Visão geral", icon: "layout-dashboard" }, { id: "incidente", label: "Incidentes", icon: "shield-alert", count: 2, attention: true }] }]} />
          </div>
          <Linha rotulo="Modo">
            <ModeIndicator mode="replay" position={replay.passo} total={replay.estado.total} at={replay.estado.atual?.at} />
            <ModeIndicator mode="ao-vivo" at={replay.estado.atual?.at} />
          </Linha>
          <Linha rotulo="Segmentos">
            <Segmented label="Modo" value={segmento} onChange={setSegmento} options={[{ value: "replay", label: "Replay", icon: "history" }, { value: "ao-vivo", label: "Ao vivo", icon: "radio" }]} />
          </Linha>
          <Tabs label="Seções do incidente" value={aba} onChange={setAba} tabs={[{ id: "veredito", label: "Veredito" }, { id: "agentes", label: "Agentes", count: noFim?.chamadas }, { id: "propostas", label: "Propostas", count: noFim?.propostas.length }, { id: "historico", label: "Histórico" }]} />
          <div className="sx-split">
            <Panel eyebrow="Classificador" title="Painel comum">
              <p className="body sx-muted app-nota">A superfície de todo bloco.</p>
            </Panel>
            <Panel eyebrow="Requer você" title="Painel em atenção" tone="attention" actions={<StatusBadge kind="proposal" value="aguardando_aprovacao" />}>
              <p className="body sx-muted app-nota">Quando algo dentro espera uma pessoa.</p>
            </Panel>
          </div>
        </Grupo>

        <Grupo titulo="Formulários" componentes="TextField · Select">
          <div className="sx-demo__grid2">
            <TextField label="Usuário" icon="user" placeholder="ex.: operador" />
            <TextField label="Senha" type="password" icon="lock" defaultValue="segredo" />
            <TextField label="Motivo da rejeição (opcional)" placeholder="Escreva com suas palavras" hint="Aparece como texto de pessoa no log." />
            <TextField label="Senha" type="password" icon="lock" defaultValue="errada" error="Senha incorreta." />
            <Select label="Incidente" options={fim.incidentes.map((incidente) => ({ value: incidente.id, label: `${incidente.id} · ${incidente.category ?? incidente.modelCategory}` }))} />
            <TextField label="Desabilitado" defaultValue={primeiro ?? "sem incidente"} disabled />
          </div>
        </Grupo>

        <Grupo titulo="Dados" componentes="AggregationFunnel · MetricCard · ConfidenceMeter · ClassifierVerdict · IncidentQueue · FeatureTable · AddressList">
          <AggregationFunnel windows={fim.janelas} counterfactual={fim.janelasDeAtaque} incidents={fim.incidentes.length} aiCalls={fim.chamadas} scope={`log carregado · ${fim.total} eventos`} />
          <div className="sx-demo__grid4">
            <MetricCard label="Janelas analisadas" value={fim.janelas} icon="layers" context={`em ${fim.total} eventos do log`} />
            <MetricCard label="Aguardando aprovação" value={pendente.aguardando} icon="hourglass" tone="attention" context={`no evento ${passoPendente}`} />
            <MetricCard label="Tokens" value={fim.tokens} icon="coins" spark={fim.tokensAcumulados} context={`${fim.chamadas} chamadas à IA`} />
            <MetricCard label="Latência" value="2,1" unit="s" icon="timer" delta={{ text: "exemplo de variação", tone: "neutral" }} context="cartão com unidade e variação" />
          </div>
          <Linha rotulo="Confiança">
            <ConfidenceMeter value={0.97} />
            <ConfidenceMeter value={0.55} />
            <ConfidenceMeter value={0.91} format="decimal" />
            <ConfidenceMeter value={0.93} size="sm" />
          </Linha>
          {noFim && (
            <>
              <ClassifierVerdict model={noFim.incidente.modelCategory} category={noFim.incidente.category} sources={noFim.incidente.sources} confidence={noFim.incidente.confidence} />
              <ClassifierVerdict model={noFim.incidente.modelCategory} sources={noFim.incidente.sources} confidence={noFim.incidente.confidence} />
              <Panel eyebrow="Fila" title="Incidentes" flush>
                <IncidentQueue incidents={fim.incidentes} selectedId={primeiro} />
              </Panel>
              <Panel eyebrow="Features" title="Contra a referência benigna" flush>
                <FeatureTable rows={noFim.features} />
              </Panel>
              <div className="sx-split">
                <Panel eyebrow="Endereços" title="Resolvidos localmente">
                  <AddressList title="Origens" items={noFim.origens} total={noFim.incidente.sources} />
                </Panel>
                <Panel eyebrow="Endereços" title="Como a nuvem vê">
                  <div className="sx-stack sx-stack--sm">
                    <AddressList title="Origens" items={noFim.origens.slice(0, 3)} total={noFim.incidente.sources} hideAddresses />
                    <AddressList title="Destinos" items={noFim.destinos} total={noFim.incidente.destinations} hideAddresses />
                  </div>
                </Panel>
              </div>
            </>
          )}
        </Grupo>

        <Grupo titulo="Agentes e decisões" componentes="EventTimeline · ProposalCard · VoiceQuote">
          <div className="sx-split">
            <Panel eyebrow={`Replay no evento ${passoPendente}`} title="Completa">
              <EventTimeline events={linhas.slice(Math.max(0, passoPendente - 6), passoPendente + 4)} cursor={passoPendente} />
            </Panel>
            <Panel eyebrow="Rastro dos agentes" title="Compacta">
              <EventTimeline events={linhas.filter((linha) => linha.agent).slice(0, 10)} density="compact" cursor={passoPendente} />
            </Panel>
          </div>
          <div className="sx-split">
            <div className="sx-stack sx-stack--sm">
              {aguardando && <ProposalCard proposal={aguardando} onApprove={() => undefined} onReject={() => undefined} />}
            </div>
            <div className="sx-stack sx-stack--sm">
              {noFim?.propostas.map((proposta) => <ProposalCard key={proposta.id} proposal={proposta} />)}
            </div>
          </div>
          <div className="sx-split">
            {recomendacao && (
              <VoiceQuote voice="agent" agent={recomendacao.agent} author={recomendacao.model} refId={recomendacao.id} at={recomendacao.at}>
                {recomendacao.text}
              </VoiceQuote>
            )}
            {rejeitada?.decision?.reason && (
              <VoiceQuote voice="person" author={rejeitada.decision.user} channel={rejeitada.decision.channel} refId={rejeitada.id} at={rejeitada.decision.at}>
                {rejeitada.decision.reason}
              </VoiceQuote>
            )}
          </div>
        </Grupo>

        <Grupo titulo="Avisos" componentes="Alert · EmptyState · Skeleton · Tooltip · ConfirmDialog">
          <Alert tone="info" title="Replay carregado">{`${fim.total} eventos no log.`}</Alert>
          <Alert tone="attention" title="Linha inválida no log, ignorada" line={37} onDismiss={() => undefined}>JSON incompleto. A tela segue com os outros eventos.</Alert>
          <Alert tone="danger" title="O log não pôde ser lido">O arquivo não existe na pasta configurada.</Alert>
          <div className="sx-split">
            <EmptyState icon="shield-check" title="Nenhum incidente até aqui">As janelas classificadas até este evento não viraram incidente.</EmptyState>
            <div className="sx-stack sx-stack--sm">
              <Skeleton lines={3} />
              <Skeleton shape="block" height={64} />
              <span className="app-espaco-dica">
                <Tooltip content="Negação de serviço distribuída: muitas origens.">
                  <span tabIndex={0}><CategoryBadge category="DDoS" /></span>
                </Tooltip>
              </span>
            </div>
          </div>
          {aguardando && (
            <div className="sx-demo__grid3">
              <ConfirmDialog inline open logNote={NOTA_DO_LOG} kind="approve" subject={aguardando.action} refId={aguardando.id} user="operador" reasons={aguardando.reasons} summary={[{ label: "Alvo", value: <TargetLabel label={aguardando.target.label} address={aguardando.target.address} free={aguardando.target.free} /> }, { label: "Risco", value: <RiskBadge level={aguardando.risk} /> }]} />
              <ConfirmDialog inline open logNote={NOTA_DO_LOG} kind="reject" subject={aguardando.action} refId={aguardando.id} user="operador" />
              <ConfirmDialog inline open logNote={NOTA_DO_LOG} kind="resolve" subject={primeiro ?? ""} refId={primeiro ?? ""} user="operador" />
            </div>
          )}
        </Grupo>

        <Grupo titulo="Gráficos" componentes="AreaChart · CategoryBars · ConfusionMatrix">
          {chamadas.length > 1 && (
            <AreaChart
              ariaLabel="Tokens e latência por chamada à IA"
              labels={chamadas.map((chamada) => chamada.at)}
              series={[{ name: "Tokens", values: chamadas.map((chamada) => chamada.tokens ?? 0) }, { name: "Latência (ms)", values: chamadas.map((chamada) => Math.round((chamada.seconds ?? 0) * 1000)) }]}
              defaultIndex={1}
            />
          )}
          <div className="sx-split">
            <CategoryBars ariaLabel="Janelas de teste por classe" showShare data={CLASSES.map((classe, i) => ({ category: classe, value: MATRIZ[i].reduce((soma, valor) => soma + valor, 0) }))} />
            <div className="sx-demo--gray">
              <CategoryBars ariaLabel="Janelas de teste por classe, em cinza" data={CLASSES.map((classe, i) => ({ category: classe, value: MATRIZ[i].reduce((soma, valor) => soma + valor, 0) }))} />
            </div>
          </div>
          <ConfusionMatrix labels={CLASSES} matrix={MATRIZ} />
        </Grupo>

        <Grupo titulo="Chat" componentes="ChatMessage · PromptBox · ModelSelect · ProviderBar">
          <ProviderBar providers={provedores} selectedId={modelo} onSelect={setModelo} />
          <div className="sx-chatlog">
            <ChatMessage role="system">Skill carregada · prompt de sistema trocado</ChatMessage>
            <ChatMessage role="user">O alerta do {primeiro ?? "incidente"} é coerente com as features?</ChatMessage>
            <ChatMessage role="assistant" author={modelo} tokens={1336} seconds={2.1}>Mensagem do modelo, na voz de agente.</ChatMessage>
            <ChatMessage role="assistant" author={modelo} tokens={null} seconds={1.4}>Resposta de um provedor que não informa os tokens.</ChatMessage>
          </div>
          <PromptBox value={rascunho} onChange={setRascunho} tokens={Math.ceil(rascunho.length / 4)} tools={<ModelSelect providers={provedores} value={modelo} onChange={setModelo} compact />} />
          <PromptBox value="" disabled placeholder="Enviando: a caixa espera a resposta" />
        </Grupo>

        <Grupo titulo="Relatório" componentes="ReportCover · ReportPage · ReportSection · ReportFacts">
          <p className="body sx-muted app-nota">A capa e as páginas completas estão na tela Relatórios. Aqui, uma página com as três peças.</p>
          <div className="app-relatorio">
            <ReportPage logoSrc={ASSETS.mark128} docTitle="Relatório de incidente · exemplo" date="2026-10-20" page={2} pages={3}>
              <ReportSection n="01" title="Fatos do log">
                <ReportFacts items={[{ label: "Janelas", value: fmtInt(fim.janelas) }, { label: "Incidentes", value: fmtInt(fim.incidentes.length) }, { label: "Chamadas à IA", value: fmtInt(fim.chamadas) }]} />
              </ReportSection>
              {recomendacao && (
                <ReportSection n="02" title="Recomendação" voice="agent" agent={recomendacao.agent}>
                  <p>{recomendacao.text}</p>
                </ReportSection>
              )}
            </ReportPage>
          </div>
        </Grupo>
      </div>
    </>
  );
}
