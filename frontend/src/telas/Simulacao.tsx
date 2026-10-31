import { useRef, useState } from "react";
import { propostasDaTela } from "../adaptador";
import {
  AGENT,
  Alert,
  Button,
  CATEGORY,
  CategoryBars,
  EmptyState,
  Icon,
  IncidentQueue,
  MetricCard,
  PageHeader,
  Panel,
  ProposalCard,
  StatusBadge,
  fmtInt,
  type AnyCategory,
  type IconName,
  type Proposal,
} from "../design-system";
import {
  ErroDaSimulacao,
  agentesAtivos,
  iniciarSimulacao,
  pararSimulacao,
  tamanhoDoArquivo,
  ultimoAgente,
  type AgentesDaSimulacao,
  type IncidenteNosAgentes,
  type ResultadoDaSimulacao,
} from "../simulacao";
import type { Evento } from "../types";
import { AVISO_DO_EFEITO, DialogoDeDecisao, type PedidoDeDecisao } from "./comum";
import type { PropsDaTela } from "./replay";

export interface PropsDaSimulacao extends PropsDaTela {
  /** A última simulação, guardada pelo app para sobreviver à troca de tela. */
  resultado?: ResultadoDaSimulacao | null;
  /** Chamado com o resultado: o app carrega o log dele nas outras telas. */
  aoSimular?: (resultado: ResultadoDaSimulacao) => void;
}

interface Etapa {
  icone: IconName;
  titulo: string;
  detalhe: string;
  feita: boolean;
}

/** Como o orquestrador terminou cada incidente, para quem lê a tela. */
const DESFECHO: Record<string, string> = {
  resolvido: "Resolvido: efeito verificado",
  sem_resolucao: "Sem resolução depois de todas as rodadas",
  incidente_encerrado: "O incidente já estava encerrado",
  agente_parou: "Um agente parou antes do fim: o incidente segue aberto, sem ação",
  sem_proposta: "O agente de decisão não propôs ação",
  sem_aprovacao: "Sem decisão de uma pessoa a tempo",
  todas_rejeitadas: "Propostas rejeitadas",
  efeito_nao_verificado: "O efeito não foi verificado",
};

function tratados(agentes: AgentesDaSimulacao): string {
  const total = agentes.incidentes.length;
  const feitos = agentes.incidentes.filter((item) => item.situacao === "concluido" || item.situacao === "erro").length;
  return `${fmtInt(feitos)} de ${fmtInt(total)} ${total === 1 ? "incidente tratado" : "incidentes tratados"}`;
}

function etapaDosAgentes({ agentes }: ResultadoDaSimulacao): Etapa {
  const etapa = { icone: "bot" as IconName, titulo: "Agentes" };
  if (agentes.estado === "sem_incidentes") {
    return { ...etapa, detalhe: "Nenhum incidente para os agentes", feita: true };
  }
  if (agentes.estado === "sem_modelo") {
    return { ...etapa, detalhe: agentes.motivo ?? "O modelo não está configurado", feita: false };
  }
  return { ...etapa, detalhe: `Triagem, decisão, aprovação e execução: ${tratados(agentes)}`, feita: agentes.estado === "concluidos" };
}

/** Em que ponto o incidente está: o ícone e o texto da linha dele. */
function situacaoNaTela(item: IncidenteNosAgentes, ativos: boolean, eventos: Evento[], pendentes: Proposal[]): { icone: IconName; texto: string; feita: boolean } {
  if (item.situacao === "na_fila") {
    return ativos ? { icone: "clock", texto: "Na fila", feita: false } : { icone: "pause", texto: "Não tratado", feita: false };
  }
  if (item.situacao === "concluido") {
    return { icone: "circle-check", texto: DESFECHO[item.desfecho ?? ""] ?? "Concluído", feita: true };
  }
  if (item.situacao === "erro") {
    return { icone: "circle-x", texto: item.erro ?? "Os agentes falharam neste incidente", feita: false };
  }
  if (item.situacao === "interrompido") {
    return { icone: "pause", texto: "Interrompido", feita: false };
  }
  if (pendentes.some((proposta) => proposta.incident === item.id)) {
    return { icone: "hourglass", texto: "Aguardando a decisão de uma pessoa", feita: false };
  }
  const agente = ultimoAgente(eventos, item.id);
  return { icone: "loader-circle", texto: agente ? `Agente de ${AGENT[agente].label.toLowerCase()}` : "Começando", feita: false };
}

function etapas(r: ResultadoDaSimulacao): Etapa[] {
  const { regra, limiar, seguidas } = r.ponto_de_operacao;
  const eventos = r.eventos.split("\n").filter(Boolean).length;
  const alem = r.incidentes_alem_do_teto > 0 ? `, mais ${fmtInt(r.incidentes_alem_do_teto)} além do teto` : "";
  const puladas = r.janelas_puladas > 0 ? `, das quais ${fmtInt(r.janelas_puladas)} do trecho de treino ficaram de fora da classificação` : "";
  return [
    { icone: "file-text", titulo: "pcap", detalhe: `${r.arquivo}: ${fmtInt(r.quadros)} quadros`, feita: true },
    {
      icone: "scan-search",
      titulo: "Extrator",
      detalhe: `${fmtInt(r.janelas)} janelas de 100 quadros${puladas}; ${fmtInt(r.ignorados)} quadros fora do filtro (nem IPv4 nem ARP)`,
      feita: true,
    },
    {
      icone: "brain-circuit",
      titulo: "Classificador",
      detalhe: `${r.modelo}, regra ${regra === "argmax" ? "argmax" : `limiar ${limiar}`}, incidente com ${seguidas} janelas de ataque seguidas`,
      feita: true,
    },
    {
      icone: "siren",
      titulo: "Política de acionamento",
      detalhe: `${fmtInt(r.incidentes.length)} ${r.incidentes.length === 1 ? "incidente" : "incidentes"}${alem}`,
      feita: true,
    },
    { icone: "server", titulo: "Servidor MCP", detalhe: `${fmtInt(eventos)} eventos no log ${r.log}`, feita: true },
    etapaDosAgentes(r),
  ];
}

function mediana(valores: number[]): number | null {
  if (valores.length === 0) {
    return null;
  }
  const ordenados = [...valores].sort((a, b) => a - b);
  return ordenados[Math.floor(ordenados.length / 2)];
}

const segundos = (valor: number) => `${valor.toFixed(valor < 10 ? 2 : 1).replace(".", ",")} s`;

/** Duração em s, min ou h, conforme o tamanho. */
function duracao(valor: number): string {
  if (valor >= 3600) {
    return `${(valor / 3600).toFixed(1).replace(".", ",")} h`;
  }
  if (valor >= 60) {
    return `${(valor / 60).toFixed(1).replace(".", ",")} min`;
  }
  return segundos(valor);
}

/** Simulação: um pcap anexado passa pelo sistema inteiro, e cada incidente segue como um incidente de verdade. */
export function TelaSimulacao({ replay, navegar, resultado = null, aoSimular }: PropsDaSimulacao) {
  const entrada = useRef<HTMLInputElement>(null);
  const [arquivo, setArquivo] = useState<File | null>(null);
  const [soTeste, setSoTeste] = useState(true);
  const [rodando, setRodando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);
  const [decisao, setDecisao] = useState<PedidoDeDecisao | null>(null);
  const [erroAoParar, setErroAoParar] = useState<string | null>(null);

  const iniciar = async () => {
    if (!arquivo) {
      return;
    }
    setRodando(true);
    setErro(null);
    try {
      aoSimular?.(await iniciarSimulacao(arquivo, arquivo.name, soTeste));
    } catch (falha) {
      setErro(falha instanceof ErroDaSimulacao ? falha.message : "Falha inesperada ao enviar o pcap.");
    } finally {
      setRodando(false);
    }
  };

  const atraso = resultado ? mediana(resultado.incidentes.map((i) => i.atraso_de_deteccao_s)) : null;
  const porCategoria = resultado
    ? Object.entries(resultado.por_categoria)
        .filter(([categoria]) => categoria in CATEGORY)
        .map(([categoria, valor]) => ({ category: categoria as AnyCategory, value: valor }))
    : [];
  const agentes = resultado?.agentes ?? null;
  const ativos = agentes !== null && agentesAtivos(agentes);
  const pendentes = replay.estado.agregado.incidentes.flatMap((view) => propostasDaTela(view).filter((proposta) => proposta.state === "aguardando_aprovacao"));

  const parar = async () => {
    setErroAoParar(null);
    try {
      await pararSimulacao();
    } catch (falha) {
      setErroAoParar(falha instanceof ErroDaSimulacao ? falha.message : "Falha inesperada ao pedir a parada.");
    }
  };

  return (
    <>
      <PageHeader eyebrow="SentryIoT" title="Simulação com um pcap" />
      <div className="sx-grid">
        <Panel className="sx-span-12" eyebrow="Captura" title="Iniciar simulação">
          <p className="body-sm sx-muted app-nota">
            O pcap passa pelo extrator, pelo classificador e pela política de acionamento, e cada incidente segue para os agentes: triagem,
            decisão, aprovação de uma pessoa quando o risco é alto, execução e verificação do efeito.
          </p>
          <div className="app-simulacao-envio">
            <input
              ref={entrada}
              className="app-escondido"
              type="file"
              accept=".pcap,application/vnd.tcpdump.pcap"
              aria-label="Arquivo pcap"
              onChange={(evento) => {
                setArquivo(evento.target.files?.[0] ?? null);
                setErro(null);
              }}
            />
            <Button icon="upload" onClick={() => entrada.current?.click()} disabled={rodando}>
              {arquivo ? "Trocar o pcap" : "Anexar pcap"}
            </Button>
            <span className="body-sm sx-muted app-nome-do-arquivo">
              {arquivo ? (
                <>
                  <span className="data-sm">{arquivo.name}</span> · {tamanhoDoArquivo(arquivo.size)}
                </>
              ) : (
                "Nenhum arquivo escolhido. Formato pcap clássico, Ethernet, até 600 MB."
              )}
            </span>
            <label className="body-sm app-opcao">
              <input type="checkbox" checked={soTeste} onChange={(evento) => setSoTeste(evento.target.checked)} disabled={rodando} />
              Só o trecho que o modelo não viu no treino
            </label>
            <Button variant="primary" icon="play" onClick={iniciar} disabled={!arquivo || rodando || ativos} loading={rodando}>
              {rodando ? "Processando…" : "Iniciar simulação"}
            </Button>
          </div>
          {erro && (
            <Alert tone="danger" title="A simulação não rodou." className="app-simulacao-erro">
              {erro}
            </Alert>
          )}
        </Panel>

        {!resultado ? (
          <Panel className="sx-span-12" eyebrow="Resultado" title="Nenhuma simulação ainda">
            <EmptyState icon="flask-conical" title="Anexe um pcap e inicie a simulação">
              Os incidentes encontrados aparecem aqui e nas telas de operação, e os agentes tratam cada um deles. O que depende de uma pessoa
              espera a decisão nesta tela.
            </EmptyState>
          </Panel>
        ) : (
          <>
            {!resultado.trecho.so_teste && (
              <Alert tone="attention" title="Esta simulação inclui o trecho do pcap usado no treino do modelo." className="sx-span-12">
                Os incidentes servem para demonstrar o fluxo, e não para medir a detecção. Para medir, marque "só o trecho que o modelo não viu
                no treino" ou use um pcap que ficou inteiro fora do treino.
              </Alert>
            )}
            <Panel className="sx-span-12" eyebrow="Fluxo" title={`Do ${resultado.arquivo} até a resposta ao incidente`}>
              <ol className="app-fluxo">
                {etapas(resultado).map((etapa) => (
                  <li key={etapa.titulo} className={etapa.feita ? "app-fluxo__etapa is-feita" : "app-fluxo__etapa is-parada"}>
                    <Icon name={etapa.feita ? "circle-check" : etapa.titulo === "Agentes" && ativos ? "loader-circle" : "pause"} size={18} />
                    <Icon name={etapa.icone} size={18} />
                    <span className="app-fluxo__titulo">{etapa.titulo}</span>
                    <span className="body-sm sx-muted">{etapa.detalhe}</span>
                  </li>
                ))}
              </ol>
            </Panel>
            {pendentes.length > 0 && (
              <Panel className="sx-span-12" eyebrow="Requer você" title="Decisões pendentes" tone="attention" actions={<StatusBadge kind="proposal" value="aguardando_aprovacao" />}>
                <div className="sx-stack sx-stack--sm">
                  {pendentes.map((proposta) => (
                    <ProposalCard key={proposta.id} proposal={proposta} onApprove={() => setDecisao({ tipo: "approve", proposta })} onReject={() => setDecisao({ tipo: "reject", proposta })} />
                  ))}
                </div>
              </Panel>
            )}
            {agentes && agentes.incidentes.length > 0 && (
              <Panel
                className="sx-span-12"
                eyebrow="Agentes"
                title="Resposta aos incidentes"
                actions={
                  ativos ? (
                    <Button size="sm" variant="secondary" icon="pause" onClick={parar} disabled={agentes.estado === "parando"}>
                      {agentes.estado === "parando" ? "Parando…" : "Parar os agentes"}
                    </Button>
                  ) : undefined
                }
              >
                <p className="body-sm sx-muted app-nota">
                  Configuração {agentes.configuracao}, modelo <span className="data-sm">{agentes.modelo || "não configurado"}</span>. Um incidente por vez,
                  na ordem em que abriram.
                </p>
                <ol className="app-fluxo app-simulacao-bloco">
                  {agentes.incidentes.map((item) => {
                    const situacao = situacaoNaTela(item, ativos, replay.eventos, pendentes);
                    return (
                      <li key={item.id} className={situacao.feita ? "app-fluxo__etapa is-feita" : "app-fluxo__etapa"}>
                        <Icon name={situacao.icone} size={18} />
                        <Icon name="shield-alert" size={18} />
                        <span className="app-fluxo__titulo data-sm">
                          <Button size="sm" variant="ghost" onClick={() => navegar({ tela: "incidente", incidente: item.id })}>
                            {item.id}
                          </Button>
                        </span>
                        <span className="body-sm sx-muted">{situacao.texto}</span>
                      </li>
                    );
                  })}
                </ol>
                <p className="body-sm sx-muted app-nota app-simulacao-bloco">{AVISO_DO_EFEITO}</p>
                {erroAoParar && (
                  <Alert tone="danger" title="Os agentes não pararam." className="app-simulacao-erro">
                    {erroAoParar}
                  </Alert>
                )}
              </Panel>
            )}
            <MetricCard className="sx-span-3" label="Janelas" value={resultado.janelas} icon="layers" context={`${fmtInt(resultado.quadros)} quadros lidos`} />
            <MetricCard
              className="sx-span-3"
              label="Incidentes"
              value={resultado.incidentes.length}
              icon="shield-alert"
              context={resultado.incidentes_alem_do_teto > 0 ? `${fmtInt(resultado.incidentes_alem_do_teto)} além do teto` : "Todos dentro do teto."}
            />
            <MetricCard
              className="sx-span-3"
              label="Tempo até a detecção"
              value={atraso === null ? "—" : segundos(atraso)}
              icon="timer"
              context={atraso === null ? "Sem incidente." : "Mediana, da primeira janela de ataque à abertura."}
            />
            <MetricCard
              className="sx-span-3"
              label="Processamento"
              value={segundos(resultado.processamento_s)}
              icon="gauge"
              context={`O pcap cobre ${duracao(resultado.duracao_do_pcap_s)} de captura.`}
            />
            <Panel className="sx-span-12" eyebrow="Classificador" title="Janelas por categoria">
              <CategoryBars data={porCategoria} showShare ariaLabel="Janelas do pcap em cada categoria do modelo" />
            </Panel>
            <Panel
              className="sx-span-12"
              eyebrow="Servidor MCP"
              title="Incidentes no log"
              flush
              actions={
                <Button size="sm" variant="ghost" icon="layout-dashboard" onClick={() => navegar({ tela: "visao-geral", incidente: null })}>
                  Visão geral
                </Button>
              }
            >
              <IncidentQueue
                incidents={replay.estado.incidentes}
                onSelect={(id) => navegar({ tela: "incidente", incidente: id })}
                empty={
                  <EmptyState icon="shield-check" title="Nenhum incidente">
                    Nenhuma sequência de janelas de ataque chegou ao ponto de operação neste pcap.
                  </EmptyState>
                }
              />
            </Panel>
          </>
        )}
      </div>
      <DialogoDeDecisao pedido={decisao} aoFechar={() => setDecisao(null)} />
    </>
  );
}
