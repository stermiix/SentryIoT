import { useRef, useState } from "react";
import {
  AgentBadge,
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
  fmtInt,
  type AnyCategory,
  type IconName,
} from "../design-system";
import { ErroDaSimulacao, iniciarSimulacao, parametrosDoPedido, tamanhoDoArquivo, type ResultadoDaSimulacao } from "../simulacao";
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
    {
      icone: "send-horizontal",
      titulo: "Modelo da triagem",
      detalhe: r.para_o_llm ? `pedido de ${r.para_o_llm.incidente} montado, não enviado` : "nenhum incidente para enviar",
      feita: false,
    },
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

/** Simulação: um pcap anexado passa pelo sistema até a porta do modelo da triagem, sem chamá-lo. */
export function TelaSimulacao({ replay, navegar, resultado = null, aoSimular }: PropsDaSimulacao) {
  const entrada = useRef<HTMLInputElement>(null);
  const [arquivo, setArquivo] = useState<File | null>(null);
  const [soTeste, setSoTeste] = useState(true);
  const [rodando, setRodando] = useState(false);
  const [erro, setErro] = useState<string | null>(null);

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
  const llm = resultado?.para_o_llm ?? null;

  return (
    <>
      <PageHeader eyebrow="SentryIoT" title="Simulação com um pcap" />
      <div className="sx-grid">
        <Panel className="sx-span-12" eyebrow="Captura" title="Iniciar simulação">
          <p className="body-sm sx-muted app-nota">
            O pcap passa pelo extrator, pelo classificador e pela política de acionamento; os incidentes vão para o log do servidor MCP, e o
            pedido ao modelo da triagem é montado sem ser enviado.
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
            <Button variant="primary" icon="play" onClick={iniciar} disabled={!arquivo || rodando} loading={rodando}>
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
              Os incidentes encontrados aparecem aqui e nas telas de operação. O pedido ao modelo da triagem é mostrado como iria, sem envio.
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
            <Panel className="sx-span-12" eyebrow="Fluxo" title={`Do ${resultado.arquivo} até a porta do modelo`}>
              <ol className="app-fluxo">
                {etapas(resultado).map((etapa) => (
                  <li key={etapa.titulo} className={etapa.feita ? "app-fluxo__etapa is-feita" : "app-fluxo__etapa is-parada"}>
                    <Icon name={etapa.feita ? "circle-check" : "pause"} size={18} />
                    <Icon name={etapa.icone} size={18} />
                    <span className="app-fluxo__titulo">{etapa.titulo}</span>
                    <span className="body-sm sx-muted">{etapa.detalhe}</span>
                  </li>
                ))}
              </ol>
            </Panel>
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
            {llm && (
              <Panel
                className="sx-span-12"
                eyebrow="Na porta do modelo"
                title={`Pedido à triagem para ${llm.incidente}`}
                actions={
                  <span className="app-linha-com-icone body-sm">
                    <Icon name="lock" size={16} /> Não enviado
                  </span>
                }
              >
                <div className="app-pedido">
                  <div className="app-pedido__linha">
                    <AgentBadge agent="triagem" location="local" model={llm.pedido.model} />
                    <span className="body-sm sx-muted">{llm.motivo}</span>
                  </div>
                  <dl className="app-pedido__parametros">
                    {parametrosDoPedido(llm.pedido).map(([chave, valor]) => (
                      <div key={chave}>
                        <dt className="data-sm">{chave}</dt>
                        <dd className="data-sm">{valor}</dd>
                      </div>
                    ))}
                  </dl>
                  <details className="app-detalhes">
                    <summary className="body-sm">
                      Prompt de sistema: skill triagem-do-alerta, {fmtInt(llm.pedido.messages[0]?.content.length ?? 0)} caracteres
                    </summary>
                    <pre className="app-json">{llm.pedido.messages[0]?.content}</pre>
                  </details>
                  <p className="body-sm app-nota">
                    <strong>Mensagem:</strong> {llm.pedido.messages[1]?.content}
                  </p>
                  <p className="body-sm app-nota">
                    <strong>Tools:</strong> {llm.pedido.tools.map((tool) => tool.function.name).join(", ")}
                  </p>
                  <div className="app-pedido__leituras">
                    <div>
                      <h4 className="body-sm">
                        O que a triagem lê em <span className="data-sm">{llm.primeira_leitura.tool}</span> (modelo local, com endereços)
                      </h4>
                      <pre className="app-json">{JSON.stringify(llm.primeira_leitura.resultado, null, 2)}</pre>
                    </div>
                    <div>
                      <h4 className="body-sm">
                        O que chegaria à fronteira em <span className="data-sm">{llm.visao_da_fronteira.tool}</span> (rótulos neutros, sem endereços)
                      </h4>
                      <pre className="app-json">{JSON.stringify(llm.visao_da_fronteira.resultado, null, 2)}</pre>
                    </div>
                  </div>
                </div>
              </Panel>
            )}
          </>
        )}
      </div>
    </>
  );
}
