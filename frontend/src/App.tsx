import { Component, Suspense, lazy, useCallback, useEffect, useRef, useState, type ErrorInfo, type ReactNode } from "react";
import { listarModelos } from "./chat";
import { Alert, Skeleton } from "./design-system";
import { CAMINHO_DO_LOG, agregar, carregarLog, lerLog, type LogLido } from "./log";
import { ligarSimulacao } from "./operacao";
import { acharExecucao, carregarExecucao, carregarIndice, execucaoInicial, type IndiceDaRodada } from "./rodada";
import { ancoraDa, lerRota, type Rota } from "./rotas";
import { agentesAtivos, consultarSimulacao, type ResultadoDaSimulacao } from "./simulacao";
import { TelaAoVivo } from "./telas/AoVivo";
import { ChatDoModelo } from "./telas/Chat";
import { TelaCustoLatencia } from "./telas/CustoLatencia";
import { TelaEntrar } from "./telas/Entrar";
import { TelaIncidente } from "./telas/Incidente";
import { TelaIsoladoIntegrado } from "./telas/IsoladoIntegrado";
import { BarraDaFonte } from "./telas/Medidas";
import { Moldura, type ModeloDoBackend } from "./telas/Moldura";
import { TelaQualidadeModelo } from "./telas/QualidadeModelo";
import { TelaRelatorio } from "./telas/Relatorio";
import { TelaRodada } from "./telas/Rodada";
import { TelaSimulacao } from "./telas/Simulacao";
import { TelaVisaoGeral } from "./telas/VisaoGeral";
import { useReplay, type PropsDaTela } from "./telas/replay";
import "./estilo.css";

// De quanto em quanto tempo o log é lido enquanto os agentes rodam.
const INTERVALO_DA_SIMULACAO_MS = 2000;

// O catálogo de componentes só carrega quando alguém abre a tela dele.
const TelaComponentes = lazy(() => import("./telas/Componentes").then((modulo) => ({ default: modulo.TelaComponentes })));

interface PropsDoLimite {
  /** O que não pôde ser mostrado, para a mensagem. */
  parte: string;
  /** Quando muda (outra tela, outro passo do replay), a parte é desenhada de novo. */
  chave: string;
  children: ReactNode;
}

/**
 * Um erro ao desenhar uma tela fica restrito a ela: sem isto, o React desmonta a árvore inteira e
 * a página fica em branco na frente da banca.
 */
export class LimiteDeErro extends Component<PropsDoLimite, { erro: Error | null }> {
  state = { erro: null as Error | null };

  static getDerivedStateFromError(erro: Error) {
    return { erro };
  }

  componentDidCatch(erro: Error, info: ErrorInfo) {
    console.error(`Erro ao mostrar ${this.props.parte}:`, erro, info.componentStack);
  }

  componentDidUpdate(anteriores: PropsDoLimite) {
    if (this.state.erro && anteriores.chave !== this.props.chave) {
      this.setState({ erro: null });
    }
  }

  render() {
    if (this.state.erro) {
      return (
        <Alert tone="danger" title={`Não foi possível mostrar ${this.props.parte}.`}>
          {this.state.erro.message}
        </Alert>
      );
    }
    return this.props.children;
  }
}

/** A tela da rota, já dentro da moldura. Separada do `App` para os testes a desenharem em qualquer passo. */
export interface PropsDaPagina extends PropsDaTela {
  rota: Rota;
  modelo: ModeloDoBackend;
  erroDoLog?: string | null;
  /**
   * A interface abre a rodada final que vem no build: é o modo sem `VITE_LOG_DE_EVENTOS`. Falso, as telas
   * leem o log da variável, como antes.
   */
  modoRodada?: boolean;
  /** O índice da rodada final; nulo quando o build não trouxe os dados. */
  indice?: IndiceDaRodada | null;
  carregandoExecucao?: boolean;
  /** A simulação cujo log está nas telas, e o que fazer com uma nova (ver a tela Simulação). */
  simulacao?: ResultadoDaSimulacao | null;
  aoSimular?: (resultado: ResultadoDaSimulacao) => void;
  /** A última simulação do backend, que não está nas telas (terminou antes de a página abrir, ou a pessoa voltou à rodada). */
  ultimaSimulacao?: ResultadoDaSimulacao | null;
  /** Tira a simulação das telas e volta ao log de antes (a rodada final ou o da variável). */
  voltar?: () => void;
  /** Abre uma execução da rodada final e, depois que o log dela carrega, vai para a rota pedida. */
  abrirExecucao?: (id: string, destino: Rota | null) => void;
}

// As telas que mostram o log: elas levam no alto a barra que diz de onde ele vem.
const DO_LOG = new Set<Rota["tela"]>(["visao-geral", "incidente", "isolado-integrado", "custo-latencia", "relatorio"]);

export function Pagina({
  rota,
  modelo,
  erroDoLog = null,
  modoRodada = false,
  indice = null,
  carregandoExecucao = false,
  simulacao = null,
  aoSimular,
  ultimaSimulacao = null,
  voltar,
  abrirExecucao,
  ...props
}: PropsDaPagina) {
  const simulacaoAtiva = simulacao !== null && agentesAtivos(simulacao.agentes);
  // Ao trocar a execução no seletor, o detalhe e o relatório passam ao incidente da execução nova.
  const escolher = (id: string) => {
    const alvo = indice && acharExecucao(indice, id);
    const segue = alvo && (rota.tela === "incidente" || rota.tela === "relatorio") ? { ...rota, incidente: alvo.execucao.incidente } : null;
    abrirExecucao?.(id, segue);
  };
  const daTela = { ...props, escolherExecucao: (id: string) => abrirExecucao?.(id, null) };
  const tela = (() => {
    switch (rota.tela) {
      case "rodada":
        return (
          <>
            {simulacaoAtiva && (
              <Alert tone="attention" title="As telas mostram a simulação, e os agentes dela ainda rodam.">
                Pare os agentes na tela Simulação para abrir uma execução da rodada final.
              </Alert>
            )}
            <TelaRodada
              indice={indice}
              atual={simulacao ? null : (props.rodada?.execucao.id ?? null)}
              abrir={(execucao) => abrirExecucao?.(execucao.id, { tela: "incidente", incidente: execucao.incidente, aba: "conversa" })}
            />
          </>
        );
      case "visao-geral":
        return <TelaVisaoGeral {...daTela} />;
      case "incidente":
        return <TelaIncidente {...daTela} incidente={rota.incidente} aba={rota.aba} efeitoSimulado={simulacao !== null} />;
      case "ao-vivo":
        return <TelaAoVivo />;
      case "simulacao":
        return (
          <TelaSimulacao
            {...daTela}
            resultado={simulacao}
            aoSimular={aoSimular}
            ultima={ultimaSimulacao}
            voltar={voltar}
            voltarPara={modoRodada ? "à rodada final" : "ao log configurado"}
          />
        );
      case "isolado-integrado":
        return <TelaIsoladoIntegrado {...daTela} />;
      case "custo-latencia":
        return <TelaCustoLatencia {...daTela} />;
      case "qualidade":
        return <TelaQualidadeModelo />;
      case "chat":
        return <ChatDoModelo />;
      case "relatorio":
        return <TelaRelatorio {...daTela} incidente={rota.incidente} efeitoSimulado={simulacao !== null || Boolean(props.rodada)} />;
      case "componentes":
        return (
          <Suspense fallback={<Skeleton lines={6} label="Carregando o catálogo" />}>
            <TelaComponentes {...props} />
          </Suspense>
        );
      case "entrar":
        return null;
    }
  })();
  // Telas que não dependem do replay não levam o controle dele no pé.
  const semReplay = rota.tela === "chat" || rota.tela === "qualidade" || rota.tela === "ao-vivo" || rota.tela === "simulacao" || rota.tela === "rodada";
  const barra =
    DO_LOG.has(rota.tela) && (modoRodada || simulacao) ? (
      <BarraDaFonte
        rodada={simulacao ? null : (props.rodada ?? null)}
        semDados={modoRodada && !indice && !erroDoLog}
        simulacao={simulacao}
        simulacaoAtiva={simulacaoAtiva}
        carregando={carregandoExecucao}
        escolher={escolher}
        voltar={voltar}
        abrirRodada={modoRodada ? () => props.navegar({ tela: "rodada", incidente: null }) : undefined}
        voltarPara={modoRodada ? "à rodada final" : "ao log configurado"}
      />
    ) : null;
  return (
    <Moldura {...props} ativa={rota.tela} modelo={modelo} dock={semReplay ? null : undefined} cheia={rota.tela === "chat"} modoRodada={modoRodada}>
      {erroDoLog && !semReplay && (
        <Alert tone="danger" title="O log de eventos não pôde ser lido. As telas ficam vazias.">
          {erroDoLog}
        </Alert>
      )}
      {barra}
      <LimiteDeErro parte="esta tela" chave={`${ancoraDa(rota)}:${props.replay.passo}`}>
        {tela}
      </LimiteDeErro>
    </Moldura>
  );
}

function useRota(): [Rota, (rota: Rota) => void] {
  const [rota, setRota] = useState<Rota>(() => lerRota(typeof window === "undefined" ? "" : window.location.hash));
  useEffect(() => {
    const ler = () => setRota(lerRota(window.location.hash));
    window.addEventListener("hashchange", ler);
    return () => window.removeEventListener("hashchange", ler);
  }, []);
  const navegar = useCallback((nova: Rota) => {
    window.location.hash = ancoraDa(nova);
    window.scrollTo({ top: 0 });
  }, []);
  return [rota, navegar];
}

/** O modelo padrão do backend do chat, para o rodapé da barra lateral. */
function useModeloDoBackend(): ModeloDoBackend {
  const [modelo, setModelo] = useState<ModeloDoBackend>(null);
  useEffect(() => {
    let ativo = true;
    listarModelos()
      .then((lista) => ativo && setModelo({ nome: lista.padrao, online: true }))
      .catch(() => ativo && setModelo({ online: false }));
    return () => {
      ativo = false;
    };
  }, []);
  return modelo;
}

const SEM_LOG: LogLido = { eventos: [], avisos: [] };

/** O log lido com os avisos da leitura e da reconstrução, como as telas os mostram. */
function comAvisos(lido: LogLido): LogLido {
  return { eventos: lido.eventos, avisos: [...lido.avisos, ...agregar(lido.eventos).avisos] };
}

// Sem `VITE_LOG_DE_EVENTOS`, a interface abre a rodada final que vem no build.
const MODO_RODADA = !CAMINHO_DO_LOG;

export default function App() {
  const [rota, navegar] = useRota();
  const modelo = useModeloDoBackend();
  // O log de base: o da execução da rodada final escolhida ou o da variável.
  const [base, setBase] = useState<LogLido>(SEM_LOG);
  const [erro, setErro] = useState<string | null>(null);
  const [carregando, setCarregando] = useState(true);
  const [indice, setIndice] = useState<IndiceDaRodada | null>(null);
  // A execução pedida no seletor e a que está carregada: as telas só mudam quando o log novo chega.
  const [pedida, setPedida] = useState<string | null>(null);
  const [carregada, setCarregada] = useState<string | null>(null);
  const [carregandoExecucao, setCarregandoExecucao] = useState(false);
  const destino = useRef<Rota | null>(null);
  // A simulação cujo log está nas telas, e a última do backend que ficou fora delas.
  const [simulacao, setSimulacao] = useState<ResultadoDaSimulacao | null>(null);
  const [logDaSimulacao, setLogDaSimulacao] = useState<LogLido | null>(null);
  const [ultimaSimulacao, setUltimaSimulacao] = useState<ResultadoDaSimulacao | null>(null);
  const textoDaSimulacao = useRef<string | null>(null);
  const atual = logDaSimulacao ?? base;
  const replay = useReplay(atual.eventos, atual.avisos);
  const rodada = MODO_RODADA && !logDaSimulacao && indice ? acharExecucao(indice, carregada) : null;

  // O log da simulação passa a ser o das telas: a fila, o detalhe e o relatório mostram os incidentes do pcap.
  const aoSimular = useCallback((resultado: ResultadoDaSimulacao) => {
    ligarSimulacao(agentesAtivos(resultado.agentes));
    setSimulacao(resultado);
    setUltimaSimulacao(null);
    // Sem evento novo, só o estado dos agentes mudou: o replay fica onde está.
    if (resultado.eventos === textoDaSimulacao.current) {
      return;
    }
    textoDaSimulacao.current = resultado.eventos;
    // A última linha sem quebra pode estar no meio da gravação, porque os agentes escrevem no log.
    setLogDaSimulacao(comAvisos(lerLog(resultado.eventos, { ignorarUltimaIncompleta: true })));
    setErro(null);
  }, []);

  // Volta ao log de antes da simulação. Enquanto os agentes rodam, não: eles esperam decisões nas telas.
  const voltar = useCallback(() => {
    if (simulacao && agentesAtivos(simulacao.agentes)) {
      return;
    }
    textoDaSimulacao.current = null;
    ligarSimulacao(false);
    setUltimaSimulacao(simulacao);
    setSimulacao(null);
    setLogDaSimulacao(null);
  }, [simulacao]);

  const abrirExecucao = useCallback(
    (id: string, rotaDepois: Rota | null) => {
      if (simulacao && agentesAtivos(simulacao.agentes)) {
        return;
      }
      if (simulacao) {
        voltar();
      }
      if (id === carregada) {
        if (rotaDepois) {
          navegar(rotaDepois);
        }
        return;
      }
      destino.current = rotaDepois;
      setPedida(id);
    },
    [simulacao, voltar, carregada, navegar],
  );

  // Ao abrir: o log da variável, quando ela existe; senão, o índice da rodada final e a execução inicial dele.
  useEffect(() => {
    let ativo = true;
    if (!MODO_RODADA) {
      carregarLog()
        .then((lido) => ativo && setBase(comAvisos(lido)))
        .catch((falha: Error) => ativo && setErro(falha.message))
        .finally(() => ativo && setCarregando(false));
    } else {
      carregarIndice()
        .then((lido) => {
          if (!ativo) {
            return;
          }
          setIndice(lido);
          if (lido) {
            setPedida(execucaoInicial(lido));
          } else {
            setCarregando(false);
          }
        })
        .catch((falha: Error) => {
          if (ativo) {
            setErro(falha.message);
            setCarregando(false);
          }
        });
    }
    return () => {
      ativo = false;
    };
  }, []);

  // A execução pedida: o log dela substitui o de antes só quando chega inteiro.
  useEffect(() => {
    const alvo = indice && pedida ? acharExecucao(indice, pedida) : null;
    if (!alvo) {
      return;
    }
    let ativo = true;
    setCarregandoExecucao(true);
    carregarExecucao(alvo.execucao)
      .then((lido) => {
        if (!ativo) {
          return;
        }
        setBase(comAvisos(lido));
        setCarregada(alvo.execucao.id);
        setErro(null);
        if (destino.current) {
          navegar(destino.current);
          destino.current = null;
        }
      })
      .catch((falha: Error) => ativo && setErro(falha.message))
      .finally(() => {
        if (ativo) {
          setCarregandoExecucao(false);
          setCarregando(false);
        }
      });
    return () => {
      ativo = false;
    };
  }, [indice, pedida, navegar]);

  // Ao abrir a página, retoma a simulação que o backend tem, para um recarregamento não largar os agentes.
  // Na rodada final, a simulação que já terminou não toma as telas: ela fica à mão na tela Simulação.
  useEffect(() => {
    if (carregando) {
      return;
    }
    let ligado = true;
    consultarSimulacao()
      .then((resultado) => {
        if (!ligado || !resultado) {
          return;
        }
        if (!MODO_RODADA || agentesAtivos(resultado.agentes)) {
          aoSimular(resultado);
        } else {
          setUltimaSimulacao(resultado);
        }
      })
      .catch(() => undefined);
    return () => {
      ligado = false;
    };
  }, [carregando, aoSimular]);

  // Enquanto os agentes rodam, o log é lido de novo a cada poucos segundos, em qualquer tela.
  const acompanhando = simulacao !== null && agentesAtivos(simulacao.agentes);
  useEffect(() => {
    if (!acompanhando) {
      return;
    }
    let ligado = true;
    let lendo = false;
    const ler = async () => {
      if (lendo) {
        return;
      }
      lendo = true;
      try {
        const resultado = await consultarSimulacao();
        if (!ligado) {
          return;
        }
        if (resultado) {
          aoSimular(resultado);
        } else {
          // O backend reiniciou: ninguém mais trata os incidentes.
          ligarSimulacao(false);
          setSimulacao((atual) => atual && { ...atual, agentes: { ...atual.agentes, estado: "interrompidos" } });
        }
      } catch {
        // Fora do ar por um instante: a próxima leitura tenta de novo.
      } finally {
        lendo = false;
      }
    };
    const relogio = window.setInterval(() => void ler(), INTERVALO_DA_SIMULACAO_MS);
    return () => {
      ligado = false;
      window.clearInterval(relogio);
    };
  }, [acompanhando, aoSimular]);

  if (rota.tela === "entrar") {
    return <TelaEntrar navegar={navegar} />;
  }
  // O chat não depende do log: abre mesmo enquanto ele carrega. Sem log, ou com log vazio ou
  // ilegível, cada tela abre vazia; os avisos da leitura aparecem nas telas que os mostram.
  if (rota.tela !== "chat" && carregando) {
    return (
      <Moldura replay={replay} navegar={navegar} ativa={rota.tela} modelo={modelo} dock={null} modoRodada={MODO_RODADA}>
        <Skeleton lines={8} label={MODO_RODADA ? "Carregando a rodada final" : "Carregando o log de eventos"} />
      </Moldura>
    );
  }
  return (
    <Pagina
      rota={rota}
      replay={replay}
      navegar={navegar}
      modelo={modelo}
      erroDoLog={erro}
      modoRodada={MODO_RODADA}
      indice={indice}
      rodada={rodada}
      carregandoExecucao={carregandoExecucao}
      simulacao={simulacao}
      aoSimular={aoSimular}
      ultimaSimulacao={ultimaSimulacao}
      voltar={voltar}
      abrirExecucao={abrirExecucao}
    />
  );
}
