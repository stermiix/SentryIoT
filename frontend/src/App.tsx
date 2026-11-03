import { Component, Suspense, lazy, useCallback, useEffect, useRef, useState, type ErrorInfo, type ReactNode } from "react";
import { listarModelos } from "./chat";
import { Alert, Button, Skeleton } from "./design-system";
import { CAMINHO_DO_LOG, agregar, carregarLog, lerLog, type LogLido } from "./log";
import { ligarSimulacao } from "./operacao";
import {
  CargaMaisRecente,
  acharExecucao,
  ancoraCorrigida,
  carregarExecucao,
  carregarIndice,
  navegacaoNaFonte,
  rotaNaExecucao,
  type ContextoDaRodada,
  type IndiceDaRodada,
} from "./rodada";
import { ancoraDa, lerRota, temIncidente, type Rota } from "./rotas";
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
  /** O índice da rodada final ou o log da variável não puderam ser lidos. */
  erroDoLog?: string | null;
  /**
   * A interface abre a rodada final que vem no build: é o modo sem `VITE_LOG_DE_EVENTOS`. Falso, as telas
   * leem o log da variável, como antes.
   */
  modoRodada?: boolean;
  /** O índice da rodada final; nulo quando o build não trouxe os dados. */
  indice?: IndiceDaRodada | null;
  /**
   * A execução que a âncora pede. Enquanto o log dela não chega (ou se ele falha), as telas do log não
   * aparecem: o incidente da âncora é de outro log, e mostrá-lo no log de antes seria mostrar outro incidente.
   */
  rodadaPedida?: ContextoDaRodada | null;
  carregandoExecucao?: boolean;
  /** O log da execução pedida não pôde ser lido. */
  erroDaExecucao?: string | null;
  tentarDeNovo?: () => void;
  /** A simulação cujo log está nas telas, e o que fazer com uma nova (ver a tela Simulação). */
  simulacao?: ResultadoDaSimulacao | null;
  aoSimular?: (resultado: ResultadoDaSimulacao) => void;
  /** A última simulação do backend, que não está nas telas (terminou antes de a página abrir, ou a pessoa voltou à rodada). */
  ultimaSimulacao?: ResultadoDaSimulacao | null;
  /** Tira a simulação das telas e volta ao log de antes (a rodada final ou o da variável). */
  voltar?: () => void;
  /** Abre uma execução da rodada final; `destino` é a rota depois dela (sem ela, a mesma tela, no incidente da execução). */
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
  rodadaPedida = null,
  carregandoExecucao = false,
  erroDaExecucao = null,
  tentarDeNovo,
  simulacao = null,
  aoSimular,
  ultimaSimulacao = null,
  voltar,
  abrirExecucao,
  ...props
}: PropsDaPagina) {
  const simulacaoAtiva = simulacao !== null && agentesAtivos(simulacao.agentes);
  const daTela = { ...props, escolherExecucao: (id: string) => abrirExecucao?.(id, null) };
  // A âncora pede uma execução cujo log ainda não está nas telas.
  const esperando = modoRodada && !simulacao && rodadaPedida !== null && rodadaPedida.execucao.id !== props.rodada?.execucao.id;
  const tela = (() => {
    if (esperando && DO_LOG.has(rota.tela)) {
      return erroDaExecucao ? (
        <Alert
          tone="danger"
          title={`O log da execução ${rodadaPedida.execucao.rodada} não pôde ser lido.`}
          action={
            tentarDeNovo ? (
              <Button size="sm" variant="secondary" icon="refresh-cw" onClick={tentarDeNovo}>
                Tentar de novo
              </Button>
            ) : undefined
          }
        >
          {erroDaExecucao}
        </Alert>
      ) : (
        <Skeleton lines={8} label={`Carregando a execução ${rodadaPedida.execucao.rodada}`} />
      );
    }
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
              modoRodada={modoRodada}
              erro={erroDoLog}
              atual={simulacao ? null : (rodadaPedida?.execucao.id ?? props.rodada?.execucao.id ?? null)}
              abrir={(execucao) => abrirExecucao?.(execucao.id, { tela: "incidente", incidente: execucao.incidente, aba: "conversa" })}
            />
          </>
        );
      case "visao-geral":
        return <TelaVisaoGeral {...daTela} />;
      case "incidente":
        return (
          <TelaIncidente
            {...daTela}
            incidente={rota.incidente}
            aba={rota.aba}
            efeitoSimulado={simulacao !== null}
            logTerminado={Boolean(props.rodada) || (simulacao !== null && !simulacaoAtiva)}
          />
        );
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
        rodada={simulacao ? null : (rodadaPedida ?? props.rodada ?? null)}
        semDados={modoRodada && !indice && !erroDoLog}
        simulacao={simulacao}
        simulacaoAtiva={simulacaoAtiva}
        carregando={carregandoExecucao}
        escolher={(id) => abrirExecucao?.(id, null)}
        voltar={voltar}
        abrirRodada={modoRodada ? () => props.navegar({ tela: "rodada", incidente: null }) : undefined}
        voltarPara={modoRodada ? "à rodada final" : "ao log configurado"}
      />
    ) : null;
  return (
    <Moldura
      {...props}
      ativa={rota.tela}
      modelo={modelo}
      dock={semReplay || (esperando && DO_LOG.has(rota.tela)) ? null : undefined}
      cheia={rota.tela === "chat"}
      modoRodada={modoRodada}
    >
      {erroDoLog && !semReplay && (
        <Alert tone="danger" title={modoRodada ? "A rodada final não pôde ser lida. As telas ficam vazias." : "O log de eventos não pôde ser lido. As telas ficam vazias."}>
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

/** A rota da âncora, `navegar` (uma entrada nova no histórico) e `substituir` (a mesma entrada, sem voltar a ela). */
function useRota(): [Rota, (rota: Rota) => void, (rota: Rota) => void] {
  const [rota, setRota] = useState<Rota>(() => lerRota(typeof window === "undefined" ? "" : window.location.hash));
  useEffect(() => {
    const ler = () => setRota(lerRota(window.location.hash));
    window.addEventListener("hashchange", ler);
    return () => window.removeEventListener("hashchange", ler);
  }, []);
  // O estado acompanha a âncora já na mesma vez, sem esperar o hashchange: um efeito que leia a rota logo
  // depois não vê a de antes.
  const navegar = useCallback((nova: Rota) => {
    window.location.hash = ancoraDa(nova);
    setRota(lerRota(window.location.hash));
    window.scrollTo({ top: 0 });
  }, []);
  const substituir = useCallback((nova: Rota) => {
    window.history.replaceState(window.history.state, "", ancoraDa(nova));
    setRota(lerRota(window.location.hash));
  }, []);
  return [rota, navegar, substituir];
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
  const [rota, navegarNaAncora, substituir] = useRota();
  const modelo = useModeloDoBackend();
  // O log de base: o da execução da rodada final carregada ou o da variável.
  const [base, setBase] = useState<LogLido>(SEM_LOG);
  const [erro, setErro] = useState<string | null>(null);
  const [carregando, setCarregando] = useState(true);
  const [indice, setIndice] = useState<IndiceDaRodada | null>(null);
  // A execução carregada nas telas; a pedida vem da âncora (`?execucao=`), e a mais recente sempre vence.
  const [carregada, setCarregada] = useState<string | null>(null);
  const [carregandoExecucao, setCarregandoExecucao] = useState(false);
  const [erroDaExecucao, setErroDaExecucao] = useState<{ id: string; mensagem: string } | null>(null);
  const [tentativa, setTentativa] = useState(0);
  // A simulação cujo log está nas telas, e a última do backend que ficou fora delas.
  const [simulacao, setSimulacao] = useState<ResultadoDaSimulacao | null>(null);
  const [logDaSimulacao, setLogDaSimulacao] = useState<LogLido | null>(null);
  const [ultimaSimulacao, setUltimaSimulacao] = useState<ResultadoDaSimulacao | null>(null);
  const textoDaSimulacao = useRef<string | null>(null);
  const naSimulacao = logDaSimulacao !== null;
  const atual = logDaSimulacao ?? base;
  const replay = useReplay(atual.eventos, atual.avisos);
  // Na simulação, a âncora não leva execução, e a rodada fica onde estava.
  const pedida = MODO_RODADA && indice ? (naSimulacao ? carregada : (acharExecucao(indice, rota.execucao)?.execucao.id ?? null)) : null;
  const rodada = MODO_RODADA && !naSimulacao && indice ? acharExecucao(indice, carregada) : null;
  const rodadaPedida = MODO_RODADA && !naSimulacao && indice ? acharExecucao(indice, pedida) : null;

  // As telas navegam sem saber da execução: a navegação a mantém na âncora, e a tira dela na simulação e no log da variável.
  const estado = useRef({ rota, naSimulacao });
  estado.current = { rota, naSimulacao };
  const navegar = useCallback(
    (nova: Rota) => {
      const { rota: daAncora, naSimulacao: simulando } = estado.current;
      navegarNaAncora(navegacaoNaFonte(nova, daAncora, { modoRodada: MODO_RODADA, simulando }));
    },
    [navegarNaAncora],
  );

  // O log da simulação passa a ser o das telas: a fila, o detalhe e o relatório mostram os incidentes do pcap.
  const aoSimular = useCallback(
    (resultado: ResultadoDaSimulacao) => {
      ligarSimulacao(agentesAtivos(resultado.agentes));
      setSimulacao(resultado);
      setUltimaSimulacao(null);
      // Sem evento novo, só o estado dos agentes mudou: o replay fica onde está.
      if (resultado.eventos === textoDaSimulacao.current) {
        return;
      }
      // Ao entrar na simulação, a âncora larga a execução e o incidente dela: o inc-0001 da simulação é outro.
      const entrando = textoDaSimulacao.current === null;
      textoDaSimulacao.current = resultado.eventos;
      if (entrando && (estado.current.rota.execucao || (temIncidente(estado.current.rota) && estado.current.rota.incidente))) {
        substituir(rotaNaExecucao(estado.current.rota, null));
      }
      // A última linha sem quebra pode estar no meio da gravação, porque os agentes escrevem no log.
      setLogDaSimulacao(comAvisos(lerLog(resultado.eventos, { ignorarUltimaIncompleta: true })));
      setErro(null);
    },
    [substituir],
  );

  /** Tira a simulação das telas; o log de antes volta a ser o delas. */
  const largarSimulacao = useCallback(() => {
    textoDaSimulacao.current = null;
    ligarSimulacao(false);
    setUltimaSimulacao(simulacao);
    setSimulacao(null);
    setLogDaSimulacao(null);
  }, [simulacao]);

  // Volta ao log de antes da simulação, na execução e no incidente certos: nunca o inc-000N da simulação no
  // log da rodada. Enquanto os agentes rodam, não: eles esperam decisões nas telas.
  const voltar = useCallback(() => {
    if (simulacao && agentesAtivos(simulacao.agentes)) {
      return;
    }
    largarSimulacao();
    navegarNaAncora(rotaNaExecucao(rota, indice ? acharExecucao(indice, carregada) : null));
  }, [simulacao, largarSimulacao, navegarNaAncora, rota, indice, carregada]);

  const abrirExecucao = useCallback(
    (id: string, rotaDepois: Rota | null) => {
      const alvo = indice ? acharExecucao(indice, id) : null;
      if (!alvo || (simulacao && agentesAtivos(simulacao.agentes))) {
        return;
      }
      if (simulacao) {
        largarSimulacao();
      }
      // Repetir a escolha que falhou tenta de novo.
      if (erroDaExecucao?.id === id) {
        setTentativa((n) => n + 1);
      }
      navegarNaAncora(rotaDepois ? { ...rotaDepois, execucao: id } : rotaNaExecucao(rota, alvo));
    },
    [indice, simulacao, largarSimulacao, erroDaExecucao, navegarNaAncora, rota],
  );

  // Ao abrir: o log da variável, quando ela existe; senão, o índice da rodada final.
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
          if (ativo) {
            setIndice(lido);
            if (!lido) {
              setCarregando(false);
            }
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

  // Âncora sem execução (ou com uma que o índice não tem): a carregada, ou a inicial na primeira vez. Sem
  // saber de que log era o incidente da âncora (uma entrada antiga do histórico, da simulação), ele passa a
  // ser o que os agentes trataram na execução.
  useEffect(() => {
    const corrigida = MODO_RODADA && indice && !naSimulacao ? ancoraCorrigida(indice, rota, carregada) : null;
    if (corrigida) {
      substituir(corrigida);
    }
  }, [indice, rota, naSimulacao, carregada, substituir]);

  // A execução pedida: o log dela substitui o de antes só quando chega inteiro. Outra escolha no meio
  // cancela esta, e a mais recente vence; voltar à carregada cancela a que estava a caminho.
  const carga = useRef(new CargaMaisRecente<LogLido>());
  useEffect(() => {
    const alvo = indice && pedida ? acharExecucao(indice, pedida) : null;
    if (!alvo) {
      return;
    }
    if (alvo.execucao.id === carregada) {
      carga.current.cancelar();
      setCarregandoExecucao(false);
      setErroDaExecucao(null);
      return;
    }
    setCarregandoExecucao(true);
    setErroDaExecucao(null);
    void carga.current.carregar(() => carregarExecucao(alvo.execucao)).then((resultado) => {
      if (resultado.tipo === "superada") {
        return;
      }
      if (resultado.tipo === "ok") {
        setBase(comAvisos(resultado.valor));
        setCarregada(alvo.execucao.id);
      } else {
        setErroDaExecucao({ id: alvo.execucao.id, mensagem: resultado.erro.message });
      }
      setCarregandoExecucao(false);
      setCarregando(false);
    });
  }, [indice, pedida, carregada, tentativa]);

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
      rodadaPedida={rodadaPedida}
      carregandoExecucao={carregandoExecucao}
      erroDaExecucao={erroDaExecucao && erroDaExecucao.id === pedida ? erroDaExecucao.mensagem : null}
      tentarDeNovo={() => setTentativa((n) => n + 1)}
      simulacao={simulacao}
      aoSimular={aoSimular}
      ultimaSimulacao={ultimaSimulacao}
      voltar={voltar}
      abrirExecucao={abrirExecucao}
    />
  );
}
