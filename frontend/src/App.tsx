import { Component, Suspense, lazy, useCallback, useEffect, useRef, useState, type ErrorInfo, type ReactNode } from "react";
import { listarModelos } from "./chat";
import { Alert, Skeleton } from "./design-system";
import { CAMINHO_DO_LOG, agregar, carregarLog, lerLog } from "./log";
import { ligarSimulacao } from "./operacao";
import { ancoraDa, lerRota, type Rota } from "./rotas";
import { agentesAtivos, consultarSimulacao, type ResultadoDaSimulacao } from "./simulacao";
import { TelaAoVivo } from "./telas/AoVivo";
import { ChatDoModelo } from "./telas/Chat";
import { TelaCustoLatencia } from "./telas/CustoLatencia";
import { TelaEntrar } from "./telas/Entrar";
import { TelaIncidente } from "./telas/Incidente";
import { TelaIsoladoIntegrado } from "./telas/IsoladoIntegrado";
import { Moldura, type ModeloDoBackend } from "./telas/Moldura";
import { TelaQualidadeModelo } from "./telas/QualidadeModelo";
import { TelaRelatorio } from "./telas/Relatorio";
import { TelaSimulacao } from "./telas/Simulacao";
import { TelaVisaoGeral } from "./telas/VisaoGeral";
import { useReplay, type PropsDaTela } from "./telas/replay";
import type { Evento } from "./types";
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
interface PropsDaPagina extends PropsDaTela {
  rota: Rota;
  modelo: ModeloDoBackend;
  erroDoLog?: string | null;
  /** A última simulação e o que fazer com uma nova (ver a tela Simulação). */
  simulacao?: ResultadoDaSimulacao | null;
  aoSimular?: (resultado: ResultadoDaSimulacao) => void;
}

export function Pagina({ rota, modelo, erroDoLog = null, simulacao = null, aoSimular, ...props }: PropsDaPagina) {
  const tela = (() => {
    switch (rota.tela) {
      case "visao-geral":
        return <TelaVisaoGeral {...props} />;
      case "incidente":
        return <TelaIncidente {...props} incidente={rota.incidente} efeitoSimulado={simulacao !== null} />;
      case "ao-vivo":
        return <TelaAoVivo />;
      case "simulacao":
        return <TelaSimulacao {...props} resultado={simulacao} aoSimular={aoSimular} />;
      case "isolado-integrado":
        return <TelaIsoladoIntegrado {...props} />;
      case "custo-latencia":
        return <TelaCustoLatencia {...props} />;
      case "qualidade":
        return <TelaQualidadeModelo />;
      case "chat":
        return <ChatDoModelo />;
      case "relatorio":
        return <TelaRelatorio {...props} incidente={rota.incidente} efeitoSimulado={simulacao !== null} />;
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
  const semReplay =
    rota.tela === "chat" || rota.tela === "qualidade" || rota.tela === "ao-vivo" || rota.tela === "simulacao";
  return (
    <Moldura {...props} ativa={rota.tela} modelo={modelo} dock={semReplay ? null : undefined} cheia={rota.tela === "chat"}>
      {erroDoLog && !semReplay && (
        <Alert tone="danger" title="O log de eventos não pôde ser lido. As telas ficam vazias.">
          {erroDoLog}
        </Alert>
      )}
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

export default function App() {
  const [rota, navegar] = useRota();
  const modelo = useModeloDoBackend();
  const [eventos, setEventos] = useState<Evento[]>([]);
  const [avisos, setAvisos] = useState<string[]>([]);
  const [erro, setErro] = useState<string | null>(null);
  // Sem log configurado, não há o que carregar: as telas abrem vazias.
  const [carregando, setCarregando] = useState(Boolean(CAMINHO_DO_LOG));
  const replay = useReplay(eventos, avisos);
  const [simulacao, setSimulacao] = useState<ResultadoDaSimulacao | null>(null);
  const logDaSimulacao = useRef<string | null>(null);
  // O log da simulação passa a ser o das telas: a fila, o detalhe e o relatório mostram os incidentes do pcap.
  const aoSimular = useCallback((resultado: ResultadoDaSimulacao) => {
    ligarSimulacao(agentesAtivos(resultado.agentes));
    setSimulacao(resultado);
    // Sem evento novo, só o estado dos agentes mudou: o replay fica onde está.
    if (resultado.eventos === logDaSimulacao.current) {
      return;
    }
    logDaSimulacao.current = resultado.eventos;
    // A última linha sem quebra pode estar no meio da gravação, porque os agentes escrevem no log.
    const lido = lerLog(resultado.eventos, { ignorarUltimaIncompleta: true });
    setEventos(lido.eventos);
    setAvisos([...lido.avisos, ...agregar(lido.eventos).avisos]);
    setErro(null);
  }, []);

  useEffect(() => {
    if (!CAMINHO_DO_LOG) {
      return;
    }
    carregarLog()
      .then((lido) => {
        // Os avisos valem para o log inteiro; o replay começa no estado final.
        setEventos(lido.eventos);
        setAvisos([...lido.avisos, ...agregar(lido.eventos).avisos]);
      })
      .catch((falha: Error) => setErro(falha.message))
      .finally(() => setCarregando(false));
  }, []);

  // Ao abrir a página, retoma a simulação que o backend tem, para um recarregamento não largar os agentes.
  useEffect(() => {
    if (carregando) {
      return;
    }
    let ligado = true;
    consultarSimulacao()
      .then((resultado) => {
        if (ligado && resultado) {
          aoSimular(resultado);
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
      <Moldura replay={replay} navegar={navegar} ativa={rota.tela} modelo={modelo} dock={null}>
        <Skeleton lines={8} label="Carregando o log de eventos" />
      </Moldura>
    );
  }
  return <Pagina rota={rota} replay={replay} navegar={navegar} modelo={modelo} erroDoLog={erro} simulacao={simulacao} aoSimular={aoSimular} />;
}
