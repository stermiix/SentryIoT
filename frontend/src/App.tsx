import { Component, Suspense, lazy, useCallback, useEffect, useState, type ErrorInfo, type ReactNode } from "react";
import { listarModelos } from "./chat";
import { Alert, EmptyState, Skeleton } from "./design-system";
import { agregar, carregarLog } from "./log";
import { ancoraDa, lerRota, type Rota } from "./rotas";
import { TelaAoVivo } from "./telas/AoVivo";
import { ChatDoModelo } from "./telas/Chat";
import { TelaCustoLatencia } from "./telas/CustoLatencia";
import { TelaEntrar } from "./telas/Entrar";
import { TelaIncidente } from "./telas/Incidente";
import { TelaIsoladoIntegrado } from "./telas/IsoladoIntegrado";
import { Moldura, type ModeloDoBackend } from "./telas/Moldura";
import { TelaQualidadeModelo } from "./telas/QualidadeModelo";
import { TelaRelatorio } from "./telas/Relatorio";
import { TelaSegurancaMcp } from "./telas/SegurancaMcp";
import { TelaVisaoGeral } from "./telas/VisaoGeral";
import { useReplay, type PropsDaTela } from "./telas/replay";
import type { Evento } from "./types";
import "./estilo.css";

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
export function Pagina({ rota, modelo, ...props }: PropsDaTela & { rota: Rota; modelo: ModeloDoBackend }) {
  const tela = (() => {
    switch (rota.tela) {
      case "visao-geral":
        return <TelaVisaoGeral {...props} />;
      case "incidente":
        return <TelaIncidente {...props} incidente={rota.incidente} />;
      case "ao-vivo":
        return <TelaAoVivo {...props} />;
      case "isolado-integrado":
        return <TelaIsoladoIntegrado {...props} />;
      case "custo-latencia":
        return <TelaCustoLatencia {...props} />;
      case "qualidade":
        return <TelaQualidadeModelo />;
      case "seguranca-mcp":
        return <TelaSegurancaMcp />;
      case "chat":
        return <ChatDoModelo />;
      case "relatorio":
        return <TelaRelatorio {...props} incidente={rota.incidente} />;
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
  const semReplay = rota.tela === "chat" || rota.tela === "qualidade" || rota.tela === "seguranca-mcp" || rota.tela === "ao-vivo";
  return (
    <Moldura {...props} ativa={rota.tela} modelo={modelo} dock={semReplay ? null : undefined}>
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
  const [carregando, setCarregando] = useState(true);
  const replay = useReplay(eventos, avisos);

  useEffect(() => {
    carregarLog()
      .then((lido) => {
        // Os avisos valem para o log inteiro; o replay começa no estado final.
        setEventos(lido.eventos);
        setAvisos([...lido.avisos, ...agregar(lido.eventos).avisos]);
      })
      .catch((falha: Error) => setErro(falha.message))
      .finally(() => setCarregando(false));
  }, []);

  if (rota.tela === "entrar") {
    return <TelaEntrar navegar={navegar} />;
  }
  // O chat não depende do log: abre mesmo que ele não carregue.
  if (rota.tela !== "chat" && (carregando || erro || eventos.length === 0)) {
    return (
      <Moldura replay={replay} navegar={navegar} ativa={rota.tela} modelo={modelo} dock={null}>
        {carregando ? (
          <Skeleton lines={8} label="Carregando o log de exemplo" />
        ) : erro ? (
          <Alert tone="danger" title="O log não pôde ser lido">
            {erro}
          </Alert>
        ) : (
          <EmptyState icon="inbox" title="O log está vazio">
            Nenhum evento passou na conferência. Os avisos da leitura explicam por quê.
          </EmptyState>
        )}
        {!carregando && avisos.length > 0 && (
          <Alert tone="attention" title="Avisos da leitura">
            {avisos.join(" ")}
          </Alert>
        )}
      </Moldura>
    );
  }
  return <Pagina rota={rota} replay={replay} navegar={navegar} modelo={modelo} />;
}
