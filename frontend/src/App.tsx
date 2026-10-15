import { Component, Suspense, lazy, useCallback, useEffect, useState, type ErrorInfo, type ReactNode } from "react";
import { listarModelos } from "./chat";
import { Alert, Skeleton } from "./design-system";
import { CAMINHO_DO_LOG, agregar, carregarLog } from "./log";
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
export function Pagina({ rota, modelo, erroDoLog = null, ...props }: PropsDaTela & { rota: Rota; modelo: ModeloDoBackend; erroDoLog?: string | null }) {
  const tela = (() => {
    switch (rota.tela) {
      case "visao-geral":
        return <TelaVisaoGeral {...props} />;
      case "incidente":
        return <TelaIncidente {...props} incidente={rota.incidente} />;
      case "ao-vivo":
        return <TelaAoVivo />;
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
  return <Pagina rota={rota} replay={replay} navegar={navegar} modelo={modelo} erroDoLog={erro} />;
}
