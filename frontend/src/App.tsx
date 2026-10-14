import { useEffect, useMemo, useState } from "react";
import ChatDoModelo from "./components/ChatDoModelo";
import ControleDoReplay from "./components/ControleDoReplay";
import DetalheDoIncidente from "./components/DetalheDoIncidente";
import FilaDeIncidentes from "./components/FilaDeIncidentes";
import LimiteDeErro from "./components/LimiteDeErro";
import ResumoMetricas from "./components/ResumoMetricas";
import { type Agregado, agregar, carregarLog } from "./log";
import type { Evento } from "./types";

export type Tela = "incidentes" | "chat";

/** A tela vem da âncora da página: `#chat` abre o chat; qualquer outra, a visão geral. */
export function telaDaAncora(ancora: string): Tela {
  return ancora === "#chat" ? "chat" : "incidentes";
}

export interface PropsDaPagina {
  tela?: Tela;
  eventos: Evento[];
  avisos: string[];
  passo: number;
  onMudarPasso: (passo: number) => void;
  selecionadoId: string | null;
  onSelecionar: (id: string) => void;
  carregando: boolean;
  erro: string | null;
}

/**
 * A página, desenhada a partir dos eventos e do passo do replay. Não guarda estado nem busca o
 * log: isso fica no `App`, e esta parte pode ser desenhada nos testes em qualquer passo.
 */
export function Pagina({ tela = "incidentes", eventos, avisos, passo, onMudarPasso, selecionadoId, onSelecionar, carregando, erro }: PropsDaPagina) {
  // O estado das telas é o dos eventos até o passo atual do replay.
  const agregado = useMemo((): { valor: Agregado } | { falha: string } => {
    try {
      return { valor: agregar(eventos.slice(0, passo)) };
    } catch (falha) {
      return { falha: (falha as Error).message };
    }
  }, [eventos, passo]);
  const resumo = "valor" in agregado ? agregado.valor.resumo : null;
  const incidentes = "valor" in agregado ? agregado.valor.incidentes : [];
  // Se o incidente escolhido ainda não abriu neste passo, o detalhe mostra o primeiro da fila.
  const selecionado = incidentes.find((view) => view.id === selecionadoId) ?? incidentes[0] ?? null;

  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="#inicio" aria-label="SentryIoT início">
          <span className="brand-mark">S</span>
          <span>Sentry<span className="brand-light">IoT</span></span>
        </a>
        <div className="sidebar-label">PLATAFORMA</div>
        <nav className="navigation" aria-label="Navegação principal">
          <a className={tela === "incidentes" ? "nav-item active" : "nav-item"} href="#incidentes"><span className="nav-icon">◈</span> Incidentes <span className="nav-count">{incidentes.length}</span></a>
          <a className={tela === "chat" ? "nav-item active" : "nav-item"} href="#chat"><span className="nav-icon">✎</span> Chat com o modelo</a>
          <button className="nav-item muted nav-future" disabled title="Disponível em uma próxima etapa"><span className="nav-icon">⌁</span> Atividade <span className="nav-soon">em breve</span></button>
          <button className="nav-item muted nav-future" disabled title="Disponível em uma próxima etapa"><span className="nav-icon">▤</span> Qualidade do modelo <span className="nav-soon">em breve</span></button>
        </nav>
        <div className="sidebar-spacer" />
        <div className="sidebar-project">
          <span className="project-dot" />
          <div><strong>SentryIoT</strong><small>TCC II · Mackenzie</small></div>
          <span className="project-menu">···</span>
        </div>
        <div className="sidebar-footer">DETECÇÃO · RESPOSTA · CONTROLE</div>
      </aside>

      <main className="main-area" id="inicio">
        <div className="topbar">
          <div className="breadcrumb">Visão geral <span>/</span> {tela === "chat" ? "Chat com o modelo" : "Incidentes"}</div>
          <div className="topbar-actions">
            <span className="replay-pill"><span className="status-dot" /> {tela === "chat" ? "CHAT" : "REPLAY"}</span>
            <span className="topbar-divider" />
            <span className="avatar" title="Projeto acadêmico">SI</span>
          </div>
        </div>

        {tela === "chat" ? (
          <div className="content">
            <section className="page-heading" id="chat">
              <div>
                <div className="eyebrow">FERRAMENTA DE TESTE</div>
                <h1>Chat com o modelo</h1>
                <p>Converse com o modelo do provedor configurado no backend e veja tokens e tempo de cada resposta.</p>
              </div>
            </section>
            <LimiteDeErro parte="o chat com o modelo" chave="chat">
              <ChatDoModelo />
            </LimiteDeErro>
            <footer className="page-footer"><span>SentryIoT <span className="footer-separator">·</span> TCC II FCI Mackenzie</span><span>O chat não grava no log de eventos</span></footer>
          </div>
        ) : (
        <div className="content">
          <section className="page-heading" id="incidentes">
            <div>
              <div className="eyebrow">CENTRO DE OPERAÇÕES · IOT</div>
              <h1>Visão geral</h1>
              <p>Acompanhe alertas, decisões e ações do pipeline de detecção e resposta.</p>
            </div>
            <div className="replay-meta">
              <span className="replay-icon">▶</span>
              <div><strong>Execução demonstrativa</strong><small>Dados roteirizados · sem tráfego real</small></div>
            </div>
          </section>

          {erro && <div className="error-banner" role="alert"><strong>Não foi possível abrir o replay.</strong><span>{erro}</span></div>}
          {"falha" in agregado && <div className="error-banner" role="alert"><strong>Não foi possível montar o replay.</strong><span>{agregado.falha}</span></div>}
          {avisos.length > 0 && (
            <div className="warning-banner" role="status">
              <strong>O log tem {avisos.length} aviso(s). A tela mostra só o que passou na conferência.</strong>
              <ul>{avisos.map((aviso, indice) => <li key={indice}>{aviso}</li>)}</ul>
            </div>
          )}
          {carregando && <div className="loading-state">Carregando execução demonstrativa…</div>}
          {!carregando && !erro && eventos.length > 0 && <ControleDoReplay eventos={eventos} passo={passo} onMudar={onMudarPasso} />}
          {!carregando && !erro && resumo && (
            <>
              <ResumoMetricas resumo={resumo} incidentes={incidentes} />
              <div className="section-heading">
                <div><h2>Fila de incidentes</h2><p>Alertas agrupados para análise e resposta</p></div>
                <span className="table-count">{incidentes.length} incidente{incidentes.length === 1 ? "" : "s"}</span>
              </div>
              <LimiteDeErro parte="a fila de incidentes" chave={String(passo)}>
                <FilaDeIncidentes resumo={resumo} incidentes={incidentes} selecionadoId={selecionado?.id ?? null} onSelecionar={onSelecionar} />
              </LimiteDeErro>
            </>
          )}
          {selecionado && (
            <LimiteDeErro parte={`o detalhe do incidente ${selecionado.id}`} chave={`${selecionado.id}:${passo}`}>
              <DetalheDoIncidente key={selecionado.id} incidente={selecionado} />
            </LimiteDeErro>
          )}

          <footer className="page-footer"><span>SentryIoT <span className="footer-separator">·</span> TCC II FCI Mackenzie</span><span>Protótipo em modo replay · dados ilustrativos</span></footer>
        </div>
        )}
      </main>
    </div>
  );
}

export default function App() {
  const [eventos, setEventos] = useState<Evento[]>([]);
  const [avisos, setAvisos] = useState<string[]>([]);
  const [passo, setPasso] = useState(0);
  const [selecionadoId, setSelecionadoId] = useState<string | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [carregando, setCarregando] = useState(true);
  const [tela, setTela] = useState<Tela>(() => telaDaAncora(typeof window === "undefined" ? "" : window.location.hash));

  useEffect(() => {
    const ler = () => setTela(telaDaAncora(window.location.hash));
    window.addEventListener("hashchange", ler);
    return () => window.removeEventListener("hashchange", ler);
  }, []);

  useEffect(() => {
    carregarLog()
      .then((lido) => {
        // Os avisos valem para o log inteiro; o replay começa no estado final.
        const final = agregar(lido.eventos);
        setEventos(lido.eventos);
        setAvisos([...lido.avisos, ...final.avisos]);
        setPasso(lido.eventos.length);
        setSelecionadoId(final.incidentes[0]?.id ?? null);
      })
      .catch((erroCarregado: Error) => setErro(erroCarregado.message))
      .finally(() => setCarregando(false));
  }, []);

  return (
    <Pagina
      tela={tela}
      eventos={eventos}
      avisos={avisos}
      passo={passo}
      onMudarPasso={setPasso}
      selecionadoId={selecionadoId}
      onSelecionar={setSelecionadoId}
      carregando={carregando}
      erro={erro}
    />
  );
}
