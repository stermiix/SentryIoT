import { useEffect, useState } from "react";
import DetalheDoIncidente from "./components/DetalheDoIncidente";
import FilaDeIncidentes from "./components/FilaDeIncidentes";
import ResumoMetricas from "./components/ResumoMetricas";
import { agregar, carregarLog } from "./log";
import type { IncidenteView, ResumoGeral } from "./types";

export default function App() {
  const [resumo, setResumo] = useState<ResumoGeral | null>(null);
  const [incidentes, setIncidentes] = useState<IncidenteView[]>([]);
  const [selecionadoId, setSelecionadoId] = useState<string | null>(null);
  const [erro, setErro] = useState<string | null>(null);
  const [carregando, setCarregando] = useState(true);

  useEffect(() => {
    carregarLog()
      .then((eventos) => {
        const agregado = agregar(eventos);
        setResumo(agregado.resumo);
        setIncidentes(agregado.incidentes);
        setSelecionadoId(agregado.incidentes[0]?.id ?? null);
      })
      .catch((erroCarregado: Error) => setErro(erroCarregado.message))
      .finally(() => setCarregando(false));
  }, []);

  const selecionado = incidentes.find((view) => view.id === selecionadoId) ?? null;

  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="#inicio" aria-label="SentryIoT início">
          <span className="brand-mark">S</span>
          <span>Sentry<span className="brand-light">IoT</span></span>
        </a>
        <div className="sidebar-label">PLATAFORMA</div>
        <nav className="navigation" aria-label="Navegação principal">
          <a className="nav-item active" href="#incidentes"><span className="nav-icon">◈</span> Incidentes <span className="nav-count">{incidentes.length}</span></a>
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
          <div className="breadcrumb">Visão geral <span>/</span> Incidentes</div>
          <div className="topbar-actions">
            <span className="replay-pill"><span className="status-dot" /> REPLAY</span>
            <span className="topbar-divider" />
            <span className="avatar" title="Projeto acadêmico">SI</span>
          </div>
        </div>

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

          {erro && <div className="error-banner"><strong>Não foi possível abrir o replay.</strong><span>{erro}</span></div>}
          {carregando && <div className="loading-state">Carregando execução demonstrativa…</div>}
          {resumo && <ResumoMetricas resumo={resumo} incidentes={incidentes} />}

          <div className="section-heading">
            <div><h2>Fila de incidentes</h2><p>Alertas agrupados para análise e resposta</p></div>
            <span className="table-count">{incidentes.length} incidente{incidentes.length === 1 ? "" : "s"}</span>
          </div>

          {resumo && <FilaDeIncidentes resumo={resumo} incidentes={incidentes} selecionadoId={selecionadoId} onSelecionar={setSelecionadoId} />}
          {selecionado && <DetalheDoIncidente incidente={selecionado} />}

          <footer className="page-footer"><span>SentryIoT <span className="footer-separator">·</span> TCC II FCI Mackenzie</span><span>Protótipo em modo replay · dados ilustrativos</span></footer>
        </div>
      </main>
    </div>
  );
}
