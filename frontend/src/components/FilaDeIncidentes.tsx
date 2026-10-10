import type { IncidenteView, ResumoGeral } from "../types";

interface Props {
  resumo: ResumoGeral;
  incidentes: IncidenteView[];
  selecionadoId: string | null;
  onSelecionar: (id: string) => void;
}

function percentual(confianca: number) {
  return `${Math.round(confianca * 100)}%`;
}

/** Fila selecionável com categoria, prioridade e métricas úteis para triagem. */
export default function FilaDeIncidentes({ resumo, incidentes, selecionadoId, onSelecionar }: Props) {
  return (
    <section className="queue-card" aria-label="Incidentes detectados">
      <table className="tabela-incidentes">
        <thead>
          <tr>
            <th scope="col">INCIDENTE</th>
            <th scope="col">CATEGORIA</th>
            <th scope="col">PERFIL</th>
            <th scope="col">ESTADO</th>
            <th scope="col">CONFIANÇA</th>
            <th scope="col">JANELAS</th>
            <th scope="col">IA</th>
          </tr>
        </thead>
        <tbody>
          {incidentes.map((view) => (
            <tr key={view.id} className={view.id === selecionadoId ? "selecionada" : ""}>
              <td>
                <button className="incident-select" onClick={() => onSelecionar(view.id)} aria-pressed={view.id === selecionadoId}>
                  <span className="incident-marker" />
                  <span><strong>{view.id}</strong><small>Detecção automática</small></span>
                </button>
              </td>
              <td><span className="category-pill">{view.incidente?.categoria ?? "—"}</span></td>
              <td><span className={`severity ${view.incidente?.distribuido ? "severity-distributed" : "severity-single"}`}><span />{view.incidente?.distribuido ? "Distribuído" : "Uma origem"}</span></td>
              <td><span className={`state-pill ${view.incidente?.estado === "aberto" ? "state-open" : "state-closed"}`}><span />{view.incidente?.estado === "aberto" ? "Em análise" : "Encerrado"}</span></td>
              <td><span className="confidence-value">{view.incidente ? percentual(view.incidente.confianca) : "—"}</span></td>
              <td>{view.incidente?.janelas.toLocaleString("pt-BR") ?? "—"}</td>
              <td><span className="ai-count">✳ {view.chamadasLLM}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      {incidentes.length === 0 && <div className="empty-state">Nenhum incidente foi encontrado neste replay.</div>}
      <div className="queue-footnote"><span><i className="tiny-dot" /> Dados de demonstração</span><span>{resumo.totalIncidentes} registro(s) no arquivo</span></div>
    </section>
  );
}
