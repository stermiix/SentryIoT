import { inteiro } from "../formato";
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

function estadoNaFila(view: IncidenteView): { classe: string; texto: string } {
  return view.incidente.estado === "encerrado"
    ? { classe: "state-closed", texto: "Encerrado" }
    : { classe: "state-open", texto: "Em análise" };
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
          {incidentes.map((view) => {
            const estado = estadoNaFila(view);
            return (
              <tr key={view.id} className={view.id === selecionadoId ? "selecionada" : ""}>
                <td>
                  <button className="incident-select" onClick={() => onSelecionar(view.id)} aria-pressed={view.id === selecionadoId}>
                    <span className="incident-marker" />
                    <span><strong>{view.id}</strong><small>Detecção automática</small></span>
                  </button>
                </td>
                <td><span className="category-pill">{view.incidente.categoria}</span></td>
                <td><span className={`severity ${view.incidente.distribuido ? "severity-distributed" : "severity-single"}`}><span />{view.incidente.distribuido ? "Distribuído" : "Uma origem"}</span></td>
                <td><span className={`state-pill ${estado.classe}`}><span />{estado.texto}</span></td>
                <td><span className="confidence-value">{percentual(view.incidente.confianca)}</span></td>
                <td>{inteiro(view.incidente.janelas)}</td>
                <td><span className="ai-count">✳ {view.chamadasLLM}</span></td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {incidentes.length === 0 && <div className="empty-state">Nenhum incidente aberto até este ponto do replay.</div>}
      <div className="queue-footnote">
        <span><i className="tiny-dot" /> Dados de demonstração</span>
        <span>
          {resumo.totalIncidentes} incidente(s) com abertura no log
          {resumo.eventosSemAbertura > 0 && ` · ${resumo.eventosSemAbertura} evento(s) de incidente sem abertura, fora da fila`}
        </span>
      </div>
    </section>
  );
}
