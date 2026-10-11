import { ROTULO_DO_EVENTO, rotulo } from "../rotulos";
import type { Evento } from "../types";
import Instante from "./Instante";

interface Props {
  eventos: Evento[];
  /** Quantos eventos já foram aplicados: 0 é antes do primeiro, `eventos.length` é o estado final. */
  passo: number;
  onMudar: (passo: number) => void;
}

/** Avanço do replay evento a evento, na ordem dos ids. As telas mostram o estado até o passo atual. */
export default function ControleDoReplay({ eventos, passo, onMudar }: Props) {
  const total = eventos.length;
  const atual = passo > 0 ? eventos[passo - 1] : null;
  const ir = (novo: number) => onMudar(Math.min(Math.max(novo, 0), total));

  return (
    <section className="replay-control" aria-label="Avanço do replay">
      <div className="replay-buttons">
        <button type="button" onClick={() => ir(0)} disabled={passo === 0}>Início</button>
        <button type="button" onClick={() => ir(passo - 1)} disabled={passo === 0}>◀ Anterior</button>
        <button type="button" onClick={() => ir(passo + 1)} disabled={passo === total}>Próximo ▶</button>
        <button type="button" onClick={() => ir(total)} disabled={passo === total}>Fim</button>
      </div>
      <input
        className="replay-range"
        type="range"
        min={0}
        max={total}
        value={passo}
        onChange={(evento) => ir(Number(evento.target.value))}
        aria-label="Posição no replay"
      />
      <div className="replay-position" aria-live="polite">
        <strong>Evento {passo} de {total}</strong>
        {atual ? (
          <span><code className="event-id">{atual.id}</code> · <Instante valor={atual.instante} /> · {rotulo(ROTULO_DO_EVENTO, atual.tipo)}</span>
        ) : (
          <span>Antes do primeiro evento</span>
        )}
      </div>
    </section>
  );
}
