import { instanteEmMs } from "./contrato";

// A hora dos eventos nas telas, no fuso de quem abre a página. Os números seguem os formatos do
// design system (`fmtInt`, `fmtNum`, `fmtPct`, em `design-system/components/util.ts`).

const HORA = new Intl.DateTimeFormat("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

/** Hora do instante no fuso local, como 14:03:52. Se o instante não puder ser lido, volta o texto dele. */
export function hora(instante: string): string {
  const ms = instanteEmMs(instante);
  return Number.isFinite(ms) ? HORA.format(ms) : instante;
}
