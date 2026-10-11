import { instanteEmMs } from "./contrato";

// Formatos de número e de hora usados nas telas. A hora sai no fuso de quem abre a página.

const HORA = new Intl.DateTimeFormat("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const COMPLETO = new Intl.DateTimeFormat("pt-BR", {
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  timeZoneName: "short",
});

/** Hora do instante no fuso local, como 14:03:52. Se o instante não puder ser lido, volta o texto dele. */
export function hora(instante: string): string {
  const ms = instanteEmMs(instante);
  return Number.isFinite(ms) ? HORA.format(ms) : instante;
}

/** Data, hora com milissegundos e fuso, para o `title`: vários eventos caem no mesmo segundo. */
export function instanteCompleto(instante: string): string {
  const ms = instanteEmMs(instante);
  if (!Number.isFinite(ms)) {
    return instante;
  }
  const milissegundos = String(new Date(ms).getMilliseconds()).padStart(3, "0");
  return COMPLETO.formatToParts(ms)
    .map((parte) => (parte.type === "second" ? `${parte.value},${milissegundos}` : parte.value))
    .join("");
}

/** Valores de feature como o IAT (2,8e-5) virariam "0" com o arredondamento padrão de três casas. */
export function numero(valor: number): string {
  const opcoes = Math.abs(valor) < 1 && valor !== 0 ? { maximumSignificantDigits: 3 } : undefined;
  return valor.toLocaleString("pt-BR", opcoes);
}

export function inteiro(valor: number): string {
  return valor.toLocaleString("pt-BR");
}
