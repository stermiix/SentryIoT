/* Shared helpers: class names and pt-BR formatting (vírgula decimal, ponto de milhar). */

export function cx(...parts: Array<string | false | null | undefined | 0>): string {
  return parts.filter(Boolean).join(' ');
}

const intFmt = new Intl.NumberFormat('pt-BR', { maximumFractionDigits: 0 });

/** 10946 → "10.946" */
export function fmtInt(n: number): string {
  return intFmt.format(Math.round(n));
}

/** 35778.4 → "35.778,4"; 0,0104 → "0,0104"; 0.000028 → "0,000028" (three significant digits below 1). */
export function fmtNum(n: number, decimals?: number): string {
  if (decimals === undefined) {
    const abs = Math.abs(n);
    if (abs > 0 && abs < 1) return new Intl.NumberFormat('pt-BR', { maximumSignificantDigits: 3 }).format(n);
    decimals = Number.isInteger(n) ? 0 : 1;
  }
  return new Intl.NumberFormat('pt-BR', { minimumFractionDigits: decimals, maximumFractionDigits: decimals }).format(n);
}

/** How many times fewer: 10.734 windows for 11 calls → 975 (rounded down, never overstated). */
export function ratioDown(total: number, part: number): number {
  return part > 0 ? Math.floor(total / part) : 0;
}

/** 0.97 → "97%"; with decimals 1 → "97,0%" */
export function fmtPct(fraction: number, decimals = 0): string {
  return new Intl.NumberFormat('pt-BR', { minimumFractionDigits: decimals, maximumFractionDigits: decimals }).format(fraction * 100) + '%';
}

/** Confidence 0..1 shown as the project wants: "0,97" */
export function fmtConfidence(fraction: number): string {
  return fmtNum(fraction, 2);
}

/** seconds → "1,9 s" / "820 ms" */
export function fmtDuration(seconds: number): string {
  if (seconds < 1) return fmtInt(seconds * 1000) + ' ms';
  return fmtNum(seconds, 1) + ' s';
}

/** "2026-10-14" → "14/10/2026" */
export function fmtDate(iso: string): string {
  const [y, m, d] = iso.slice(0, 10).split('-');
  return `${d}/${m}/${y}`;
}

const MONTHS = ['JAN', 'FEV', 'MAR', 'ABR', 'MAI', 'JUN', 'JUL', 'AGO', 'SET', 'OUT', 'NOV', 'DEZ'];
/** "2026-10-14" → "14 OUT 2026" (capa do relatório) */
export function fmtDateWide(iso: string): string {
  const [y, m, d] = iso.slice(0, 10).split('-');
  return `${d} ${MONTHS[Number(m) - 1]} ${y}`;
}

export function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}
