import * as React from 'react';
import { Icon } from './Icon';
import { cx, fmtInt, fmtPct } from './util';
import { CATEGORY, type AnyCategory, type ModelCategory } from './vocab';

// Layout effect in the browser; plain effect where there is no DOM (server rendering in the tests).
const useClientLayoutEffect = typeof window === 'undefined' ? React.useEffect : React.useLayoutEffect;

function useWidth(ref: React.RefObject<HTMLElement>, fallback: number): number {
  const [w, setW] = React.useState(fallback);
  useClientLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => { const cw = entries[0]?.contentRect.width; if (cw) setW(cw); });
    ro.observe(el);
    setW(el.getBoundingClientRect().width || fallback);
    return () => ro.disconnect();
  }, []);
  return w;
}

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
}

/* ---------------- AreaChart ---------------- */
export interface ChartSeries {
  name: string;
  values: number[];
}
export interface AreaChartProps {
  /** First series is drawn as the glacier area; the second as a dashed slate line (works in grayscale). */
  series: ChartSeries[];
  /** X labels, one per value ("#1", "14:03:12"). */
  labels: string[];
  /** Formats values on the axis and in the tooltip. */
  format?: (v: number) => string;
  /** Unit after the tooltip value. */
  unit?: string;
  height?: number;
  /** Accessible summary of what the chart shows. */
  ariaLabel: string;
  /** Point shown with the tooltip when nothing is hovered (figures for the article). */
  defaultIndex?: number;
  className?: string;
}

/** Smooth area over time with a floating tooltip; arrow keys move the tooltip. */
export function AreaChart({ series, labels, format = (v) => fmtInt(v), unit, height = 220, ariaLabel, defaultIndex, className }: AreaChartProps): React.ReactElement {
  const ref = React.useRef<HTMLDivElement>(null);
  const width = useWidth(ref as React.RefObject<HTMLElement>, 640);
  const [hover, setHover] = React.useState<number | null>(defaultIndex ?? null);
  const padL = 56, padR = 16, padT = 16, padB = 32;
  const n = labels.length;
  const max = niceMax(Math.max(...series.flatMap((s) => s.values)) * 1.08);
  const x = (i: number) => padL + (n > 1 ? (i / (n - 1)) * (width - padL - padR) : 0);
  const y = (v: number) => padT + (1 - v / max) * (height - padT - padB);
  const path = (vals: number[]) => {
    let d = '';
    vals.forEach((v, i) => {
      if (i === 0) { d += `M${x(0)} ${y(v)}`; return; }
      const x0 = x(i - 1), y0 = y(vals[i - 1]), x1 = x(i), y1 = y(v), cx1 = x0 + (x1 - x0) / 2;
      d += ` C${cx1} ${y0}, ${cx1} ${y1}, ${x1} ${y1}`;
    });
    return d;
  };
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((t) => t * max);
  const step = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((width - padL - padR) / 72))));
  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
    const px = e.clientX - r.left;
    const i = Math.round(((px - padL) / (width - padL - padR)) * (n - 1));
    setHover(Math.max(0, Math.min(n - 1, i)));
  };
  const onKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'ArrowRight') { setHover((h) => Math.min(n - 1, (h ?? -1) + 1)); e.preventDefault(); }
    if (e.key === 'ArrowLeft') { setHover((h) => Math.max(0, (h ?? n) - 1)); e.preventDefault(); }
  };
  const main = series[0];
  // The series can shrink (the replay going back): a point that no longer exists is not drawn.
  const shown = hover != null && hover < n ? hover : defaultIndex != null && defaultIndex < n ? defaultIndex : null;
  const tipLeft = shown != null ? Math.min(Math.max(x(shown), 90), width - 90) : 0;
  return (
    <div className={cx('sx-chart', className)} ref={ref} tabIndex={0} onKeyDown={onKey} onBlur={() => setHover(defaultIndex ?? null)} role="img" aria-label={ariaLabel}>
      <svg width={width} height={height} onMouseMove={onMove} onMouseLeave={() => setHover(defaultIndex ?? null)}>
        <defs>
          <linearGradient id="sx-area-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" style={{ stopColor: 'var(--glacier-deep)', stopOpacity: 0.55 }} />
            <stop offset="1" style={{ stopColor: 'var(--glacier-deep)', stopOpacity: 0 }} />
          </linearGradient>
        </defs>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={padL} x2={width - padR} y1={y(t)} y2={y(t)} className="sx-chart__grid" />
            <text x={padL - 10} y={y(t) + 4} className="sx-chart__axis" textAnchor="end">{format(t)}</text>
          </g>
        ))}
        {labels.map((l, i) => (i % step === 0 || i === n - 1) && (
          <text key={i} x={x(i)} y={height - 8} className="sx-chart__axis" textAnchor="middle">{l}</text>
        ))}
        {main && <path d={path(main.values) + ` L${x(n - 1)} ${y(0)} L${x(0)} ${y(0)} Z`} fill="url(#sx-area-fill)" />}
        {series.slice(1).map((s) => <path key={s.name} d={path(s.values)} className="sx-chart__line2" />)}
        {main && <path d={path(main.values)} className="sx-chart__line" />}
        {shown != null && (
          <g>
            <line x1={x(shown)} x2={x(shown)} y1={padT} y2={height - padB} className="sx-chart__cursor" />
            {series.map((s, k) => <circle key={s.name} cx={x(shown)} cy={y(s.values[shown])} r={k === 0 ? 6 : 4} className={k === 0 ? 'sx-chart__dot' : 'sx-chart__dot2'} />)}
          </g>
        )}
      </svg>
      {shown != null && (
        <div className="sx-chart__tip" style={{ left: tipLeft, top: 4 }}>
          <div className="data-sm sx-chart__tiplabel">{labels[shown]}</div>
          {series.map((s, k) => (
            <div key={s.name} className="sx-chart__tiprow">
              <span className={cx('sx-chart__key', k > 0 && 'is-dashed')} />
              <span className="body-sm">{s.name}</span>
              <span className="data sx-chart__tipval">{format(s.values[shown])}{unit ? ' ' + unit : ''}</span>
            </div>
          ))}
        </div>
      )}
      {series.length > 1 && (
        <div className="sx-chart__legend body-sm">
          {series.map((s, k) => <span key={s.name}><span className={cx('sx-chart__key', k > 0 && 'is-dashed')} />{s.name}</span>)}
        </div>
      )}
    </div>
  );
}

/* ---------------- CategoryBars ---------------- */
export interface CategoryBarsProps {
  data: { category: AnyCategory; value: number }[];
  /** Formats the value at the end of each bar. */
  format?: (v: number) => string;
  /** Show each bar's share of the total after the value. */
  showShare?: boolean;
  ariaLabel: string;
  className?: string;
}

/** Horizontal bars by category: colour, glyph and a print pattern, so the figure survives grayscale. */
export function CategoryBars({ data, format = (v) => fmtInt(v), showShare = false, ariaLabel, className }: CategoryBarsProps): React.ReactElement {
  const max = Math.max(...data.map((d) => d.value), 1);
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  return (
    <div className={cx('sx-bars', className)} role="img" aria-label={ariaLabel}>
      {data.map((d) => {
        const c = CATEGORY[d.category];
        return (
          <div className="sx-bars__row" key={d.category} style={{ ['--cat' as string]: `var(--${c.token})` }}>
            <span className="sx-bars__label"><span className="sx-bars__glyph"><Icon name={c.icon} size={14} strokeWidth={1.9} /></span>{c.label}</span>
            <span className="sx-bars__track"><span className={cx('sx-bars__bar', 'sx-pattern--' + c.pattern)} style={{ width: Math.max(0.6, (d.value / max) * 100) + '%' }} /></span>
            <span className="sx-bars__value data">{format(d.value)}{showShare && <span className="sx-bars__share"> {fmtPct(d.value / total, 1)}</span>}</span>
          </div>
        );
      })}
    </div>
  );
}

/* ---------------- ConfusionMatrix ---------------- */
export interface ConfusionMatrixProps {
  /** The model's classes, in order (7 for SentryIoT). */
  labels: ModelCategory[];
  /** matrix[real][previsto] counts. */
  matrix: number[][];
  ariaLabel?: string;
  className?: string;
}

function heat(f: number): number { return f === 0 ? 0 : f < 0.05 ? 1 : f < 0.2 ? 2 : f < 0.5 ? 3 : f < 0.8 ? 4 : 5; }

/** 7×7 heat map: rows are the real class, columns the predicted one, shaded by share of the row. Diagonal outlined. */
export function ConfusionMatrix({ labels, matrix, ariaLabel = 'Matriz de confusão do classificador', className }: ConfusionMatrixProps): React.ReactElement {
  const [hover, setHover] = React.useState<[number, number] | null>(null);
  const n = labels.length;
  return (
    <div className={cx('sx-cm', className)} role="table" aria-label={ariaLabel} style={{ ['--n' as string]: n }}>
      <div className="sx-cm__axis sx-cm__axis--x sx-eyebrow eyebrow" aria-hidden="true">Previsto</div>
      <div className="sx-cm__axis sx-cm__axis--y sx-eyebrow eyebrow" aria-hidden="true">Real</div>
      <div className="sx-cm__grid" role="rowgroup">
        <div className="sx-cm__row" role="row">
          <span className="sx-cm__corner" />
          {labels.map((l) => (
            <span key={l} className="sx-cm__colhead" role="columnheader" title={l}><Icon name={CATEGORY[l].icon} size={14} /><span>{l.replace('+', '+\u200b')}</span></span>
          ))}
        </div>
        {matrix.map((row, i) => {
          const sum = row.reduce((s, v) => s + v, 0) || 1;
          return (
            <div className="sx-cm__row" role="row" key={labels[i]}>
              <span className="sx-cm__rowhead" role="rowheader"><Icon name={CATEGORY[labels[i]].icon} size={14} /><span>{labels[i]}</span></span>
              {row.map((v, j) => {
                const f = v / sum;
                const on = hover && hover[0] === i && hover[1] === j;
                return (
                  <span
                    key={j}
                    role="cell"
                    tabIndex={0}
                    className={cx('sx-cm__cell', 'sx-heat-' + heat(f), i === j && 'is-diag', on && 'is-hover')}
                    onMouseEnter={() => setHover([i, j])}
                    onMouseLeave={() => setHover(null)}
                    onFocus={() => setHover([i, j])}
                    onBlur={() => setHover(null)}
                    aria-label={`Real ${labels[i]}, previsto ${labels[j]}: ${fmtInt(v)} janelas, ${fmtPct(f, 1)} da linha`}
                  >
                    <span className="sx-cm__count">{v === 0 ? '·' : fmtInt(v)}</span>
                    {on && <span className="sx-cm__tip body-sm">Real <b>{labels[i]}</b> · previsto <b>{labels[j]}</b><br /><span className="data">{fmtInt(v)} janelas · {fmtPct(f, 1)}</span></span>}
                  </span>
                );
              })}
            </div>
          );
        })}
      </div>
      <div className="sx-cm__legend body-sm" aria-hidden="true">
        <span>% da linha</span>
        {[1, 2, 3, 4, 5].map((k) => <span key={k} className={cx('sx-cm__swatch', 'sx-heat-' + k)} />)}
        <span className="data-sm">0 → 100%</span>
      </div>
    </div>
  );
}
