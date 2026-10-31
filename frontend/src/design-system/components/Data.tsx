import * as React from 'react';
import { Icon, type IconName } from './Icon';
import { CategoryBadge, StatusBadge, TargetLabel } from './Badges';
import { cx, fmtInt, fmtNum, fmtPct, clamp, ratioDown } from './util';
import type { Category, ModelCategory } from './vocab';
import type { Incident, FeatureRow, Address } from './modelos';

/* ---------------- MetricCard ---------------- */
export interface MetricCardProps {
  /** Mono label: "Tokens", "Chamadas à IA". */
  label: string;
  value: number | string;
  /** Small unit after the number ("s", "%", "tokens"). */
  unit?: string;
  /** One line of context under the number. */
  context?: React.ReactNode;
  icon?: IconName;
  /** Variation chip, e.g. { text: "−47% na nuvem", tone: "success" }. */
  delta?: { text: string; tone?: 'success' | 'danger' | 'neutral' | 'attention' };
  /** Sparkline values (left → right). */
  spark?: number[];
  /** attention: the number asks for a person (propostas aguardando). */
  tone?: 'default' | 'attention';
  className?: string;
}

/** Big number with a mono label: the "340 Executions" card of the references. */
export function MetricCard({ label, value, unit, context, icon, delta, spark, tone = 'default', className }: MetricCardProps): React.ReactElement {
  const shown = typeof value === 'number' ? fmtInt(value) : value;
  return (
    <div className={cx('sx-metric', tone === 'attention' && 'sx-metric--attention', className)}>
      <div className="sx-metric__top">
        <span className="sx-eyebrow eyebrow">{label}</span>
        {icon && <Icon name={icon} size={18} className="sx-metric__icon" />}
      </div>
      <div className="sx-metric__row">
        <span className="sx-metric__value metric">{shown}</span>
        {unit && <span className="sx-metric__unit">{unit}</span>}
        {delta && <span className={cx('sx-delta', 'sx-tone--' + (delta.tone ?? 'neutral'))}>{delta.text}</span>}
      </div>
      {spark && spark.length > 1 && <Sparkline values={spark} />}
      {context != null && <div className="sx-metric__context body-sm">{context}</div>}
    </div>
  );
}

function Sparkline({ values }: { values: number[] }): React.ReactElement {
  const w = 160, h = 32, max = Math.max(...values), min = Math.min(...values);
  const pts = values.map((v, i) => [(i / (values.length - 1)) * w, h - 3 - ((v - min) / (max - min || 1)) * (h - 6)]);
  const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  return (
    <svg className="sx-spark" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-hidden="true">
      <path d={d + ` L${w} ${h} L0 ${h} Z`} className="sx-spark__area" />
      <path d={d} className="sx-spark__line" />
    </svg>
  );
}

/* ---------------- AggregationFunnel ---------------- */
export interface AggregationFunnelProps {
  /** Windows classified by the Random Forest. */
  windows: number;
  /** Incidents those windows became (handed to the agents). */
  incidents: number;
  /** Calls to the language models. */
  aiCalls: number;
  /** Calls there would be without aggregation: one per window classified as attack. Default `windows`. */
  counterfactual?: number;
  /** Mono note on the scope, e.g. "LOG DE EXEMPLO · 52 EVENTOS". */
  scope?: string;
  /** Extra line under the counterfactual. */
  footnote?: React.ReactNode;
  className?: string;
}

/** The argument of the work at a glance: janelas classificadas → incidente → chamadas à IA,
 *  and what it would cost without aggregation (Denial of Wallet). */
export function AggregationFunnel({ windows, incidents, aiCalls, counterfactual = windows, scope, footnote, className }: AggregationFunnelProps): React.ReactElement {
  const ratio = ratioDown(counterfactual, aiCalls);
  const lines = React.useMemo(() => {
    const out: { y: number; len: number }[] = [];
    let s = 7;
    for (let i = 0; i < 46; i++) { s = (s * 9301 + 49297) % 233280; out.push({ y: 14 + i * 3, len: 70 + (s / 233280) * 130 }); }
    return out;
  }, []);
  const calls = Math.min(aiCalls, 24);
  const nodeX = 500, nodeY = 82;
  return (
    <section className={cx('sx-funnel', className)} aria-label={`${fmtInt(windows)} janelas classificadas, ${incidents} ${incidents === 1 ? 'incidente' : 'incidentes'}, ${aiCalls} chamadas à IA`}>
      <div className="sx-funnel__head">
        <span className="sx-eyebrow eyebrow">Do tráfego à IA</span>
        {scope && <span className="sx-funnel__scope data-sm">{scope}</span>}
      </div>
      <div className="sx-funnel__numbers">
        <div className="sx-funnel__stage">
          <span className="sx-funnel__num display-xl">{fmtInt(windows)}</span>
          <span className="sx-funnel__label body-lg">janelas classificadas</span>
        </div>
        <Icon name="chevron-right" size={28} className="sx-funnel__arrow sx-funnel__arrow--a" />
        <div className="sx-funnel__stage sx-funnel__stage--mid">
          <span className="sx-funnel__num display-xl">{fmtInt(incidents)}</span>
          <span className="sx-funnel__label body-lg">{incidents === 1 ? 'incidente' : 'incidentes'}</span>
        </div>
        <Icon name="chevron-right" size={28} className="sx-funnel__arrow sx-funnel__arrow--b" />
        <div className="sx-funnel__stage sx-funnel__stage--end">
          <span className="sx-funnel__num sx-funnel__num--ice display-xl">{fmtInt(aiCalls)}</span>
          <span className="sx-funnel__label body-lg">chamadas à IA</span>
        </div>
      </div>
      <svg className="sx-funnel__graph" viewBox="0 0 1000 168" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
        {/* no window yet: no threads, only the node */}
        {(windows > 0 ? lines : []).map((l, i) => (
          <g key={i}>
            <line x1={200 - l.len} y1={l.y} x2={200} y2={l.y} className="sx-funnel__win" />
            <path d={`M200 ${l.y} C 340 ${l.y}, 380 ${nodeY}, ${nodeX - 14} ${nodeY}`} className="sx-funnel__flow" />
          </g>
        ))}
        {Array.from({ length: calls }, (_, i) => {
          const y = calls === 1 ? nodeY : 22 + (i * 120) / (calls - 1);
          return (
            <g key={'c' + i}>
              <path d={`M${nodeX + 14} ${nodeY} C 640 ${nodeY}, 700 ${y}, 948 ${y}`} className="sx-funnel__out" />
              <circle cx={956} cy={y} r={5} className="sx-funnel__call" />
            </g>
          );
        })}
        <circle cx={nodeX} cy={nodeY} r={34} className="sx-funnel__halo" />
        <circle cx={nodeX} cy={nodeY} r={12} className="sx-funnel__node" />
      </svg>
      <div className="sx-funnel__foot">
        <span className="sx-funnel__counter body">
          {windows > 0 ? (
            <>Sem agregação, cada janela de ataque seria uma chamada: <strong className="data">{fmtInt(counterfactual)} chamadas à IA</strong>, o risco de <em>Denial of Wallet</em>.</>
          ) : (
            'Nenhuma janela classificada ainda.'
          )}
        </span>
        {ratio > 1 && <span className="sx-funnel__ratio"><Icon name="trending-down" size={16} />{fmtInt(ratio)}× menos chamadas</span>}
      </div>
      {footnote != null && <div className="sx-funnel__note body-sm">{footnote}</div>}
    </section>
  );
}

/* ---------------- ConfidenceMeter ---------------- */
export interface ConfidenceMeterProps {
  /** Classifier confidence 0..1. */
  value: number;
  /** pct: "97%" (default, telas) · decimal: "0,97" (como no log). */
  format?: 'pct' | 'decimal';
  size?: 'sm' | 'md';
  className?: string;
}

/** Classifier confidence as a number plus a thin bar. Below 0,60 the bar turns amber. */
export function ConfidenceMeter({ value, format = 'pct', size = 'md', className }: ConfidenceMeterProps): React.ReactElement {
  const v = clamp(value, 0, 1);
  const text = format === 'pct' ? fmtPct(v) : fmtNum(v, 2);
  return (
    <span className={cx('sx-conf', 'sx-conf--' + size, v < 0.6 && 'is-low', className)} role="meter" aria-valuemin={0} aria-valuemax={1} aria-valuenow={v} aria-label={`Confiança ${text}`}>
      <span className="sx-conf__value">{text}</span>
      <span className="sx-conf__track"><span className="sx-conf__fill" style={{ width: v * 100 + '%' }} /></span>
    </span>
  );
}

/* ---------------- ClassifierVerdict ---------------- */
export interface ClassifierVerdictProps {
  /** What the Random Forest said (7 classes). */
  model: ModelCategory;
  /** The incident's category after counting sources (undefined while unknown). */
  category?: Category;
  sources: number;
  confidence: number;
  className?: string;
}

/** Both categories side by side: "o modelo disse DDoS+DoS; com 37 origens, é um DDoS". */
export function ClassifierVerdict({ model, category, sources, confidence, className }: ClassifierVerdictProps): React.ReactElement {
  return (
    <div className={cx('sx-verdict', className)}>
      <div className="sx-verdict__chain">
        <div className="sx-verdict__step">
          <span className="sx-eyebrow eyebrow">O modelo disse</span>
          <CategoryBadge category={model} model size="lg" />
        </div>
        <Icon name="arrow-right" size={20} className="sx-verdict__arrow" />
        <div className="sx-verdict__step">
          <span className="sx-eyebrow eyebrow">{category ? `Com ${fmtInt(sources)} ${sources === 1 ? 'origem' : 'origens'}, é` : `Origens até agora: ${fmtInt(sources)}`}</span>
          {category ? <CategoryBadge category={category} size="lg" /> : <span className="sx-verdict__pending body-sm">aguardando a contagem final de origens</span>}
        </div>
        <div className="sx-verdict__step sx-verdict__step--conf">
          <span className="sx-eyebrow eyebrow">Confiança</span>
          <ConfidenceMeter value={confidence} />
        </div>
      </div>
      <p className="sx-verdict__sentence body-lg">
        O modelo disse <strong>{model}</strong>{category ? <>; com {fmtInt(sources)} {sources === 1 ? 'origem' : 'origens'}, é um <strong>{category}</strong>.</> : '.'}
      </p>
    </div>
  );
}

/* ---------------- IncidentQueue ---------------- */
export interface IncidentQueueProps {
  incidents: Incident[];
  selectedId?: string;
  onSelect?: (id: string) => void;
  /** Rendered when the list is empty. */
  empty?: React.ReactNode;
  className?: string;
}

/** The incident queue: category (final + model), state, pending approvals, confidence, windows, sources, time. */
export function IncidentQueue({ incidents, selectedId, onSelect, empty, className }: IncidentQueueProps): React.ReactElement {
  if (incidents.length === 0 && empty != null) return <>{empty}</>;
  return (
    <div className={cx('sx-tablewrap', className)}>
      <table className="sx-table sx-queue">
        <thead>
          <tr>
            <th scope="col">Incidente</th>
            <th scope="col">Categoria</th>
            <th scope="col">Estado</th>
            <th scope="col">Confiança</th>
            <th scope="col" className="is-num">Janelas</th>
            <th scope="col" className="is-num">Origens</th>
            <th scope="col">Horário</th>
          </tr>
        </thead>
        <tbody>
          {incidents.map((inc) => {
            const on = inc.id === selectedId;
            return (
              <tr key={inc.id} className={cx(on && 'is-selected', inc.awaiting > 0 && 'is-attention')} onClick={() => onSelect?.(inc.id)}>
                <td>
                  <button type="button" className="sx-rowlink data" aria-pressed={on} onClick={(e: React.MouseEvent<HTMLButtonElement>) => { e.stopPropagation(); onSelect?.(inc.id); }}>
                    {inc.id}
                  </button>
                </td>
                <td>
                  <span className="sx-queue__cats">
                    {inc.category ? <CategoryBadge category={inc.category} /> : <CategoryBadge category={inc.modelCategory} model />}
                    {inc.category && inc.category !== inc.modelCategory && <CategoryBadge category={inc.modelCategory} model size="sm" />}
                  </span>
                </td>
                <td>
                  <span className="sx-queue__state">
                    <StatusBadge kind="incident" value={inc.state} />
                    {inc.awaiting > 0 && <StatusBadge kind="proposal" value="aguardando_aprovacao" size="sm" className="sx-queue__await" />}
                    {inc.awaiting > 1 && <span className="sx-queue__awaitn data-sm">×{inc.awaiting}</span>}
                  </span>
                </td>
                <td><ConfidenceMeter value={inc.confidence} size="sm" /></td>
                <td className="is-num data">{fmtInt(inc.windows)}</td>
                <td className="is-num data">{fmtInt(inc.sources)}</td>
                <td className="data sx-queue__time">{inc.start}{inc.end !== inc.start && <span className="sx-muted"> · {fmtInt(secondsBetween(inc.start, inc.end))} s</span>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function secondsBetween(a: string, b: string): number {
  const t = (x: string) => x.split(':').reduce((s, v) => s * 60 + Number(v), 0);
  return Math.max(0, t(b) - t(a));
}

/* ---------------- FeatureTable ---------------- */
export interface FeatureTableProps {
  rows: FeatureRow[];
  className?: string;
}

function ratioLabel(value: number, benign: number): { text: string; log: number } {
  if (value === 0 && benign === 0) return { text: 'igual', log: 0 };
  if (value === 0) return { text: 'zero', log: -4 };
  if (benign === 0) return { text: 'novo', log: 4 };
  const r = value / benign;
  const log = clamp(Math.log10(r), -4, 4);
  if (r >= 1) return { text: '×' + fmtInt(r), log };
  return { text: '÷' + fmtInt(1 / r), log };
}

/** Features of the incident against the benign reference, on a log scale centred on "igual ao benigno". */
export function FeatureTable({ rows, className }: FeatureTableProps): React.ReactElement {
  return (
    <div className={cx('sx-tablewrap', className)}>
      <table className="sx-table sx-features">
        <thead>
          <tr>
            <th scope="col">Feature</th>
            <th scope="col" className="is-num">Incidente</th>
            <th scope="col" className="is-num">Ref. benigna</th>
            <th scope="col">Comparação <span className="sx-th-note">escala log</span></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const { text, log } = ratioLabel(r.value, r.benign);
            const w = (Math.abs(log) / 4) * 50;
            return (
              <tr key={r.name}>
                <td className="data sx-features__name">{r.name}</td>
                <td className="is-num data">{fmtNum(r.value, r.decimals)}</td>
                <td className="is-num data sx-muted">{fmtNum(r.benign, r.decimals)}</td>
                <td>
                  <span className="sx-ratio">
                    <span className="sx-ratio__track" aria-hidden="true">
                      <span className="sx-ratio__zero" />
                      <span className={cx('sx-ratio__bar', log < 0 && 'is-below')} style={log >= 0 ? { left: '50%', width: w + '%' } : { right: '50%', width: w + '%' }} />
                    </span>
                    <span className={cx('sx-ratio__text data', Math.abs(log) >= 1 && 'is-strong')}>{text}</span>
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/* ---------------- AddressList ---------------- */
export interface AddressListProps {
  /** "Origens" / "Destinos". */
  title: string;
  items: Address[];
  /** Total in the incident; the rest is summarised as "+ N". */
  total?: number;
  /** Hide real addresses (figure for the article, screen shared with the cloud view). */
  hideAddresses?: boolean;
  /** One address of the list singled out with a short tag, e.g. the attacker the triage pointed at. */
  mark?: { address: string; label: string; icon: IconName };
  className?: string;
}

/** Addresses with frame counts and the neutral label each one gets before reaching the cloud agent. */
export function AddressList({ title, items, total, hideAddresses = false, mark, className }: AddressListProps): React.ReactElement {
  const max = Math.max(...items.map((i) => i.frames), 1);
  const more = (total ?? items.length) - items.length;
  return (
    <div className={cx('sx-addr', className)}>
      <div className="sx-addr__head">
        <span className="sx-eyebrow eyebrow">{title}<span className="sx-addr__total data-sm">{fmtInt(total ?? items.length)}</span></span>
        <span className="sx-addr__unit data-sm">quadros</span>
      </div>
      <ul className="sx-addr__list">
        {items.map((a) => (
          <li key={a.address} className="sx-addr__row">
            {mark?.address === a.address ? (
              <span className="sx-addr__who">
                <TargetLabel label={a.label} address={hideAddresses ? undefined : a.address} />
                <span className="sx-addr__mark data-sm"><Icon name={mark.icon} size={12} />{mark.label}</span>
              </span>
            ) : (
              <TargetLabel label={a.label} address={hideAddresses ? undefined : a.address} />
            )}
            <span className="sx-addr__bar" aria-hidden="true"><span style={{ width: (a.frames / max) * 100 + '%' }} /></span>
            <span className="sx-addr__frames data">{fmtInt(a.frames)}</span>
          </li>
        ))}
      </ul>
      {more > 0 && <div className="sx-addr__more data-sm">+ {fmtInt(more)} {a11yPlural(more, title)}</div>}
    </div>
  );
}
function a11yPlural(n: number, title: string): string {
  const t = title.toLowerCase();
  return n === 1 ? t.replace(/s$/, '') : t;
}
