import * as React from 'react';
import { Icon, type IconName } from './Icon';
import { GlassBackdrop, Logo } from './Brand';
import { cx, fmtDateWide, fmtDate } from './util';
import { AGENT, type AgentName } from './vocab';

/* ---------------- ReportCover ---------------- */
export interface ReportCoverProps {
  /** Small mark for the lockup (sentryiot-mark-128.png). */
  logoSrc: string;
  /** Large mark lit behind the title (sentryiot-mark.png). */
  heroSrc: string;
  /** Top-right kicker. Default "Relatório de incidente". */
  kicker?: string;
  /** Two short lines under the kicker. Default ["Detecta.", "Responde."]. */
  motto?: [string, string];
  /** Two lines under the logo. */
  tagline?: [string, string];
  /** Wide mono line above the title: "Resposta autônoma a intrusão". */
  eyebrow: string;
  title: React.ReactNode;
  /** Rows with an icon box, a mono label and a value (incidente, categoria, id, alvo). */
  meta: { icon: IconName; label: string; value: React.ReactNode }[];
  /** ISO date of generation, shown as "14 OUT 2026". */
  date: string;
  /** "Modo replay" / "Ao vivo". */
  mode: string;
  /** Lower-right confidentiality seal. Default true. */
  confidential?: boolean;
  /** Footer line. */
  footer?: string;
  className?: string;
}

/** A4 cover (794 × 1123 px) of the report the language model writes at the end, in the composition of the reference cover, lit in ice. */
export function ReportCover({ logoSrc, heroSrc, kicker = 'Relatório de incidente', motto = ['Detecta.', 'Responde.'], tagline = ['Detecção e resposta', 'a intrusões em redes IoT'], eyebrow, title, meta, date, mode, confidential = true, footer = '© 2026 SentryIoT · TCC · Mackenzie', className }: ReportCoverProps): React.ReactElement {
  return (
    <article className={cx('sx-report', 'sx-cover', className)} aria-label="Capa do relatório">
      <GlassBackdrop src={heroSrc} variant="report" />
      <header className="sx-cover__top">
        <div className="sx-cover__brand">
          <Logo src={logoSrc} size="lg" descriptor={false} />
          <div className="sx-cover__tagline sx-wide eyebrow-wide">{tagline[0]}<br />{tagline[1]}</div>
        </div>
        <div className="sx-cover__kicker">
          <div className="sx-cover__kickline sx-wide eyebrow-wide">{kicker}<span className="sx-cover__dash" /></div>
          <div className="sx-cover__motto sx-wide eyebrow-wide">{motto[0]}<br />{motto[1]}</div>
        </div>
      </header>

      <div className="sx-cover__main">
        <span className="sx-accent-bar" />
        <div className="sx-cover__eyebrow sx-wide eyebrow-wide">{eyebrow}</div>
        <h1 className="sx-cover__title display-md">{title}</h1>
        <dl className="sx-cover__meta">
          {meta.map((m) => (
            <div className="sx-cover__row" key={m.label}>
              <span className="sx-cover__ibox"><Icon name={m.icon} size={20} /></span>
              <dt className="sx-cover__label sx-wide data-sm">{m.label}</dt>
              <dd className="sx-cover__value">{m.value}</dd>
            </div>
          ))}
        </dl>
        <span className="sx-accent-bar" />
        <div className="sx-cover__date sx-wide eyebrow-wide">{fmtDateWide(date)} — {mode}</div>
      </div>

      <footer className="sx-cover__foot">
        <div className="sx-cover__copy sx-wide data-sm">{footer}</div>
        {confidential && (
          <div className="sx-cover__seal">
            <div className="sx-seal"><Icon name="lock" size={18} /><span className="sx-seal__bar" /><span className="sx-seal__text">Confidencial</span></div>
            <div className="sx-cover__sealnote sx-wide data-sm">Este documento contém<br />informações sensíveis.</div>
          </div>
        )}
      </footer>
    </article>
  );
}

/* ---------------- ReportPage ---------------- */
export interface ReportPageProps {
  logoSrc: string;
  /** "Relatório de incidente · inc-0001" */
  docTitle: string;
  /** ISO date. */
  date: string;
  page: number;
  pages: number;
  children?: React.ReactNode;
  className?: string;
}

/** An inner A4 page: running header, body and a confidential footer with the page count. */
export function ReportPage({ logoSrc, docTitle, date, page, pages, children, className }: ReportPageProps): React.ReactElement {
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    <article className={cx('sx-report', 'sx-rpage', className)} aria-label={`Página ${page} de ${pages}`}>
      <header className="sx-rpage__head">
        <Logo src={logoSrc} size="sm" descriptor={false} />
        <span className="sx-wide data-sm sx-rpage__doc">{docTitle}</span>
        <span className="data-sm sx-rpage__date">{fmtDate(date)}</span>
      </header>
      <div className="sx-rpage__body">{children}</div>
      <footer className="sx-rpage__foot">
        <span className="sx-rpage__conf data-sm"><Icon name="lock" size={13} />Confidencial</span>
        <span className="sx-wide data-sm">SentryIoT · TCC 2026</span>
        <span className="data-sm sx-rpage__num">{pad(page)} / {pad(pages)}</span>
      </footer>
    </article>
  );
}

/* ---------------- ReportSection ---------------- */
export interface ReportSectionProps {
  /** Section number, "01". */
  n: string;
  title: string;
  /** system: facts from the log (sans) · agent: narrative written by a model (marked, Lora itálico). */
  voice?: 'system' | 'agent';
  /** Which agent wrote it (voice="agent"). */
  agent?: AgentName;
  children?: React.ReactNode;
  className?: string;
}

/** A numbered report section. Agent-written sections carry the "gerado por agente" seal. */
export function ReportSection({ n, title, voice = 'system', agent, children, className }: ReportSectionProps): React.ReactElement {
  return (
    <section className={cx('sx-rsec', 'sx-rsec--' + voice, className)}>
      <header className="sx-rsec__head">
        <span className="sx-rsec__n data">{n}</span>
        <h2 className="sx-rsec__title title-2">{title}</h2>
        {voice === 'agent' && (
          <span className="sx-rsec__seal data-sm"><Icon name="brain-circuit" size={13} />Gerado pelo agente{agent ? ' · ' + AGENT[agent].label : ''}</span>
        )}
      </header>
      <div className={cx('sx-rsec__body', voice === 'agent' && 'voice-agent')}>{children}</div>
    </section>
  );
}

/* ---------------- ReportFacts ---------------- */
export interface ReportFactsProps { items: { label: string; value: React.ReactNode }[]; columns?: 2 | 3 | 4; className?: string }

/** Key facts from the log in a grid of mono label + value. */
export function ReportFacts({ items, columns = 3, className }: ReportFactsProps): React.ReactElement {
  return (
    <dl className={cx('sx-rfacts', className)} style={{ gridTemplateColumns: `repeat(${columns}, 1fr)` }}>
      {items.map((i) => (
        <div key={i.label} className="sx-rfacts__item">
          <dt className="sx-eyebrow eyebrow">{i.label}</dt>
          <dd className="sx-rfacts__value">{i.value}</dd>
        </div>
      ))}
    </dl>
  );
}
