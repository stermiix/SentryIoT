import * as React from 'react';
import { Icon, Kbd, type IconName } from './Icon';
import { Button } from './Button';
import { TextField } from './Fields';
import { cx } from './util';
import { RISK_REASON, type RiskReason } from './vocab';

/* ---------------- Alert ---------------- */
export interface AlertProps {
  /** info · attention (atenção) · danger (erro). */
  tone?: 'info' | 'attention' | 'danger';
  title: React.ReactNode;
  children?: React.ReactNode;
  /** Reading warning: number of the log line that failed. Switches the icon to a file warning. */
  line?: number;
  /** Event number the warning refers to. */
  event?: number;
  action?: React.ReactNode;
  onDismiss?: () => void;
  className?: string;
}

const ALERT_ICON: Record<NonNullable<AlertProps['tone']>, IconName> = { info: 'info', attention: 'triangle-alert', danger: 'octagon-x' };

/** Inline notice. Reading warnings ("linha 37 inválida") keep the screen working and say so. */
export function Alert({ tone = 'info', title, children, line, event, action, onDismiss, className }: AlertProps): React.ReactElement {
  return (
    <div className={cx('sx-alert', 'sx-tone--' + tone, className)} role={tone === 'danger' ? 'alert' : 'status'}>
      <Icon name={line != null ? 'file-warning' : ALERT_ICON[tone]} size={20} className="sx-alert__icon" />
      <div className="sx-alert__body">
        <div className="sx-alert__title">
          <span>{title}</span>
          {line != null && <span className="sx-alert__ref data-sm">linha {line}</span>}
          {event != null && <span className="sx-alert__ref data-sm">evento {event}</span>}
        </div>
        {children != null && <div className="sx-alert__text body-sm">{children}</div>}
      </div>
      {action != null && <div className="sx-alert__action">{action}</div>}
      {onDismiss && <button type="button" className="sx-alert__close" aria-label="Dispensar aviso" onClick={onDismiss}><Icon name="x" size={16} /></button>}
    </div>
  );
}

/* ---------------- EmptyState ---------------- */
export interface EmptyStateProps { icon?: IconName; title: React.ReactNode; children?: React.ReactNode; action?: React.ReactNode; className?: string }

/** What a block shows when there is nothing yet. Says why and what will make it fill. */
export function EmptyState({ icon = 'inbox', title, children, action, className }: EmptyStateProps): React.ReactElement {
  return (
    <div className={cx('sx-empty', className)}>
      <span className="sx-empty__icon"><Icon name={icon} size={24} /></span>
      <div className="sx-empty__title title-3">{title}</div>
      {children != null && <div className="sx-empty__text body">{children}</div>}
      {action != null && <div className="sx-empty__action">{action}</div>}
    </div>
  );
}

/* ---------------- Skeleton ---------------- */
export interface SkeletonProps { lines?: number; height?: number | string; width?: number | string; shape?: 'text' | 'block' | 'circle'; label?: string; className?: string }

/** Loading placeholder. The shimmer stops with prefers-reduced-motion. */
export function Skeleton({ lines = 1, height, width, shape = 'text', label = 'Carregando', className }: SkeletonProps): React.ReactElement {
  if (shape !== 'text') {
    return <span className={cx('sx-skel', 'sx-skel--' + shape, className)} style={{ height, width }} role="status" aria-label={label} />;
  }
  return (
    <span className={cx('sx-skel-group', className)} role="status" aria-label={label}>
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} className="sx-skel sx-skel--text" style={{ width: i === lines - 1 && lines > 1 ? '62%' : width, height }} />
      ))}
    </span>
  );
}

/* ---------------- Tooltip ---------------- */
export interface TooltipProps { content: React.ReactNode; children: React.ReactNode; side?: 'top' | 'bottom'; className?: string }

/** Small label on hover and keyboard focus. The trigger must be focusable. */
export function Tooltip({ content, children, side = 'top', className }: TooltipProps): React.ReactElement {
  const id = React.useId();
  return (
    <span className={cx('sx-tip', 'sx-tip--' + side, className)} aria-describedby={id}>
      {children}
      <span className="sx-tip__bubble body-sm" role="tooltip" id={id}>{content}</span>
    </span>
  );
}

/* ---------------- ConfirmDialog ---------------- */
export interface ConfirmDialogProps {
  open: boolean;
  /** approve: aprovar proposta de risco alto · reject: rejeitar proposta · resolve: marcar incidente como já resolvido. */
  kind: 'approve' | 'reject' | 'resolve';
  /** What is decided: the action ("ativar_syn_cookies") or the incident id. */
  subject: string;
  /** Id shown in the eyebrow: prop-0003, inc-0002. */
  refId: string;
  /** Facts to read before deciding. */
  summary?: { label: string; value: React.ReactNode }[];
  /** High-risk reasons, shown on approve. */
  reasons?: RiskReason[];
  /** Operator recorded with the decision. */
  user: string;
  onConfirm?: (reason: string) => void;
  onCancel?: () => void;
  /** What a new action does, as the agent described it (shown after the summary, in the agent's voice). */
  details?: React.ReactNode;
  /** The line about what goes to the log. Default: recorded as a decision through the interface. */
  logNote?: React.ReactNode;
  /** The decision is being sent: the confirm button spins and both buttons wait. */
  busy?: boolean;
  /** Why the decision could not be recorded (shown inside the dialog, which stays open). */
  error?: React.ReactNode;
  /** Render in the flow instead of over the page (documentation, figures). */
  inline?: boolean;
  className?: string;
}

const DIALOG = {
  approve: { eyebrow: 'Aprovar proposta', title: (s: string) => `Aprovar ${s}?`, confirm: 'Aprovar e executar', variant: 'confirm' as const, icon: 'badge-check' as IconName, field: null },
  reject: { eyebrow: 'Rejeitar proposta', title: (s: string) => `Rejeitar ${s}?`, confirm: 'Rejeitar', variant: 'danger-solid' as const, icon: 'ban' as IconName, field: 'Motivo da rejeição (opcional)' },
  resolve: { eyebrow: 'Marcar como já resolvido', title: (s: string) => `Marcar ${s} como já resolvido?`, confirm: 'Marcar como já resolvido', variant: 'primary' as const, icon: 'user-check' as IconName, field: 'O que você fez? (opcional)' },
};

/** Confirmation for every human decision. Says what will happen and that it is recorded in the log. */
export function ConfirmDialog({ open, kind, subject, refId, summary, reasons, user, onConfirm, onCancel, details, logNote, busy = false, error, inline = false, className }: ConfirmDialogProps): React.ReactElement | null {
  // Give the dialog a `key` per decision (refId and kind) so each opening starts with an empty reason.
  const [reason, setReason] = React.useState('');
  const titleId = React.useId();
  React.useEffect(() => {
    if (!open || inline) return;
    // Esc cancels, but not while the decision is being sent.
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape' && !busy) onCancel?.(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, inline, onCancel, busy]);
  if (!open) return null;
  const d = DIALOG[kind];
  const dialog = (
    <div className={cx('sx-dialog', 'sx-dialog--' + kind, className)} role="dialog" aria-modal={!inline} aria-labelledby={titleId}>
      <div className="sx-dialog__head">
        <span className="sx-eyebrow eyebrow">{d.eyebrow} · {refId}</span>
        <h2 className="sx-dialog__title title-2" id={titleId}>{d.title(subject)}</h2>
      </div>
      {summary && summary.length > 0 && (
        <dl className="sx-dialog__summary">
          {summary.map((s) => <div key={s.label}><dt className="sx-eyebrow eyebrow">{s.label}</dt><dd>{s.value}</dd></div>)}
        </dl>
      )}
      {details != null && <div className="sx-dialog__details">{details}</div>}
      {kind === 'approve' && reasons && reasons.length > 0 && (
        <div className="sx-dialog__reasons">
          <div className="sx-eyebrow eyebrow">Você está aprovando uma ação de risco alto porque</div>
          <ul>{reasons.map((r) => <li key={r} className="body"><Icon name="triangle-alert" size={14} strokeWidth={2} />{RISK_REASON[r]}</li>)}</ul>
        </div>
      )}
      {kind === 'resolve' && <p className="body sx-dialog__text">Os agentes deixam de agir neste incidente. Nenhuma proposta nova será criada.</p>}
      {d.field && <TextField label={d.field} multiline rows={3} value={reason} onChange={(e) => setReason((e.target as HTMLTextAreaElement).value)} placeholder="Escreva com suas palavras" hint="Aparece como texto de pessoa no log e no relatório." />}
      {error != null && <Alert tone="danger" title="A decisão não foi registrada">{error}</Alert>}
      <p className="sx-dialog__log body-sm"><Icon name="scroll-text" size={14} />{logNote ?? <>Fica registrado no log: decisão pela interface · {user} · hora local.</>}</p>
      <div className="sx-dialog__actions">
        <span className="sx-dialog__keys body-sm"><Kbd>Esc</Kbd> cancela</span>
        <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancelar</Button>
        <Button variant={d.variant} icon={d.icon} loading={busy} onClick={() => onConfirm?.(reason)}>{d.confirm}</Button>
      </div>
    </div>
  );
  if (inline) return dialog;
  return <div className="sx-scrim">{dialog}</div>;
}
