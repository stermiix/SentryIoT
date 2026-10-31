import * as React from 'react';
import { Icon } from './Icon';
import { cx } from './util';
import {
  AGENT, CATEGORY, CHANNEL, EFFECT, EXECUTION_STATE, INCIDENT_STATE, PROPOSAL_STATE, RISK,
  type AgentName, type AnyCategory, type Channel, type EffectResult, type ExecutionState,
  type IncidentState, type ProposalState, type ProviderLocation, type Risk, type StateInfo,
} from './vocab';

export interface CategoryBadgeProps {
  /** One of the 8 incident categories or the 7 model classes ("DDoS+DoS"). */
  category: AnyCategory;
  /** The classifier's raw class: dashed outline + "modelo" prefix. Default false (the incident's category). */
  model?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

/** Category chip: a glyph square in the category colour plus the name. Readable in grayscale by glyph and word. */
export function CategoryBadge({ category, model = false, size = 'md', className }: CategoryBadgeProps): React.ReactElement {
  const c = CATEGORY[category];
  return (
    <span
      className={cx('sx-cat', 'sx-cat--' + size, model && 'sx-cat--model', category === 'Benign' && 'sx-cat--benign', className)}
      style={{ ['--cat' as string]: `var(--${c.token})` }}
      title={model ? `Saída do modelo: ${c.label}` : c.description}
    >
      <span className="sx-cat__glyph"><Icon name={c.icon} size={size === 'sm' ? 12 : size === 'lg' ? 18 : 14} strokeWidth={1.9} /></span>
      {model && <span className="sx-cat__prefix">modelo</span>}
      <span className="sx-cat__label">{c.label}</span>
    </span>
  );
}

type StatusKind =
  | { kind: 'incident'; value: IncidentState }
  | { kind: 'proposal'; value: ProposalState }
  | { kind: 'execution'; value: ExecutionState }
  | { kind: 'effect'; value: EffectResult };

export type StatusBadgeProps = StatusKind & {
  size?: 'sm' | 'md';
  /** Solid emphasis for the card header (default for "aguardando"). */
  emphasis?: boolean;
  className?: string;
};

function infoOf(p: StatusKind): StateInfo {
  switch (p.kind) {
    case 'incident': return INCIDENT_STATE[p.value];
    case 'proposal': return PROPOSAL_STATE[p.value];
    case 'execution': return EXECUTION_STATE[p.value];
    case 'effect': return EFFECT[p.value];
  }
}

/** State of an incident, proposal, execution or verified effect: tinted pill, icon and the exact label.
 *  "Aguardando aprovação" pulses and is the only state that asks a person for something. */
export function StatusBadge(props: StatusBadgeProps): React.ReactElement {
  const info = infoOf(props);
  const waiting = props.kind === 'proposal' && props.value === 'aguardando_aprovacao';
  return (
    <span className={cx('sx-status', 'sx-tone--' + info.tone, 'sx-status--' + (props.size ?? 'md'), (props.emphasis || waiting) && 'sx-status--emphasis', props.className)}>
      {waiting ? <span className="sx-pulse" aria-hidden="true" /> : <Icon name={info.icon} size={props.size === 'sm' ? 13 : 15} strokeWidth={1.9} />}
      <span>{info.label}</span>
    </span>
  );
}

export interface RiskBadgeProps { level: Risk; size?: 'sm' | 'md'; className?: string }

/** Risk of a proposed action. "Risco alto" is hatched, iconed and bold: unmistakable without colour. */
export function RiskBadge({ level, size = 'md', className }: RiskBadgeProps): React.ReactElement {
  const r = RISK[level];
  return (
    <span className={cx('sx-risk', 'sx-risk--' + level, 'sx-risk--' + size, className)}>
      <Icon name={r.icon} size={size === 'sm' ? 13 : 15} strokeWidth={level === 'alto' ? 2 : 1.8} />
      <span>{r.label}</span>
    </span>
  );
}

export interface AgentBadgeProps {
  agent: AgentName;
  /** Where the call ran. Execução is always local. */
  location?: ProviderLocation;
  /** Model name shown after the location, in mono. */
  model?: string;
  size?: 'sm' | 'md';
  className?: string;
}

/** Which of the three agents acted, and optionally where (local / nuvem). */
export function AgentBadge({ agent, location, model, size = 'md', className }: AgentBadgeProps): React.ReactElement {
  const a = AGENT[agent];
  return (
    <span className={cx('sx-agent', 'sx-agent--' + size, className)} title={a.role}>
      <Icon name={a.icon} size={size === 'sm' ? 13 : 15} />
      <span className="sx-agent__name">{a.label}</span>
      {location && (
        <span className={cx('sx-agent__where', 'sx-agent__where--' + location)}>
          <Icon name={location === 'local' ? 'cpu' : 'cloud'} size={12} />
          {location}{model ? ' · ' + model : ''}
        </span>
      )}
    </span>
  );
}

export interface ChannelTagProps { channel: Channel; user?: string; at?: string; className?: string }

/** How a human decision arrived: "pelo terminal" or "pela interface", with user and time. */
export function ChannelTag({ channel, user, at, className }: ChannelTagProps): React.ReactElement {
  const c = CHANNEL[channel];
  return (
    <span className={cx('sx-channel', className)}>
      <Icon name={c.icon} size={14} />
      <span>{c.label}</span>
      {user && <span className="sx-channel__meta">· {user}</span>}
      {at && <span className="sx-channel__meta">· {at}</span>}
    </span>
  );
}

export interface TargetLabelProps {
  /** Neutral label the cloud model sees, e.g. "origem-1", "destino-1". */
  label: string;
  /** Real address, resolved only locally. Omit where the screen must not show it. */
  address?: string;
  /** The target of a new action, written by the agent in free text: drawn in the agent's voice, never as a label. */
  free?: boolean;
  className?: string;
}

/** A neutral label (origem-1, destino-1) with the real address beside it, resolved locally. */
export function TargetLabel({ label, address, free = false, className }: TargetLabelProps): React.ReactElement {
  if (free) {
    return <span className={cx('sx-target--free voice-agent', className)} title="Alvo descrito pelo agente, em texto livre">“{label}”</span>;
  }
  return (
    <span className={cx('sx-target', className)}>
      <span className="sx-target__label">{label}</span>
      {address && <span className="sx-target__addr">{address}</span>}
    </span>
  );
}
