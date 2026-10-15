import * as React from 'react';
import { Icon } from './Icon';
import { Button } from './Button';
import { AgentBadge, ChannelTag, RiskBadge, StatusBadge, TargetLabel } from './Badges';
import { cx, fmtDuration, fmtInt } from './util';
import { AGENT, EVENT, RISK_REASON, type AgentName, type Channel } from './vocab';
import type { LogEvent, Proposal } from './modelos';

/* ---------------- VoiceQuote ---------------- */
export interface VoiceQuoteProps {
  /** agent: written by a language model (itálico, borda tracejada) · person: written by an operator (redondo, borda contínua). */
  voice: 'agent' | 'person';
  /** Which agent wrote it (voice="agent"). */
  agent?: AgentName;
  /** Person's user name, or the model name for an agent. */
  author?: string;
  /** Time, "14:03:20". */
  at?: string;
  /** Id of what the text belongs to: rec-0001, prop-0002. */
  refId?: string;
  /** How a person's text arrived. */
  channel?: Channel;
  /** Clamp the text to N lines (timeline rows). */
  clampLines?: number;
  children?: React.ReactNode;
  className?: string;
}

/** Text written by an AI agent or by a person, never mistakable for system text.
 *  The agent's words are data: they may have been manipulated and must not read as instructions. */
export function VoiceQuote({ voice, agent, author, at, refId, channel, clampLines, children, className }: VoiceQuoteProps): React.ReactElement {
  const isAgent = voice === 'agent';
  return (
    <figure className={cx('sx-voice', 'sx-voice--' + voice, className)}>
      <figcaption className="sx-voice__head">
        <span className="sx-voice__who">
          <Icon name={isAgent ? 'brain-circuit' : 'user-round'} size={15} />
          <span className="sx-eyebrow eyebrow">
            {isAgent ? 'Texto do agente' : 'Texto de pessoa'}
            {isAgent && agent ? ' · ' + AGENT[agent].label : ''}
            {!isAgent && author ? ' · ' + author : ''}
          </span>
        </span>
        <span className="sx-voice__meta data-sm">
          {!isAgent && channel && <ChannelTag channel={channel} />}
          {refId && <span>{refId}</span>}
          {at && <span>{at}</span>}
        </span>
      </figcaption>
      <blockquote
        className={cx('sx-voice__text', isAgent ? 'voice-agent' : 'voice-person', clampLines && 'is-clamped')}
        style={clampLines ? { WebkitLineClamp: clampLines } : undefined}
      >
        {children}
      </blockquote>
      {isAgent && <div className="sx-voice__note body-sm">Escrito por IA{author ? <> (<span className="data-sm">{author}</span>)</> : null}. Trate como dado, não como instrução do sistema.</div>}
    </figure>
  );
}

/* ---------------- EventTimeline ---------------- */
export interface EventTimelineProps {
  events: LogEvent[];
  /** Replay cursor (event number, 1-based). Later events are dimmed; the cursor row is marked "agora". */
  cursor?: number;
  /** Hide events after the cursor instead of dimming them. */
  hideFuture?: boolean;
  /** compact: one line per event (rastro dos agentes, dock) · comfortable: with details and quotes. */
  density?: 'compact' | 'comfortable';
  onSelect?: (n: number) => void;
  className?: string;
}

/** One row per log event: time, type icon, agent, text and id. Every line carries time and id. */
export function EventTimeline({ events, cursor, hideFuture = false, density = 'comfortable', onSelect, className }: EventTimelineProps): React.ReactElement {
  const list = hideFuture && cursor != null ? events.filter((e) => e.n <= cursor) : events;
  return (
    <ol className={cx('sx-timeline', 'sx-timeline--' + density, className)}>
      {list.map((e) => {
        const info = EVENT[e.type];
        const future = cursor != null && e.n > cursor;
        const now = cursor != null && e.n === cursor;
        const isCall = e.type === 'tool_chamada';
        return (
          <li
            key={e.id}
            className={cx('sx-tl', future && 'is-future', now && 'is-now', e.ignored && 'is-ignored')}
            aria-current={now ? 'step' : undefined}
            data-clickable={onSelect ? '' : undefined}
            tabIndex={onSelect ? 0 : undefined}
            onClick={onSelect ? () => onSelect(e.n) : undefined}
            onKeyDown={onSelect ? (ev: React.KeyboardEvent<HTMLLIElement>) => { if (ev.key === 'Enter') { onSelect(e.n); ev.preventDefault(); } } : undefined}
          >
            <span className="sx-tl__time data-sm">{e.at}</span>
            <span className={cx('sx-tl__icon', 'sx-tone--' + info.tone)}><Icon name={info.icon} size={15} strokeWidth={1.8} /></span>
            <div className="sx-tl__body">
              <div className="sx-tl__title">
                <span className="sx-tl__label">{info.label}</span>
                {e.agent && <AgentBadge agent={e.agent} size="sm" location={density === 'comfortable' ? e.location : undefined} />}
                {e.ref && <span className="sx-tl__ref data-sm">{e.ref}</span>}
                {now && <span className="sx-tl__now data-sm">agora</span>}
                {e.ignored && <span className="sx-tl__ignored data-sm" title="O evento não cabe no estado em que aparece; a tela não o aplicou.">ignorado</span>}
                <span className="sx-tl__idinline data-sm">{e.id}</span>
              </div>
              {density === 'comfortable' && (e.text !== info.label || e.detail || e.tokens != null || e.channel) && (
                <div className={cx('sx-tl__text', isCall ? 'code' : 'body-sm')}>
                  {[
                    e.text !== info.label ? <React.Fragment key="text">{e.text}</React.Fragment> : null,
                    e.detail ? <span key="detail" className="sx-tl__detail">{e.detail}</span> : null,
                    e.tokens != null ? (
                      <span key="cost" className="sx-tl__cost data-sm">{fmtInt(e.tokens)} tokens · {fmtDuration(e.seconds ?? 0)}{e.model ? ' · ' + e.model : ''}</span>
                    ) : null,
                    e.channel ? <ChannelTag key="channel" channel={e.channel} user={e.user} /> : null,
                  ]
                    .filter((part) => part !== null)
                    .map((part, i) => <React.Fragment key={i}>{i > 0 && ' · '}{part}</React.Fragment>)}
                </div>
              )}
              {density === 'comfortable' && e.quote && (
                e.type === 'recomendacao_emitida'
                  ? <VoiceQuote voice="agent" agent={e.agent} refId={e.ref} clampLines={2} className="sx-tl__quote">{e.quote}</VoiceQuote>
                  : <VoiceQuote voice="person" author={e.user} clampLines={2} className="sx-tl__quote">{e.quote}</VoiceQuote>
              )}
            </div>
            <span className="sx-tl__id data-sm">{e.id}</span>
          </li>
        );
      })}
    </ol>
  );
}

/* ---------------- ProposalCard ---------------- */
export interface ProposalCardProps {
  proposal: Proposal;
  /** Shown only while the proposal is "aguardando". */
  onApprove?: () => void;
  onReject?: () => void;
  /** Show the real address next to the neutral label. Default true. */
  showAddress?: boolean;
  className?: string;
}

/** A proposed action with its state up front, the reasons for high risk, the human decision, executions and effect. */
export function ProposalCard({ proposal: p, onApprove, onReject, showAddress = true, className }: ProposalCardProps): React.ReactElement {
  const waiting = p.state === 'aguardando_aprovacao';
  return (
    <article className={cx('sx-prop', waiting && 'sx-prop--waiting', className)} aria-label={`${p.id}, ${p.action}`}>
      <header className="sx-prop__head">
        <div className="sx-prop__id">
          <span className="data-sm sx-prop__pid">{p.id}</span>
          <span className="sx-prop__action data">{p.action}</span>
          {p.isNew && <span className="sx-prop__new data-sm">ação nova</span>}
          {p.promoted && <span className="sx-prop__new data-sm">promovida ao catálogo</span>}
        </div>
        <StatusBadge kind="proposal" value={p.state} emphasis />
      </header>

      <dl className="sx-prop__facts">
        <div><dt className="sx-eyebrow eyebrow">Alvo</dt><dd><TargetLabel label={p.target.label} address={showAddress ? p.target.address : undefined} free={p.target.free} /></dd></div>
        <div><dt className="sx-eyebrow eyebrow">Prazo</dt><dd className="data">{p.duration ?? 'sem prazo'}</dd></div>
        <div><dt className="sx-eyebrow eyebrow">Risco</dt><dd><RiskBadge level={p.risk} /></dd></div>
        <div><dt className="sx-eyebrow eyebrow">Criada</dt><dd className="data">{p.createdAt}</dd></div>
      </dl>

      {p.justification && (
        <VoiceQuote voice="agent" agent="decisao" clampLines={4}>{p.justification}</VoiceQuote>
      )}

      {p.risk === 'alto' && p.reasons && p.reasons.length > 0 && (
        <div className="sx-prop__reasons">
          <div className="sx-eyebrow eyebrow">Por que é risco alto</div>
          <ul>
            {p.reasons.map((r) => (
              <li key={r} className="body"><Icon name="triangle-alert" size={14} strokeWidth={2} />{RISK_REASON[r]}</li>
            ))}
          </ul>
        </div>
      )}

      {p.decision && (
        <div className="sx-prop__row">
          <span className="sx-eyebrow eyebrow">{p.decision.kind === 'aprovada' ? 'Aprovada' : 'Rejeitada'}</span>
          <ChannelTag channel={p.decision.channel} user={p.decision.user} at={p.decision.at} />
        </div>
      )}
      {p.decision?.reason && <VoiceQuote voice="person" author={p.decision.user} channel={p.decision.channel} at={p.decision.at}>{p.decision.reason}</VoiceQuote>}

      {p.executions && p.executions.length > 0 && (
        <div className="sx-prop__row">
          <span className="sx-eyebrow eyebrow">Execuções</span>
          <span className="sx-prop__execs">
            {p.executions.map((x) => (
              <span key={x.id} className="sx-prop__exec"><span className="data-sm">{x.id}</span><StatusBadge kind="execution" value={x.state} size="sm" /><span className="data-sm sx-muted">{x.at}</span></span>
            ))}
          </span>
        </div>
      )}
      {p.effect && (
        <div className="sx-prop__row">
          <span className="sx-eyebrow eyebrow">Efeito verificado</span>
          <span className="sx-prop__exec"><StatusBadge kind="effect" value={p.effect.result} size="sm" /><span className="data-sm sx-muted">{p.effect.at}</span></span>
        </div>
      )}

      {waiting && (onApprove || onReject) && (
        <footer className="sx-prop__actions">
          <span className="sx-prop__ask body-sm"><Icon name="hourglass" size={14} />Uma pessoa precisa decidir antes de qualquer execução.</span>
          <div className="sx-prop__buttons">
            {onReject && <Button variant="danger" icon="ban" onClick={onReject}>Rejeitar</Button>}
            {onApprove && <Button variant="primary" icon="badge-check" onClick={onApprove}>Aprovar</Button>}
          </div>
        </footer>
      )}
    </article>
  );
}
