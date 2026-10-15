import * as React from 'react';
import { IconButton } from './Button';
import { Kbd } from './Icon';
import { cx, clamp } from './util';
import type { Tone } from './vocab';

export interface ReplayMark { n: number; tone: Tone; label?: string }

export interface ReplayControlProps {
  /** Current event (1-based). */
  position: number;
  total: number;
  onChange?: (n: number) => void;
  playing?: boolean;
  onPlayToggle?: () => void;
  /** The event at the cursor. */
  current?: { id: string; label: string; at: string };
  /** Events worth seeing on the track (human decisions, incidents opened). */
  marks?: ReplayMark[];
  /** Listen to ← → Home End and Espaço on the page. Default true. */
  keyboard?: boolean;
  className?: string;
}

/** Walks the log event by event. Every screen shows the state up to the cursor. Works from the keyboard. */
export function ReplayControl({ position, total, onChange, playing = false, onPlayToggle, current, marks = [], keyboard = true, className }: ReplayControlProps): React.ReactElement {
  const go = React.useCallback((n: number) => onChange?.(clamp(n, 1, total)), [onChange, total]);
  React.useEffect(() => {
    if (!keyboard) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const t = e.target instanceof HTMLElement ? e.target : null;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
      // Keys that belong to another control: a focused button (Space clicks it), a segmented group,
      // a chart, or anything while a dialog is open.
      if (t && (t.tagName === 'BUTTON' || t.closest('[role="radiogroup"], [role="tablist"], [role="listbox"], .sx-chart, [role="dialog"]'))) return;
      if (document.querySelector('[role="dialog"][aria-modal="true"]')) return;
      if (e.key === 'ArrowRight') { go(position + 1); e.preventDefault(); }
      else if (e.key === 'ArrowLeft') { go(position - 1); e.preventDefault(); }
      else if (e.key === 'Home') { go(1); e.preventDefault(); }
      else if (e.key === 'End') { go(total); e.preventDefault(); }
      else if (e.key === ' ' && onPlayToggle) { onPlayToggle(); e.preventDefault(); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [keyboard, go, position, total, onPlayToggle]);

  const pct = total > 1 ? ((position - 1) / (total - 1)) * 100 : 100;
  return (
    <div className={cx('sx-replay', className)} role="group" aria-label="Controle do replay">
      <div className="sx-replay__transport">
        <IconButton icon="chevron-first" label="Início (Home)" size="sm" onClick={() => go(1)} disabled={position <= 1} />
        <IconButton icon="chevron-left" label="Evento anterior (←)" size="sm" onClick={() => go(position - 1)} disabled={position <= 1} />
        <IconButton icon={playing ? 'pause' : 'play'} label={playing ? 'Pausar (Espaço)' : 'Reproduzir (Espaço)'} variant="primary" onClick={onPlayToggle} pressed={playing} />
        <IconButton icon="chevron-right" label="Próximo evento (→)" size="sm" onClick={() => go(position + 1)} disabled={position >= total} />
        <IconButton icon="chevron-last" label="Fim (End)" size="sm" onClick={() => go(total)} disabled={position >= total} />
      </div>

      <div className="sx-replay__scrub">
        <div className="sx-replay__now">
          {current ? (
            <>
              <span className="data-sm sx-replay__id">{current.id}</span>
              <span className="sx-replay__label">{current.label}</span>
              <span className="data-sm sx-replay__at">{current.at}</span>
            </>
          ) : <span className="sx-replay__label">&nbsp;</span>}
        </div>
        <div className="sx-replay__track" style={{ ['--pct' as string]: pct + '%' }}>
          <div className="sx-replay__ticks" aria-hidden="true">
            {Array.from({ length: total }, (_, i) => (
              <span key={i} className={cx('sx-replay__tick', i + 1 <= position && 'is-past')} style={{ left: (total > 1 ? (i / (total - 1)) * 100 : 0) + '%' }} />
            ))}
            {marks.map((m) => (
              <span key={'m' + m.n} className={cx('sx-replay__mark', 'sx-tone--' + m.tone)} title={m.label} style={{ left: (total > 1 ? ((m.n - 1) / (total - 1)) * 100 : 0) + '%' }} />
            ))}
          </div>
          <input
            className="sx-replay__range"
            type="range"
            min={1}
            max={total}
            step={1}
            value={position}
            aria-label="Posição no log"
            aria-valuetext={`evento ${position} de ${total}${current ? ': ' + current.label : ''}`}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) => go(Number((e.target as HTMLInputElement).value))}
          />
        </div>
      </div>

      <div className="sx-replay__pos">
        <span className="sx-replay__count"><span className="sx-replay__n">{position}</span><span className="sx-replay__of"> de {total}</span></span>
        <span className="sx-replay__keys" aria-hidden="true"><Kbd>←</Kbd><Kbd>→</Kbd><Kbd>Espaço</Kbd></span>
      </div>
    </div>
  );
}
