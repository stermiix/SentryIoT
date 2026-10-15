import * as React from 'react';
import { Icon } from './Icon';
import { IconButton } from './Button';
import { cx, fmtDuration, fmtInt } from './util';
import type { Provider } from './modelos';

/* ---------------- ChatMessage ---------------- */
export interface ChatMessageProps {
  /** user: a person (texto de pessoa) · assistant: the model (texto de agente) · system: a note from the tool. */
  role: 'user' | 'assistant' | 'system';
  /** User name or model name. */
  author?: string;
  at?: string;
  /** Assistant only: cost line. `null`: the provider did not report the usage. */
  tokens?: number | null;
  /** Tooltip of the token count, e.g. "1.240 de entrada · 96 de saída". */
  tokensDetail?: string;
  seconds?: number;
  location?: 'local' | 'nuvem';
  children?: React.ReactNode;
  className?: string;
}

/** One message of the model chat. Model replies use the agent voice; your messages the person voice. */
export function ChatMessage({ role, author, at, tokens, tokensDetail, seconds, location, children, className }: ChatMessageProps): React.ReactElement {
  if (role === 'system') {
    return <div className={cx('sx-msg', 'sx-msg--system', className)}><Icon name="scroll-text" size={14} /><span className="data-sm">{children}</span></div>;
  }
  const isUser = role === 'user';
  return (
    <div className={cx('sx-msg', isUser ? 'sx-msg--user' : 'sx-msg--assistant', className)}>
      <div className="sx-msg__head">
        <Icon name={isUser ? 'user-round' : 'brain-circuit'} size={14} />
        <span className="sx-eyebrow eyebrow">{isUser ? 'Pessoa' : 'Modelo'}</span>
        {author && <span className="data-sm sx-msg__author">{author}</span>}
        {location && <span className={cx('sx-msg__where', 'is-' + location)}><Icon name={location === 'local' ? 'cpu' : 'cloud'} size={12} />{location}</span>}
        {at && <span className="data-sm sx-msg__at">{at}</span>}
      </div>
      <div className={cx('sx-msg__bubble', isUser ? 'voice-person' : 'voice-agent')}>{children}</div>
      {!isUser && (tokens !== undefined || seconds != null) && (
        <div className="sx-msg__cost data-sm">
          {[
            tokens === null ? 'tokens não informados' : tokens !== undefined ? <span key="t" title={tokensDetail}>{fmtInt(tokens)} tokens</span> : null,
            seconds != null ? fmtDuration(seconds) : null,
          ].filter((part) => part !== null).map((part, i) => <React.Fragment key={i}>{i > 0 && ' · '}{part}</React.Fragment>)}
        </div>
      )}
    </div>
  );
}

/* ---------------- ModelSelect ---------------- */
export interface ModelSelectProps {
  providers: Provider[];
  value: string;
  onChange?: (id: string) => void;
  /** Render the list open (documentation). */
  defaultOpen?: boolean;
  compact?: boolean;
  /** While a message is being sent. */
  disabled?: boolean;
  className?: string;
}

/** Picks the language model. Offline models are listed but cannot be chosen. */
export function ModelSelect({ providers, value, onChange, defaultOpen = false, compact = false, disabled = false, className }: ModelSelectProps): React.ReactElement {
  const [open, setOpen] = React.useState(defaultOpen);
  const cur = providers.find((p) => p.id === value) ?? providers[0];
  const listId = React.useId();
  const root = React.useRef<HTMLDivElement>(null);
  // Closes on a click outside or on Esc.
  React.useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (root.current && !root.current.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    window.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); window.removeEventListener('keydown', onKey); };
  }, [open]);
  if (!cur) {
    return (
      <div className={cx('sx-msel', compact && 'sx-msel--compact', className)}>
        <button type="button" className="sx-msel__btn" disabled aria-label="Nenhum modelo disponível">
          <Icon name="cloud-off" size={16} />
          <span className="sx-msel__name">Nenhum modelo</span>
        </button>
      </div>
    );
  }
  const pick = (p: Provider) => { if (p.status !== 'offline') { onChange?.(p.id); setOpen(false); } };
  return (
    <div ref={root} className={cx('sx-msel', compact && 'sx-msel--compact', open && 'is-open', className)}>
      <button type="button" className="sx-msel__btn" aria-haspopup="listbox" aria-expanded={open} aria-controls={listId} disabled={disabled} onClick={() => setOpen((o) => !o)}>
        <Icon name={cur.location === 'local' ? 'cpu' : 'cloud'} size={16} />
        <span className="sx-msel__name">{cur.label}</span>
        <span className="data-sm sx-msel__model">{cur.model}</span>
        <span className={cx('sx-dot', cur.status === 'online' ? 'is-online' : 'is-offline')} aria-label={cur.status} />
        <Icon name="chevron-down" size={16} className="sx-msel__chev" />
      </button>
      {open && (
        <ul className="sx-msel__list" role="listbox" id={listId} aria-label="Modelos">
          {(['local', 'nuvem'] as const).map((loc) => (
            <li key={loc} role="presentation">
              <div className="sx-msel__group sx-eyebrow eyebrow">{loc === 'local' ? 'Local' : 'Nuvem'}</div>
              <ul role="presentation">
                {providers.filter((p) => p.location === loc).map((p) => (
                  <li
                    key={p.id}
                    role="option"
                    aria-selected={p.id === value}
                    aria-disabled={p.status === 'offline'}
                    tabIndex={p.status === 'offline' ? -1 : 0}
                    className={cx('sx-msel__opt', p.id === value && 'is-on', p.status === 'offline' && 'is-off')}
                    onClick={() => pick(p)}
                    onKeyDown={(e: React.KeyboardEvent<HTMLLIElement>) => { if (e.key === 'Enter' || e.key === ' ') { pick(p); e.preventDefault(); } }}
                  >
                    <Icon name={loc === 'local' ? 'cpu' : 'cloud'} size={16} />
                    <span className="data">{p.model}</span>
                    <span className={cx('sx-dot', p.status === 'online' ? 'is-online' : 'is-offline')} />
                    <span className="body-sm sx-msel__status">{p.status}</span>
                    {p.id === value && <Icon name="check" size={16} className="sx-msel__check" />}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/* ---------------- PromptBox ---------------- */
export interface PromptBoxProps {
  value: string;
  onChange?: (v: string) => void;
  onSend?: () => void;
  placeholder?: string;
  /** Left of the send button: usually a compact ModelSelect. */
  tools?: React.ReactNode;
  disabled?: boolean;
  /** Rough token count of the draft. */
  tokens?: number;
  className?: string;
}

/** The chat input. Enter sends, Shift+Enter breaks the line. */
export function PromptBox({ value, onChange, onSend, placeholder = 'Escreva para o modelo…', tools, disabled, tokens, className }: PromptBoxProps): React.ReactElement {
  return (
    <div className={cx('sx-prompt', disabled && 'is-disabled', className)}>
      <textarea
        className="sx-prompt__input body"
        value={value}
        rows={2}
        placeholder={placeholder}
        disabled={disabled}
        aria-label="Mensagem para o modelo"
        onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => onChange?.((e.target as HTMLTextAreaElement).value)}
        onKeyDown={(e: React.KeyboardEvent<HTMLTextAreaElement>) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); onSend?.(); } }}
      />
      <div className="sx-prompt__bar">
        <div className="sx-prompt__tools">{tools}</div>
        {tokens != null && <span className="data-sm sx-prompt__tokens">≈ {fmtInt(tokens)} tokens</span>}
        <IconButton icon="send-horizontal" label="Enviar (Enter)" variant="primary" onClick={onSend} disabled={disabled || !value.trim()} />
      </div>
    </div>
  );
}

/* ---------------- ProviderBar ---------------- */
export interface ProviderBarProps {
  providers: Provider[];
  /** The provider used by the next call. */
  selectedId: string;
  onSelect?: (id: string) => void;
  /** Note at the right end. Default: the reminder that the cloud only gets neutral labels; false hides it. */
  note?: React.ReactNode | false;
  disabled?: boolean;
  className?: string;
}

/** AI providers: local models (online/offline) and cloud models. The chosen one appears in every call. */
export function ProviderBar({ providers, selectedId, onSelect, note = 'A nuvem só recebe rótulos neutros (origem-1, destino-1).', disabled = false, className }: ProviderBarProps): React.ReactElement {
  return (
    <div className={cx('sx-providers', className)} role="radiogroup" aria-label="Provedores de IA">
      <span className="sx-eyebrow eyebrow sx-providers__label">Provedores de IA</span>
      {providers.map((p) => {
        const on = p.id === selectedId;
        return (
          <button
            key={p.id}
            type="button"
            role="radio"
            aria-checked={on}
            disabled={disabled || p.status === 'offline'}
            className={cx('sx-provider', on && 'is-on', p.status === 'offline' && 'is-off')}
            onClick={() => onSelect?.(p.id)}
          >
            <Icon name={p.location === 'local' ? 'cpu' : 'cloud'} size={16} />
            <span className="sx-provider__name">{p.location === 'local' ? 'Local' : 'Nuvem'}</span>
            <span className="data-sm">{p.model}</span>
            <span className={cx('sx-dot', p.status === 'online' ? 'is-online' : 'is-offline')} />
            <span className="sx-provider__status body-sm">{p.status}</span>
          </button>
        );
      })}
      {note !== false && <span className="sx-providers__note body-sm"><Icon name="eye-off" size={14} />{note}</span>}
    </div>
  );
}
