import * as React from 'react';
import { Icon, type IconName } from './Icon';
import { cx } from './util';

export interface TextFieldProps {
  label: string;
  /** Hide the label visually (still read by screen readers). */
  hideLabel?: boolean;
  value?: string;
  defaultValue?: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => void;
  placeholder?: string;
  /** text, password (with show/hide button), search… */
  type?: string;
  /** Leading icon. */
  icon?: IconName;
  hint?: React.ReactNode;
  /** Error message; turns the border coral and is announced. */
  error?: React.ReactNode;
  disabled?: boolean;
  /** Textarea instead of input. */
  multiline?: boolean;
  rows?: number;
  /** Mono text (prompts de sistema, ids). */
  mono?: boolean;
  autoComplete?: string;
  name?: string;
  size?: 'md' | 'lg';
  className?: string;
}

/** Labelled text input or textarea, with hint and error. */
export function TextField({ label, hideLabel, value, defaultValue, onChange, placeholder, type = 'text', icon, hint, error, disabled, multiline, rows = 4, mono, autoComplete, name, size = 'md', className }: TextFieldProps): React.ReactElement {
  const id = React.useId();
  const [show, setShow] = React.useState(false);
  const describedBy = [hint ? id + '-hint' : '', error ? id + '-err' : ''].filter(Boolean).join(' ') || undefined;
  const common = {
    id, name, value, defaultValue, placeholder, disabled,
    onChange: onChange as any,
    'aria-invalid': error ? true : undefined,
    'aria-describedby': describedBy,
    className: cx('sx-field__control', mono && 'code'),
  };
  return (
    <div className={cx('sx-field', 'sx-field--' + size, error && 'is-error', disabled && 'is-disabled', className)}>
      <label htmlFor={id} className={cx('sx-field__label', hideLabel && 'sx-visually-hidden')}>{label}</label>
      <div className={cx('sx-field__box', multiline && 'sx-field__box--multi')}>
        {icon && !multiline && <Icon name={icon} size={18} className="sx-field__icon" />}
        {multiline
          ? <textarea {...common} rows={rows} />
          : <input {...common} type={type === 'password' && show ? 'text' : type} autoComplete={autoComplete} />}
        {type === 'password' && !multiline && (
          <button type="button" className="sx-field__eye" aria-label={show ? 'Ocultar senha' : 'Mostrar senha'} aria-pressed={show} onClick={() => setShow((s) => !s)}>
            <Icon name={show ? 'eye-off' : 'eye'} size={18} />
          </button>
        )}
      </div>
      {error && <div className="sx-field__error body-sm" id={id + '-err'} role="alert"><Icon name="circle-alert" size={14} />{error}</div>}
      {hint && !error && <div className="sx-field__hint body-sm" id={id + '-hint'}>{hint}</div>}
    </div>
  );
}

export interface SelectOption { value: string; label: string; disabled?: boolean }
export interface SelectProps {
  label: string;
  hideLabel?: boolean;
  options: SelectOption[];
  value?: string;
  defaultValue?: string;
  onChange?: (value: string) => void;
  icon?: IconName;
  disabled?: boolean;
  hint?: React.ReactNode;
  className?: string;
}

/** Native select with the field styling (keyboard and screen readers for free). */
export function Select({ label, hideLabel, options, value, defaultValue, onChange, icon, disabled, hint, className }: SelectProps): React.ReactElement {
  const id = React.useId();
  return (
    <div className={cx('sx-field', disabled && 'is-disabled', className)}>
      <label htmlFor={id} className={cx('sx-field__label', hideLabel && 'sx-visually-hidden')}>{label}</label>
      <div className="sx-field__box sx-field__box--select">
        {icon && <Icon name={icon} size={18} className="sx-field__icon" />}
        <select id={id} className="sx-field__control" value={value} defaultValue={defaultValue} disabled={disabled} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => onChange?.((e.target as HTMLSelectElement).value)}>
          {options.map((o) => <option key={o.value} value={o.value} disabled={o.disabled}>{o.label}</option>)}
        </select>
        <Icon name="chevron-down" size={18} className="sx-field__chev" />
      </div>
      {hint && <div className="sx-field__hint body-sm">{hint}</div>}
    </div>
  );
}
