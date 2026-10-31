import * as React from 'react';
import { Icon, type IconName } from './Icon';
import { cx } from './util';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** primary: gelo, one per view · secondary: vidro · ghost: sem borda · danger: rejeitar/desfazer
   *  · danger-solid: confirmar uma rejeição no modal · confirm: confirmar uma aprovação no modal. */
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-solid' | 'confirm';
  /** sm 32 px (tabelas, dock) · md 40 px · lg 48 px (login, modal). */
  size?: 'sm' | 'md' | 'lg';
  /** Leading icon. */
  icon?: IconName;
  /** Trailing icon (e.g. "arrow-right" for navigation). */
  iconRight?: IconName;
  /** Shows a spinner, keeps the width, sets aria-busy and blocks clicks. */
  loading?: boolean;
  /** Full width. */
  block?: boolean;
}

/** Button. Verb first, sentence case: "Aprovar ação", "Rejeitar", "Gerar relatório". */
export function Button({ variant = 'secondary', size = 'md', icon, iconRight, loading = false, block = false, className, children, disabled, type = 'button', ...rest }: ButtonProps): React.ReactElement {
  const iconSize = size === 'sm' ? 16 : 18;
  return (
    <button
      {...rest}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cx('sx-btn', 'sx-btn--' + variant, 'sx-btn--' + size, block && 'sx-btn--block', loading && 'is-loading', className)}
    >
      {loading ? <Icon name="loader-circle" size={iconSize} className="sx-spin" /> : icon && <Icon name={icon} size={iconSize} />}
      {children != null && <span className="sx-btn__label">{children}</span>}
      {iconRight && !loading && <Icon name={iconRight} size={iconSize} />}
    </button>
  );
}

export interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** The icon. */
  icon: IconName;
  /** Accessible name, also shown as the native tooltip. Required. */
  label: string;
  /** glass: botão com fundo e fio (padrão) · ghost: sem fundo · primary: gelo (play do replay, enviar). */
  variant?: 'glass' | 'ghost' | 'primary';
  size?: 'sm' | 'md' | 'lg';
  /** Toggle state (e.g. play/pause, collapse). */
  pressed?: boolean;
}

/** Square button for a single icon. */
export function IconButton({ icon, label, variant = 'glass', size = 'md', pressed, className, type = 'button', ...rest }: IconButtonProps): React.ReactElement {
  return (
    <button
      {...rest}
      type={type}
      aria-label={label}
      title={label}
      aria-pressed={pressed}
      className={cx('sx-iconbtn', 'sx-iconbtn--' + variant, 'sx-iconbtn--' + size, className)}
    >
      <Icon name={icon} size={size === 'sm' ? 16 : size === 'lg' ? 22 : 18} />
    </button>
  );
}
