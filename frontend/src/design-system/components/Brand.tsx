import * as React from 'react';
import { cx } from './util';

export interface LogoProps {
  /** URL of the glass mark with transparent background (assets/Logos/sentryiot-mark*.png). */
  src: string;
  /** sm 24 px mark (rail, rodapé) · md 32 px (barra lateral) · lg 48 px (login, relatório) · xl 72 px. */
  size?: 'sm' | 'md' | 'lg' | 'xl';
  /** Show the "SentryIoT" wordmark next to the mark. Default true. */
  wordmark?: boolean;
  /** Short descriptor tag after the wordmark. Default "NIDR"; false hides it. */
  descriptor?: string | false;
  className?: string;
}

/** The SentryIoT lockup: the glass mark plus the wordmark set in type. */
export function Logo({ src, size = 'md', wordmark = true, descriptor = 'NIDR', className }: LogoProps): React.ReactElement {
  return (
    <span className={cx('sx-logo', 'sx-logo--' + size, className)}>
      <img className="sx-logo__mark" src={src} alt={wordmark ? '' : 'SentryIoT'} draggable={false} />
      {wordmark && (
        <span className="sx-logo__word" aria-label="SentryIoT">
          <span className="sx-logo__sentry">Sentry</span><span className="sx-logo__iot">IoT</span>
        </span>
      )}
      {wordmark && descriptor && <span className="sx-logo__tag">{descriptor}</span>}
    </span>
  );
}

export interface GlassBackdropProps {
  /** URL of the glass mark (transparent PNG, the larger the better: sentryiot-mark.png). */
  src: string;
  /** login: mark centred on the right half · report: mark bleeding off the right edge of an A4 cover. */
  variant?: 'login' | 'report';
  className?: string;
}

/** Decorative background of the login and the report cover: the glass mark lit in ice,
 *  translucent slabs, diagonal light and a dot grid. Fills its positioned parent; aria-hidden. */
export function GlassBackdrop({ src, variant = 'login', className }: GlassBackdropProps): React.ReactElement {
  return (
    <div className={cx('sx-backdrop', 'sx-backdrop--' + variant, className)} aria-hidden="true">
      <svg className="sx-backdrop__rays" viewBox="0 0 1000 1000" preserveAspectRatio="none">
        <line x1="80" y1="1000" x2="1000" y2="80" />
        <line x1="300" y1="1000" x2="1000" y2="300" />
        <line x1="0" y1="760" x2="760" y2="0" />
        <line x1="520" y1="1000" x2="1000" y2="520" />
      </svg>
      <div className="sx-backdrop__glow" />
      <svg className="sx-backdrop__slabs" viewBox="0 0 600 1000" preserveAspectRatio="xMaxYMid slice">
        <defs>
          <linearGradient id="sx-slab-fill" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" style={{ stopColor: 'var(--ice)', stopOpacity: 0.07 }} />
            <stop offset="1" style={{ stopColor: 'var(--ice)', stopOpacity: 0 }} />
          </linearGradient>
          <linearGradient id="sx-slab-edge" gradientUnits="userSpaceOnUse" x1="0" y1="1000" x2="0" y2="80">
            <stop offset="0" style={{ stopColor: 'var(--glacier)', stopOpacity: 0.85 }} />
            <stop offset="0.55" style={{ stopColor: 'var(--ice)', stopOpacity: 0.18 }} />
            <stop offset="1" style={{ stopColor: 'var(--ice)', stopOpacity: 0 }} />
          </linearGradient>
        </defs>
        <polygon className="sx-backdrop__slab" points="180,120 600,380 600,760 180,500" />
        <polygon className="sx-backdrop__slab" points="300,470 600,660 600,1000 300,810" />
        <line className="sx-backdrop__edge" x1="180" y1="500" x2="600" y2="760" />
        <line className="sx-backdrop__edge" x1="300" y1="810" x2="600" y2="1000" />
      </svg>
      <img className="sx-backdrop__logo" src={src} alt="" draggable={false} />
      <div className="sx-backdrop__dots" />
    </div>
  );
}
