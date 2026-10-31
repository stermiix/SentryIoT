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

/** Background of the login and the report cover: the large glass mark on the black ground.
 *  Fills its positioned parent; aria-hidden. */
export function GlassBackdrop({ src, variant = 'login', className }: GlassBackdropProps): React.ReactElement {
  return (
    <div className={cx('sx-backdrop', 'sx-backdrop--' + variant, className)} aria-hidden="true">
      <img className="sx-backdrop__logo" src={src} alt="" draggable={false} />
    </div>
  );
}
