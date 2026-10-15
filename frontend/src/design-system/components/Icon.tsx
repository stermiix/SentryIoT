import * as React from 'react';
import { ICONS, type IconName } from './icons-data';
import { cx } from './util';

export type { IconName };

export interface IconProps {
  /** Lucide icon name (kebab-case), e.g. "radar", "triangle-alert". */
  name: IconName;
  /** Pixel size; 16 in badges and tables, 20 in buttons and navigation, 24 in headers. */
  size?: number;
  /** Stroke width; 1.6 by default (thin, as in the references). */
  strokeWidth?: number;
  /** Accessible name. Without it the icon is decorative (aria-hidden). */
  title?: string;
  className?: string;
  style?: React.CSSProperties;
}

/** Thin-stroke Lucide icon drawn with currentColor. */
export function Icon({ name, size = 20, strokeWidth = 1.6, title, className, style }: IconProps): React.ReactElement {
  const shapes = ICONS[name] as unknown as ReadonlyArray<readonly [string, Readonly<Record<string, string>>]>;
  return (
    <svg
      className={cx('sx-icon', className)}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      style={style}
      focusable="false"
    >
      {(shapes ?? []).map(([tag, attrs], i) => React.createElement(tag, { key: i, ...attrs }))}
    </svg>
  );
}

export interface KbdProps { children?: React.ReactNode; className?: string }
/** A keyboard key, used for replay and modal shortcuts. */
export function Kbd({ children, className }: KbdProps): React.ReactElement {
  return <kbd className={cx('sx-kbd', className)}>{children}</kbd>;
}
