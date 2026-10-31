import * as React from 'react';
import { Icon, type IconName } from './Icon';
import { IconButton } from './Button';
import { Logo } from './Brand';
import { cx } from './util';

/* ---------------- Panel ---------------- */
export interface PanelProps {
  /** Label above the title ("Veredito do classificador"). */
  eyebrow?: React.ReactNode;
  title?: React.ReactNode;
  /** Right side of the header: buttons, segmented control, a count. */
  actions?: React.ReactNode;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  /** attention: something inside waits for a person (amber halo). */
  tone?: 'default' | 'attention';
  /** Remove body padding (tables that run edge to edge). */
  flush?: boolean;
  className?: string;
  style?: React.CSSProperties;
  as?: 'section' | 'div' | 'article';
}

/** The glass surface every block sits on. */
export function Panel({ eyebrow, title, actions, children, footer, tone = 'default', flush = false, className, style, as = 'section' }: PanelProps): React.ReactElement {
  const Tag = as as any;
  const hasHead = eyebrow != null || title != null || actions != null;
  return (
    <Tag className={cx('sx-panel', tone === 'attention' && 'sx-panel--attention', className)} style={style}>
      {hasHead && (
        <header className="sx-panel__head">
          <div className="sx-panel__titles">
            {eyebrow != null && <div className="sx-eyebrow eyebrow">{eyebrow}</div>}
            {title != null && <h2 className="sx-panel__title title-3">{title}</h2>}
          </div>
          {actions != null && <div className="sx-panel__actions">{actions}</div>}
        </header>
      )}
      <div className={cx('sx-panel__body', flush && 'sx-panel__body--flush')}>{children}</div>
      {footer != null && <footer className="sx-panel__foot">{footer}</footer>}
    </Tag>
  );
}

/* ---------------- Mode indicator ---------------- */
export interface ModeIndicatorProps {
  mode: 'replay' | 'ao-vivo';
  /** Replay position (1-based) and total events. */
  position?: number;
  total?: number;
  /** Time of the current event, "14:03:20". */
  at?: string;
  className?: string;
}

/** "REPLAY · EVENTO 23 DE 52" or a pulsing "AO VIVO". Always visible in the header. */
export function ModeIndicator({ mode, position, total, at, className }: ModeIndicatorProps): React.ReactElement {
  return (
    <span className={cx('sx-mode', 'sx-mode--' + mode, className)} role="status">
      <span className="sx-mode__dot" aria-hidden="true" />
      <span className="sx-mode__name">{mode === 'replay' ? 'Replay' : 'Ao vivo'}</span>
      {mode === 'replay' && position != null && total != null && (
        <span className="sx-mode__pos">evento {position} de {total}</span>
      )}
      {at && <span className="sx-mode__at">{at}</span>}
    </span>
  );
}

/* ---------------- Page header ---------------- */
export interface PageHeaderProps {
  /** Breadcrumb-like mono label: "INCIDENTES / INC-0001". */
  eyebrow?: React.ReactNode;
  title: React.ReactNode;
  /** Row under the title: badges, confidence, ids. */
  meta?: React.ReactNode;
  /** Right side: mode indicator, actions. */
  actions?: React.ReactNode;
  className?: string;
}

/** Title block of a screen. One per screen, no greetings. */
export function PageHeader({ eyebrow, title, meta, actions, className }: PageHeaderProps): React.ReactElement {
  return (
    <header className={cx('sx-pagehead', className)}>
      <div className="sx-pagehead__main">
        {eyebrow != null && <div className="sx-eyebrow eyebrow">{eyebrow}</div>}
        <h1 className="sx-pagehead__title title-1">{title}</h1>
        {meta != null && <div className="sx-pagehead__meta">{meta}</div>}
      </div>
      {actions != null && <div className="sx-pagehead__actions">{actions}</div>}
    </header>
  );
}

/* ---------------- Segmented ---------------- */
export interface SegmentedOption { value: string; label: string; icon?: IconName; disabled?: boolean; hint?: string }
export interface SegmentedProps {
  options: SegmentedOption[];
  value: string;
  onChange?: (value: string) => void;
  size?: 'sm' | 'md';
  /** Accessible name of the group. */
  label: string;
  /** Stretch to the container, equal segments. */
  block?: boolean;
  className?: string;
}

/** Segmented control ("Replay | Ao vivo", "Local | Nuvem"). Arrow keys move the selection. */
export function Segmented({ options, value, onChange, size = 'md', label, block = false, className }: SegmentedProps): React.ReactElement {
  const onKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const enabled = options.filter((o) => !o.disabled);
    const i = enabled.findIndex((o) => o.value === value);
    const next = enabled[(i + (e.key === 'ArrowRight' ? 1 : enabled.length - 1)) % enabled.length];
    if (next) { onChange?.(next.value); e.preventDefault(); }
  };
  return (
    <div className={cx('sx-seg', 'sx-seg--' + size, block && 'sx-seg--block', className)} role="radiogroup" aria-label={label} onKeyDown={onKey}>
      {options.map((o) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={on}
            tabIndex={on ? 0 : -1}
            disabled={o.disabled}
            title={o.hint}
            className={cx('sx-seg__item', on && 'is-on')}
            onClick={() => onChange?.(o.value)}
          >
            {o.icon && <Icon name={o.icon} size={size === 'sm' ? 14 : 16} />}
            <span>{o.label}</span>
          </button>
        );
      })}
    </div>
  );
}

/* ---------------- Tabs ---------------- */
export interface TabItem { id: string; label: string; count?: number; disabled?: boolean }
export interface TabsProps { tabs: TabItem[]; value: string; onChange?: (id: string) => void; label: string; className?: string }

/** Underlined tabs for sections of one object (incident: Veredito · Agentes · Propostas · Histórico). */
export function Tabs({ tabs, value, onChange, label, className }: TabsProps): React.ReactElement {
  return (
    <div className={cx('sx-tabs', className)} role="tablist" aria-label={label}>
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={t.id === value}
          disabled={t.disabled}
          className={cx('sx-tabs__tab', t.id === value && 'is-on')}
          onClick={() => onChange?.(t.id)}
        >
          {t.label}
          {t.count != null && <span className="sx-tabs__count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

/* ---------------- Sidebar ---------------- */
export interface NavItem { id: string; label: string; icon: IconName; count?: number; attention?: boolean; planned?: boolean }
export interface NavSection { label: string; items: NavItem[] }
export interface SidebarProps {
  /** Logo URL (assets/Logos/sentryiot-mark-128.png). */
  logoSrc: string;
  sections: NavSection[];
  activeId: string;
  onNavigate?: (id: string) => void;
  /** Icon-only rail. */
  collapsed?: boolean;
  onToggle?: () => void;
  /** Bottom area: provider status, operator, settings. */
  footer?: React.ReactNode;
  className?: string;
}

/** Floating navigation with wide and icon-only versions: black, with the active item in solid ice. */
export function Sidebar({ logoSrc, sections, activeId, onNavigate, collapsed = false, onToggle, footer, className }: SidebarProps): React.ReactElement {
  return (
    <nav className={cx('sx-sidebar', collapsed && 'sx-sidebar--collapsed', className)} aria-label="Navegação principal">
      <div className="sx-sidebar__head">
        <Logo src={logoSrc} size={collapsed ? 'sm' : 'md'} wordmark={!collapsed} />
        {onToggle && (
          <IconButton
            className="sx-sidebar__toggle"
            icon={collapsed ? 'panel-left-open' : 'panel-left-close'}
            label={collapsed ? 'Abrir navegação' : 'Recolher navegação'}
            variant="ghost"
            size="sm"
            onClick={onToggle}
          />
        )}
      </div>
      <div className="sx-sidebar__scroll">
        {sections.map((s) => (
          <div className="sx-sidebar__section" key={s.label}>
            <div className="sx-sidebar__label sx-eyebrow eyebrow" aria-hidden={collapsed || undefined}>{s.label}</div>
            <ul className="sx-sidebar__list">
              {s.items.map((it) => {
                const on = it.id === activeId;
                return (
                  <li key={it.id}>
                    <button
                      type="button"
                      className={cx('sx-nav', on && 'is-on', it.planned && 'is-planned')}
                      aria-current={on ? 'page' : undefined}
                      aria-label={collapsed ? it.label + (it.planned ? ' (planejada)' : '') : undefined}
                      title={collapsed ? it.label : it.planned ? 'Tela planejada' : undefined}
                      onClick={() => onNavigate?.(it.id)}
                    >
                      <Icon name={it.icon} size={20} />
                      <span className="sx-nav__label">{it.label}</span>
                      {it.count != null && <span className={cx('sx-nav__count', it.attention && 'is-attention')}>{it.count}</span>}
                      {it.planned && <span className="sx-nav__planned" aria-hidden="true" />}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
      {footer != null && <div className="sx-sidebar__foot">{footer}</div>}
    </nav>
  );
}

/* ---------------- App shell ---------------- */
export interface AppShellProps {
  sidebar: React.ReactNode;
  children?: React.ReactNode;
  /** Bottom dock, normally the ReplayControl. */
  dock?: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

/** Page frame on the black ground: floating sidebar, scrolling content and the replay dock. */
export function AppShell({ sidebar, children, dock, className, style }: AppShellProps): React.ReactElement {
  return (
    <div className={cx('sx-app', className)} style={style}>
      <div className="sx-app__side">{sidebar}</div>
      <div className="sx-app__main">
        <main className="sx-app__content">{children}</main>
        {dock != null && <div className="sx-app__dock">{dock}</div>}
      </div>
    </div>
  );
}
