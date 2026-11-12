import { useEffect, useId, useLayoutEffect, useRef, useState, type ComponentType, type ReactNode } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Check, CircleAlert, Copy, Info, OctagonAlert, ShieldAlert, ShieldCheck, ShieldQuestion, TriangleAlert, type LucideProps } from "lucide-react";
import type { Finding, Verdict } from "../lib/api";
import { VERDICT_LABEL, VERDICT_TONE, toneOf } from "../lib/format";

export function BrandMark() {
  return <span className="brand-mark">trace.</span>;
}

export interface SegOption<T extends string> {
  value: T;
  label: string;
  icon?: ComponentType<LucideProps>;
  count?: number;
}

export function Segmented<T extends string>({ value, onChange, options, label, size = 15 }: { value: T; onChange: (v: T) => void; options: SegOption<T>[]; label: string; size?: number }) {
  const id = useId();
  const move = (dir: number) => {
    const i = options.findIndex((o) => o.value === value);
    onChange(options[(i + dir + options.length) % options.length].value);
  };
  return (
    <div
      className="segmented"
      role="radiogroup"
      aria-label={label}
      onKeyDown={(e) => {
        if (e.key === "ArrowRight" || e.key === "ArrowDown") {
          e.preventDefault();
          move(1);
        } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
          e.preventDefault();
          move(-1);
        }
      }}
    >
      {options.map((o) => {
        const active = o.value === value;
        const Icon = o.icon;
        return (
          <button key={o.value} type="button" role="radio" aria-checked={active} tabIndex={active ? 0 : -1} onClick={() => onChange(o.value)}>
            {active && <motion.span layoutId={`seg-${id}`} className="seg-pill" transition={{ type: "spring", stiffness: 500, damping: 40 }} />}
            {Icon ? <Icon size={size} aria-hidden="true" /> : null}
            {o.label}
            {o.count !== undefined ? <span className="count">{o.count}</span> : null}
          </button>
        );
      })}
    </div>
  );
}

export function Switch({ checked, onChange, label, description }: { checked: boolean; onChange: (v: boolean) => void; label: string; description?: string }) {
  return (
    <label className="switch">
      <span className="switch-label">
        {label}
        {description ? <span className="switch-desc">{description}</span> : null}
      </span>
      <input type="checkbox" role="switch" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="switch-track" aria-hidden="true">
        <motion.span className="switch-thumb" animate={{ x: checked ? 16 : 0 }} transition={{ type: "spring", stiffness: 600, damping: 36 }} />
      </span>
    </label>
  );
}

const VERDICT_ICON = { safe: ShieldCheck, suspicious: ShieldQuestion, malicious: ShieldAlert };

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const Icon = VERDICT_ICON[verdict];
  return (
    <span className="verdict-badge" data-tone={VERDICT_TONE[verdict]}>
      <Icon size={13} aria-hidden="true" />
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

export function SeverityIcon({ finding, size = 17 }: { finding: Pick<Finding, "kind" | "severity">; size?: number }) {
  const tone = toneOf(finding);
  const Icon =
    finding.kind === "trust"
      ? ShieldCheck
      : finding.kind === "info"
        ? Info
        : finding.severity === "critical" || finding.severity === "high"
          ? OctagonAlert
          : finding.severity === "medium"
            ? TriangleAlert
            : CircleAlert;
  return (
    <span className="sev-icon" data-tone={tone}>
      <Icon size={size} aria-hidden="true" />
    </span>
  );
}

/** Four signal bars plus the number: risk at a glance in a table row. */
export function RiskBars({ score }: { score: number }) {
  const lit = score >= 65 ? 4 : score >= 35 ? 3 : score >= 15 ? 2 : 1;
  return (
    <span className="risk-bars" role="img" aria-label={`Risk ${score} of 100`}>
      <span aria-hidden="true">
        {[1, 2, 3, 4].map((n) => (
          <i key={n} data-on={n <= lit} style={{ height: 3 + n * 3 }} />
        ))}
      </span>
      <b aria-hidden="true">{score}</b>
    </span>
  );
}

export function Ring({ score, verdict, size = 44, stroke = 3.5 }: { score: number; verdict: Verdict; size?: number; stroke?: number }) {
  const r = (size - stroke) / 2;
  return (
    <span className="ring" data-tone={VERDICT_TONE[verdict]} style={{ width: size, height: size }} role="img" aria-label={`${score} of 100`}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle className="track" cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} />
        <motion.circle className="val" cx={size / 2} cy={size / 2} r={r} fill="none" strokeWidth={stroke} initial={{ pathLength: 0 }} animate={{ pathLength: Math.max(score, 1) / 100 }} transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }} />
      </svg>
      <b style={{ fontSize: size * 0.3 }}>{score}</b>
    </span>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {children ? <p>{children}</p> : null}
      {action}
    </div>
  );
}

export function Kbd({ keys }: { keys: string[] }) {
  return (
    <span className="kbd-group" aria-hidden="true">
      {keys.map((k) => (
        <kbd key={k}>{k}</kbd>
      ))}
    </span>
  );
}

export const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
export const MOD = isMac ? "⌘" : "Ctrl";

export function ConfirmDialog({ open, title, body, confirmLabel, onConfirm, onClose }: { open: boolean; title: string; body: string; confirmLabel: string; onConfirm: () => void; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current!;
    if (open && !d.open) d.showModal();
    else if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} className="modal" onClose={onClose} onClick={(e) => e.target === ref.current && onClose()}>
      <div className="modal-body">
        <h2>{title}</h2>
        <p>{body}</p>
      </div>
      <div className="modal-foot">
        <button type="button" className="btn btn-outline" onClick={onClose} autoFocus>
          Cancel
        </button>
        <button
          type="button"
          className="btn btn-danger"
          onClick={() => {
            onClose();
            onConfirm();
          }}
        >
          {confirmLabel}
        </button>
      </div>
    </dialog>
  );
}

export function ConfirmButton({ onConfirm, children, title, body, confirmLabel, className = "btn btn-outline btn-sm", ariaLabel, tip }: { onConfirm: () => void; children: ReactNode; title: string; body: string; confirmLabel: string; className?: string; ariaLabel?: string; tip?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className={`${className} is-danger`} onClick={() => setOpen(true)} aria-label={ariaLabel} data-tip={tip}>
        {children}
      </button>
      <ConfirmDialog open={open} title={title} body={body} confirmLabel={confirmLabel} onConfirm={onConfirm} onClose={() => setOpen(false)} />
    </>
  );
}

export function CopyButton({ text, label = "Copy", className = "btn btn-outline btn-sm" }: { text: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className={className}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          window.setTimeout(() => setDone(false), 1600);
        } catch {
          /* clipboard blocked */
        }
      }}
    >
      {done ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
      {done ? "Copied" : label}
    </button>
  );
}

export interface MenuItem {
  label: string;
  icon?: ComponentType<LucideProps>;
  checked?: boolean;
  danger?: boolean;
  onSelect: () => void;
}

/** Trigger plus a popover menu. Fixed-positioned so tables can't clip it. */
export function Dropdown({ trigger, label, items, className = "btn btn-outline btn-sm", tip }: { trigger: ReactNode; label: string; items: MenuItem[]; className?: string; tip?: string }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ top: 0, right: 0 });
  const btn = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    if (!open) return;
    const r = btn.current!.getBoundingClientRect();
    const height = 44 * items.length + 12;
    setPos({ top: r.bottom + height + 8 > window.innerHeight ? Math.max(8, r.top - height - 6) : r.bottom + 6, right: window.innerWidth - r.right });
    menu.current?.querySelector("button")?.focus();
    const close = (e: Event) => {
      if (e.type === "scroll" || !menu.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    window.addEventListener("scroll", close, true);
    return () => {
      document.removeEventListener("mousedown", close);
      window.removeEventListener("scroll", close, true);
    };
  }, [open, items.length]);

  const onKey = (e: React.KeyboardEvent) => {
    const buttons = [...menu.current!.querySelectorAll("button")];
    const i = buttons.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "Escape") {
      setOpen(false);
      btn.current?.focus();
    } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      buttons[(i + (e.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length].focus();
    }
  };

  return (
    <>
      <button
        ref={btn}
        type="button"
        className={className}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={label}
        data-tip={open ? undefined : tip}
        onClick={(e) => {
          e.stopPropagation();
          setOpen((o) => !o);
        }}
      >
        {trigger}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            ref={menu}
            className="menu"
            role="menu"
            aria-label={label}
            style={{ top: pos.top, right: pos.right }}
            onKeyDown={onKey}
            onClick={(e) => e.stopPropagation()}
            initial={{ opacity: 0, scale: 0.97, y: -4 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.98, transition: { duration: 0.1 } }}
            transition={{ duration: 0.14, ease: [0.22, 1, 0.36, 1] }}
          >
            {items.map((it) => (
              <button
                key={it.label}
                type="button"
                role="menuitem"
                data-danger={it.danger || undefined}
                onClick={() => {
                  setOpen(false);
                  it.onSelect();
                }}
              >
                {it.icon ? <it.icon size={15} aria-hidden="true" /> : null}
                <span>{it.label}</span>
                {it.checked ? <Check size={15} aria-hidden="true" className="menu-check" /> : null}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
