import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { useNavigate } from "react-router-dom";
import { Ban, CornerDownLeft, Globe, History, LayoutDashboard, Link2, Mail, ScanSearch as Radar, Search, Settings2, type LucideIcon } from "lucide-react";
import { api, type ScanListItem, type ScanType } from "../lib/api";
import { detectInputType, relativeTime, shorten, VERDICT_LABEL } from "../lib/format";

interface Item {
  id: string;
  group: string;
  title: string;
  sub?: string;
  icon: LucideIcon;
  mono?: boolean;
  run: () => void;
}

const SCAN_ICON: Record<ScanType, LucideIcon> = { url: Link2, domain: Globe, email: Mail };

export default function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const [recent, setRecent] = useState<ScanListItem[]>([]);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    setQ("");
    setActive(0);
    api.scans({ limit: 30 }).then((r) => setRecent(r.items)).catch(() => setRecent([]));
    const t = window.setTimeout(() => inputRef.current?.focus(), 20);
    return () => window.clearTimeout(t);
  }, [open]);

  const items = useMemo<Item[]>(() => {
    const go = (path: string, state?: unknown) => () => {
      onClose();
      navigate(path, state ? { state } : undefined);
    };
    const out: Item[] = [];
    const kind = detectInputType(q);
    if (kind) {
      const label = kind === "url" ? "Scan link" : kind === "domain" ? "Scan domain" : "Scan email";
      out.push({
        id: "scan",
        group: "Scan",
        title: kind === "email" ? `${label} (${q.trim().split("\n").length} lines)` : `${label} ${shorten(q.trim(), 70)}`,
        sub: kind === "email" ? "Checks sender, authentication, wording, links and attachments" : "Full scan with redirects, domain checks and threat feeds",
        icon: SCAN_ICON[kind],
        run: go("/scan", { autoScan: { kind, value: q } }),
      });
    }
    const term = q.trim().toLowerCase();
    const pages: Item[] = [
      { id: "p-scan", group: "Go to", title: "New scan", icon: Radar, run: go("/scan") },
      { id: "p-hist", group: "Go to", title: "History", icon: History, run: go("/history") },
      { id: "p-over", group: "Go to", title: "Overview", icon: LayoutDashboard, run: go("/overview") },
      { id: "p-block", group: "Go to", title: "Blocklist", icon: Ban, run: go("/blocklist") },
      { id: "p-setup", group: "Go to", title: "Detection setup", icon: Settings2, run: go("/setup") },
    ];
    if (!kind) out.push(...pages.filter((p) => !term || p.title.toLowerCase().includes(term)));
    const matches = recent.filter((r) => !term || r.target.toLowerCase().includes(term)).slice(0, kind ? 3 : 6);
    out.push(
      ...matches.map((r) => ({
        id: `r-${r.id}`,
        group: "Recent scans",
        title: r.target,
        sub: `${VERDICT_LABEL[r.verdict]}, risk ${r.risk_score}, ${relativeTime(r.created_at)}`,
        icon: SCAN_ICON[r.scan_type],
        mono: r.scan_type !== "email",
        run: go(`/scans/${r.id}`),
      })),
    );
    return out;
  }, [q, recent, navigate, onClose]);

  useEffect(() => setActive(0), [q]);
  useEffect(() => {
    listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, items.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      items[active]?.run();
    }
  };

  let lastGroup = "";
  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div className="palette-scrim" onClick={onClose} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.18 }} />
          <div className="palette-wrap">
            <motion.div
              className="palette"
              role="dialog"
              aria-modal="true"
              aria-label="Command palette"
              initial={{ opacity: 0, scale: 0.96, y: -10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, y: -6, transition: { duration: 0.14 } }}
              transition={{ type: "spring", stiffness: 520, damping: 36 }}
              onKeyDown={onKey}
            >
              <div className="palette-input">
                <Search size={20} aria-hidden="true" />
                <textarea
                  ref={inputRef}
                  rows={1}
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Paste a link, domain or email, or jump to a page"
                  aria-label="Paste something to scan or search"
                  aria-controls="palette-list"
                  aria-activedescendant={items[active] ? `pi-${items[active].id}` : undefined}
                  spellCheck={false}
                />
              </div>
              <div className="palette-list" id="palette-list" role="listbox" ref={listRef}>
                {items.length === 0 && <p className="faint small" style={{ padding: 16 }}>Nothing matches. Paste a full link or domain to scan it.</p>}
                {items.map((it, i) => {
                  const header = it.group !== lastGroup ? <div className="palette-group">{it.group}</div> : null;
                  lastGroup = it.group;
                  const Icon = it.icon;
                  return (
                    <div key={it.id}>
                      {header}
                      <button
                        id={`pi-${it.id}`}
                        role="option"
                        aria-selected={i === active}
                        data-active={i === active}
                        data-index={i}
                        className="palette-item"
                        onMouseMove={() => setActive(i)}
                        onClick={it.run}
                      >
                        <span className="pi-icon">
                          <Icon size={16} aria-hidden="true" />
                        </span>
                        <span className="pi-text">
                          <span className={`pi-title ${it.mono ? "pi-mono" : ""}`}>{it.title}</span>
                          {it.sub ? <span className="pi-sub">{it.sub}</span> : null}
                        </span>
                        {i === active ? <CornerDownLeft size={16} className="faint" aria-hidden="true" /> : null}
                      </button>
                    </div>
                  );
                })}
              </div>
              <div className="palette-foot" aria-hidden="true">
                <span>
                  <kbd>↑</kbd>
                  <kbd>↓</kbd> move
                </span>
                <span>
                  <kbd>↵</kbd> open
                </span>
                <span>
                  <kbd>esc</kbd> close
                </span>
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}
