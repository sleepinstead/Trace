import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ChevronDown, Copy, Ellipsis, ExternalLink, Globe, Link2, Mail, RotateCw, Search, Trash2 } from "lucide-react";
import { api, type ScanListItem, type Verdict } from "../lib/api";
import { relativeTime, TYPE_LABEL, VERDICT_LABEL } from "../lib/format";
import { useToast } from "../lib/toast";
import { ConfirmDialog, Dropdown, Empty, RiskBars, Segmented, VerdictBadge } from "../components/ui";

const PAGE = 30;
const TYPE_ICON = { url: Link2, domain: Globe, email: Mail };
type VerdictFilter = "all" | Verdict;

export default function HistoryPage() {
  const navigate = useNavigate();
  const toast = useToast();
  const [items, setItems] = useState<ScanListItem[] | null>(null);
  const [total, setTotal] = useState(0);
  const [type, setType] = useState<"all" | "url" | "domain" | "email">("all");
  const [verdict, setVerdict] = useState<VerdictFilter>("all");
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [pending, setPending] = useState<ScanListItem | null>(null);

  const query = useCallback((offset: number) => api.scans({ scan_type: type === "all" ? undefined : type, verdict: verdict === "all" ? undefined : verdict, q, limit: PAGE, offset }), [type, verdict, q]);

  useEffect(() => {
    const t = window.setTimeout(() => {
      query(0)
        .then((r) => {
          setItems(r.items);
          setTotal(r.total);
          setError(null);
        })
        .catch((e) => setError(e.message));
    }, items === null ? 0 : 180);
    return () => window.clearTimeout(t);
  }, [query]);

  const more = async () => {
    if (!items) return;
    setLoadingMore(true);
    try {
      const r = await query(items.length);
      setItems([...items, ...r.items]);
      setTotal(r.total);
    } finally {
      setLoadingMore(false);
    }
  };

  const remove = async (s: ScanListItem) => {
    try {
      await api.deleteScan(s.id);
      setItems((xs) => xs?.filter((x) => x.id !== s.id) ?? null);
      setTotal((t) => t - 1);
      toast({ tone: "success", title: "Scan deleted" });
    } catch (e) {
      toast({ tone: "error", title: "Couldn't delete the scan", body: (e as Error).message });
    }
  };

  const verdictOptions: VerdictFilter[] = ["all", "malicious", "suspicious", "safe"];
  const filtered = type !== "all" || verdict !== "all" || q;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">History</h1>
          <p className="page-sub">Every scan, with its full evidence, stored on this machine.</p>
        </div>
        <Link to="/scan" className="btn btn-primary btn-sm">
          New scan
        </Link>
      </div>

      <div className="toolbar">
        <Segmented
          label="Type"
          value={type}
          onChange={setType}
          options={[
            { value: "all", label: "All" },
            { value: "url", label: "Links" },
            { value: "domain", label: "Domains" },
            { value: "email", label: "Emails" },
          ]}
        />
        <div className="toolbar-right">
          <Dropdown
            label="Filter by verdict"
            trigger={
              <>
                {verdict === "all" ? "Any verdict" : VERDICT_LABEL[verdict]}
                <ChevronDown size={14} aria-hidden="true" />
              </>
            }
            items={verdictOptions.map((v) => ({ label: v === "all" ? "Any verdict" : VERDICT_LABEL[v], checked: verdict === v, onSelect: () => setVerdict(v) }))}
          />
          <div className="search">
            <Search size={15} aria-hidden="true" />
            <label className="visually-hidden" htmlFor="h-q">
              Search history
            </label>
            <input id="h-q" className="field field-sm" placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
        </div>
      </div>

      {error && (
        <p className="callout" data-tone="danger">
          {error}
        </p>
      )}

      {items === null && !error && <div className="skeleton" style={{ height: 320 }} />}

      {items && items.length === 0 && (
        <div className="card">
          {filtered ? (
            <Empty title="No matching scans">
              Try a different search or clear the filters.
            </Empty>
          ) : (
            <Empty title="Nothing scanned yet" action={<Link className="btn btn-primary" to="/scan">Scan your first link</Link>}>
              Every link, domain and email you check will be kept here.
            </Empty>
          )}
        </div>
      )}

      {items && items.length > 0 && (
        <>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Scanned</th>
                  <th scope="col" className="hide-sm">
                    Verdict
                  </th>
                  <th scope="col" className="hide-sm">
                    Type
                  </th>
                  <th scope="col">Risk</th>
                  <th scope="col" className="hide-sm">
                    When
                  </th>
                  <th scope="col">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((s) => {
                  const Icon = TYPE_ICON[s.scan_type];
                  return (
                    <tr key={s.id} className="clickable" onClick={() => navigate(`/scans/${s.id}`)}>
                      <td className="cell-target">
                        <Link to={`/scans/${s.id}`} className={s.scan_type === "email" ? undefined : "mono"} onClick={(e) => e.stopPropagation()} title={s.target}>
                          {s.target}
                        </Link>
                      </td>
                      <td className="hide-sm">
                        <VerdictBadge verdict={s.verdict} />
                      </td>
                      <td className="hide-sm">
                        <span className="cell-type">
                          <Icon size={14} aria-hidden="true" />
                          {TYPE_LABEL[s.scan_type]}
                        </span>
                      </td>
                      <td>
                        <RiskBars score={s.risk_score} />
                      </td>
                      <td className="hide-sm muted nowrap">{relativeTime(s.created_at)}</td>
                      <td className="cell-actions">
                        <Dropdown
                          label={`Actions for ${s.target}`}
                          className="icon-btn icon-btn-sm"
                          trigger={<Ellipsis size={16} aria-hidden="true" />}
                          items={[
                            { label: "Open", icon: ExternalLink, onSelect: () => navigate(`/scans/${s.id}`) },
                            ...(s.scan_type !== "email" ? [{ label: "Scan again", icon: RotateCw, onSelect: () => navigate("/scan", { state: { autoScan: { kind: s.scan_type, value: s.target } } }) }] : []),
                            { label: "Copy", icon: Copy, onSelect: () => void navigator.clipboard.writeText(s.target).catch(() => {}) },
                            { label: "Delete", icon: Trash2, danger: true, onSelect: () => setPending(s) },
                          ]}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="table-foot">
            <span>
              {total} scan{total === 1 ? "" : "s"}
            </span>
            {items.length < total && (
              <button className="btn btn-outline btn-sm" onClick={more} disabled={loadingMore}>
                {loadingMore ? "Loading…" : `Show ${Math.min(PAGE, total - items.length)} more`}
              </button>
            )}
          </div>
        </>
      )}

      <ConfirmDialog open={pending !== null} title="Delete this scan?" body="Its findings and evidence will be gone for good." confirmLabel="Delete scan" onConfirm={() => pending && void remove(pending)} onClose={() => setPending(null)} />
    </>
  );
}
