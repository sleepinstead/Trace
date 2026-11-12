import { useCallback, useEffect, useState, type FormEvent } from "react";
import { AtSign, Globe, Link2, Search, Server, Trash2 } from "lucide-react";
import { api, type ThreatRecord } from "../lib/api";
import { relativeTime } from "../lib/format";
import { useToast } from "../lib/toast";
import { ConfirmButton, Empty, Segmented } from "../components/ui";

type Kind = "domain" | "url" | "ip" | "email";
const KINDS: { value: Kind; label: string; icon: typeof Globe; placeholder: string }[] = [
  { value: "domain", label: "Domain", icon: Globe, placeholder: "secure-login-paypa1.com" },
  { value: "url", label: "Link", icon: Link2, placeholder: "https://secure-login-paypa1.com/verify" },
  { value: "ip", label: "IP", icon: Server, placeholder: "185.234.72.19" },
  { value: "email", label: "Sender", icon: AtSign, placeholder: "billing@secure-login-paypa1.com" },
];

export default function BlocklistPage() {
  const toast = useToast();
  const [items, setItems] = useState<ThreatRecord[] | null>(null);
  const [kind, setKind] = useState<Kind>("domain");
  const [indicator, setIndicator] = useState("");
  const [note, setNote] = useState("");
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    api.threats(q).then((r) => setItems(r.items)).catch((e) => setError(e.message));
  }, [q]);

  useEffect(() => {
    const t = window.setTimeout(load, items === null ? 0 : 180);
    return () => window.clearTimeout(t);
  }, [load]);

  const add = async (e: FormEvent) => {
    e.preventDefault();
    if (!indicator.trim()) {
      setError("Enter the domain, link, IP or address you want to block.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const rec = await api.addThreat({ indicator: indicator.trim(), indicator_type: kind, threat_type: "phishing", description: note.trim() });
      setItems((xs) => [rec, ...(xs ?? []).filter((x) => x.id !== rec.id)]);
      setIndicator("");
      setNote("");
      toast({ tone: "success", title: "Blocked", body: rec.indicator, action: { label: "Undo", run: () => void remove(rec) } });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const restore = async (rec: ThreatRecord) => {
    try {
      const saved = await api.addThreat({ indicator: rec.indicator, indicator_type: rec.indicator_type, threat_type: rec.threat_type, description: rec.description });
      setItems((xs) => [saved, ...(xs ?? [])]);
      toast({ tone: "info", title: "Blocked again", body: saved.indicator });
    } catch (e) {
      toast({ tone: "error", title: "Couldn't restore it", body: (e as Error).message });
    }
  };

  const remove = async (rec: ThreatRecord) => {
    try {
      await api.deleteThreat(rec.id);
      setItems((xs) => xs?.filter((x) => x.id !== rec.id) ?? null);
      toast({ tone: "success", title: "Unblocked", body: rec.indicator, action: { label: "Undo", run: () => void restore(rec) } });
    } catch (e) {
      toast({ tone: "error", title: "Couldn't remove it", body: (e as Error).message });
    }
  };

  const current = KINDS.find((k) => k.value === kind)!;

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Blocklist</h1>
          <p className="page-sub">Anything that matches an entry here is marked as phishing, with a score of at least 90.</p>
        </div>
      </div>

      <form className="card card-pad block-form" onSubmit={add} noValidate>
        <Segmented label="Indicator type" value={kind} onChange={setKind} options={KINDS} />
        <div className="block-fields">
          <div>
            <label className="field-label" htmlFor="b-ind">
              {current.label}
            </label>
            <input id="b-ind" className="field mono" placeholder={current.placeholder} value={indicator} onChange={(e) => setIndicator(e.target.value)} autoComplete="off" spellCheck={false} />
          </div>
          <div>
            <label className="field-label" htmlFor="b-note">
              Note <span className="faint">(optional)</span>
            </label>
            <input id="b-note" className="field" placeholder="Where you saw it" value={note} onChange={(e) => setNote(e.target.value)} />
          </div>
          <button className="btn btn-primary" type="submit" disabled={saving}>
            Add
          </button>
        </div>
        {error && (
          <p className="field-error" role="alert">
            {error}
          </p>
        )}
      </form>

      {items && (items.length > 0 || q) && (
        <div className="toolbar toolbar-end">
          <div className="search">
            <Search size={15} aria-hidden="true" />
            <label className="visually-hidden" htmlFor="b-q">
              Search the blocklist
            </label>
            <input id="b-q" className="field field-sm" placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
        </div>
      )}

      {items && items.length === 0 && (
        <div className="card">
          {q ? (
            <Empty title="No entries match">
              Try a shorter search.
            </Empty>
          ) : (
            <Empty title="Your blocklist is empty">
              Add an indicator above, or press Block on any flagged scan.
            </Empty>
          )}
        </div>
      )}

      {items && items.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Indicator</th>
                <th scope="col">Type</th>
                <th scope="col" className="hide-sm">
                  Note
                </th>
                <th scope="col" className="hide-sm">
                  Added
                </th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => {
                const K = KINDS.find((k) => k.value === r.indicator_type) ?? KINDS[0];
                return (
                  <tr key={r.id}>
                    <td className="cell-target mono" title={r.indicator}>
                      {r.indicator}
                    </td>
                    <td>
                      <span className="cell-type">
                        <K.icon size={14} aria-hidden="true" />
                        {K.label}
                      </span>
                    </td>
                    <td className="hide-sm muted cell-note">{r.description || "None"}</td>
                    <td className="hide-sm muted nowrap">{relativeTime(r.created_at)}</td>
                    <td className="cell-actions">
                      <ConfirmButton className="icon-btn icon-btn-sm" onConfirm={() => void remove(r)} title="Remove from blocklist?" body={`Scans matching ${r.indicator} will no longer be forced to phishing.`} confirmLabel="Remove" ariaLabel={`Remove ${r.indicator}`}>
                        <Trash2 size={15} aria-hidden="true" />
                      </ConfirmButton>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {!items && !error && <div className="skeleton" style={{ height: 200 }} />}
    </>
  );
}
