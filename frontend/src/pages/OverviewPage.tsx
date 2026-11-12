import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Stats } from "../lib/api";
import { BarList, Legend, ShareBar, Timeline } from "../components/charts";
import { Empty } from "../components/ui";

export default function OverviewPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.stats().then(setStats).catch((e) => setError(e.message));
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Overview</h1>
          <p className="page-sub">What you've scanned in the last 30 days, and the tricks that came up most.</p>
        </div>
      </div>

      {error && (
        <p className="callout" data-tone="danger">
          {error}
        </p>
      )}
      {!stats && !error && <div className="skeleton" style={{ height: 420 }} />}

      {stats && stats.total_scans === 0 && (
        <div className="card">
          <Empty title="No scans to chart yet" action={<Link className="btn btn-primary" to="/scan">Start scanning</Link>}>
            Trends and common techniques appear here once you've checked a few things.
          </Empty>
        </div>
      )}

      {stats && stats.total_scans > 0 && (
        <div className="overview">
          <dl className="stats card">
            {[
              ["Scans", stats.total_scans],
              ["Likely phishing", stats.by_verdict.malicious],
              ["Suspicious", stats.by_verdict.suspicious],
              ["Looked safe", stats.by_verdict.safe],
              ["Average risk", Math.round(stats.average_risk)],
              ["Blocked", stats.threat_records],
            ].map(([k, v]) => (
              <div key={k} className="stat">
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>

          <section className="card card-pad span-2" aria-labelledby="tl-title">
            <div className="card-head">
              <h2 id="tl-title">Scans per day</h2>
              <Legend />
            </div>
            <Timeline data={stats.timeline} />
          </section>

          <section className="card card-pad" aria-labelledby="share-title">
            <div className="card-head">
              <h2 id="share-title">Verdict share</h2>
            </div>
            <ShareBar counts={stats.by_verdict} />
            <h3 className="subhead">By type</h3>
            <BarList
              items={[
                { key: "url", label: "Links", value: stats.by_type.url },
                { key: "domain", label: "Domains", value: stats.by_type.domain },
                { key: "email", label: "Emails", value: stats.by_type.email },
              ]}
            />
          </section>

          <section className="card card-pad" aria-labelledby="tech-title">
            <div className="card-head">
              <h2 id="tech-title">Most common tricks</h2>
            </div>
            {stats.top_techniques.length ? <BarList items={stats.top_techniques.map((t) => ({ key: t.id, label: t.title, value: t.count }))} /> : <p className="muted small">Nothing has been flagged yet.</p>}
          </section>
        </div>
      )}
    </>
  );
}
