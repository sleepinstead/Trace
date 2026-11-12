import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ExternalLink } from "lucide-react";
import { api, type ModelInfo, type ProviderStatus } from "../lib/api";
import { formatDate, pct } from "../lib/format";
import { updateOnboarding, useOnboarding } from "../lib/onboarding";
import { useTheme, type ThemePref } from "../lib/theme";
import { BarList } from "../components/charts";
import { Tabs } from "../components/Evidence";
import { CopyButton, Segmented, Switch } from "../components/ui";

const PROVIDER_INFO: Record<string, { what: string; url?: string }> = {
  virustotal: { what: "Verdicts from dozens of antivirus and URL scanners.", url: "https://www.virustotal.com/gui/my-apikey" },
  safebrowsing: { what: "Google's list of phishing and malware sites.", url: "https://developers.google.com/safe-browsing/v4/get-started" },
  urlhaus: { what: "abuse.ch's feed of URLs distributing malware.", url: "https://auth.abuse.ch/" },
  phishtank: { what: "Community-verified phishing URLs.", url: "https://phishtank.org/" },
  local: { what: "Your own blocklist. Always on." },
};

const METRICS = [
  { key: "accuracy", label: "Accuracy" },
  { key: "precision", label: "Precision" },
  { key: "recall", label: "Recall" },
  { key: "f1", label: "F1" },
  { key: "roc_auc", label: "ROC AUC" },
];

export default function SetupPage() {
  const navigate = useNavigate();
  const ob = useOnboarding();
  const { pref, setPref } = useTheme();
  const [providers, setProviders] = useState<ProviderStatus[] | null>(null);
  const [model, setModel] = useState<ModelInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.providers(), api.model()])
      .then(([p, m]) => {
        setProviders(p);
        setModel(m);
      })
      .catch((e) => setError(e.message));
  }, []);

  const general = (
    <div className="settings-section">
      <h2>Scans</h2>
      <div className="settings-rows">
        <Switch checked={ob.deep} onChange={(deep) => updateOnboarding({ deep })} label="Investigate by default" description="Visit each link from the scanner and look up its domain." />
        <Switch checked={ob.useIntel} onChange={(useIntel) => updateOnboarding({ useIntel })} label="Check threat feeds" description="Your blocklist plus any feeds connected below." />
      </div>
      <h2>Appearance</h2>
      <div className="settings-rows">
        <div className="setting-row">
          <span className="switch-label">
            Theme<span className="switch-desc">Black and white, either way round.</span>
          </span>
          <Segmented<ThemePref>
            label="Theme"
            value={pref}
            onChange={setPref}
            options={[
              { value: "system", label: "System" },
              { value: "light", label: "Light" },
              { value: "dark", label: "Dark" },
            ]}
          />
        </div>
      </div>
      <h2>Getting started</h2>
      <div className="settings-rows">
        <div className="setting-row">
          <span className="switch-label">
            Onboarding<span className="switch-desc">Go through the welcome steps and guided tour again.</span>
          </span>
          <button
            type="button"
            className="btn btn-outline btn-sm"
            onClick={() => {
              updateOnboarding({ tourDone: false });
              navigate("/onboarding");
            }}
          >
            View onboarding
          </button>
        </div>
        <Switch checked={!ob.checklistHidden && ob.tourDone} onChange={(on) => updateOnboarding({ checklistHidden: !on, tourDone: true })} label="Getting started checklist" description="Show the checklist in the corner of every page." />
      </div>
    </div>
  );

  const feeds = providers && (
    <div className="settings-section">
      <p className="muted small">Put a key in the project's <code>.env</code> and restart the API to connect a feed.</p>
      <div className="settings-rows">
        {providers.map((p) => {
          const info = PROVIDER_INFO[p.source] ?? { what: "" };
          return (
            <div key={p.source} className="setting-row">
              <span className="switch-label">
                {p.name}
                <span className="switch-desc">{info.what}</span>
                {p.env ? <code className="env-name">{p.env}</code> : null}
              </span>
              <span className="feed-actions">
                <span className="verdict-badge" data-tone={p.enabled ? "danger" : "trust"}>
                  {p.enabled ? "Connected" : "Not connected"}
                </span>
                {p.env ? <CopyButton text={`${p.env}=`} label="Copy name" /> : null}
                {info.url && !p.enabled ? (
                  <a href={info.url} target="_blank" rel="noreferrer noopener" className="icon-btn icon-btn-sm" aria-label={`Get a ${p.name} key`} data-tip="Get a key">
                    <ExternalLink size={14} aria-hidden="true" />
                  </a>
                ) : null}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );

  const modelPanel = model && (
    <div className="settings-section">
      <p className="muted small">
        XGBoost and random forest, weighted {Math.round((model.ensemble_weights.xgboost ?? 0.6) * 100)}/{Math.round((model.ensemble_weights.random_forest ?? 0.4) * 100)}. Trained {formatDate(model.trained_at)} on {model.n_samples.toLocaleString()} URLs using {model.n_features} features, scored on {model.test_size.toLocaleString()} held-out URLs.
      </p>
      {model.dataset.startsWith("synthetic") && (
        <p className="callout" data-tone="warn">
          This model learned from generated examples, so these numbers overstate real-world accuracy. Retrain on labelled data with <code>python -m app.ml.train --csv urls.csv</code>.
        </p>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Model</th>
              {METRICS.map((m) => (
                <th key={m.key} scope="col" className="num">
                  {m.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Object.entries(model.metrics).map(([name, m]) => (
              <tr key={name}>
                <td>{name === "xgboost" ? "XGBoost" : name === "random_forest" ? "Random forest" : "Ensemble"}</td>
                {METRICS.map((k) => (
                  <td key={k.key} className="num">
                    {k.key === "roc_auc" ? m[k.key].toFixed(3) : pct(m[k.key], 1)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h2>What the model relies on most</h2>
      <BarList items={model.top_features.slice(0, 8).map((f) => ({ key: f.feature, label: f.label, value: f.importance, display: `${(f.importance * 100).toFixed(1)}%` }))} />
    </div>
  );

  return (
    <div className="setup">
      <div className="page-head">
        <div>
          <h1 className="page-title">Setup</h1>
          <p className="page-sub">Scan defaults, threat feeds and the URL model.</p>
        </div>
      </div>
      {error && (
        <p className="callout" data-tone="danger">
          {error}
        </p>
      )}
      <Tabs
        label="Setup"
        tabs={[
          { id: "general", label: "General", content: general },
          { id: "feeds", label: "Threat feeds", content: feeds ?? <div className="skeleton" style={{ height: 300 }} /> },
          { id: "model", label: "URL model", content: modelPanel ?? <div className="skeleton" style={{ height: 300 }} /> },
        ]}
      />
    </div>
  );
}
