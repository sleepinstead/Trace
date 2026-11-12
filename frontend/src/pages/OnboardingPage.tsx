import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "motion/react";
import { ArrowRight, FileSearch, ListChecks, ScanSearch } from "lucide-react";
import { BrandMark, Segmented, Switch } from "../components/ui";
import { updateOnboarding, useOnboarding } from "../lib/onboarding";
import { useTheme, type ThemePref } from "../lib/theme";

const STEPS = [
  { title: "Welcome to Trace", sub: "Three quick choices and you're scanning." },
  { title: "How thorough should scans be?", sub: "You can change these for any single scan." },
  { title: "Choose your look", sub: "Black and white, either way round." },
];

const INTRO = [
  { icon: ScanSearch, title: "Paste anything suspicious", body: "Links, domains and full emails." },
  { icon: FileSearch, title: "See what gives it away", body: "Evidence marked where it appears." },
  { icon: ListChecks, title: "Keep a record", body: "Every result stays on this machine." },
];

export default function OnboardingPage() {
  const navigate = useNavigate();
  const ob = useOnboarding();
  const { pref, setPref } = useTheme();
  const [step, setStep] = useState(0);
  const last = step === STEPS.length - 1;

  const finish = () => {
    updateOnboarding({ onboarded: true });
    navigate("/scan", { replace: true });
  };

  return (
    <div className="ob">
      <section className="ob-left">
        <Link to="/welcome" className="brand">
          <BrandMark />
        </Link>
        <div className="ob-form">
          <motion.div key={step} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}>
            <h1>{STEPS[step].title}</h1>
            <p className="ob-sub">{STEPS[step].sub}</p>
          </motion.div>
          <div className="ob-progress" role="progressbar" aria-valuemin={1} aria-valuemax={STEPS.length} aria-valuenow={step + 1} aria-label="Setup progress">
            {STEPS.map((s, i) => (
              <span key={s.title} data-on={i <= step} />
            ))}
          </div>
          <motion.div key={`body-${step}`} className="ob-body" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.25, delay: 0.05 }}>
            {step === 0 && (
              <ul className="ob-intro">
                {INTRO.map(({ icon: Icon, title, body }) => (
                  <li key={title}>
                    <span className="ob-icon">
                      <Icon size={17} aria-hidden="true" />
                    </span>
                    <span>
                      <strong>{title}</strong>
                      <small>{body}</small>
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {step === 1 && (
              <div className="settings-rows">
                <Switch checked={ob.deep} onChange={(deep) => updateOnboarding({ deep })} label="Investigate by default" description="Visit each link from the scanner and look up its domain." />
                <Switch checked={ob.useIntel} onChange={(useIntel) => updateOnboarding({ useIntel })} label="Check threat feeds" description="Your blocklist plus any feeds you connect later." />
              </div>
            )}
            {step === 2 && (
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
            )}
          </motion.div>
          <button type="button" className="btn btn-primary btn-block" onClick={() => (last ? finish() : setStep(step + 1))}>
            {last ? "Start scanning" : "Continue"}
            <ArrowRight size={16} aria-hidden="true" />
          </button>
          <div className="ob-alt">
            {step > 0 ? (
              <button type="button" className="link-btn" onClick={() => setStep(step - 1)}>
                Back
              </button>
            ) : (
              <span />
            )}
            {!last && (
              <button type="button" className="link-btn" onClick={finish}>
                Skip setup
              </button>
            )}
          </div>
        </div>
      </section>

      <section className="ob-right" aria-hidden="true">
        <div className="ob-frame">
          <div className="ob-frame-top">
            <span className="sk sk-mark" />
            <span className="sk" style={{ width: 90 }} />
          </div>
          <div className="ob-frame-body">
            <span className="sk sk-title" />
            <span className="sk" style={{ width: "62%" }} />
            <motion.div className="sk-card" animate={{ height: step === 0 ? 150 : step === 1 ? 210 : 120 }} transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }} />
            <span className="sk" style={{ width: "80%" }} />
            <span className="sk" style={{ width: "48%" }} />
          </div>
          <div className="ob-frame-dock">
            <span className="sk-dot is-on" />
            <span className="sk-dot" />
            <span className="sk-dot" />
            <span className="sk-dot" />
            <span className="sk-dot" />
          </div>
        </div>
      </section>
    </div>
  );
}
