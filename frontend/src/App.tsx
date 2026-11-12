import { Fragment, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { Link, Navigate, NavLink, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { MotionConfig } from "motion/react";
import { Ban, ChartColumn, ChevronRight, History, Moon, ScanSearch, Search, SlidersHorizontal, Sun } from "lucide-react";
import CommandPalette from "./components/CommandPalette";
import { Checklist, Tour } from "./components/Onboarding";
import { BrandMark, Empty, Kbd, MOD } from "./components/ui";
import { ToastProvider } from "./lib/toast";
import { useTheme } from "./lib/theme";
import { updateOnboarding, useOnboarding } from "./lib/onboarding";
import { api } from "./lib/api";
import ScanPage from "./pages/ScanPage";
import ResultPage from "./pages/ResultPage";
import HistoryPage from "./pages/HistoryPage";
import OverviewPage from "./pages/OverviewPage";
import BlocklistPage from "./pages/BlocklistPage";
import SetupPage from "./pages/SetupPage";
import LandingPage from "./pages/LandingPage";
import OnboardingPage from "./pages/OnboardingPage";

const NAV = [
  { to: "/scan", label: "Scan", icon: ScanSearch },
  { to: "/history", label: "History", icon: History },
  { to: "/overview", label: "Overview", icon: ChartColumn },
  { to: "/blocklist", label: "Blocklist", icon: Ban },
  { to: "/setup", label: "Setup", icon: SlidersHorizontal },
];

function useApiHealth() {
  const [up, setUp] = useState<boolean | null>(null);
  useEffect(() => {
    let alive = true;
    const check = () =>
      api
        .health()
        .then(() => alive && setUp(true))
        .catch(() => alive && setUp(false));
    check();
    const t = window.setInterval(check, 15000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);
  return up;
}

function Shell() {
  const { pathname } = useLocation();
  const { resolved, toggle } = useTheme();
  const ob = useOnboarding();
  const apiUp = useApiHealth();
  const [paletteOpen, setPaletteOpen] = useState(false);

  const openPalette = useCallback(() => {
    updateOnboarding({ openedPalette: true });
    setPaletteOpen(true);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        updateOnboarding({ openedPalette: true });
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const isResult = pathname.startsWith("/scans/");
  const current = isResult ? NAV[1] : NAV.find((n) => pathname.startsWith(n.to));

  // Measured rather than layout-animated: the dock is fixed, so scroll must never affect the highlight.
  const dockRef = useRef<HTMLElement>(null);
  const [pill, setPill] = useState<{ left: number; width: number } | null>(null);
  useLayoutEffect(() => {
    const dock = dockRef.current!;
    const measure = () => {
      const active = dock.querySelector<HTMLElement>("a.is-active");
      setPill(active ? { left: active.offsetLeft, width: active.offsetWidth } : null);
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(dock);
    return () => observer.disconnect();
  }, [current?.to]);

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <Link to="/scan" className="brand" aria-label="Trace home">
          <BrandMark />
        </Link>
        <nav className="crumbs" aria-label="Breadcrumb">
          <ChevronRight size={14} aria-hidden="true" />
          {isResult ? (
            <>
              <Link to="/history">History</Link>
              <ChevronRight size={14} aria-hidden="true" />
              <span aria-current="page">Scan result</span>
            </>
          ) : (
            <span aria-current="page">{current?.label ?? "Not found"}</span>
          )}
        </nav>
        <div className="topbar-right">
          <span className="api-status" data-state={apiUp === null ? "unknown" : apiUp ? "up" : "down"} role="status">
            <i aria-hidden="true" />
            {apiUp === null ? "Connecting" : apiUp ? "Online" : "Scanner offline"}
          </span>
          <button className="icon-btn" onClick={toggle} aria-label={resolved === "dark" ? "Switch to light theme" : "Switch to dark theme"} data-tip={resolved === "dark" ? "Light theme" : "Dark theme"}>
            {resolved === "dark" ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </div>
      </header>

      <main id="main" className="main">
        <Fragment key={pathname}>
          <Outlet />
        </Fragment>
      </main>

      <nav ref={dockRef} className="dock" aria-label="Main">
        {pill && <span className="dock-pill" style={pill} aria-hidden="true" />}
        {NAV.map(({ to, label, icon: Icon }) => {
          const active = current?.to === to;
          return (
            <NavLink key={to} to={to} aria-label={label} aria-current={active ? "page" : undefined} className={active ? "is-active" : undefined}>
                            <Icon size={16} aria-hidden="true" />
              <span className="dock-label">{label}</span>
            </NavLink>
          );
        })}
        <span className="dock-sep" aria-hidden="true" />
        <button className="dock-search" onClick={openPalette} aria-label="Scan or search">
          <Search size={16} aria-hidden="true" />
          <Kbd keys={[MOD, "K"]} />
        </button>
      </nav>

      {ob.onboarded && !ob.tourDone && pathname === "/scan" && <Tour />}
      {ob.onboarded && ob.tourDone && !ob.checklistHidden && <Checklist onOpenPalette={openPalette} />}
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </>
  );
}

function Home() {
  return useOnboarding().onboarded ? <Navigate to="/scan" replace /> : <LandingPage />;
}

/** Runs every route change, however it was triggered, through one browser view transition. */
function useTransitionedLocation() {
  const location = useLocation();
  const [shown, setShown] = useState(location);

  useEffect(() => {
    if (location.pathname === shown.pathname) return;
    if (!document.startViewTransition || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setShown(location);
      return;
    }
    document.startViewTransition(() => flushSync(() => setShown(location))).ready.catch(() => {}); // rejects when a newer navigation skips this one
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location]);

  // Same page (query or state change): nothing to animate, so use the live location.
  const displayed = shown.pathname === location.pathname ? location : shown;

  useLayoutEffect(() => {
    window.scrollTo(0, 0);
  }, [displayed.pathname]);

  return displayed;
}

export default function App() {
  const location = useTransitionedLocation();
  return (
    <MotionConfig reducedMotion="user">
      <ToastProvider>
        <Routes location={location}>
          <Route path="/" element={<Home />} />
          <Route path="/welcome" element={<LandingPage />} />
          <Route path="/onboarding" element={<OnboardingPage />} />
          <Route element={<Shell />}>
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/scans/:id" element={<ResultPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/overview" element={<OverviewPage />} />
            <Route path="/blocklist" element={<BlocklistPage />} />
            <Route path="/setup" element={<SetupPage />} />
            <Route
              path="*"
              element={
                <Empty title="This page doesn't exist" action={<Link className="btn btn-primary" to="/scan">Start a scan</Link>}>
                  Head back to the scanner to check a link, domain or email.
                </Empty>
              }
            />
          </Route>
        </Routes>
      </ToastProvider>
    </MotionConfig>
  );
}
