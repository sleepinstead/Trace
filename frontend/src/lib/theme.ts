import { useEffect, useSyncExternalStore } from "react";

export type ThemePref = "system" | "light" | "dark";
const KEY = "trace.theme";

function read(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

let pref = read();
const listeners = new Set<() => void>();
const media = window.matchMedia("(prefers-color-scheme: dark)");

function apply() {
  if (pref === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", pref);
}
apply();

function setPref(next: ThemePref) {
  pref = next;
  apply();
  try {
    if (next === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, next);
  } catch {
    /* storage unavailable: lasts for this session only */
  }
  listeners.forEach((l) => l());
}

export function useTheme() {
  const current = useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => {
        listeners.delete(cb);
      };
    },
    () => pref,
  );
  const sysDark = useSyncExternalStore(
    (cb) => {
      media.addEventListener("change", cb);
      return () => media.removeEventListener("change", cb);
    },
    () => media.matches,
  );
  useEffect(apply, [current]);
  const resolved: "light" | "dark" = current === "system" ? (sysDark ? "dark" : "light") : current;
  return { pref: current, resolved, setPref, toggle: () => setPref(resolved === "dark" ? "light" : "dark") };
}
