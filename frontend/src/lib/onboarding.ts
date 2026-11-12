import { useSyncExternalStore } from "react";

export interface OnboardingState {
  onboarded: boolean;
  tourDone: boolean;
  checklistHidden: boolean;
  openedPalette: boolean;
  openedResult: boolean;
  deep: boolean;
  useIntel: boolean;
}

const KEY = "trace.onboarding";
const DEFAULTS: OnboardingState = {
  onboarded: false,
  tourDone: false,
  checklistHidden: false,
  openedPalette: false,
  openedResult: false,
  deep: true,
  useIntel: true,
};

function load(): OnboardingState {
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(KEY) ?? "{}") };
  } catch {
    return DEFAULTS;
  }
}

let state = load();
const listeners = new Set<() => void>();

export function updateOnboarding(patch: Partial<OnboardingState>) {
  state = { ...state, ...patch };
  try {
    localStorage.setItem(KEY, JSON.stringify(state));
  } catch {
    /* storage unavailable: lasts for this session only */
  }
  listeners.forEach((l) => l());
}

export function useOnboarding() {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => {
        listeners.delete(cb);
      };
    },
    () => state,
  );
}
