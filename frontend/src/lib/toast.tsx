import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { AnimatePresence, motion } from "motion/react";

interface ToastInput {
  tone: "success" | "error" | "info";
  title: string;
  body?: string;
  action?: { label: string; run: () => void };
}
type Toast = ToastInput & { id: number };

const ToastCtx = createContext<(t: ToastInput) => void>(() => {});

export function useToast() {
  return useContext(ToastCtx);
}

/** One message at a time, in words only. A new toast replaces the last. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<Toast | null>(null);
  const seq = useRef(0);
  const timer = useRef(0);

  const push = useCallback((t: ToastInput) => {
    const id = ++seq.current;
    setToast({ ...t, id });
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setToast(null), t.tone === "error" ? 8000 : t.action ? 6000 : 3500);
  }, []);

  // An error needs a way to clear it; everything else leaves on its own.
  const action = toast?.action ?? (toast?.tone === "error" ? { label: "Dismiss", run: () => {} } : undefined);

  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toaster" role="status" aria-live="polite">
        <AnimatePresence>
          {toast && (
            <motion.div key={toast.id} className="toast" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, transition: { duration: 0.12 } }} transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}>
              <p>
                <strong>{toast.title}</strong>
                {toast.body ? <span>{toast.body}</span> : null}
              </p>
              {action ? (
                <button
                  type="button"
                  onClick={() => {
                    setToast(null);
                    action.run();
                  }}
                >
                  {action.label}
                </button>
              ) : null}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </ToastCtx.Provider>
  );
}
