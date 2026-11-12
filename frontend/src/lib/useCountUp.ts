import { useEffect, useState } from "react";
import { animate, useReducedMotion } from "motion/react";

/** Animate a number from 0 to `target`. Jumps straight to the value when reduced motion is on. */
export function useCountUp(target: number, { duration = 1.1, delay = 0, decimals = 0 } = {}) {
  const reduce = useReducedMotion();
  const [value, setValue] = useState(reduce ? target : 0);

  useEffect(() => {
    if (reduce) {
      setValue(target);
      return;
    }
    const controls = animate(0, target, {
      duration,
      delay,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: (v) => setValue(v),
    });
    return () => controls.stop();
  }, [target, duration, delay, reduce]);

  const f = 10 ** decimals;
  return Math.round(value * f) / f;
}
