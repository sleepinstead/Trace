import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiTarget = process.env.TRACE_API ?? "http://127.0.0.1:47614";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 47613,
    strictPort: true, // fail loudly instead of drifting to another port
    proxy: { "/api": { target: apiTarget, changeOrigin: true } },
  },
});
