/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The production build is served by the API (same origin, strict CSP without
// inline scripts or styles). During development the API runs on :8000.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    // Assets are never inlined as data: URIs into CSS/JS; fonts stay separate files.
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          if (id.includes("node_modules/echarts") || id.includes("node_modules/zrender")) return "charts";
          if (id.includes("node_modules/cytoscape")) return "graph";
          return undefined;
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      // Chart.tsx / EntityGraph.tsx draw on canvas (not available in jsdom); covered by Playwright E2E.
      exclude: [
        "src/**/*.test.{ts,tsx}",
        "src/test/**",
        "src/api/schema.d.ts",
        "src/main.tsx",
        "src/vite-env.d.ts",
        "src/components/Chart.tsx",
        "src/components/EntityGraph.tsx",
      ],
      thresholds: { lines: 80, statements: 80, functions: 80, branches: 75 },
      reporter: ["text-summary", "lcov"],
    },
  },
});
