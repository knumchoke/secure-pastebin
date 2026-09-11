import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "dist",
    emptyOutDir: false, // keep dist/.keep so go:embed always has the directory
    sourcemap: false,
    modulePreload: { polyfill: false },
  },
  server: {
    proxy: { "/api": { target: "http://localhost:8080", changeOrigin: false } },
  },
});
