import { svelte } from "@sveltejs/vite-plugin-svelte";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

// Static site with the interactive demo. Built into ../public, which wrangler serves as static assets.
export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  plugins: [svelte()],
  build: { outDir: "../public", emptyOutDir: true },
});
