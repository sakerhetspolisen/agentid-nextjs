import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // Keep next/server as an external — consumers bring their own Next.js
  external: ["next", "next/server"],
});
