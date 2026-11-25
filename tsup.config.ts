import { defineConfig } from "tsup";

// The schema package is bundled in (code and types), so the published SDK has no workspace
// dependency. viem stays external: customers bring their own.
export default defineConfig({
  entry: { index: "src/index.ts", policy: "src/policy.ts" },
  format: ["esm"],
  dts: true,
  clean: true,
  target: "es2022",
  noExternal: ["@palisec/policy-schema"],
  external: ["viem"],
});
