// build.config.ts
import { defineBuildConfig } from "unbuild";

export default defineBuildConfig({
  entries: ["./src/index"],
  declaration: true,
  clean: true,
  rollup: {
    emitCJS: false, // ✅ Explicit: skip CommonJS output
  },
});
