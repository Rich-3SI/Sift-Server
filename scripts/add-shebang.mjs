import { readFileSync, writeFileSync, chmodSync, existsSync } from "fs";

for (const f of ["dist/index.js", "dist/hook.js"]) {
  if (!existsSync(f)) continue;
  const c = readFileSync(f, "utf8");
  if (!c.startsWith("#!/usr/bin/env node")) {
    writeFileSync(f, "#!/usr/bin/env node\n" + c);
  }
  chmodSync(f, 0o755);
}
