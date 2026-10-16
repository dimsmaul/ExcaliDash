import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendRoot = path.resolve(__dirname, "..");

// Vercel ignores dist/404.html, so client-side routes (/login, /shared/:id)
// 404 there. On Vercel builds (VERCEL is set by the platform), emit the Build
// Output API layout instead: dist/ as static files plus a route that serves
// index.html for any path that is not a real file.
if (process.env.VERCEL) {
  const output = path.join(frontendRoot, ".vercel", "output");
  await fs.rm(output, { recursive: true, force: true });
  await fs.cp(path.join(frontendRoot, "dist"), path.join(output, "static"), {
    recursive: true,
  });
  const config = {
    version: 3,
    routes: [{ handle: "filesystem" }, { src: "/.*", dest: "/index.html" }],
  };
  await fs.writeFile(
    path.join(output, "config.json"),
    `${JSON.stringify(config, null, 2)}\n`,
  );
  console.log("[vercel-output] wrote .vercel/output with SPA fallback");
}
