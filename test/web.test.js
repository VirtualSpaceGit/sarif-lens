import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("browser surface has restrictive CSP and no remote runtime assets", async () => {
  const html = await readFile("web/index.html", "utf8");
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /connect-src 'none'/);
  assert.doesNotMatch(html, /<(?:script|link)[^>]+(?:src|href)=["']https?:\/\//i);
});

test("browser renderer never uses HTML injection sinks", async () => {
  const app = await readFile("web/app.js", "utf8");
  assert.doesNotMatch(app, /\.innerHTML\b/);
  assert.doesNotMatch(app, /insertAdjacentHTML/);
  assert.doesNotMatch(app, /document\.write/);
});

test("browser parsing is isolated in a module worker", async () => {
  const app = await readFile("web/app.js", "utf8");
  const worker = await readFile("web/worker.js", "utf8");
  assert.match(app, /new Worker\("worker\.js", \{ type: "module" \}\)/);
  assert.match(worker, /diffAnalyses/);
});

test("browser worker failures reject pending work and reset cleanly", async () => {
  const app = await readFile("web/app.js", "utf8");
  assert.match(app, /messageerror/);
  assert.match(app, /rejectPending\(new Error\(message\)\)/);
  assert.match(app, /generation !== state\.generation/);
  assert.match(app, /worker\.terminate\(\)/);
});
