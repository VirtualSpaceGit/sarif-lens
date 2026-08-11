import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { spawnSync } from "node:child_process";
import process from "node:process";

const ROOT = process.cwd();
const SKIP = new Set([".git", "node_modules", "coverage"]);
const TEXT_EXTENSIONS = new Set([
  ".js", ".json", ".md", ".html", ".css", ".yml", ".yaml", ".svg",
  ".txt", ".sarif", ".cff", ".gitignore", ".editorconfig",
]);
const errors = [];
const files = await walk(ROOT);

for (const file of files) {
  const name = relative(ROOT, file).replaceAll("\\", "/");
  const extension = extname(file).toLowerCase();
  if (!TEXT_EXTENSIONS.has(extension) && !["LICENSE", ".gitignore", ".editorconfig"].includes(name)) {
    continue;
  }
  const text = await readFile(file, "utf8");
  if (text.includes("\u2014")) errors.push(`${name}: contains an em dash`);
  if (/\r(?!\n)/.test(text)) errors.push(`${name}: contains a bare carriage return`);
  const lines = text.split(/\r?\n/);
  lines.forEach((line, index) => {
    if (/[ \t]+$/.test(line)) errors.push(`${name}:${index + 1}: trailing whitespace`);
  });
  if (extension === ".json" || extension === ".sarif") {
    try {
      JSON.parse(text);
    } catch (error) {
      errors.push(`${name}: invalid JSON: ${error.message}`);
    }
  }
  if (extension === ".js") {
    const checked = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
    if (checked.status !== 0) errors.push(`${name}: JavaScript syntax check failed\n${checked.stderr.trim()}`);
  }
}

const packageJson = JSON.parse(await readFile(join(ROOT, "package.json"), "utf8"));
const constants = await readFile(join(ROOT, "src", "core", "constants.js"), "utf8");
if (!constants.includes(`SARIF_LENS_VERSION = "${packageJson.version}"`)) {
  errors.push("package.json and SARIF_LENS_VERSION disagree");
}
if (packageJson.dependencies && Object.keys(packageJson.dependencies).length) {
  errors.push("Runtime dependencies must remain empty");
}
const webApp = await readFile(join(ROOT, "web", "app.js"), "utf8");
for (const sink of ["innerHTML", "insertAdjacentHTML", "document.write"]) {
  if (webApp.includes(sink)) errors.push(`web/app.js contains forbidden rendering sink ${sink}`);
}

if (errors.length) {
  process.stderr.write(`${errors.join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Checked ${files.length} files. No lint violations found.\n`);
}

async function walk(directory) {
  const output = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (SKIP.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(path));
    else if (entry.isFile()) output.push(path);
  }
  return output;
}

