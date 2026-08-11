import { appendFile, readFile, stat, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import process from "node:process";
import {
  diffAnalyses,
  evaluatePolicy,
  formatDiff,
  loadAnalysis,
  normalizePolicy,
  parseJsonInput,
  sanitizeHumanText,
} from "./index.js";

const MAX_ANALYSIS_BYTES = 100 * 1024 * 1024;
const MAX_POLICY_BYTES = 1024 * 1024;

export async function runAction(options = {}) {
  const env = options.env ?? process.env;
  const stderr = options.stderr ?? ((value) => process.stderr.write(value));

  try {
    const baselinePath = requiredInput("baseline", env);
    const currentPath = requiredInput("current", env);
    const policyPath = input("policy", env);
    const reportPath = input("report", env) || "sarif-lens-report.md";
    const failOn = input("fail-on", env);
    const maxNew = input("max-new", env);

    const [baselineText, currentText] = await Promise.all([
      readBoundedTextFile(baselinePath, MAX_ANALYSIS_BYTES, "baseline"),
      readBoundedTextFile(currentPath, MAX_ANALYSIS_BYTES, "current SARIF"),
    ]);
    const baseline = loadAnalysis(baselineText, { sourceName: baselinePath });
    const current = loadAnalysis(currentText, { sourceName: currentPath });
    if (current.kind !== "sarif") {
      throw new Error("The current input must be a SARIF log, not a SARIF Lens baseline.");
    }

    const diff = diffAnalyses(baseline, current);
    const filePolicy = policyPath
      ? parseJsonInput(
        await readBoundedTextFile(policyPath, MAX_POLICY_BYTES, "policy"),
        policyPath,
      )
      : {};
    const policy = normalizePolicy({
      ...filePolicy,
      ...(failOn ? { failOn } : {}),
      ...(maxNew ? { maxNew: Number(maxNew) } : {}),
    });
    const evaluation = evaluatePolicy(diff, policy);
    const markdown = formatDiff(diff, { format: "markdown" });
    await writeFile(reportPath, markdown, "utf8");
    if (env.GITHUB_STEP_SUMMARY) {
      await appendFile(env.GITHUB_STEP_SUMMARY, markdown, "utf8");
    }
    await setOutput("passed", String(evaluation.pass), env);
    await setOutput("new", String(diff.summary.new), env);
    await setOutput("updated", String(diff.summary.updated), env);
    await setOutput("fixed", String(diff.summary.fixed), env);
    await setOutput("report", reportPath, env);

    [...baseline.warnings, ...current.warnings, ...diff.warnings, ...evaluation.warnings]
      .forEach((warning) => stderr(`warning: ${sanitizeHumanText(warning)}\n`));

    if (!evaluation.pass) {
      evaluation.violations.forEach((violation) => {
        stderr(`gate: ${sanitizeHumanText(violation.message)}\n`);
      });
      return 1;
    }
    return 0;
  } catch (error) {
    stderr(`SARIF Lens action failed: ${sanitizeHumanText(error?.message ?? String(error))}\n`);
    return 2;
  }
}

function input(name, env) {
  return String(env[`INPUT_${name.replaceAll("-", "_").toUpperCase()}`] ?? "").trim();
}

function requiredInput(name, env) {
  const value = input(name, env);
  if (!value) throw new Error(`Missing required input: ${name}`);
  return value;
}

async function readBoundedTextFile(path, maxBytes, label) {
  let fileStat;
  try {
    fileStat = await stat(path);
  } catch (error) {
    throw new Error(`Cannot read ${label} file ${path}: ${error.message}`, { cause: error });
  }
  if (!fileStat.isFile()) {
    throw new Error(`${label} path ${path} is not a regular file.`);
  }
  if (fileStat.size > maxBytes) {
    throw new Error(`${label} file ${path} exceeds the ${formatByteLimit(maxBytes)} input limit.`);
  }

  let data;
  try {
    data = await readFile(path);
  } catch (error) {
    throw new Error(`Cannot read ${label} file ${path}: ${error.message}`, { cause: error });
  }
  if (data.byteLength > maxBytes) {
    throw new Error(`${label} file ${path} exceeds the ${formatByteLimit(maxBytes)} input limit.`);
  }
  return data.toString("utf8");
}

function formatByteLimit(bytes) {
  return bytes % (1024 * 1024) === 0
    ? `${bytes / (1024 * 1024)} MiB`
    : `${bytes} bytes`;
}

async function setOutput(name, value, env) {
  if (!env.GITHUB_OUTPUT) return;
  const text = String(value);
  let delimiter = "SARIF_LENS_OUTPUT";
  while (text.includes(delimiter)) delimiter += "_X";
  await appendFile(env.GITHUB_OUTPUT, `${name}<<${delimiter}\n${text}\n${delimiter}\n`, "utf8");
}

const isMain = process.argv[1]
  && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMain) {
  process.exitCode = await runAction();
}
