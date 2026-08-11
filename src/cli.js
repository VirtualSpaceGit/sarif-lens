import { readFile, stat, writeFile } from "node:fs/promises";
import process from "node:process";
import {
  createBaseline,
  diffAnalyses,
  evaluatePolicy,
  formatDiff,
  formatInspection,
  loadAnalysis,
  normalizePolicy,
  parseJsonInput,
  SARIF_LENS_VERSION,
  sanitizeHumanText,
  SarifLensError,
} from "./index.js";

const MAX_INPUT_BYTES = 100 * 1024 * 1024;
const COMMAND_FORMATS = Object.freeze({
  inspect: Object.freeze(["text", "table", "markdown", "md", "json"]),
  baseline: Object.freeze(["json"]),
  diff: Object.freeze(["text", "table", "markdown", "md", "json", "csv", "sarif"]),
  gate: Object.freeze(["text", "table", "markdown", "md", "json", "csv", "sarif"]),
});

export async function runCli(argv, io = defaultIo()) {
  let parsed = { command: "", positionals: [], options: {} };
  try {
    parsed = parseArguments(argv);
    if (parsed.command === "help") {
      io.stdout(helpText());
      return 0;
    }
    if (parsed.command === "version") {
      io.stdout(`${SARIF_LENS_VERSION}\n`);
      return 0;
    }
    if (parsed.command === "inspect") return await runInspect(parsed, io);
    if (parsed.command === "baseline") return await runBaseline(parsed, io);
    if (parsed.command === "diff") return await runDiff(parsed, io, false);
    if (parsed.command === "gate") return await runDiff(parsed, io, true);
    throw usageError(`Unknown command: ${parsed.command}`);
  } catch (error) {
    if (error instanceof SarifLensError || error?.code === "CLI_USAGE") {
      io.stderr(`error: ${sanitizeHumanText(error.message)}\n`);
      return 2;
    }
    io.stderr(`internal error: ${sanitizeHumanText(error?.message ?? String(error))}\n`);
    if (parsed.options.verbose && error?.stack) {
      io.stderr(`${sanitizeMultiline(error.stack)}\n`);
    }
    return 3;
  }
}

async function runInspect(parsed, io) {
  requirePositionals(parsed, 1, "inspect requires a SARIF file.");
  const format = outputFormat(parsed, "inspect", "text");
  const inputPath = parsed.positionals[0];
  const analysis = await readAnalysis(inputPath, parsed.options);
  analysis.warnings.forEach((warning) => io.stderr(`warning: ${sanitizeHumanText(warning)}\n`));
  const output = formatInspection(analysis, {
    format,
    color: shouldUseColor(parsed.options, io),
  });
  await emitOutput(output, parsed.options.output, io);
  return 0;
}

async function runBaseline(parsed, io) {
  requirePositionals(parsed, 1, "baseline requires a SARIF file.");
  outputFormat(parsed, "baseline", "json");
  const inputPath = parsed.positionals[0];
  const analysis = await readAnalysis(inputPath, parsed.options);
  if (analysis.kind !== "sarif") {
    throw usageError("baseline input must be a SARIF log, not an existing baseline.");
  }
  const baseline = createBaseline(analysis);
  const output = `${JSON.stringify(baseline, null, 2)}\n`;
  await emitOutput(output, parsed.options.output, io);
  return 0;
}

async function runDiff(parsed, io, forceGate) {
  requirePositionals(parsed, 2, `${parsed.command} requires BASELINE and CURRENT files.`);
  const format = outputFormat(parsed, parsed.command, "text");
  const [baselinePath, currentPath] = parsed.positionals;
  const [baseline, current] = await Promise.all([
    readAnalysis(baselinePath, parsed.options),
    readAnalysis(currentPath, parsed.options),
  ]);
  if (current.kind !== "sarif") {
    throw usageError("The current input must be a SARIF log.");
  }

  const diff = diffAnalyses(baseline, current);
  const output = formatDiff(diff, {
    format,
    color: shouldUseColor(parsed.options, io),
    states: parsed.options.states,
    severities: parsed.options.severities,
    search: parsed.options.search,
  });
  await emitOutput(output, parsed.options.output, io);
  diff.warnings.forEach((warning) => io.stderr(`warning: ${sanitizeHumanText(warning)}\n`));

  const hasGateOptions = forceGate
    || parsed.options.policy
    || parsed.options.failOn !== undefined
    || parsed.options.maxNew !== undefined;
  if (!hasGateOptions) return 0;

  const filePolicy = parsed.options.policy
    ? parseJsonInput(await readTextFile(parsed.options.policy), parsed.options.policy)
    : {};
  const policy = normalizePolicy({
    ...filePolicy,
    ...(parsed.options.failOn !== undefined ? { failOn: parsed.options.failOn } : {}),
    ...(parsed.options.maxNew !== undefined ? { maxNew: Number(parsed.options.maxNew) } : {}),
    ...(parsed.options.includeUpdated ? { includeUpdated: true } : {}),
    ...(parsed.options.includeSuppressed ? { includeSuppressed: true } : {}),
  });
  const evaluation = evaluatePolicy(diff, policy);
  evaluation.warnings.forEach((warning) => io.stderr(`warning: ${sanitizeHumanText(warning)}\n`));
  if (!evaluation.pass) {
    io.stderr(`gate failed with ${evaluation.violations.length} violation(s):\n`);
    evaluation.violations.forEach((violation) => io.stderr(`  - ${sanitizeHumanText(violation.message)}\n`));
    return 1;
  }
  io.stderr(`gate passed: ${evaluation.considered.length} finding(s) considered.\n`);
  return 0;
}

async function readAnalysis(path, options) {
  const text = await readTextFile(path);
  return loadAnalysis(text, {
    sourceName: path === "-" ? "stdin" : path,
    stripPrefixes: options.stripPrefixes ?? [],
  });
}

async function readTextFile(path) {
  if (path === "-") {
    return readStdin();
  }
  let fileStat;
  try {
    fileStat = await stat(path);
  } catch (error) {
    throw new SarifLensError(`Cannot read ${path}: ${error.message}`, {
      code: "INPUT_NOT_FOUND",
      source: path,
      cause: error,
    });
  }
  if (!fileStat.isFile()) {
    throw new SarifLensError(`${path} is not a regular file.`, {
      code: "INVALID_INPUT_FILE",
      source: path,
    });
  }
  if (fileStat.size > MAX_INPUT_BYTES) {
    throw new SarifLensError(`${path} exceeds the 100 MiB CLI input limit.`, {
      code: "INPUT_TOO_LARGE",
      source: path,
    });
  }
  return readFile(path, "utf8");
}

async function readStdin() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_INPUT_BYTES) {
      throw new SarifLensError("stdin exceeds the 100 MiB CLI input limit.", {
        code: "INPUT_TOO_LARGE",
        source: "stdin",
      });
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function emitOutput(content, outputPath, io) {
  if (outputPath && outputPath !== "-") {
    await writeFile(outputPath, content, "utf8");
    io.stderr(`wrote ${sanitizeHumanText(outputPath)}\n`);
    return;
  }
  io.stdout(content);
}

function parseArguments(argv) {
  const args = [...argv];
  if (args.length === 0 || args[0] === "help" || args.includes("--help") || args.includes("-h")) {
    return { command: "help", positionals: [], options: {} };
  }
  if (args[0] === "--version" || args[0] === "-v" || args[0] === "version") {
    return { command: "version", positionals: [], options: {} };
  }

  const command = args.shift();
  const positionals = [];
  const options = { stripPrefixes: [] };
  const valueFlags = new Map([
    ["--format", "format"],
    ["-f", "format"],
    ["--output", "output"],
    ["-o", "output"],
    ["--policy", "policy"],
    ["--fail-on", "failOn"],
    ["--max-new", "maxNew"],
    ["--state", "states"],
    ["--severity", "severities"],
    ["--search", "search"],
    ["--strip-prefix", "stripPrefix"],
  ]);
  const booleanFlags = new Map([
    ["--no-color", ["color", false]],
    ["--color", ["color", true]],
    ["--include-updated", ["includeUpdated", true]],
    ["--include-suppressed", ["includeSuppressed", true]],
    ["--verbose", ["verbose", true]],
  ]);

  while (args.length) {
    const token = args.shift();
    if (token === "--") {
      positionals.push(...args);
      break;
    }
    if (booleanFlags.has(token)) {
      const [key, value] = booleanFlags.get(token);
      options[key] = value;
      continue;
    }
    const [flag, inlineValue] = token.startsWith("--") && token.includes("=")
      ? token.split(/=(.*)/s, 2)
      : [token, undefined];
    if (valueFlags.has(flag)) {
      const value = inlineValue ?? args.shift();
      if (value === undefined || value === "") throw usageError(`${flag} requires a value.`);
      const key = valueFlags.get(flag);
      if (key === "stripPrefix") options.stripPrefixes.push(value);
      else options[key] = value;
      continue;
    }
    if (token.startsWith("-")) throw usageError(`Unknown option: ${token}`);
    positionals.push(token);
  }
  return { command, positionals, options };
}

function requirePositionals(parsed, count, message) {
  if (parsed.positionals.length !== count) {
    throw usageError(message);
  }
}

function outputFormat(parsed, command, fallback) {
  const rawFormat = parsed.options.format;
  if (rawFormat === undefined) return fallback;
  const format = String(rawFormat).trim().toLowerCase();
  const supported = COMMAND_FORMATS[command] ?? [];
  if (!supported.includes(format)) {
    const displayed = [...new Set(supported.map((entry) => entry === "table" ? "text" : entry === "md" ? "markdown" : entry))];
    throw usageError(
      `Unsupported ${command} output format: ${rawFormat}. Supported formats: ${displayed.join(", ")}.`,
    );
  }
  return format;
}

function usageError(message) {
  const error = new Error(message);
  error.code = "CLI_USAGE";
  return error;
}

function shouldUseColor(options, io) {
  if (options.color !== undefined) return options.color;
  return Boolean(io.isTTY) && !process.env.NO_COLOR;
}

function sanitizeMultiline(value) {
  return String(value ?? "")
    .split(/\r?\n/)
    .map((line) => sanitizeHumanText(line))
    .join("\n");
}

function defaultIo() {
  return {
    stdout: (value) => process.stdout.write(value),
    stderr: (value) => process.stderr.write(value),
    isTTY: process.stdout.isTTY,
  };
}

export function helpText() {
  return `SARIF Lens ${SARIF_LENS_VERSION}

Inspect and compare SARIF locally.

Usage:
  sarif-lens inspect CURRENT [options]
  sarif-lens baseline CURRENT -o baseline.json
  sarif-lens diff BASELINE CURRENT [options]
  sarif-lens gate BASELINE CURRENT --policy policy.json [options]

Commands:
  inspect    Summarize one SARIF 2.1.0 log.
  baseline   Create a compact, reviewable baseline snapshot.
  diff       Classify findings as new, updated, fixed, or unchanged.
  gate       Diff two scans and apply a versioned JSON policy.

Options:
  -f, --format FORMAT       Select a command-supported output format
  -o, --output PATH         Write output to a file instead of stdout
      --policy PATH         Read gate policy from JSON
      --fail-on SEVERITY    Fail on new findings at or above a severity
      --max-new COUNT       Maximum considered new findings
      --include-updated     Include updated findings in policy evaluation
      --include-suppressed  Include SARIF-suppressed findings in policy evaluation
      --state LIST          Filter output by comma-separated states
      --severity LIST       Filter output by comma-separated severities
      --search TEXT         Filter output by rule, path, CWE, tool, or message
      --strip-prefix PATH   Remove a stable path prefix before matching, repeatable
      --no-color            Disable ANSI colors
  -h, --help                Show this help
  -v, --version             Show the version

Formats:
  inspect                   text, markdown, or json
  baseline                  json
  diff and gate             text, markdown, json, csv, or sarif

Exit codes:
  0  Success or gate passed
  1  Gate failed
  2  Invalid input, arguments, or policy
  3  Internal failure
`;
}
