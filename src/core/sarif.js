import {
  BASELINE_FORMAT,
  BASELINE_VERSION,
  SARIF_LENS_VERSION,
  SARIF_VERSION,
  SEVERITIES,
} from "./constants.js";
import { assert, SarifLensError } from "./errors.js";
import { assignFindingIdentity } from "./fingerprint.js";

const CWE_PATTERN = /\bCWE[-_ ]?(\d{1,5})\b/gi;

export function parseJsonInput(input, sourceName = "input") {
  if (typeof input !== "string") {
    assert(input && typeof input === "object" && !Array.isArray(input),
      `${sourceName} must be a JSON object or JSON text.`,
      { code: "INVALID_JSON_INPUT", source: sourceName });
    return input;
  }

  try {
    const parsed = JSON.parse(input);
    assert(parsed && typeof parsed === "object" && !Array.isArray(parsed),
      `${sourceName} must contain a JSON object.`,
      { code: "INVALID_JSON_ROOT", source: sourceName });
    return parsed;
  } catch (error) {
    if (error instanceof SarifLensError) {
      throw error;
    }
    throw new SarifLensError(`Could not parse ${sourceName}: ${error.message}`, {
      code: "INVALID_JSON",
      source: sourceName,
      cause: error,
    });
  }
}

export function loadAnalysis(input, options = {}) {
  const sourceName = options.sourceName ?? "input";
  const value = parseJsonInput(input, sourceName);
  if (value.format === BASELINE_FORMAT) {
    return parseBaseline(value, { sourceName });
  }
  return normalizeSarif(value, { ...options, sourceName });
}

export function normalizeSarif(input, options = {}) {
  const sourceName = options.sourceName ?? "scan.sarif";
  const log = typeof input === "string" ? parseJsonInput(input, sourceName) : input;

  assert(log && typeof log === "object" && !Array.isArray(log),
    `${sourceName} is not a SARIF object.`,
    { code: "INVALID_SARIF", source: sourceName });
  assert(Array.isArray(log.runs),
    `${sourceName} does not contain a SARIF runs array.`,
    { code: "MISSING_RUNS", source: sourceName });

  const warnings = [];
  if (log.version && log.version !== SARIF_VERSION) {
    warnings.push(`Expected SARIF ${SARIF_VERSION}, received ${log.version}.`);
  }
  if (!log.version) {
    warnings.push("The SARIF version field is missing.");
  }

  const findings = [];
  const tools = new Map();
  const normalizedRuns = [];

  log.runs.forEach((run, runIndex) => {
    if (!run || typeof run !== "object") {
      warnings.push(`Run ${runIndex + 1} is not an object and was skipped.`);
      return;
    }

    const driver = run.tool?.driver ?? {};
    const tool = {
      name: cleanString(driver.name) || `Unknown tool ${runIndex + 1}`,
      version: cleanString(driver.semanticVersion) || cleanString(driver.version) || "",
      informationUri: cleanString(driver.informationUri) || "",
      automationId: cleanString(run.automationDetails?.id) || "",
    };
    const normalizedRun = {
      index: runIndex,
      guid: cleanString(run.guid),
      baselineGuid: cleanString(run.baselineGuid),
      automationId: cleanString(run.automationDetails?.id),
      automationGuid: cleanString(run.automationDetails?.guid),
      toolName: tool.name,
      key: buildRunKey(run, tool, runIndex),
    };
    normalizedRuns.push(normalizedRun);
    const toolKey = `${tool.name}\u0000${tool.version}\u0000${tool.automationId}`;
    tools.set(toolKey, tool);

    const ruleMap = buildRuleMap(driver.rules);
    const results = Array.isArray(run.results) ? run.results : [];
    if (!Array.isArray(run.results) && run.results !== undefined) {
      warnings.push(`Run ${runIndex + 1} has a non-array results field.`);
    }

    results.forEach((result, resultIndex) => {
      if (!result || typeof result !== "object") {
        warnings.push(`Result ${resultIndex + 1} in run ${runIndex + 1} was skipped.`);
        return;
      }
      const rule = resolveRule(result, driver.rules, ruleMap);
      findings.push(normalizeResult({
        result,
        rule,
        tool,
        run,
        runIndex,
        resultIndex,
        sourceName,
        normalizedRun,
        stripPrefixes: options.stripPrefixes ?? [],
      }));
    });
  });

  const identified = findings.map(assignFindingIdentity);
  return {
    kind: "sarif",
    sourceName,
    sarifVersion: log.version ?? "unknown",
    findings: identified,
    metadata: {
      runCount: log.runs.length,
      tools: [...tools.values()],
      runs: normalizedRuns,
      findingCount: identified.length,
    },
    warnings,
  };
}

function buildRuleMap(rules) {
  const byId = new Map();
  if (!Array.isArray(rules)) {
    return byId;
  }
  rules.forEach((rule, index) => {
    if (!rule || typeof rule !== "object") {
      return;
    }
    if (rule.id !== undefined) {
      byId.set(String(rule.id), rule);
    }
    byId.set(`@index:${index}`, rule);
  });
  return byId;
}

function resolveRule(result, rules, ruleMap) {
  if (result.ruleId !== undefined && ruleMap.has(String(result.ruleId))) {
    return ruleMap.get(String(result.ruleId));
  }
  if (Number.isInteger(result.ruleIndex) && Array.isArray(rules)) {
    return rules[result.ruleIndex] ?? {};
  }
  return {};
}

function normalizeResult(context) {
  const { result, rule, tool, run, normalizedRun, runIndex, resultIndex, sourceName, stripPrefixes } = context;
  const location = normalizeLocation(result.locations?.[0], run, stripPrefixes);
  const message = resolveMessage(result.message, rule);
  const severity = normalizeSeverity(result, rule);
  const cwes = extractCwes(result, rule);
  const suppressions = normalizeSuppressions(result.suppressions);
  const fingerprints = normalizeFingerprints(result.fingerprints);
  const partialFingerprints = normalizeFingerprints(result.partialFingerprints);

  return {
    id: "",
    tool,
    ruleId: cleanString(result.ruleId) || cleanString(rule.id) || "unknown-rule",
    ruleName: cleanString(rule.name) || cleanString(rule.shortDescription?.text) || "",
    message,
    severity,
    sarifLevel: normalizeSarifLevel(result.level ?? rule.defaultConfiguration?.level),
    cwes,
    helpUri: cleanString(rule.helpUri) || "",
    helpText: cleanString(rule.help?.text) || cleanString(rule.fullDescription?.text) || "",
    uri: location.uri,
    uriBaseId: location.uriBaseId,
    line: location.line,
    column: location.column,
    endLine: location.endLine,
    endColumn: location.endColumn,
    snippet: location.snippet,
    fingerprints,
    partialFingerprints,
    correlationGuid: cleanString(result.correlationGuid),
    suppressed: hasAcceptedSuppression(suppressions),
    suppressions,
    baselineState: normalizeBaselineState(result.baselineState),
    source: {
      name: sourceName,
      runIndex,
      resultIndex,
    },
    run: normalizedRun,
    properties: {
      tags: collectTags(result, rule),
    },
  };
}

function buildRunKey(run, tool, runIndex) {
  return cleanString(run.guid)
    || cleanString(run.automationDetails?.guid)
    || cleanString(run.automationDetails?.id)
    || `${tool.name}:${runIndex}`;
}

function normalizeLocation(location, run, stripPrefixes) {
  const physical = location?.physicalLocation ?? {};
  const artifact = physical.artifactLocation ?? {};
  const region = physical.region ?? {};
  let uri = cleanString(artifact.uri);

  if (!uri && artifact.index !== undefined && Array.isArray(run.artifacts)) {
    uri = cleanString(run.artifacts[artifact.index]?.location?.uri);
  }

  uri = normalizeUri(uri || "(no location)", stripPrefixes);
  return {
    uri,
    uriBaseId: cleanString(artifact.uriBaseId) || "",
    line: positiveInteger(region.startLine),
    column: positiveInteger(region.startColumn),
    endLine: positiveInteger(region.endLine),
    endColumn: positiveInteger(region.endColumn),
    snippet: cleanString(region.snippet?.text),
  };
}

export function normalizeUri(value, stripPrefixes = []) {
  let uri = cleanString(value).replaceAll("\\", "/");
  try {
    uri = decodeURIComponent(uri);
  } catch {
    // Keep malformed percent escapes visible instead of rejecting a complete scan.
  }

  if (/^file:\/\//i.test(uri)) {
    uri = uri.replace(/^file:\/\/+?/i, "");
    if (/^\/[A-Za-z]:\//.test(uri)) {
      uri = uri.slice(1);
    }
  }
  uri = uri.replace(/^\.\//, "").replace(/\/{2,}/g, "/");

  for (const rawPrefix of stripPrefixes) {
    const prefix = cleanString(rawPrefix).replaceAll("\\", "/").replace(/\/$/, "");
    if (!prefix) {
      continue;
    }
    if (uri === prefix) {
      uri = "(root)";
      break;
    }
    if (uri.startsWith(`${prefix}/`)) {
      uri = uri.slice(prefix.length + 1);
      break;
    }
  }

  return uri || "(no location)";
}

function resolveMessage(message, rule) {
  if (!message || typeof message !== "object") {
    return "No message provided";
  }
  let text = cleanString(message.text) || cleanString(message.markdown);
  if (!text && message.id && rule.messageStrings?.[message.id]) {
    const template = rule.messageStrings[message.id];
    text = cleanString(template.text) || cleanString(template.markdown);
  }
  if (!text) {
    return "No message provided";
  }
  if (Array.isArray(message.arguments)) {
    message.arguments.forEach((argument, index) => {
      text = text.replaceAll(`{${index}}`, String(argument));
    });
  }
  return text;
}

function normalizeSeverity(result, rule) {
  const values = [
    result.properties?.["security-severity"],
    result.properties?.securitySeverity,
    result.properties?.severity,
    result.properties?.["problem.severity"],
    rule.properties?.["security-severity"],
    rule.properties?.securitySeverity,
    rule.properties?.severity,
    result.level,
    rule.defaultConfiguration?.level,
  ];

  for (const value of values) {
    const severity = parseSeverity(value);
    if (severity) {
      return severity;
    }
  }
  return "none";
}

function parseSeverity(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return numericSecuritySeverity(value);
  }
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const numeric = Number(trimmed);
  if (Number.isFinite(numeric)) {
    return numericSecuritySeverity(numeric);
  }
  const normalized = trimmed.toLowerCase().replace(/[ _]/g, "-");
  const aliases = {
    critical: "critical",
    "very-high": "critical",
    fatal: "critical",
    high: "high",
    error: "high",
    important: "high",
    medium: "medium",
    moderate: "medium",
    warning: "medium",
    low: "low",
    minor: "low",
    note: "note",
    info: "note",
    informational: "note",
    recommendation: "note",
    none: "none",
    off: "none",
  };
  return aliases[normalized] ?? null;
}

function numericSecuritySeverity(value) {
  if (value >= 9) return "critical";
  if (value >= 7) return "high";
  if (value >= 4) return "medium";
  if (value > 0) return "low";
  return "none";
}

function normalizeSarifLevel(value) {
  const level = cleanString(value).toLowerCase();
  return ["error", "warning", "note", "none"].includes(level) ? level : "none";
}

function normalizeBaselineState(value) {
  const state = cleanString(value).toLowerCase();
  return ["new", "unchanged", "updated", "absent"].includes(state) ? state : "";
}

function extractCwes(result, rule) {
  const candidates = [
    result.properties?.cwe,
    result.properties?.cwes,
    result.properties?.tags,
    rule.properties?.cwe,
    rule.properties?.cwes,
    rule.properties?.tags,
    rule.relationships,
  ];
  const found = new Set();
  for (const candidate of candidates) {
    collectCweValues(candidate, found);
  }
  return [...found].sort((a, b) => Number(a.slice(4)) - Number(b.slice(4)));
}

function collectCweValues(value, found, depth = 0) {
  if (value === null || value === undefined || depth > 4) {
    return;
  }
  if (typeof value === "string" || typeof value === "number") {
    const text = String(value);
    for (const match of text.matchAll(CWE_PATTERN)) {
      found.add(`CWE-${Number(match[1])}`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry) => collectCweValues(entry, found, depth + 1));
    return;
  }
  if (typeof value === "object") {
    Object.values(value).forEach((entry) => collectCweValues(entry, found, depth + 1));
  }
}

function collectTags(result, rule) {
  const values = [result.properties?.tags, rule.properties?.tags];
  const tags = new Set();
  values.forEach((value) => {
    if (Array.isArray(value)) {
      value.forEach((tag) => {
        if (typeof tag === "string" && tag.trim()) tags.add(tag.trim());
      });
    } else if (typeof value === "string" && value.trim()) {
      tags.add(value.trim());
    }
  });
  return [...tags].sort();
}

function normalizeFingerprints(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return Object.fromEntries(Object.entries(value)
    .filter(([key, fingerprint]) => key && typeof fingerprint === "string" && fingerprint)
    .map(([key, fingerprint]) => [key, fingerprint]));
}

function normalizeSuppressions(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((suppression) => suppression && typeof suppression === "object")
    .map((suppression) => ({
      kind: cleanString(suppression.kind) || "external",
      status: cleanString(suppression.status) || "",
      justification: cleanString(suppression.justification) || "",
    }));
}

function hasAcceptedSuppression(suppressions) {
  return suppressions.some((suppression) => suppression.status === "accepted");
}

export function createBaseline(analysis, options = {}) {
  assert(analysis && Array.isArray(analysis.findings),
    "A normalized SARIF analysis is required to create a baseline.",
    { code: "INVALID_ANALYSIS" });
  const createdAt = options.createdAt ?? new Date().toISOString();
  return {
    format: BASELINE_FORMAT,
    version: BASELINE_VERSION,
    createdAt,
    generator: `SARIF Lens ${SARIF_LENS_VERSION}`,
    source: analysis.sourceName ?? "scan.sarif",
    findings: analysis.findings.map(compactFinding),
  };
}

function compactFinding(finding) {
  return {
    id: finding.id,
    tool: finding.tool,
    ruleId: finding.ruleId,
    ruleName: finding.ruleName,
    message: finding.message,
    severity: finding.severity,
    sarifLevel: finding.sarifLevel,
    cwes: finding.cwes,
    helpUri: finding.helpUri,
    uri: finding.uri,
    uriBaseId: finding.uriBaseId,
    line: finding.line,
    column: finding.column,
    endLine: finding.endLine,
    endColumn: finding.endColumn,
    snippet: finding.snippet,
    fingerprints: finding.fingerprints,
    partialFingerprints: finding.partialFingerprints,
    correlationGuid: finding.correlationGuid,
    suppressed: finding.suppressed,
    suppressions: finding.suppressions,
    baselineState: finding.baselineState,
    properties: finding.properties,
    run: finding.run,
  };
}

export function parseBaseline(input, options = {}) {
  const sourceName = options.sourceName ?? "baseline.json";
  const baseline = typeof input === "string" ? parseJsonInput(input, sourceName) : input;
  assert(baseline?.format === BASELINE_FORMAT,
    `${sourceName} is not a SARIF Lens baseline.`,
    { code: "INVALID_BASELINE_FORMAT", source: sourceName });
  assert(baseline.version === BASELINE_VERSION,
    `${sourceName} uses unsupported baseline version ${baseline.version}.`,
    { code: "UNSUPPORTED_BASELINE_VERSION", source: sourceName });
  assert(Array.isArray(baseline.findings),
    `${sourceName} does not contain a findings array.`,
    { code: "INVALID_BASELINE", source: sourceName });

  const warnings = [];
  const findings = baseline.findings.map((finding, index) => {
    assert(finding && typeof finding === "object" && !Array.isArray(finding),
      `${sourceName} finding ${index + 1} is invalid.`,
      { code: "INVALID_BASELINE_FINDING", source: sourceName });
    const suppressions = normalizeSuppressions(finding.suppressions);
    const normalized = {
      ...finding,
      id: cleanString(finding.id),
      tool: {
        name: cleanString(finding.tool?.name) || "Unknown tool",
        version: cleanString(finding.tool?.version),
        informationUri: cleanString(finding.tool?.informationUri),
        automationId: cleanString(finding.tool?.automationId),
      },
      ruleId: cleanString(finding.ruleId) || "unknown-rule",
      ruleName: cleanString(finding.ruleName),
      message: cleanString(finding.message) || "No message provided",
      severity: SEVERITIES.includes(finding.severity) ? finding.severity : "none",
      sarifLevel: normalizeSarifLevel(finding.sarifLevel),
      cwes: Array.isArray(finding.cwes) ? finding.cwes.map(String) : [],
      uri: normalizeUri(finding.uri || "(no location)"),
      uriBaseId: cleanString(finding.uriBaseId),
      line: positiveInteger(finding.line),
      column: positiveInteger(finding.column),
      endLine: positiveInteger(finding.endLine),
      endColumn: positiveInteger(finding.endColumn),
      snippet: cleanString(finding.snippet),
      fingerprints: normalizeFingerprints(finding.fingerprints),
      partialFingerprints: normalizeFingerprints(finding.partialFingerprints),
      correlationGuid: cleanString(finding.correlationGuid),
      suppressed: hasAcceptedSuppression(suppressions),
      suppressions,
      baselineState: normalizeBaselineState(finding.baselineState),
      source: {
        name: sourceName,
        runIndex: Number.isInteger(finding.run?.index) ? finding.run.index : 0,
        resultIndex: index,
      },
      run: normalizeBaselineRun(finding.run, finding.tool, index),
      properties: finding.properties && typeof finding.properties === "object"
        ? finding.properties
        : { tags: [] },
    };
    return assignFindingIdentity(normalized);
  });

  return {
    kind: "baseline",
    sourceName,
    sarifVersion: SARIF_VERSION,
    findings,
    metadata: {
      runCount: 0,
      tools: uniqueTools(findings),
      runs: uniqueRuns(findings),
      findingCount: findings.length,
      createdAt: baseline.createdAt ?? "",
      generator: baseline.generator ?? "",
      originalSource: baseline.source ?? "",
    },
    warnings,
  };
}

function normalizeBaselineRun(run, tool, fallbackIndex) {
  const index = Number.isInteger(run?.index) ? run.index : 0;
  return {
    index,
    guid: cleanString(run?.guid),
    baselineGuid: cleanString(run?.baselineGuid),
    automationId: cleanString(run?.automationId) || cleanString(tool?.automationId),
    automationGuid: cleanString(run?.automationGuid),
    toolName: cleanString(run?.toolName) || cleanString(tool?.name) || "Unknown tool",
    key: cleanString(run?.key) || `${cleanString(tool?.name) || "Unknown tool"}:${index}:${fallbackIndex}`,
  };
}

function uniqueRuns(findings) {
  const runs = new Map();
  findings.forEach(({ run }) => runs.set(run.key, run));
  return [...runs.values()].sort((a, b) => a.index - b.index || a.key.localeCompare(b.key));
}

function uniqueTools(findings) {
  const tools = new Map();
  findings.forEach(({ tool }) => {
    const key = `${tool.name}\u0000${tool.version}\u0000${tool.automationId}`;
    tools.set(key, tool);
  });
  return [...tools.values()];
}

function cleanString(value) {
  return typeof value === "string" ? value.trim() : value === undefined || value === null ? "" : String(value).trim();
}

function positiveInteger(value) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : null;
}
