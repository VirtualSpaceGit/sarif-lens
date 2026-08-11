import { SARIF_LENS_VERSION, SARIF_VERSION, SEVERITY_RANK, STATE_LABELS } from "./constants.js";

const ANSI = {
  reset: "\u001b[0m",
  bold: "\u001b[1m",
  dim: "\u001b[2m",
  red: "\u001b[31m",
  green: "\u001b[32m",
  yellow: "\u001b[33m",
  blue: "\u001b[34m",
  magenta: "\u001b[35m",
  cyan: "\u001b[36m",
};

const CSV_FORMULA_PREFIX = /^[\u0000-\u0020\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u206f\ufeff]*[=+\-@]/u;

export function sanitizeHumanText(value) {
  const input = String(value ?? "");
  let output = "";
  let index = 0;

  while (index < input.length) {
    const codePoint = input.codePointAt(index);
    const width = codePoint > 0xffff ? 2 : 1;

    if (codePoint === 0x1b) {
      const end = consumeEscSequence(input, index);
      if (end > index + 1) {
        index = end;
        continue;
      }
      output += visibleCodePoint(codePoint);
      index += 1;
      continue;
    }

    if (codePoint === 0x9b) {
      index = consumeCsi(input, index + 1);
      continue;
    }
    if (codePoint === 0x90 || codePoint === 0x98 || codePoint === 0x9d
      || codePoint === 0x9e || codePoint === 0x9f) {
      index = consumeControlString(input, index + 1);
      continue;
    }

    if (isC0OrC1(codePoint) || isBidiControl(codePoint)) {
      output += visibleCodePoint(codePoint);
      index += width;
      continue;
    }

    output += String.fromCodePoint(codePoint);
    index += width;
  }

  return output;
}

export function formatDiff(diff, options = {}) {
  const format = String(options.format ?? "text").toLowerCase();
  const filtered = filterDiff(diff, options);
  if (format === "json") return `${JSON.stringify(filtered, null, 2)}\n`;
  if (format === "markdown" || format === "md") return formatMarkdown(filtered, options);
  if (format === "csv") return formatCsv(filtered);
  if (format === "sarif") return `${JSON.stringify(diffToSarif(filtered), null, 2)}\n`;
  if (format === "text" || format === "table") return formatText(filtered, options);
  throw new Error(`Unsupported output format: ${format}`);
}

export function formatInspection(analysis, options = {}) {
  const format = String(options.format ?? "text").toLowerCase();
  const summary = summarizeAnalysis(analysis);
  if (format === "json") {
    return `${JSON.stringify({ sourceName: analysis.sourceName, ...summary, findings: analysis.findings }, null, 2)}\n`;
  }
  if (format === "markdown" || format === "md") {
    const rows = analysis.findings.map((finding) => [
      finding.severity.toUpperCase(),
      `\`${escapeMarkdownCode(finding.ruleId)}\``,
      escapeMarkdown(locationText(finding)),
      escapeMarkdown(finding.message),
    ]);
    return [
      `# SARIF inspection: ${escapeMarkdown(analysis.sourceName)}`,
      "",
      `**Findings:** ${summary.total} | **Tools:** ${summary.tools.length}`,
      "",
      markdownTable(["Severity", "Rule", "Location", "Message"], rows),
      "",
    ].join("\n");
  }
  if (format === "text" || format === "table") {
    const color = options.color !== false;
    const safeTools = summary.tools.map((tool) => sanitizeHumanText(tool));
    const lines = [
      paint("SARIF Lens inspection", "bold", color),
      `${sanitizeHumanText(analysis.sourceName)}: ${summary.total} findings from ${safeTools.join(", ") || "unknown tool"}`,
      severitySummary(summary.bySeverity),
      "",
    ];
    analysis.findings
      .slice()
      .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))
      .forEach((finding) => {
        lines.push(`${severityToken(finding.severity, color)} ${sanitizeHumanText(finding.ruleId)}  ${sanitizeHumanText(locationText(finding))}`);
        lines.push(`  ${sanitizeHumanText(finding.message)}`);
      });
    return `${lines.join("\n")}\n`;
  }
  throw new Error(`Unsupported inspection output format: ${format}`);
}

export function summarizeAnalysis(analysis) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, note: 0, none: 0 };
  const tools = new Set();
  analysis.findings.forEach((finding) => {
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
    tools.add(finding.tool?.name ?? "Unknown tool");
  });
  return { total: analysis.findings.length, bySeverity, tools: [...tools].sort() };
}

export function filterDiff(diff, options = {}) {
  const states = toSet(options.states);
  const severities = toSet(options.severities);
  const search = String(options.search ?? "").toLowerCase().trim();
  const tools = toSet(options.tools);
  const items = diff.items.filter((item) => {
    const finding = item.after ?? item.before;
    if (states.size && !states.has(item.state)) return false;
    if (severities.size && !severities.has(finding.severity)) return false;
    if (tools.size && !tools.has(finding.tool?.name)) return false;
    if (search) {
      const haystack = [finding.ruleId, finding.ruleName, finding.message, finding.uri, finding.cwes.join(" "), finding.tool?.name]
        .join(" ").toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });
  return { ...diff, items, summary: summarizeFiltered(items) };
}

function formatText(diff, options) {
  const color = options.color !== false;
  const lines = [
    paint("SARIF Lens diff", "bold", color),
    `${sanitizeHumanText(diff.baseline.sourceName)}  ->  ${sanitizeHumanText(diff.current.sourceName)}`,
    [
      stateToken("new", diff.summary.new, color),
      stateToken("updated", diff.summary.updated, color),
      stateToken("fixed", diff.summary.fixed, color),
      stateToken("unchanged", diff.summary.unchanged, color),
    ].join("  "),
    "",
  ];

  if (diff.items.length === 0) {
    lines.push("No findings match the selected filters.");
  }

  diff.items.forEach((item) => {
    const finding = item.after ?? item.before;
    lines.push(`${stateSymbol(item.state, color)} ${severityToken(finding.severity, color)} ${sanitizeHumanText(finding.ruleId)}`);
    lines.push(`  ${sanitizeHumanText(locationText(finding))}  ${sanitizeHumanText(finding.message)}`);
    if (item.state === "updated" && item.changes.significant.length) {
      const changes = item.changes.significant.map((change) => sanitizeHumanText(change.field)).join(", ");
      lines.push(paint(`  changed: ${changes}`, "dim", color));
    }
  });

  if (diff.warnings.length) {
    lines.push("", paint(`Warnings: ${diff.warnings.length}`, "yellow", color));
  }
  return `${lines.join("\n")}\n`;
}

function formatMarkdown(diff) {
  const rows = diff.items.map((item) => {
    const finding = item.after ?? item.before;
    return [
      STATE_LABELS[item.state],
      finding.severity.toUpperCase(),
      `\`${escapeMarkdownCode(finding.ruleId)}\``,
      escapeMarkdown(locationText(finding)),
      escapeMarkdown(finding.message),
    ];
  });
  return [
    "# SARIF Lens diff",
    "",
    `Baseline: \`${escapeMarkdownCode(diff.baseline.sourceName)}\`  `,
    `Current: \`${escapeMarkdownCode(diff.current.sourceName)}\``,
    "",
    `**New:** ${diff.summary.new} | **Updated:** ${diff.summary.updated} | **Fixed:** ${diff.summary.fixed} | **Unchanged:** ${diff.summary.unchanged}`,
    "",
    markdownTable(["State", "Severity", "Rule", "Location", "Message"], rows),
    "",
    "Generated locally with [SARIF Lens](https://github.com/VirtualSpaceGit/sarif-lens).",
    "",
  ].join("\n");
}

function formatCsv(diff) {
  const rows = [["state", "severity", "tool", "rule_id", "cwe", "path", "line", "message", "match_strategy"]];
  diff.items.forEach((item) => {
    const finding = item.after ?? item.before;
    rows.push([
      item.state,
      finding.severity,
      finding.tool?.name ?? "",
      finding.ruleId,
      finding.cwes.join(" "),
      finding.uri,
      finding.line ?? "",
      finding.message,
      item.match?.strategy ?? "",
    ]);
  });
  return `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`;
}

export function diffToSarif(diff) {
  const rules = new Map();
  const results = diff.items.map((item) => {
    const finding = item.after ?? item.before;
    const originalTool = sanitizeHumanText(finding.tool?.name ?? "Unknown tool");
    const originalRuleId = sanitizeHumanText(finding.ruleId);
    const prefixedRule = `${slug(originalTool || "tool")}:${originalRuleId}`;
    if (!rules.has(prefixedRule)) {
      rules.set(prefixedRule, {
        id: prefixedRule,
        name: sanitizeHumanText(finding.ruleName || finding.ruleId),
        shortDescription: { text: sanitizeHumanText(finding.ruleName || finding.ruleId) },
        helpUri: finding.helpUri || undefined,
        properties: {
          originalTool,
          originalRuleId,
          tags: finding.cwes,
        },
      });
    }
    const physicalLocation = finding.uri === "(no location)" ? null : {
      artifactLocation: { uri: sanitizeHumanText(finding.uri) },
      ...(finding.line ? {
        region: {
          startLine: finding.line,
          startColumn: finding.column ?? undefined,
          endLine: finding.endLine ?? undefined,
          endColumn: finding.endColumn ?? undefined,
          snippet: finding.snippet ? { text: sanitizeHumanText(finding.snippet) } : undefined,
        },
      } : {}),
    };
    return {
      ruleId: prefixedRule,
      level: severityToSarifLevel(finding.severity),
      baselineState: item.state === "fixed" ? "absent" : item.state,
      message: { text: sanitizeHumanText(finding.message) },
      locations: physicalLocation ? [{ physicalLocation }] : [],
      partialFingerprints: { "sarifLensId/v1": finding.id },
      properties: {
        sarifLensState: item.state,
        severity: finding.severity,
        cwe: finding.cwes,
        originalTool,
        originalRuleId,
        matchStrategy: item.match?.strategy ?? "",
      },
    };
  });
  return {
    version: SARIF_VERSION,
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "SARIF Lens",
          semanticVersion: SARIF_LENS_VERSION,
          informationUri: "https://github.com/VirtualSpaceGit/sarif-lens",
          rules: [...rules.values()],
        },
      },
      automationDetails: { id: "sarif-lens/diff/" },
      results,
    }],
  };
}

function summarizeFiltered(items) {
  const summary = {
    total: items.length,
    new: 0,
    updated: 0,
    fixed: 0,
    unchanged: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, note: 0, none: 0 },
    newBySeverity: { critical: 0, high: 0, medium: 0, low: 0, note: 0, none: 0 },
    suppressed: 0,
  };
  items.forEach((item) => {
    const finding = item.after ?? item.before;
    summary[item.state] += 1;
    summary.bySeverity[finding.severity] += 1;
    if (item.state === "new") summary.newBySeverity[finding.severity] += 1;
    if (finding.suppressed) summary.suppressed += 1;
  });
  return summary;
}

function markdownTable(headers, rows) {
  const safeRows = rows.length ? rows : [["None", "", "", "", ""]];
  return [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...safeRows.map((row) => `| ${row.join(" | ")} |`),
  ].join("\n");
}

function escapeMarkdown(value) {
  return sanitizeHumanText(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("`", "&#96;")
    .replace(/([\\*_{}\[\]()#+\-.!|~])/g, "\\$1");
}

function escapeMarkdownCode(value) {
  return sanitizeHumanText(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("`", "&#96;")
    .replaceAll("|", "&#124;");
}

function csvCell(value) {
  const raw = String(value ?? "");
  let text = sanitizeHumanText(raw);
  if (CSV_FORMULA_PREFIX.test(raw) || /^[ ]*[=+\-@]/.test(text)) {
    text = `'${text}`;
  }
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function locationText(finding) {
  return finding.line ? `${finding.uri}:${finding.line}` : finding.uri;
}

function severitySummary(bySeverity) {
  return ["critical", "high", "medium", "low", "note", "none"]
    .filter((severity) => bySeverity[severity])
    .map((severity) => `${severity} ${bySeverity[severity]}`)
    .join(" | ") || "no findings";
}

function stateToken(state, count, color) {
  const palette = { new: "red", updated: "yellow", fixed: "green", unchanged: "dim" };
  return paint(`${STATE_LABELS[state]} ${count}`, palette[state], color);
}

function stateSymbol(state, color) {
  const symbol = { new: "+", updated: "~", fixed: "-", unchanged: "=" }[state];
  const palette = { new: "red", updated: "yellow", fixed: "green", unchanged: "dim" };
  return paint(symbol, palette[state], color);
}

function severityToken(severity, color) {
  const palette = { critical: "magenta", high: "red", medium: "yellow", low: "blue", note: "cyan", none: "dim" };
  return paint(severity.toUpperCase().padEnd(8), palette[severity] ?? "dim", color);
}

function paint(value, style, enabled) {
  return enabled && ANSI[style] ? `${ANSI[style]}${value}${ANSI.reset}` : value;
}

function consumeEscSequence(input, start) {
  if (start + 1 >= input.length) return start + 1;
  const next = input.charCodeAt(start + 1);
  if (next === 0x5b) return consumeCsi(input, start + 2);
  if (next === 0x5d || next === 0x50 || next === 0x58 || next === 0x5e || next === 0x5f) {
    return consumeControlString(input, start + 2);
  }

  let index = start + 1;
  while (index < input.length && input.charCodeAt(index) >= 0x20 && input.charCodeAt(index) <= 0x2f) {
    index += 1;
  }
  const final = input.charCodeAt(index);
  return final >= 0x30 && final <= 0x7e ? index + 1 : start + 1;
}

function consumeCsi(input, start) {
  for (let index = start; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    if (code >= 0x40 && code <= 0x7e) return index + 1;
  }
  return input.length;
}

function consumeControlString(input, start) {
  for (let index = start; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    if (code === 0x07 || code === 0x9c) return index + 1;
    if (code === 0x1b && input.charCodeAt(index + 1) === 0x5c) return index + 2;
  }
  return input.length;
}

function isC0OrC1(codePoint) {
  return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
}

function isBidiControl(codePoint) {
  return codePoint === 0x061c
    || codePoint === 0x200e
    || codePoint === 0x200f
    || (codePoint >= 0x202a && codePoint <= 0x202e)
    || (codePoint >= 0x2066 && codePoint <= 0x206f)
    || codePoint === 0xfeff;
}

function visibleCodePoint(codePoint) {
  return codePoint <= 0xffff
    ? `\\u${codePoint.toString(16).toUpperCase().padStart(4, "0")}`
    : `\\u{${codePoint.toString(16).toUpperCase()}}`;
}

function severityToSarifLevel(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  if (severity === "low" || severity === "note") return "note";
  return "none";
}

function slug(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "tool";
}

function toSet(value) {
  if (!value) return new Set();
  if (value instanceof Set) return value;
  if (Array.isArray(value)) return new Set(value);
  return new Set(String(value).split(",").map((entry) => entry.trim()).filter(Boolean));
}
