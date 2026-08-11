import { SEVERITY_RANK, SEVERITIES } from "./constants.js";
import { assert } from "./errors.js";

const POLICY_FIELDS = new Set([
  "$schema",
  "version",
  "failOn",
  "maxNew",
  "maxNewBySeverity",
  "includeUpdated",
  "includeSuppressed",
  "denyRules",
  "ignore",
]);

const IGNORE_FIELDS = new Set([
  "rule",
  "path",
  "tool",
  "state",
  "reason",
  "expires",
]);

const IGNORE_MATCHER_FIELDS = ["rule", "path", "tool", "state"];

export const DEFAULT_POLICY = Object.freeze({
  version: 1,
  failOn: "none",
  maxNew: null,
  maxNewBySeverity: {},
  includeUpdated: false,
  includeSuppressed: false,
  denyRules: [],
  ignore: [],
});

export function normalizePolicy(value = {}) {
  assert(value && typeof value === "object" && !Array.isArray(value),
    "Policy must be a JSON object.", { code: "INVALID_POLICY" });
  assertAllowedKeys(value, POLICY_FIELDS, "Policy", "INVALID_POLICY_FIELD");
  if (value.$schema !== undefined) {
    assert(typeof value.$schema === "string",
      "$schema must be a string.", { code: "INVALID_POLICY_FIELD" });
  }
  const version = value.version === undefined ? 1 : value.version;
  assert(version === 1, `Unsupported policy version: ${version}.`, { code: "UNSUPPORTED_POLICY_VERSION" });
  if (value.failOn !== undefined) {
    assert(typeof value.failOn === "string",
      "failOn must be a string.", { code: "INVALID_POLICY_FIELD" });
  }
  const failOn = (value.failOn ?? DEFAULT_POLICY.failOn).toLowerCase();
  assert(SEVERITIES.includes(failOn),
    `Unsupported failOn severity: ${failOn}.`, { code: "INVALID_POLICY_SEVERITY" });

  assertOptionalBoolean(value.includeUpdated, "includeUpdated");
  assertOptionalBoolean(value.includeSuppressed, "includeSuppressed");

  const maxNew = nullableNonNegativeInteger(value.maxNew, "maxNew");
  const maxNewBySeverity = {};
  if (value.maxNewBySeverity !== undefined) {
    assert(value.maxNewBySeverity && typeof value.maxNewBySeverity === "object" && !Array.isArray(value.maxNewBySeverity),
      "maxNewBySeverity must be an object.", { code: "INVALID_POLICY_LIMITS" });
    for (const [severity, limit] of Object.entries(value.maxNewBySeverity)) {
      assert(SEVERITIES.includes(severity),
        `Unsupported maxNewBySeverity key: ${severity}.`, { code: "INVALID_POLICY_SEVERITY" });
      maxNewBySeverity[severity] = nullableNonNegativeInteger(limit, `maxNewBySeverity.${severity}`);
    }
  }

  return {
    version,
    failOn,
    maxNew,
    maxNewBySeverity,
    includeUpdated: value.includeUpdated ?? DEFAULT_POLICY.includeUpdated,
    includeSuppressed: value.includeSuppressed ?? DEFAULT_POLICY.includeSuppressed,
    denyRules: normalizeStringArray(value.denyRules, "denyRules"),
    ignore: normalizeIgnoreRules(value.ignore),
  };
}

export function evaluatePolicy(diff, inputPolicy = {}) {
  assert(diff && Array.isArray(diff.items),
    "A SARIF Lens diff is required for policy evaluation.", { code: "INVALID_DIFF" });
  const policy = normalizePolicy(inputPolicy);
  const now = new Date();
  const ignored = [];
  const considered = [];
  const warnings = [];

  for (const item of diff.items) {
    if (item.state !== "new" && !(policy.includeUpdated && item.state === "updated")) {
      continue;
    }
    const finding = item.after ?? item.before;
    if (finding.suppressed && !policy.includeSuppressed) {
      ignored.push({ item, reason: "SARIF suppression" });
      continue;
    }
    const ignore = findMatchingIgnore(policy.ignore, item, now, warnings);
    if (ignore) {
      ignored.push({ item, reason: ignore.reason || "Policy ignore rule" });
      continue;
    }
    considered.push(item);
  }

  const violations = [];
  if (policy.failOn !== "none") {
    const threshold = SEVERITY_RANK[policy.failOn];
    considered.forEach((item) => {
      const finding = item.after ?? item.before;
      if ((SEVERITY_RANK[finding.severity] ?? 0) >= threshold) {
        violations.push({
          type: "severity",
          message: `${item.state} ${finding.severity} finding ${finding.ruleId} meets the ${policy.failOn} threshold.`,
          item,
        });
      }
    });
  }

  for (const pattern of policy.denyRules) {
    considered.forEach((item) => {
      const finding = item.after ?? item.before;
      if (globMatch(finding.ruleId, pattern)) {
        violations.push({
          type: "denied-rule",
          message: `${item.state} finding ${finding.ruleId} matches denied rule ${pattern}.`,
          item,
        });
      }
    });
  }

  if (policy.maxNew !== null && considered.length > policy.maxNew) {
    violations.push({
      type: "max-new",
      message: `${considered.length} considered findings exceed maxNew ${policy.maxNew}.`,
      count: considered.length,
      limit: policy.maxNew,
    });
  }

  for (const [severity, limit] of Object.entries(policy.maxNewBySeverity)) {
    if (limit === null) continue;
    const count = considered.filter((item) => (item.after ?? item.before).severity === severity).length;
    if (count > limit) {
      violations.push({
        type: "max-new-by-severity",
        message: `${count} considered ${severity} findings exceed the limit ${limit}.`,
        severity,
        count,
        limit,
      });
    }
  }

  return {
    pass: violations.length === 0,
    policy,
    considered,
    ignored,
    violations,
    warnings: [...new Set(warnings)],
  };
}

function normalizeStringArray(value, field) {
  if (value === undefined) return [];
  assert(Array.isArray(value) && value.every((entry) => typeof entry === "string" && entry.trim()),
    `${field} must be an array of non-empty strings.`, { code: "INVALID_POLICY_FIELD" });
  return value.map((entry) => entry.trim());
}

function normalizeIgnoreRules(value) {
  if (value === undefined) return [];
  assert(Array.isArray(value), "ignore must be an array.", { code: "INVALID_POLICY_IGNORE" });
  return value.map((entry, index) => {
    assert(entry && typeof entry === "object" && !Array.isArray(entry),
      `ignore[${index}] must be an object.`, { code: "INVALID_POLICY_IGNORE" });
    assertAllowedKeys(entry, IGNORE_FIELDS, `ignore[${index}]`, "INVALID_POLICY_IGNORE");
    const presentMatchers = IGNORE_MATCHER_FIELDS.filter((field) => entry[field] !== undefined);
    assert(presentMatchers.length > 0,
      `ignore[${index}] must include a matcher.`, { code: "INVALID_POLICY_IGNORE" });
    presentMatchers.forEach((field) => {
      assert(typeof entry[field] === "string" && entry[field].trim(),
        `ignore[${index}].${field} must be a non-empty string.`, { code: "INVALID_POLICY_IGNORE" });
    });
    assertOptionalString(entry.reason, `ignore[${index}].reason`, "INVALID_POLICY_IGNORE");
    assertOptionalString(entry.expires, `ignore[${index}].expires`, "INVALID_POLICY_IGNORE");
    const rule = entry.rule === undefined ? "*" : entry.rule.trim();
    const path = entry.path === undefined ? "**" : entry.path.trim();
    const tool = entry.tool === undefined ? "*" : entry.tool.trim();
    const state = entry.state === undefined ? "*" : entry.state.trim();
    return {
      rule,
      path,
      tool,
      state,
      reason: entry.reason === undefined ? "" : entry.reason,
      expires: entry.expires === undefined ? "" : entry.expires,
    };
  });
}

function nullableNonNegativeInteger(value, field) {
  if (value === undefined || value === null) return null;
  assert(typeof value === "number" && Number.isInteger(value) && value >= 0,
    `${field} must be a non-negative integer or null.`, { code: "INVALID_POLICY_LIMIT" });
  return value;
}

function assertAllowedKeys(value, allowed, field, code) {
  for (const key of Object.keys(value)) {
    assert(allowed.has(key),
      `${field} contains unsupported field ${key}.`, { code });
  }
}

function assertOptionalBoolean(value, field) {
  if (value === undefined) return;
  assert(typeof value === "boolean",
    `${field} must be a boolean.`, { code: "INVALID_POLICY_FIELD" });
}

function assertOptionalString(value, field, code) {
  if (value === undefined) return;
  assert(typeof value === "string",
    `${field} must be a string.`, { code });
}

function findMatchingIgnore(rules, item, now, warnings) {
  const finding = item.after ?? item.before;
  for (const rule of rules) {
    if (rule.expires) {
      const expiry = new Date(`${rule.expires}T23:59:59.999Z`);
      if (Number.isNaN(expiry.getTime())) {
        warnings.push(`Ignore rule for ${rule.rule} has invalid expiry ${rule.expires}.`);
        continue;
      }
      if (expiry < now) {
        warnings.push(`Ignore rule for ${rule.rule} expired on ${rule.expires}.`);
        continue;
      }
    }
    if (globMatch(finding.ruleId, rule.rule)
      && globMatch(finding.uri, rule.path)
      && globMatch(finding.tool?.name ?? "", rule.tool)
      && globMatch(item.state, rule.state)) {
      return rule;
    }
  }
  return null;
}

export function globMatch(value, pattern) {
  const input = String(value ?? "").replaceAll("\\", "/");
  const glob = String(pattern ?? "*").replaceAll("\\", "/");
  let expression = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      expression += ".*";
      index += 1;
    } else if (character === "*") {
      expression += "[^/]*";
    } else if (character === "?") {
      expression += "[^/]";
    } else {
      expression += character.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
    }
  }
  expression += "$";
  return new RegExp(expression, "i").test(input);
}
