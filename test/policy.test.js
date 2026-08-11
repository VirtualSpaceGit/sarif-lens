import test from "node:test";
import assert from "node:assert/strict";
import {
  diffAnalyses,
  evaluatePolicy,
  globMatch,
  normalizePolicy,
  normalizeSarif,
  SarifLensError,
} from "../src/index.js";
import { sarifLog } from "./helpers.js";

function newFindingsDiff(results) {
  const currentLog = sarifLog(results);
  results.forEach((result, index) => {
    if (result.suppressions !== undefined) {
      currentLog.runs[0].results[index].suppressions = result.suppressions;
    }
  });
  const current = normalizeSarif(currentLog, { sourceName: "current.sarif" });
  const baseline = {
    kind: "empty",
    sourceName: "baseline.sarif",
    findings: [],
    warnings: [],
    metadata: {
      runs: current.metadata.runs.map((run) => ({ ...run, key: `empty:${run.key}` })),
    },
  };
  return diffAnalyses(baseline, current);
}

test("severity gate fails on new findings at threshold", () => {
  const diff = newFindingsDiff([
    { ruleId: "HIGH", securitySeverity: 8, uri: "src/a.js" },
    { ruleId: "LOW", securitySeverity: 3, uri: "src/b.js" },
  ]);
  const evaluation = evaluatePolicy(diff, { version: 1, failOn: "high" });
  assert.equal(evaluation.pass, false);
  assert.equal(evaluation.violations.filter((entry) => entry.type === "severity").length, 1);
});

test("policy honors path ignores and suppression defaults", () => {
  const diff = newFindingsDiff([
    { ruleId: "TEST-1", securitySeverity: 9, uri: "test/fixture.js" },
    { ruleId: "SUPPRESSED", securitySeverity: 9, uri: "src/a.js", suppressed: true },
  ]);
  const evaluation = evaluatePolicy(diff, {
    version: 1,
    failOn: "critical",
    ignore: [{ rule: "TEST-*", path: "test/**", expires: "2099-01-01", reason: "fixture" }],
  });
  assert.equal(evaluation.pass, true);
  assert.equal(evaluation.ignored.length, 2);
});

test("only accepted suppressions bypass the default gate", () => {
  const cases = [
    { name: "absent suppressions", result: {}, pass: false },
    { name: "absent status", result: { suppressions: [{ kind: "external" }] }, pass: false },
    { name: "under review", result: { suppressions: [{ kind: "external", status: "underReview" }] }, pass: false },
    { name: "rejected", result: { suppressions: [{ kind: "external", status: "rejected" }] }, pass: false },
    { name: "accepted", result: { suppressions: [{ kind: "external", status: "accepted" }] }, pass: true },
  ];

  cases.forEach((entry) => {
    const diff = newFindingsDiff([{
      ruleId: entry.name,
      securitySeverity: 9,
      uri: "src/a.js",
      ...entry.result,
    }]);
    const evaluation = evaluatePolicy(diff, { version: 1, failOn: "critical" });
    assert.equal(evaluation.pass, entry.pass, entry.name);
    assert.equal(evaluation.ignored.length, entry.pass ? 1 : 0, entry.name);
  });
});

test("policy rejects unknown fields and empty ignore matchers", () => {
  const invalidPolicies = [
    { version: 1, failon: "critical" },
    { version: 1, ignore: [{}] },
    { version: 1, ignore: [{ reason: "missing matcher" }] },
    { version: 1, ignore: [{ rul: "RULE" }] },
    { version: 1, ignore: [{ rule: "" }] },
  ];

  invalidPolicies.forEach((policy) => {
    assert.throws(
      () => normalizePolicy(policy),
      (error) => error instanceof SarifLensError && error.code.startsWith("INVALID_POLICY"),
    );
  });
});

test("policy rejects wrong runtime types", () => {
  const invalidPolicies = [
    { version: null },
    { version: "1" },
    { version: 1, $schema: false },
    { version: 1, failOn: true },
    { version: 1, maxNew: "1" },
    { version: 1, maxNewBySeverity: { critical: "0" } },
    { version: 1, includeUpdated: "false" },
    { version: 1, includeSuppressed: 1 },
    { version: 1, denyRules: [1] },
    { version: 1, ignore: [{ rule: 1 }] },
    { version: 1, ignore: [{ rule: "RULE", reason: false }] },
    { version: 1, ignore: [{ rule: "RULE", expires: 1 }] },
  ];

  invalidPolicies.forEach((policy) => assert.throws(() => normalizePolicy(policy), SarifLensError));
});

test("policy preserves all documented version one fields", () => {
  const policy = normalizePolicy({
    $schema: "https://example.invalid/policy.schema.json",
    version: 1,
    failOn: "high",
    maxNew: 3,
    maxNewBySeverity: { critical: 0 },
    includeUpdated: true,
    includeSuppressed: true,
    denyRules: ["DENY-*"],
    ignore: [{
      rule: "RULE-*",
      path: "src/**",
      tool: "Scanner",
      state: "new",
      reason: "fixture",
      expires: "2099-01-01",
    }],
  });

  assert.deepEqual(policy, {
    version: 1,
    failOn: "high",
    maxNew: 3,
    maxNewBySeverity: { critical: 0 },
    includeUpdated: true,
    includeSuppressed: true,
    denyRules: ["DENY-*"],
    ignore: [{
      rule: "RULE-*",
      path: "src/**",
      tool: "Scanner",
      state: "new",
      reason: "fixture",
      expires: "2099-01-01",
    }],
  });
});

test("an omitted ignore path matches nested artifact paths", () => {
  const diff = newFindingsDiff([{ ruleId: "NESTED", securitySeverity: 9, uri: "src/deep/a.js" }]);
  const evaluation = evaluatePolicy(diff, {
    version: 1,
    failOn: "critical",
    ignore: [{ rule: "NESTED", reason: "reviewed" }],
  });
  assert.equal(evaluation.pass, true);
  assert.equal(evaluation.ignored.length, 1);
});

test("expired ignore no longer hides a finding", () => {
  const diff = newFindingsDiff([{ ruleId: "OLD", securitySeverity: 9, uri: "src/a.js" }]);
  const evaluation = evaluatePolicy(diff, {
    version: 1,
    failOn: "critical",
    ignore: [{ rule: "OLD", expires: "2000-01-01" }],
  });
  assert.equal(evaluation.pass, false);
  assert.ok(evaluation.warnings.some((warning) => warning.includes("expired")));
});

test("glob matching distinguishes one segment from recursive paths", () => {
  assert.equal(globMatch("src/deep/file.js", "src/**"), true);
  assert.equal(globMatch("src/deep/file.js", "src/*"), false);
  assert.equal(globMatch("RULE-123", "RULE-*"), true);
});
