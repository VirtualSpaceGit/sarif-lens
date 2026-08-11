import test from "node:test";
import assert from "node:assert/strict";
import {
  createBaseline,
  loadAnalysis,
  normalizeSarif,
  normalizeUri,
  parseBaseline,
  SarifLensError,
} from "../src/index.js";
import { sarifLog } from "./helpers.js";

test("normalizes security severity, CWE, paths, and source metadata", () => {
  const log = sarifLog([{
    ruleId: "RULE-1",
    securitySeverity: 9.4,
    cwe: "CWE-89",
    uri: ".\\src\\db.py",
    line: 42,
    message: "Raw query",
  }], { guid: "run-guid" });
  const analysis = normalizeSarif(log, { sourceName: "scan.sarif" });
  assert.equal(analysis.findings.length, 1);
  assert.equal(analysis.findings[0].severity, "critical");
  assert.deepEqual(analysis.findings[0].cwes, ["CWE-89"]);
  assert.equal(analysis.findings[0].uri, "src/db.py");
  assert.equal(analysis.findings[0].line, 42);
  assert.equal(analysis.findings[0].run.guid, "run-guid");
  assert.match(analysis.findings[0].id, /^sl1_[0-9a-f]{16}$/);
});

test("result severity overrides rule severity", () => {
  const analysis = normalizeSarif(sarifLog([{
    ruleId: "RULE-2",
    securitySeverity: 8,
    resultSeverity: "3.2",
  }]));
  assert.equal(analysis.findings[0].severity, "low");
});

test("only accepted suppressions mark findings as suppressed", () => {
  const cases = [
    { ruleId: "ACCEPTED", suppressions: [{ kind: "external", status: "accepted" }], expected: true },
    { ruleId: "NO-STATUS", suppressions: [{ kind: "external" }], expected: false },
    { ruleId: "UNDER-REVIEW", suppressions: [{ kind: "external", status: "underReview" }], expected: false },
    { ruleId: "REJECTED", suppressions: [{ kind: "external", status: "rejected" }], expected: false },
    { ruleId: "ABSENT", expected: false },
  ];
  const log = sarifLog(cases);
  cases.forEach((entry, index) => {
    if (entry.suppressions) log.runs[0].results[index].suppressions = entry.suppressions;
  });

  const analysis = normalizeSarif(log);
  assert.deepEqual(
    analysis.findings.map((finding) => [finding.ruleId, finding.suppressed]),
    cases.map((entry) => [entry.ruleId, entry.expected]),
  );
});

test("normalizes file URIs and optional prefixes", () => {
  assert.equal(normalizeUri("file:///C:/agent/work/repo/src/a.js", ["C:/agent/work/repo"]), "src/a.js");
  assert.equal(normalizeUri("./src//a.js"), "src/a.js");
});

test("compact baseline round trips finding identity", () => {
  const analysis = normalizeSarif(sarifLog([{
    ruleId: "RULE-3",
    fingerprint: "stable-value",
    uri: "src/a.js",
  }]), { sourceName: "current.sarif" });
  const baseline = createBaseline(analysis, { createdAt: "2026-08-11T00:00:00.000Z" });
  const restored = parseBaseline(baseline, { sourceName: "baseline.json" });
  assert.equal(restored.kind, "baseline");
  assert.equal(restored.findings[0].id, analysis.findings[0].id);
  assert.deepEqual(restored.findings[0].partialFingerprints, { "context/v1": "stable-value" });
});

test("compact baseline recomputes accepted suppression state", () => {
  const log = sarifLog([
    { ruleId: "ACCEPTED" },
    { ruleId: "REJECTED" },
  ]);
  log.runs[0].results[0].suppressions = [{ kind: "external", status: "accepted" }];
  log.runs[0].results[1].suppressions = [{ kind: "external", status: "rejected" }];
  const baseline = createBaseline(normalizeSarif(log));
  baseline.findings.forEach((finding) => { finding.suppressed = true; });

  const restored = parseBaseline(baseline);
  assert.equal(restored.findings[0].suppressed, true);
  assert.equal(restored.findings[1].suppressed, false);
});

test("loadAnalysis detects compact baseline format", () => {
  const analysis = normalizeSarif(sarifLog([{ ruleId: "RULE-4" }]));
  const text = JSON.stringify(createBaseline(analysis));
  assert.equal(loadAnalysis(text, { sourceName: "base.json" }).kind, "baseline");
});

test("invalid JSON and missing runs produce typed errors", () => {
  assert.throws(() => loadAnalysis("{"), (error) => error instanceof SarifLensError && error.code === "INVALID_JSON");
  assert.throws(() => normalizeSarif({ version: "2.1.0" }), (error) => error instanceof SarifLensError && error.code === "MISSING_RUNS");
});
