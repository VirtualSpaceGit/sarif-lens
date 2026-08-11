import test from "node:test";
import assert from "node:assert/strict";
import { diffAnalyses, normalizeSarif } from "../src/index.js";
import { sarifLog } from "./helpers.js";

function analysis(log, name) {
  return normalizeSarif(log, { sourceName: name });
}

test("classifies moved, updated, fixed, and new instances", () => {
  const baselineGuid = "11111111-1111-4111-8111-111111111111";
  const baseline = analysis(sarifLog([
    { ruleId: "MOVE", correlationGuid: "a", uri: "src/a.js", line: 2, message: "same" },
    { ruleId: "UPDATE", correlationGuid: "b", uri: "src/b.js", line: 4, message: "before" },
    { ruleId: "FIXED", correlationGuid: "c", uri: "src/c.js", line: 6 },
  ], { automationGuid: baselineGuid }), "baseline.sarif");
  const current = analysis(sarifLog([
    { ruleId: "MOVE", correlationGuid: "a", uri: "src/a.js", line: 20, message: "same" },
    { ruleId: "UPDATE", correlationGuid: "b", uri: "src/b.js", line: 4, message: "after" },
    { ruleId: "NEW", correlationGuid: "d", uri: "src/d.js", line: 8 },
  ], { baselineGuid }), "current.sarif");
  const diff = diffAnalyses(baseline, current);
  assert.deepEqual(
    { new: diff.summary.new, updated: diff.summary.updated, fixed: diff.summary.fixed, unchanged: diff.summary.unchanged },
    { new: 1, updated: 1, fixed: 1, unchanged: 1 },
  );
  const moved = diff.items.find((item) => (item.after ?? item.before).ruleId === "MOVE");
  assert.equal(moved.state, "unchanged");
  assert.deepEqual(moved.changes.movement.map((change) => change.field), ["line"]);
  assert.equal(moved.match.strategy, "correlation-guid");
  assert.equal(moved.match.runPairStrategy, "baseline-guid");
});

test("detects same-count churn instead of comparing aggregate counts", () => {
  const baseline = analysis(sarifLog([{ ruleId: "RULE", uri: "src/old.js", message: "same message" }]), "old.sarif");
  const current = analysis(sarifLog([{ ruleId: "RULE", uri: "src/new.js", message: "same message" }]), "new.sarif");
  const diff = diffAnalyses(baseline, current);
  assert.equal(diff.summary.new, 1);
  assert.equal(diff.summary.fixed, 1);
  assert.equal(diff.summary.unchanged, 0);
});

test("refuses duplicate fingerprint candidates rather than guessing", () => {
  const baseline = analysis(sarifLog([{
    ruleId: "DUP",
    uri: "src/a.js",
    fingerprint: "duplicate",
    message: "baseline",
  }]), "old.sarif");
  const current = analysis(sarifLog([
    { ruleId: "DUP", uri: "src/b.js", fingerprint: "duplicate", message: "one" },
    { ruleId: "DUP", uri: "src/c.js", fingerprint: "duplicate", message: "two" },
  ]), "new.sarif");
  const diff = diffAnalyses(baseline, current);
  assert.equal(diff.summary.fixed, 1);
  assert.equal(diff.summary.new, 2);
  assert.ok(diff.warnings.some((warning) => warning.includes("Refused ambiguous partial-fingerprint match")));
});

test("refuses a reverse duplicate fingerprint collision rather than consuming the current result", () => {
  const baseline = analysis(sarifLog([
    { ruleId: "DUP", uri: "src/a.js", fingerprint: "duplicate", message: "baseline one" },
    { ruleId: "DUP", uri: "src/b.js", fingerprint: "duplicate", message: "baseline two" },
  ]), "old.sarif");
  const current = analysis(sarifLog([
    { ruleId: "DUP", uri: "src/c.js", fingerprint: "duplicate", message: "current" },
  ]), "new.sarif");
  const diff = diffAnalyses(baseline, current);
  assert.equal(diff.summary.fixed, 2);
  assert.equal(diff.summary.new, 1);
  assert.equal(diff.summary.unchanged, 0);
  assert.ok(diff.warnings.some((warning) => warning.includes("2 baseline candidates")));
});

test("refuses a many-to-many duplicate fingerprint collision", () => {
  const baseline = analysis(sarifLog([
    { ruleId: "DUP", uri: "src/a.js", fingerprint: "duplicate", message: "baseline one" },
    { ruleId: "DUP", uri: "src/b.js", fingerprint: "duplicate", message: "baseline two" },
  ]), "old.sarif");
  const current = analysis(sarifLog([
    { ruleId: "DUP", uri: "src/c.js", fingerprint: "duplicate", message: "current one" },
    { ruleId: "DUP", uri: "src/d.js", fingerprint: "duplicate", message: "current two" },
  ]), "new.sarif");
  const diff = diffAnalyses(baseline, current);
  assert.equal(diff.summary.fixed, 2);
  assert.equal(diff.summary.new, 2);
  assert.equal(diff.summary.unchanged, 0);
  assert.ok(diff.warnings.some((warning) => warning.includes("2 current candidates")));
  assert.ok(diff.warnings.some((warning) => warning.includes("2 baseline candidates")));
});

test("does not override conflicting producer fingerprints with a weaker fallback", () => {
  const baseline = normalizeSarif(sarifLog([{
    ruleId: "SAME",
    uri: "src/a.js",
    line: 10,
    message: "Repeated finding message",
    fingerprint: "baseline-identity",
  }]), { sourceName: "baseline.sarif" });
  const current = normalizeSarif(sarifLog([{
    ruleId: "SAME",
    uri: "src/a.js",
    line: 10,
    message: "Repeated finding message",
    fingerprint: "current-identity",
  }]), { sourceName: "current.sarif" });

  const diff = diffAnalyses(baseline, current);
  assert.equal(diff.summary.new, 1);
  assert.equal(diff.summary.fixed, 1);
  assert.equal(diff.summary.updated, 0);
  assert.equal(diff.summary.unchanged, 0);
});

test("pairs reordered multi-run inputs through automationDetails guid", () => {
  const firstAutomationGuid = "11111111-1111-4111-8111-111111111111";
  const secondAutomationGuid = "22222222-2222-4222-8222-222222222222";
  const baseline = analysis({
    version: "2.1.0",
    runs: [
      sarifLog([{ ruleId: "A", fingerprint: "a" }], {
        guid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        automationGuid: firstAutomationGuid,
        automationId: "baseline/one/",
        tool: "Scanner",
      }).runs[0],
      sarifLog([{ ruleId: "B", fingerprint: "b" }], {
        guid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        automationGuid: secondAutomationGuid,
        automationId: "baseline/two/",
        tool: "Scanner",
      }).runs[0],
    ],
  }, "old.sarif");
  const current = analysis({
    version: "2.1.0",
    runs: [
      sarifLog([{ ruleId: "B", fingerprint: "b" }], {
        guid: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        automationGuid: "33333333-3333-4333-8333-333333333333",
        baselineGuid: secondAutomationGuid,
        automationId: "current/two/",
        tool: "Scanner",
      }).runs[0],
      sarifLog([{ ruleId: "A", fingerprint: "a" }], {
        guid: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        automationGuid: "44444444-4444-4444-8444-444444444444",
        baselineGuid: firstAutomationGuid,
        automationId: "current/one/",
        tool: "Scanner",
      }).runs[0],
    ],
  }, "new.sarif");
  const diff = diffAnalyses(baseline, current);
  assert.equal(diff.summary.unchanged, 2);
  assert.equal(diff.summary.new, 0);
  assert.equal(diff.summary.fixed, 0);
  assert.ok(diff.items.every((item) => item.match.runPairStrategy === "baseline-guid"));
});

test("refuses baseline-guid run collisions in both directions", async (t) => {
  const sharedGuid = "55555555-5555-4555-8555-555555555555";

  await t.test("one current run to many baseline runs", () => {
    const baseline = analysis({
      version: "2.1.0",
      runs: [
        sarifLog([{ ruleId: "BASE_A", fingerprint: "a" }], {
          automationGuid: sharedGuid, automationId: "baseline/a/", tool: "Baseline A",
        }).runs[0],
        sarifLog([{ ruleId: "BASE_B", fingerprint: "b" }], {
          automationGuid: sharedGuid, automationId: "baseline/b/", tool: "Baseline B",
        }).runs[0],
      ],
    }, "old.sarif");
    const current = analysis(sarifLog([{ ruleId: "CURRENT", fingerprint: "c" }], {
      baselineGuid: sharedGuid, automationId: "current/", tool: "Current",
    }), "new.sarif");
    const diff = diffAnalyses(baseline, current);
    assert.equal(diff.summary.fixed, 2);
    assert.equal(diff.summary.new, 1);
    assert.ok(diff.warnings.some((warning) => warning.includes("2 baseline candidates")));
  });

  await t.test("many current runs to one baseline run", () => {
    const baseline = analysis(sarifLog([{ ruleId: "BASE", fingerprint: "a" }], {
      automationGuid: sharedGuid, automationId: "baseline/", tool: "Baseline",
    }), "old.sarif");
    const current = analysis({
      version: "2.1.0",
      runs: [
        sarifLog([{ ruleId: "CURRENT_A", fingerprint: "b" }], {
          baselineGuid: sharedGuid, automationId: "current/a/", tool: "Current A",
        }).runs[0],
        sarifLog([{ ruleId: "CURRENT_B", fingerprint: "c" }], {
          baselineGuid: sharedGuid, automationId: "current/b/", tool: "Current B",
        }).runs[0],
      ],
    }, "new.sarif");
    const diff = diffAnalyses(baseline, current);
    assert.equal(diff.summary.fixed, 1);
    assert.equal(diff.summary.new, 2);
    assert.ok(diff.warnings.some((warning) => warning.includes("2 current candidates")));
  });

  await t.test("many baseline runs to many current runs", () => {
    const baseline = analysis({
      version: "2.1.0",
      runs: [
        sarifLog([{ ruleId: "BASE_A", fingerprint: "a" }], {
          automationGuid: sharedGuid, automationId: "baseline/a/", tool: "Baseline A",
        }).runs[0],
        sarifLog([{ ruleId: "BASE_B", fingerprint: "b" }], {
          automationGuid: sharedGuid, automationId: "baseline/b/", tool: "Baseline B",
        }).runs[0],
      ],
    }, "old.sarif");
    const current = analysis({
      version: "2.1.0",
      runs: [
        sarifLog([{ ruleId: "CURRENT_A", fingerprint: "c" }], {
          baselineGuid: sharedGuid, automationId: "current/a/", tool: "Current A",
        }).runs[0],
        sarifLog([{ ruleId: "CURRENT_B", fingerprint: "d" }], {
          baselineGuid: sharedGuid, automationId: "current/b/", tool: "Current B",
        }).runs[0],
      ],
    }, "new.sarif");
    const diff = diffAnalyses(baseline, current);
    assert.equal(diff.summary.fixed, 2);
    assert.equal(diff.summary.new, 2);
    assert.ok(diff.warnings.some((warning) => warning.includes("2 baseline candidates")));
    assert.ok(diff.warnings.some((warning) => warning.includes("2 current candidates")));
  });
});

test("pairs multi-run inputs by automation identity", () => {
  const baseline = analysis({
    version: "2.1.0",
    runs: [
      sarifLog([{ ruleId: "A", fingerprint: "a" }], { automationId: "one/", tool: "Scanner" }).runs[0],
      sarifLog([{ ruleId: "B", fingerprint: "b" }], { automationId: "two/", tool: "Scanner" }).runs[0],
    ],
  }, "old.sarif");
  const current = analysis({
    version: "2.1.0",
    runs: [
      sarifLog([{ ruleId: "B", fingerprint: "b" }], { automationId: "two/", tool: "Scanner" }).runs[0],
      sarifLog([{ ruleId: "A", fingerprint: "a" }], { automationId: "one/", tool: "Scanner" }).runs[0],
    ],
  }, "new.sarif");
  const diff = diffAnalyses(baseline, current);
  assert.equal(diff.summary.unchanged, 2);
  assert.equal(diff.summary.new, 0);
  assert.ok(diff.items.every((item) => item.match.runPairStrategy === "automation-id"));
});
