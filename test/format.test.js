import test from "node:test";
import assert from "node:assert/strict";
import { diffAnalyses, formatDiff, normalizeSarif } from "../src/index.js";
import { sarifLog } from "./helpers.js";

function sampleDiff(message = "New finding") {
  const current = normalizeSarif(sarifLog([{ ruleId: "NEW", uri: "src/a.js", message }]), { sourceName: "new.sarif" });
  const baseline = {
    kind: "empty",
    sourceName: "old.sarif",
    findings: [],
    warnings: [],
    metadata: { runs: current.metadata.runs.map((run) => ({ ...run, key: `empty:${run.key}` })) },
  };
  return diffAnalyses(baseline, current);
}

test("markdown escapes table delimiters", () => {
  const markdown = formatDiff(sampleDiff("left | right"), { format: "markdown" });
  assert.match(markdown, /left \\| right/);
});

test("markdown neutralizes report-authored links and HTML", () => {
  const markdown = formatDiff(sampleDiff("<script>alert(1)</script> [open](javascript:alert(1))"), { format: "markdown" });
  assert.doesNotMatch(markdown, /<script>/);
  assert.doesNotMatch(markdown, /\[open\]\(javascript:/);
  assert.match(markdown, /&lt;script&gt;/);
});

test("CSV neutralizes spreadsheet formula prefixes", () => {
  const direct = formatDiff(sampleDiff("=HYPERLINK(\"https://example.invalid\")"), { format: "csv" });
  const controlled = sampleDiff("safe");
  controlled.items[0].after.message = "\t=1+1";
  const prefixed = formatDiff(controlled, { format: "csv" });
  assert.match(direct, /'=/);
  assert.match(prefixed, /'\\u0009=1\+1/);
  assert.doesNotMatch(prefixed, /\t/);
});

test("human-readable formats neutralize terminal and bidi controls", () => {
  const message = "normal \u001b[31mred\u001b[0m \u001b]0;title\u0007done \u0000nul \u009b31mc1\u009b0m \u202Ertl";
  const diff = sampleDiff(message);
  const text = formatDiff(diff, { format: "text", color: false });
  const markdown = formatDiff(diff, { format: "markdown" });

  for (const output of [text, markdown]) {
    assert.doesNotMatch(output, /\u001b|\u0000|\u0007|\u009b|\u202e/u);
    assert.match(output, /normal red done/);
    assert.match(output, /\\u0000nul/);
    assert.match(output, /\\u202Ertl/);
  }
});

test("markdown escapes formatting syntax comprehensively", () => {
  const markdown = formatDiff(sampleDiff("*bold* _em_ # heading ![image](javascript:bad) ~strike~"), {
    format: "markdown",
  });
  assert.match(markdown, /\\\*bold\\\*/);
  assert.match(markdown, /\\_em\\_/);
  assert.match(markdown, /\\# heading/);
  assert.doesNotMatch(markdown, /!\[image\]\(javascript:/);
  assert.match(markdown, /\\~strike\\~/);
});

test("SARIF export includes delta baseline state", () => {
  const exported = JSON.parse(formatDiff(sampleDiff(), { format: "sarif" }));
  assert.equal(exported.version, "2.1.0");
  assert.equal(exported.runs[0].results[0].baselineState, "new");
  assert.equal(exported.runs[0].results[0].properties.sarifLensState, "new");
});

test("SARIF export omits a region for a URI-only finding", () => {
  const current = normalizeSarif({
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Test Scanner", rules: [{ id: "URI" }] } },
      results: [{
        ruleId: "URI",
        message: { text: "URI only" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "src/only.js" } } }],
      }],
    }],
  }, { sourceName: "uri.sarif" });
  const baseline = {
    kind: "empty",
    sourceName: "empty.sarif",
    findings: [],
    warnings: [],
    metadata: { runs: current.metadata.runs.map((run) => ({ ...run, key: `empty:${run.key}` })) },
  };
  const exported = JSON.parse(formatDiff(diffAnalyses(baseline, current), { format: "sarif" }));
  const physical = exported.runs[0].results[0].locations[0].physicalLocation;
  assert.equal(physical.artifactLocation.uri, "src/only.js");
  assert.equal("region" in physical, false);
});
