import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runAction } from "../src/action.js";

function actionEnvironment(directory, overrides = {}) {
  return {
    INPUT_BASELINE: "examples/baseline.sarif",
    INPUT_CURRENT: "examples/current.sarif",
    INPUT_POLICY: "examples/policy.json",
    INPUT_REPORT: join(directory, "report.md"),
    GITHUB_OUTPUT: join(directory, "output.txt"),
    ...overrides,
  };
}

test("action preserves gate failure exit code one", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sarif-lens-action-"));
  try {
    const errors = [];
    const code = await runAction({
      env: actionEnvironment(directory),
      stderr: (value) => errors.push(value),
    });
    assert.equal(code, 1);
    assert.match(errors.join(""), /gate:/);
    assert.match(await readFile(join(directory, "output.txt"), "utf8"), /passed<<SARIF_LENS_OUTPUT\nfalse/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("action resolves required inputs inside its error boundary", async () => {
  const errors = [];
  const code = await runAction({ env: {}, stderr: (value) => errors.push(value) });
  assert.equal(code, 2);
  assert.match(errors.join(""), /Missing required input: baseline/);
});

test("action requires the current input to be SARIF", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sarif-lens-action-"));
  try {
    const baselinePath = join(directory, "compact.json");
    const reportPath = join(directory, "report.md");
    const capture = [];
    const baselineCapture = await readFile("examples/baseline.sarif", "utf8");
    const { createBaseline, loadAnalysis } = await import("../src/index.js");
    await writeFile(baselinePath, JSON.stringify(createBaseline(loadAnalysis(baselineCapture))), "utf8");
    const code = await runAction({
      env: {
        INPUT_BASELINE: baselinePath,
        INPUT_CURRENT: baselinePath,
        INPUT_REPORT: reportPath,
      },
      stderr: (value) => capture.push(value),
    });
    assert.equal(code, 2);
    assert.match(capture.join(""), /current input must be a SARIF log/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
