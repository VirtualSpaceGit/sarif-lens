import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runCli } from "../src/cli.js";

function captureIo() {
  let stdout = "";
  let stderr = "";
  return {
    io: {
      stdout: (value) => { stdout += value; },
      stderr: (value) => { stderr += value; },
      isTTY: false,
    },
    output: () => ({ stdout, stderr }),
  };
}

test("diff command returns deterministic example counts", async () => {
  const capture = captureIo();
  const code = await runCli([
    "diff", "examples/baseline.sarif", "examples/current.sarif", "--no-color",
  ], capture.io);
  assert.equal(code, 0);
  assert.match(capture.output().stdout, /New 2\s+Updated 1\s+Fixed 2\s+Unchanged 1/);
});

test("gate command returns one for a policy violation", async () => {
  const capture = captureIo();
  const code = await runCli([
    "gate", "examples/baseline.sarif", "examples/current.sarif",
    "--policy", "examples/policy.json", "--no-color",
  ], capture.io);
  assert.equal(code, 1);
  assert.match(capture.output().stderr, /gate failed/);
});

test("baseline command writes a reusable compact snapshot", async () => {
  const directory = await mkdtemp(join(tmpdir(), "sarif-lens-test-"));
  try {
    const outputPath = join(directory, "baseline.json");
    const capture = captureIo();
    const firstCode = await runCli([
      "baseline", "examples/baseline.sarif", "--output", outputPath,
    ], capture.io);
    assert.equal(firstCode, 0);
    const saved = JSON.parse(await readFile(outputPath, "utf8"));
    assert.equal(saved.format, "sarif-lens-baseline");
    const secondCode = await runCli([
      "diff", outputPath, "examples/current.sarif", "--format", "json", "--no-color",
    ], capture.io);
    assert.equal(secondCode, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("invalid command line input returns two", async () => {
  const capture = captureIo();
  assert.equal(await runCli(["inspect"], capture.io), 2);
  assert.match(capture.output().stderr, /requires a SARIF file/);
});

test("argument parsing failures are returned as usage errors", async () => {
  const capture = captureIo();
  const code = await runCli(["inspect", "examples/current.sarif", "--unknown"], capture.io);
  assert.equal(code, 2);
  assert.match(capture.output().stderr, /Unknown option/);
});

test("commands reject unsupported output formats with exit two", async () => {
  const inspectCapture = captureIo();
  const inspectCode = await runCli([
    "inspect", "examples/current.sarif", "--format", "csv",
  ], inspectCapture.io);
  assert.equal(inspectCode, 2);
  assert.match(inspectCapture.output().stderr, /Unsupported inspect output format/);

  const diffCapture = captureIo();
  const diffCode = await runCli([
    "diff", "examples/baseline.sarif", "examples/current.sarif", "--format", "xml",
  ], diffCapture.io);
  assert.equal(diffCode, 2);
  assert.match(diffCapture.output().stderr, /Unsupported diff output format/);
});
