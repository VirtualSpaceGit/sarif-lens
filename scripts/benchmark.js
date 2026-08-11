import { performance } from "node:perf_hooks";
import process from "node:process";
import { diffAnalyses, normalizeSarif } from "../src/index.js";

const count = Number(process.argv[2] ?? 25_000);
if (!Number.isInteger(count) || count < 2 || count > 100_000) {
  process.stderr.write("Usage: node scripts/benchmark.js [finding-count from 2 to 100000]\n");
  process.exitCode = 2;
} else {
  const started = performance.now();
  const baseline = normalizeSarif(logForRange(0, count), { sourceName: "benchmark-baseline.sarif" });
  const current = normalizeSarif(logForRange(1, count + 1), { sourceName: "benchmark-current.sarif" });
  const normalized = performance.now();
  const diff = diffAnalyses(baseline, current);
  const finished = performance.now();

  const expected = { new: 1, fixed: 1, updated: 0, unchanged: count - 1 };
  for (const [state, value] of Object.entries(expected)) {
    if (diff.summary[state] !== value) {
      throw new Error(`Benchmark correctness check failed for ${state}: expected ${value}, received ${diff.summary[state]}.`);
    }
  }

  process.stdout.write(`${JSON.stringify({
    findingsPerSide: count,
    normalizationMs: round(normalized - started),
    diffMs: round(finished - normalized),
    totalMs: round(finished - started),
    heapUsedMiB: round(process.memoryUsage().heapUsed / (1024 * 1024)),
    summary: diff.summary,
  }, null, 2)}\n`);
}

function logForRange(start, end) {
  return {
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "Benchmark Scanner",
          semanticVersion: "1.0.0",
          rules: [{ id: "BENCH-001", defaultConfiguration: { level: "warning" } }],
        },
      },
      automationDetails: { id: "benchmark/main", guid: "11111111-1111-4111-8111-111111111111" },
      results: Array.from({ length: end - start }, (_, offset) => {
        const identity = start + offset;
        return {
          ruleId: "BENCH-001",
          level: "warning",
          message: { text: "Synthetic benchmark finding." },
          partialFingerprints: { "benchmark/v1": `finding-${identity}` },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: `src/file-${identity % 100}.js` },
              region: { startLine: identity + 4 },
            },
          }],
        };
      }),
    }],
  };
}

function round(value) {
  return Math.round(value * 10) / 10;
}
