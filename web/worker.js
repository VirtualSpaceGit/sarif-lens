import { diffAnalyses, loadAnalysis } from "../src/core/index.js";

self.addEventListener("message", (event) => {
  const { id, baselineText, baselineName, currentText, currentName } = event.data ?? {};
  try {
    const current = loadAnalysis(currentText, { sourceName: currentName || "current.sarif" });
    if (current.kind !== "sarif") {
      throw new Error("The current file must be a SARIF log.");
    }
    const baseline = baselineText
      ? loadAnalysis(baselineText, { sourceName: baselineName || "baseline.sarif" })
      : emptyBaselineFor(current);
    const diff = diffAnalyses(baseline, current);
    self.postMessage({ id, ok: true, diff, current });
  } catch (error) {
    self.postMessage({
      id,
      ok: false,
      error: {
        message: error?.message ?? String(error),
        code: error?.code ?? "WORKER_ERROR",
      },
    });
  }
});

function emptyBaselineFor(current) {
  return {
    kind: "empty",
    sourceName: "No baseline",
    sarifVersion: "2.1.0",
    findings: [],
    metadata: {
      runCount: current.metadata.runs.length,
      tools: current.metadata.tools,
      findingCount: 0,
      runs: current.metadata.runs.map((run) => ({
        ...run,
        guid: run.baselineGuid || "",
        baselineGuid: "",
        key: `empty:${run.key}`,
      })),
    },
    warnings: [],
  };
}

