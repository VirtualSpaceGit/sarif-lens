import { MATCH_STRATEGIES, SEVERITY_RANK } from "./constants.js";
import { assert } from "./errors.js";
import { buildIdentityKeys, compareFindingOrder } from "./fingerprint.js";

export function diffAnalyses(baseline, current, options = {}) {
  assert(baseline && Array.isArray(baseline.findings),
    "The baseline analysis is invalid.", { code: "INVALID_BASELINE_ANALYSIS" });
  assert(current && Array.isArray(current.findings),
    "The current analysis is invalid.", { code: "INVALID_CURRENT_ANALYSIS" });

  const before = baseline.findings.map((finding, index) => ({ finding, index }));
  const after = current.findings.map((finding, index) => ({ finding, index }));
  const unmatchedBefore = new Set(before.map(({ index }) => index));
  const unmatchedAfter = new Set(after.map(({ index }) => index));
  const matches = [];
  const warnings = [...(baseline.warnings ?? []), ...(current.warnings ?? [])];
  const runPairing = pairRuns(baseline, current);
  warnings.push(...runPairing.warnings);

  for (const runPair of runPairing.pairs) {
    const beforeRunIndexes = new Set(before
      .filter(({ finding }) => finding.run?.key === runPair.baseline.key)
      .map(({ index }) => index));
    const afterRunIndexes = new Set(after
      .filter(({ finding }) => finding.run?.key === runPair.current.key)
      .map(({ index }) => index));

    for (const stage of MATCH_STRATEGIES) {
      const availableBefore = intersectSets(unmatchedBefore, beforeRunIndexes);
      const availableAfter = intersectSets(unmatchedAfter, afterRunIndexes);
      const currentIndex = indexKeys(after, availableAfter, stage.name);
      const baselineIndex = indexKeys(before, availableBefore, stage.name);
      const baselineCandidates = candidateSets(before, availableBefore, currentIndex, stage.name);
      const currentCandidates = candidateSets(after, availableAfter, baselineIndex, stage.name);

      for (const [index, candidates] of baselineCandidates) {
        if (candidates.size > 1) {
          const finding = before[index].finding;
          warnings.push(
            `Refused ambiguous ${stage.name} match for baseline finding ${finding.ruleId} at ${finding.uri}: ${candidates.size} current candidates.`,
          );
        }
      }
      for (const [index, candidates] of currentCandidates) {
        if (candidates.size > 1) {
          const finding = after[index].finding;
          warnings.push(
            `Refused ambiguous ${stage.name} match for current finding ${finding.ruleId} at ${finding.uri}: ${candidates.size} baseline candidates.`,
          );
        }
      }

      const orderedBefore = [...availableBefore]
        .map((index) => before[index])
        .sort((a, b) => compareFindingOrder(a.finding, b.finding));

      for (const entry of orderedBefore) {
        if (!unmatchedBefore.has(entry.index)) {
          continue;
        }
        const keys = keysForStrategy(entry.finding, stage.name);
        const candidates = baselineCandidates.get(entry.index) ?? new Set();
        if (candidates.size !== 1) {
          continue;
        }

        const selectedIndex = [...candidates][0];
        const reverseCandidates = currentCandidates.get(selectedIndex) ?? new Set();
        if (reverseCandidates.size !== 1 || !reverseCandidates.has(entry.index)) {
          continue;
        }
        const selected = after[selectedIndex];
        const sharedKey = keys.find((key) => keysForStrategy(selected.finding, stage.name).includes(key));
        matches.push({
          beforeIndex: entry.index,
          afterIndex: selected.index,
          strategy: stage.name,
          confidence: stage.confidence,
          key: sharedKey ?? "",
          ambiguousCandidates: 1,
          runPairStrategy: runPair.strategy,
        });
        unmatchedBefore.delete(entry.index);
        unmatchedAfter.delete(selected.index);
      }
    }
  }

  const items = [];
  for (const match of matches) {
    const previous = before[match.beforeIndex].finding;
    const next = after[match.afterIndex].finding;
    const comparison = compareMatchedFindings(previous, next);
    items.push({
      id: next.id,
      state: comparison.significant.length > 0 ? "updated" : "unchanged",
      before: previous,
      after: next,
      match: {
        strategy: match.strategy,
        confidence: match.confidence,
        ambiguousCandidates: match.ambiguousCandidates,
        runPairStrategy: match.runPairStrategy,
      },
      changes: comparison,
    });
  }

  for (const index of unmatchedBefore) {
    const finding = before[index].finding;
    items.push({
      id: finding.id,
      state: "fixed",
      before: finding,
      after: null,
      match: null,
      changes: { significant: [], movement: [] },
    });
  }

  for (const index of unmatchedAfter) {
    const finding = after[index].finding;
    items.push({
      id: finding.id,
      state: "new",
      before: null,
      after: finding,
      match: null,
      changes: { significant: [], movement: [] },
    });
  }

  items.sort(compareDiffItems);
  return {
    format: "sarif-lens-diff",
    version: 1,
    baseline: {
      sourceName: baseline.sourceName,
      kind: baseline.kind,
      findingCount: baseline.findings.length,
    },
    current: {
      sourceName: current.sourceName,
      kind: current.kind,
      findingCount: current.findings.length,
    },
    summary: summarizeDiff(items),
    items,
    warnings: [...new Set(warnings)],
    options: {
      matching: options.matching ?? "default",
    },
  };
}

function pairRuns(baseline, current) {
  const baselineRuns = analysisRuns(baseline);
  const currentRuns = analysisRuns(current);
  const unmatchedBaseline = new Set(baselineRuns.map((_, index) => index));
  const unmatchedCurrent = new Set(currentRuns.map((_, index) => index));
  const pairs = [];
  const warnings = [];

  const matchStage = (strategy, predicate) => {
    const baselineCandidates = new Map([...unmatchedBaseline].map((index) => [index, new Set()]));
    const currentCandidates = new Map([...unmatchedCurrent].map((index) => [index, new Set()]));

    for (const currentIndex of unmatchedCurrent) {
      const currentRun = currentRuns[currentIndex];
      for (const baselineIndex of unmatchedBaseline) {
        if (predicate(baselineRuns[baselineIndex], currentRun)) {
          currentCandidates.get(currentIndex).add(baselineIndex);
          baselineCandidates.get(baselineIndex).add(currentIndex);
        }
      }
    }

    for (const [currentIndex, candidates] of currentCandidates) {
      if (candidates.size > 1) {
        const run = currentRuns[currentIndex];
        warnings.push(
          `Refused ambiguous ${strategy} run match for current run ${run.toolName} (${run.key}): ${candidates.size} baseline candidates.`,
        );
      }
    }
    for (const [baselineIndex, candidates] of baselineCandidates) {
      if (candidates.size > 1) {
        const run = baselineRuns[baselineIndex];
        warnings.push(
          `Refused ambiguous ${strategy} run match for baseline run ${run.toolName} (${run.key}): ${candidates.size} current candidates.`,
        );
      }
    }

    const stagePairs = [];
    for (const [currentIndex, candidates] of currentCandidates) {
      if (candidates.size !== 1) continue;
      const baselineIndex = [...candidates][0];
      const reverseCandidates = baselineCandidates.get(baselineIndex) ?? new Set();
      if (reverseCandidates.size !== 1 || !reverseCandidates.has(currentIndex)) continue;
      stagePairs.push({ baselineIndex, currentIndex });
    }

    for (const { baselineIndex, currentIndex } of stagePairs) {
      pairs.push({
        baseline: baselineRuns[baselineIndex],
        current: currentRuns[currentIndex],
        strategy,
      });
      unmatchedBaseline.delete(baselineIndex);
      unmatchedCurrent.delete(currentIndex);
    }
  };

  matchStage("baseline-guid", (previous, next) => Boolean(next.baselineGuid)
    && Boolean(previous.automationGuid)
    && next.baselineGuid === previous.automationGuid);
  matchStage("automation-id", (previous, next) => Boolean(next.automationId)
    && next.automationId === previous.automationId
    && next.toolName === previous.toolName);
  matchStage("tool-and-index", (previous, next) => next.toolName === previous.toolName && next.index === previous.index);
  matchStage("unique-tool", (previous, next) => next.toolName === previous.toolName);

  for (const index of unmatchedBaseline) {
    warnings.push(`Baseline run ${baselineRuns[index].toolName} (${baselineRuns[index].key}) has no current pair.`);
  }
  for (const index of unmatchedCurrent) {
    warnings.push(`Current run ${currentRuns[index].toolName} (${currentRuns[index].key}) has no baseline pair.`);
  }
  return { pairs, warnings };
}

function analysisRuns(analysis) {
  if (Array.isArray(analysis.metadata?.runs) && analysis.metadata.runs.length) {
    return analysis.metadata.runs;
  }
  const runs = new Map();
  analysis.findings.forEach((finding) => {
    const run = finding.run ?? {
      index: finding.source?.runIndex ?? 0,
      guid: "",
      baselineGuid: "",
      automationId: finding.tool?.automationId ?? "",
      automationGuid: "",
      toolName: finding.tool?.name ?? "Unknown tool",
      key: `${finding.tool?.name ?? "Unknown tool"}:${finding.source?.runIndex ?? 0}`,
    };
    runs.set(run.key, run);
  });
  return [...runs.values()];
}

function intersectSets(left, right) {
  return new Set([...left].filter((value) => right.has(value)));
}

function indexKeys(entries, available, strategy) {
  const index = new Map();
  for (const entry of entries) {
    if (!available.has(entry.index)) continue;
    for (const key of keysForStrategy(entry.finding, strategy)) {
      if (!index.has(key)) index.set(key, []);
      index.get(key).push(entry.index);
    }
  }
  return index;
}

function candidateSets(entries, available, oppositeIndex, strategy) {
  const candidatesByIndex = new Map();
  for (const index of available) {
    const candidates = new Set();
    for (const key of keysForStrategy(entries[index].finding, strategy)) {
      for (const candidate of oppositeIndex.get(key) ?? []) {
        candidates.add(candidate);
      }
    }
    candidatesByIndex.set(index, candidates);
  }
  return candidatesByIndex;
}

function keysForStrategy(finding, strategy) {
  const keys = finding.identityKeys ?? buildIdentityKeys(finding);
  return keys.filter((entry) => entry.strategy === strategy).map((entry) => entry.key);
}

function compareMatchedFindings(previous, next) {
  const significant = [];
  const movement = [];
  compareField(significant, "severity", previous.severity, next.severity);
  compareField(significant, "message", previous.message, next.message);
  compareField(significant, "path", previous.uri, next.uri);
  compareField(significant, "snippet", previous.snippet, next.snippet);
  compareField(significant, "CWE", previous.cwes.join(","), next.cwes.join(","));
  compareField(significant, "suppression", previous.suppressed, next.suppressed);
  compareField(movement, "line", previous.line, next.line);
  compareField(movement, "column", previous.column, next.column);
  return { significant, movement };
}

function compareField(changes, field, before, after) {
  if ((before ?? null) !== (after ?? null)) {
    changes.push({ field, before: before ?? null, after: after ?? null });
  }
}

function compareDiffItems(left, right) {
  const stateOrder = { new: 0, updated: 1, fixed: 2, unchanged: 3 };
  const leftFinding = left.after ?? left.before;
  const rightFinding = right.after ?? right.before;
  return stateOrder[left.state] - stateOrder[right.state]
    || (SEVERITY_RANK[rightFinding.severity] ?? 0) - (SEVERITY_RANK[leftFinding.severity] ?? 0)
    || compareFindingOrder(leftFinding, rightFinding);
}

function summarizeDiff(items) {
  const byState = { new: 0, updated: 0, fixed: 0, unchanged: 0 };
  const bySeverity = Object.fromEntries(Object.keys(SEVERITY_RANK).map((severity) => [severity, 0]));
  const newBySeverity = Object.fromEntries(Object.keys(SEVERITY_RANK).map((severity) => [severity, 0]));
  let suppressed = 0;

  items.forEach((item) => {
    byState[item.state] += 1;
    const finding = item.after ?? item.before;
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
    if (item.state === "new") {
      newBySeverity[finding.severity] = (newBySeverity[finding.severity] ?? 0) + 1;
    }
    if (finding.suppressed) suppressed += 1;
  });

  return {
    total: items.length,
    ...byState,
    bySeverity,
    newBySeverity,
    suppressed,
  };
}
