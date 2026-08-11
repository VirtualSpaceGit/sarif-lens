export function sarifLog(results, options = {}) {
  const rules = new Map();
  results.forEach((result) => {
    if (!rules.has(result.ruleId)) {
      rules.set(result.ruleId, {
        id: result.ruleId,
        name: result.ruleId,
        properties: {
          "security-severity": String(result.securitySeverity ?? 8),
          tags: result.cwe ? [result.cwe] : [],
        },
      });
    }
  });
  return {
    version: "2.1.0",
    runs: [{
      ...(options.guid ? { guid: options.guid } : {}),
      ...(options.baselineGuid ? { baselineGuid: options.baselineGuid } : {}),
      automationDetails: {
        id: options.automationId ?? "test/run/",
        ...(options.automationGuid ? { guid: options.automationGuid } : {}),
      },
      tool: {
        driver: {
          name: options.tool ?? "Test Scanner",
          semanticVersion: options.version ?? "1.0.0",
          rules: [...rules.values()],
        },
      },
      results: results.map((result, index) => ({
        ...(result.correlationGuid ? { correlationGuid: result.correlationGuid } : {}),
        ruleId: result.ruleId,
        ruleIndex: [...rules.keys()].indexOf(result.ruleId),
        level: result.level ?? "error",
        message: { text: result.message ?? `Message for ${result.ruleId}` },
        locations: result.noLocation ? [] : [{
          physicalLocation: {
            artifactLocation: { uri: result.uri ?? `src/file-${index}.js` },
            region: {
              startLine: result.line ?? index + 1,
              ...(result.snippet ? { snippet: { text: result.snippet } } : {}),
            },
          },
        }],
        ...(result.fingerprint ? { partialFingerprints: { "context/v1": result.fingerprint } } : {}),
        ...(result.resultSeverity ? { properties: { "security-severity": result.resultSeverity } } : {}),
        ...(result.suppressed ? { suppressions: [{ kind: "external", status: "accepted" }] } : {}),
      })),
    }],
  };
}
