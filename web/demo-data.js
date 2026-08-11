const RULES = [
  {
    id: "DEMO-101",
    name: "UntrustedCommandInput",
    shortDescription: { text: "Untrusted input reaches a process invocation" },
    properties: { "security-severity": "8.2", tags: ["security", "CWE-78"] },
  },
  {
    id: "DEMO-102",
    name: "UnsafeDataQuery",
    shortDescription: { text: "Untrusted input reaches a data query" },
    properties: { "security-severity": "7.8", tags: ["security", "CWE-89"] },
  },
  {
    id: "DEMO-103",
    name: "UncontainedFilePath",
    shortDescription: { text: "A file path is not contained" },
    properties: { "security-severity": "7.5", tags: ["security", "CWE-22"] },
  },
  {
    id: "DEMO-104",
    name: "WeakIntegrityHash",
    shortDescription: { text: "A weak hash protects security data" },
    properties: { "security-severity": "3.1", tags: ["security", "CWE-328"] },
  },
];

function result({ correlationGuid, ruleId, ruleIndex, message, uri, line, snippet, fingerprint, severity }) {
  return {
    correlationGuid,
    ruleId,
    ruleIndex,
    level: severity === "low" ? "note" : "error",
    message: { text: message },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri },
        region: { startLine: line, snippet: { text: snippet } },
      },
    }],
    partialFingerprints: { primaryLocationLineHash: fingerprint },
    ...(severity === "critical" ? { properties: { "security-severity": "9.3" } } : {}),
  };
}

const BASELINE_RESULTS = [
  result({
    correlationGuid: "10000000-0000-4000-8000-000000000001",
    ruleId: "DEMO-101",
    ruleIndex: 0,
    message: "Request data reaches a process invocation without validation.",
    uri: "src/jobs.py",
    line: 18,
    snippet: "subprocess.run(job_command, shell=True)",
    fingerprint: "job-command-f1:1",
  }),
  result({
    correlationGuid: "10000000-0000-4000-8000-000000000002",
    ruleId: "DEMO-102",
    ruleIndex: 1,
    message: "Request data is concatenated into a database query.",
    uri: "src/store.py",
    line: 33,
    snippet: "cursor.execute(query + record_id)",
    fingerprint: "data-query-a2:1",
  }),
  result({
    correlationGuid: "10000000-0000-4000-8000-000000000003",
    ruleId: "DEMO-104",
    ruleIndex: 3,
    message: "A legacy hash is used for an integrity decision.",
    uri: "src/cache.py",
    line: 9,
    snippet: "digest = hashlib.md5(payload).hexdigest()",
    fingerprint: "legacy-hash-b4:1",
    severity: "low",
  }),
];

const CURRENT_RESULTS = [
  result({
    correlationGuid: "10000000-0000-4000-8000-000000000001",
    ruleId: "DEMO-101",
    ruleIndex: 0,
    message: "Request data reaches a process invocation without validation.",
    uri: "src/jobs.py",
    line: 27,
    snippet: "subprocess.run(job_command, shell=True)",
    fingerprint: "job-command-f1:1",
  }),
  result({
    correlationGuid: "10000000-0000-4000-8000-000000000002",
    ruleId: "DEMO-102",
    ruleIndex: 1,
    message: "Untrusted request data reaches a privileged raw query.",
    uri: "src/store.py",
    line: 39,
    snippet: "cursor.execute(query + record_id)",
    fingerprint: "data-query-a2:1",
    severity: "critical",
  }),
  result({
    correlationGuid: "10000000-0000-4000-8000-000000000004",
    ruleId: "DEMO-103",
    ruleIndex: 2,
    message: "A request path reaches a file read without containment validation.",
    uri: "src/files.py",
    line: 51,
    snippet: "return open(base_dir / requested_name).read()",
    fingerprint: "file-path-c7:1",
  }),
];

function log({ guid, baselineGuid, results }) {
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      guid,
      ...(baselineGuid ? { baselineGuid } : {}),
      automationDetails: { id: "sarif-lens/demo/" },
      tool: {
        driver: {
          name: "Demo SAST",
          semanticVersion: "1.0.0",
          informationUri: "https://example.com/demo-sast",
          rules: RULES,
        },
      },
      results,
    }],
  };
}

export const DEMO_BASELINE = JSON.stringify(log({
  guid: "20000000-0000-4000-8000-000000000001",
  results: BASELINE_RESULTS,
}));

export const DEMO_CURRENT = JSON.stringify(log({
  guid: "20000000-0000-4000-8000-000000000002",
  baselineGuid: "20000000-0000-4000-8000-000000000001",
  results: CURRENT_RESULTS,
}));

