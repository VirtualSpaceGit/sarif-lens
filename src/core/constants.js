export const SARIF_LENS_VERSION = "0.1.1";

export const SARIF_VERSION = "2.1.0";

export const BASELINE_FORMAT = "sarif-lens-baseline";

export const BASELINE_VERSION = 1;

export const STATES = Object.freeze(["new", "updated", "fixed", "unchanged"]);

export const SEVERITIES = Object.freeze([
  "critical",
  "high",
  "medium",
  "low",
  "note",
  "none",
]);

export const SEVERITY_RANK = Object.freeze({
  none: 0,
  note: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
});

export const STATE_LABELS = Object.freeze({
  new: "New",
  updated: "Updated",
  fixed: "Fixed",
  unchanged: "Unchanged",
});

export const MATCH_STRATEGIES = Object.freeze([
  { name: "correlation-guid", confidence: "exact" },
  { name: "fingerprint", confidence: "exact" },
  { name: "partial-fingerprint", confidence: "high" },
  { name: "snippet", confidence: "high" },
  { name: "message", confidence: "medium" },
  { name: "location", confidence: "low" },
]);
