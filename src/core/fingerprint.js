function normalizeIdentityText(value) {
  return String(value ?? "")
    .normalize("NFKC")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function normalizeSnippet(value) {
  return normalizeIdentityText(value)
    .replace(/\/\/.*$/gm, "")
    .replace(/#.*$/gm, "")
    .replace(/\s+/g, " ")
    .trim();
}

function scopeFor(finding) {
  return [
    normalizeIdentityText(finding.tool?.name || "unknown-tool"),
    normalizeIdentityText(finding.ruleId || "unknown-rule"),
  ].join("\u001f");
}

export function buildIdentityKeys(finding) {
  const scope = scopeFor(finding);
  const uri = normalizeIdentityText(finding.uri);
  const keys = [];

  if (finding.correlationGuid) {
    keys.push({
      strategy: "correlation-guid",
      confidence: "exact",
      key: `${scope}\u001fcorrelation\u001f${normalizeIdentityText(finding.correlationGuid)}`,
    });
  }

  for (const [name, value] of Object.entries(finding.fingerprints ?? {}).sort()) {
    keys.push({
      strategy: "fingerprint",
      confidence: "exact",
      key: `${scope}\u001ffull\u001f${normalizeIdentityText(name)}\u001f${normalizeIdentityText(value)}`,
    });
  }

  for (const [name, value] of Object.entries(finding.partialFingerprints ?? {}).sort()) {
    keys.push({
      strategy: "partial-fingerprint",
      confidence: "high",
      key: `${scope}\u001fpartial\u001f${normalizeIdentityText(name)}\u001f${normalizeIdentityText(value)}`,
    });
  }

  if (keys.length > 0) {
    return keys;
  }

  const snippet = normalizeSnippet(finding.snippet);
  if (snippet && uri !== "(no location)") {
    keys.push({
      strategy: "snippet",
      confidence: "high",
      key: `${scope}\u001fsnippet\u001f${uri}\u001f${snippet}`,
    });
  }

  const message = normalizeIdentityText(finding.message);
  if (message && uri !== "(no location)") {
    keys.push({
      strategy: "message",
      confidence: "medium",
      key: `${scope}\u001fmessage\u001f${uri}\u001f${message}`,
    });
  }

  if (uri !== "(no location)" && finding.line) {
    keys.push({
      strategy: "location",
      confidence: "low",
      key: `${scope}\u001flocation\u001f${uri}\u001f${finding.line}`,
    });
  }

  return keys;
}

export function assignFindingIdentity(finding) {
  const identityKeys = buildIdentityKeys(finding);
  const best = [finding.run?.key ?? finding.source?.runIndex ?? "run", identityKeys[0]?.key ?? [
    scopeFor(finding),
    normalizeIdentityText(finding.uri),
    finding.line ?? 0,
    normalizeIdentityText(finding.message),
  ].join("\u001f")].join("\u001f");

  return {
    ...finding,
    id: finding.id || `sl1_${fnv1a64(best)}`,
    identityKeys,
  };
}

export function findingDisplayKey(finding) {
  return finding.id || assignFindingIdentity(finding).id;
}

export function fnv1a64(value) {
  const text = String(value);
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  const mask = 0xffffffffffffffffn;
  const bytes = new TextEncoder().encode(text);
  for (const byte of bytes) {
    hash ^= BigInt(byte);
    hash = (hash * prime) & mask;
  }
  return hash.toString(16).padStart(16, "0");
}

export function compareFindingOrder(left, right) {
  return String(left.tool?.name ?? "").localeCompare(String(right.tool?.name ?? ""))
    || String(left.ruleId ?? "").localeCompare(String(right.ruleId ?? ""))
    || String(left.uri ?? "").localeCompare(String(right.uri ?? ""))
    || (Number(left.line) || 0) - (Number(right.line) || 0)
    || String(left.id ?? "").localeCompare(String(right.id ?? ""));
}
