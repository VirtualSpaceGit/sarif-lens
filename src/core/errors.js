export class SarifLensError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "SarifLensError";
    this.code = options.code ?? "SARIF_LENS_ERROR";
    this.source = options.source ?? null;
    this.details = options.details ?? null;
    if (options.cause) {
      this.cause = options.cause;
    }
  }
}

export function assert(condition, message, options = {}) {
  if (!condition) {
    throw new SarifLensError(message, options);
  }
}

