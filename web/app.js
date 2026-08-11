import { createBaseline, filterDiff, formatDiff, STATE_LABELS } from "../src/core/index.js";
import { DEMO_BASELINE, DEMO_CURRENT } from "./demo-data.js";

const MAX_FILE_BYTES = 50 * 1024 * 1024;
const PAGE_SIZE = 100;

const elements = Object.fromEntries([
  "baseline-file", "current-file", "baseline-zone", "current-zone",
  "baseline-status", "current-status", "load-demo", "compare", "reset",
  "notice", "results", "result-sources", "count-new", "count-updated",
  "count-fixed", "count-unchanged", "search", "state-filter",
  "severity-filter", "visible-count", "warning-count", "finding-list",
  "pagination", "page-prev", "page-next", "page-label", "save-baseline",
  "detail-dialog", "detail-close", "detail-state", "detail-title", "detail-content",
].map((id) => [id, document.getElementById(id)]));

const state = {
  baseline: null,
  current: null,
  diff: null,
  currentAnalysis: null,
  page: 1,
  requestId: 0,
  generation: 0,
  pending: new Map(),
};

let worker = createWorker();

wireFileInput("baseline");
wireFileInput("current");
wireDropZone("baseline");
wireDropZone("current");

elements.compare.addEventListener("click", compareFiles);
elements.reset.addEventListener("click", resetAll);
elements["load-demo"].addEventListener("click", loadExample);
elements.search.addEventListener("input", updateFilters);
elements["state-filter"].addEventListener("change", updateFilters);
elements["severity-filter"].addEventListener("change", updateFilters);
elements["page-prev"].addEventListener("click", () => changePage(-1));
elements["page-next"].addEventListener("click", () => changePage(1));
elements["save-baseline"].addEventListener("click", saveCurrentBaseline);
elements["detail-close"].addEventListener("click", () => elements["detail-dialog"].close());
elements["detail-dialog"].addEventListener("click", (event) => {
  if (event.target === elements["detail-dialog"]) elements["detail-dialog"].close();
});

document.querySelectorAll(".export").forEach((button) => {
  button.addEventListener("click", () => exportDiff(button.dataset.format));
});
document.querySelectorAll(".summary-card").forEach((button) => {
  button.addEventListener("click", () => {
    elements["state-filter"].value = elements["state-filter"].value === button.dataset.state ? "" : button.dataset.state;
    updateFilters();
  });
});

function createWorker() {
  const instance = new Worker("worker.js", { type: "module" });
  instance.addEventListener("message", handleWorkerMessage);
  instance.addEventListener("error", (event) => handleWorkerFailure(`Worker error: ${event.message}`));
  instance.addEventListener("messageerror", () => handleWorkerFailure("The browser could not read the worker response."));
  return instance;
}

function handleWorkerMessage(event) {
  const callback = state.pending.get(event.data?.id);
  if (!callback) return;
  state.pending.delete(event.data.id);
  if (event.data.ok) callback.resolve(event.data);
  else callback.reject(new Error(event.data.error?.message ?? "Comparison failed."));
}

function handleWorkerFailure(message) {
  state.generation += 1;
  rejectPending(new Error(message));
  worker.terminate();
  worker = null;
  elements.compare.disabled = !state.current;
  elements.compare.firstElementChild.textContent = "Compare findings";
  showNotice(message, true);
}

function rejectPending(error) {
  state.pending.forEach(({ reject }) => reject(error));
  state.pending.clear();
}

function wireFileInput(kind) {
  elements[`${kind}-file`].addEventListener("change", (event) => {
    const file = event.target.files?.[0];
    if (file) setFile(kind, file);
  });
}

function wireDropZone(kind) {
  const zone = elements[`${kind}-zone`];
  ["dragenter", "dragover"].forEach((name) => zone.addEventListener(name, (event) => {
    event.preventDefault();
    zone.classList.add("is-dragging");
  }));
  ["dragleave", "drop"].forEach((name) => zone.addEventListener(name, (event) => {
    event.preventDefault();
    zone.classList.remove("is-dragging");
  }));
  zone.addEventListener("drop", (event) => {
    const file = event.dataTransfer?.files?.[0];
    if (file) setFile(kind, file);
  });
  zone.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      elements[`${kind}-file`].click();
    }
  });
}

function setFile(kind, file) {
  if (file.size > MAX_FILE_BYTES) {
    showNotice(`${file.name} exceeds the 50 MiB browser limit. Use the CLI for files up to 100 MiB.`, true);
    return;
  }
  state[kind] = { file, name: file.name, size: file.size };
  elements[`${kind}-status`].textContent = `${file.name} · ${formatBytes(file.size)}`;
  elements[`${kind}-zone`].classList.add("has-file");
  elements.compare.disabled = !state.current;
  showNotice(`${file.name} ready.`, false);
}

async function compareFiles() {
  if (!state.current) return;
  const generation = ++state.generation;
  elements.compare.disabled = true;
  elements.compare.firstElementChild.textContent = "Comparing...";
  showNotice("Parsing and matching locally in a Web Worker.", false);
  try {
    const [baselineText, currentText] = await Promise.all([
      state.baseline ? readStoredFile(state.baseline) : Promise.resolve(null),
      readStoredFile(state.current),
    ]);
    const response = await requestWorker({
      baselineText,
      baselineName: state.baseline?.name ?? "No baseline",
      currentText,
      currentName: state.current.name,
    });
    if (generation !== state.generation) return;
    state.diff = response.diff;
    state.currentAnalysis = response.current;
    state.page = 1;
    showResults();
    showNotice(`Comparison complete. ${response.diff.items.length} finding instances classified.`, false);
  } catch (error) {
    if (generation === state.generation) showNotice(error.message, true);
  } finally {
    if (generation === state.generation) {
      elements.compare.disabled = !state.current;
      elements.compare.firstElementChild.textContent = "Compare findings";
    }
  }
}

async function readStoredFile(entry) {
  if (entry.text !== undefined) return entry.text;
  return entry.file.text();
}

function requestWorker(payload) {
  if (!worker) worker = createWorker();
  const id = ++state.requestId;
  return new Promise((resolve, reject) => {
    state.pending.set(id, { resolve, reject });
    worker.postMessage({ id, ...payload });
  });
}

function loadExample() {
  state.baseline = { text: DEMO_BASELINE, name: "demo-baseline.sarif", size: DEMO_BASELINE.length };
  state.current = { text: DEMO_CURRENT, name: "demo-current.sarif", size: DEMO_CURRENT.length };
  ["baseline", "current"].forEach((kind) => {
    elements[`${kind}-status`].textContent = `${state[kind].name} · example`;
    elements[`${kind}-zone`].classList.add("has-file");
  });
  elements.compare.disabled = false;
  showNotice("Example loaded. Compare it to see moved, updated, fixed, and new findings.", false);
  compareFiles();
}

function showResults() {
  const { summary } = state.diff;
  elements["count-new"].textContent = summary.new;
  elements["count-updated"].textContent = summary.updated;
  elements["count-fixed"].textContent = summary.fixed;
  elements["count-unchanged"].textContent = summary.unchanged;
  elements["result-sources"].textContent = `${state.diff.baseline.sourceName} compared with ${state.diff.current.sourceName}`;
  elements["warning-count"].textContent = state.diff.warnings.length
    ? `${state.diff.warnings.length} matching note${state.diff.warnings.length === 1 ? "" : "s"}`
    : "";
  elements.results.hidden = false;
  renderFindings();
  elements.results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function updateFilters() {
  state.page = 1;
  renderFindings();
}

function filteredDiff() {
  return filterDiff(state.diff, {
    states: elements["state-filter"].value,
    severities: elements["severity-filter"].value,
    search: elements.search.value,
  });
}

function renderFindings() {
  if (!state.diff) return;
  const filtered = filteredDiff();
  const totalPages = Math.max(1, Math.ceil(filtered.items.length / PAGE_SIZE));
  state.page = Math.min(state.page, totalPages);
  const start = (state.page - 1) * PAGE_SIZE;
  const items = filtered.items.slice(start, start + PAGE_SIZE);
  elements["finding-list"].replaceChildren();
  elements["visible-count"].textContent = `${filtered.items.length} finding${filtered.items.length === 1 ? "" : "s"}`;

  if (!items.length) {
    elements["finding-list"].append(element("div", "empty-state", "No findings match these filters."));
  } else {
    const fragment = document.createDocumentFragment();
    items.forEach((item) => fragment.append(findingCard(item)));
    elements["finding-list"].append(fragment);
  }

  elements.pagination.hidden = totalPages <= 1;
  elements["page-label"].textContent = `Page ${state.page} of ${totalPages}`;
  elements["page-prev"].disabled = state.page <= 1;
  elements["page-next"].disabled = state.page >= totalPages;
}

function findingCard(item) {
  const finding = item.after ?? item.before;
  const button = element("button", "finding-card");
  button.type = "button";
  button.setAttribute("aria-label", `${STATE_LABELS[item.state]} ${finding.severity} finding ${finding.ruleId} at ${location(finding)}`);
  button.append(
    element("span", `finding-state state-${item.state}`, STATE_LABELS[item.state]),
    element("span", `severity severity-${finding.severity}`, finding.severity),
    element("span", "finding-rule", finding.ruleId),
  );
  const main = element("span", "finding-main");
  main.append(element("strong", "", finding.message), element("span", "", `${location(finding)} · ${finding.tool?.name ?? "Unknown tool"}`));
  button.append(main, element("span", "finding-arrow", "→"));
  button.addEventListener("click", () => showDetail(item));
  return button;
}

function showDetail(item) {
  const finding = item.after ?? item.before;
  elements["detail-state"].textContent = `${STATE_LABELS[item.state]} · ${finding.severity}`;
  elements["detail-title"].textContent = finding.ruleName || finding.ruleId;
  const grid = element("dl", "detail-grid");
  addDetail(grid, "Rule", finding.ruleId);
  addDetail(grid, "Tool", `${finding.tool?.name ?? "Unknown tool"}${finding.tool?.version ? ` ${finding.tool.version}` : ""}`);
  addDetail(grid, "Location", location(finding));
  addDetail(grid, "CWE", finding.cwes.join(", ") || "Not provided");
  addDetail(grid, "Message", finding.message, true);
  addDetail(grid, "Source snippet", finding.snippet || "Not included in SARIF", true, true);
  if (item.match) {
    addDetail(grid, "Matched by", `${item.match.strategy} · ${item.match.confidence} confidence`);
    addDetail(grid, "Run pairing", item.match.runPairStrategy || "Not recorded");
  } else {
    addDetail(grid, "Matched by", item.state === "new" ? "No baseline match" : "No current match");
  }
  if (item.changes.significant.length || item.changes.movement.length) {
    const field = element("div", "detail-field wide");
    const term = element("dt", "", "Changes");
    const value = element("dd");
    const list = element("ul", "change-list");
    [...item.changes.significant, ...item.changes.movement].forEach((change) => {
      list.append(element("li", "", `${change.field}: ${displayValue(change.before)} → ${displayValue(change.after)}`));
    });
    value.append(list);
    field.append(term, value);
    grid.append(field);
  }
  elements["detail-content"].replaceChildren(grid);
  elements["detail-dialog"].showModal();
}

function addDetail(grid, label, value, wide = false, code = false) {
  const wrapper = element("div", `detail-field${wide ? " wide" : ""}`);
  const term = element("dt", "", label);
  const description = element("dd");
  description.append(code ? element("code", "", String(value)) : document.createTextNode(String(value)));
  wrapper.append(term, description);
  grid.append(wrapper);
}

function changePage(delta) {
  state.page += delta;
  renderFindings();
  elements["finding-list"].scrollIntoView({ behavior: "smooth", block: "start" });
}

function exportDiff(format) {
  if (!state.diff) return;
  const filtered = filteredDiff();
  const content = formatDiff(filtered, { format, color: false });
  const extensions = { markdown: "md", csv: "csv", json: "json", sarif: "sarif" };
  const mediaTypes = {
    markdown: "text/markdown",
    csv: "text/csv",
    json: "application/json",
    sarif: "application/sarif+json",
  };
  download(`sarif-lens-diff.${extensions[format]}`, content, mediaTypes[format]);
}

function saveCurrentBaseline() {
  if (!state.currentAnalysis) return;
  const baseline = createBaseline(state.currentAnalysis);
  download("sarif-lens-baseline.json", `${JSON.stringify(baseline, null, 2)}\n`, "application/json");
}

function download(name, content, type) {
  const blob = new Blob([content], { type: `${type};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function resetAll() {
  state.generation += 1;
  rejectPending(new Error("Comparison cancelled."));
  worker?.terminate();
  worker = createWorker();
  state.baseline = null;
  state.current = null;
  state.diff = null;
  state.currentAnalysis = null;
  state.page = 1;
  ["baseline", "current"].forEach((kind) => {
    elements[`${kind}-file`].value = "";
    elements[`${kind}-status`].textContent = "Drop a file or choose one";
    elements[`${kind}-zone`].classList.remove("has-file", "is-dragging");
  });
  elements.compare.disabled = true;
  elements.results.hidden = true;
  elements.search.value = "";
  elements["state-filter"].value = "";
  elements["severity-filter"].value = "";
  elements.notice.hidden = true;
}

function showNotice(message, isError) {
  elements.notice.textContent = message;
  elements.notice.classList.toggle("is-error", isError);
  elements.notice.hidden = false;
}

function element(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== "") node.textContent = text;
  return node;
}

function location(finding) {
  return finding.line ? `${finding.uri}:${finding.line}` : finding.uri;
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "not set";
  return String(value);
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}
