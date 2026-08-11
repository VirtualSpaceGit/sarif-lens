import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, resolve, sep } from "node:path";
import process from "node:process";

const root = resolve(process.cwd());
const port = Number(process.env.PORT || 4173);
const types = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".sarif": "application/sarif+json; charset=utf-8",
  ".svg": "image/svg+xml",
};

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || "127.0.0.1"}`);
    const decoded = decodeURIComponent(url.pathname);
    let requested = resolve(root, `.${decoded}`);
    if (requested !== root && !requested.startsWith(`${root}${sep}`)) {
      return send(response, 403, "Forbidden\n");
    }
    let info = await stat(requested);
    if (info.isDirectory()) {
      requested = resolve(requested, "index.html");
      info = await stat(requested);
    }
    if (!info.isFile()) return send(response, 404, "Not found\n");
    response.writeHead(200, {
      "Content-Type": types[extname(requested).toLowerCase()] || "application/octet-stream",
      "Content-Length": info.size,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Referrer-Policy": "no-referrer",
    });
    createReadStream(requested).pipe(response);
  } catch (error) {
    if (error?.code === "ENOENT") return send(response, 404, "Not found\n");
    send(response, 500, "Server error\n");
  }
});

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`SARIF Lens running at http://127.0.0.1:${port}/web/\n`);
});

function send(response, status, body) {
  response.writeHead(status, {
    "Content-Type": "text/plain; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  response.end(body);
}

