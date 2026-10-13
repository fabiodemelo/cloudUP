// Minimal zero-dependency static file server for `tauri dev`.
// Serves the frontend in ../src on http://localhost:5199 with SPA fallback.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const ROOT = join(__dirname, "..", "src");
const PORT = Number(process.env.PORT || 5199);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
};

const server = createServer(async (req, res) => {
  try {
    let urlPath = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
    if (urlPath === "/") urlPath = "/index.html";

    let filePath = normalize(join(ROOT, urlPath));
    if (!filePath.startsWith(ROOT)) {
      res.writeHead(403).end("Forbidden");
      return;
    }

    let target = filePath;
    try {
      const st = await stat(filePath);
      if (st.isDirectory()) target = join(filePath, "index.html");
    } catch {
      // SPA fallback: unknown path -> index.html (but keep real file extensions)
      if (!extname(urlPath)) target = join(ROOT, "index.html");
    }

    const data = await readFile(target);
    res.writeHead(200, { "Content-Type": MIME[extname(target)] || "application/octet-stream" });
    res.end(data);
  } catch (e) {
    res.writeHead(404).end("Not found: " + e.message);
  }
});

server.listen(PORT, () => {
  console.log(`[cloudup] serving ${ROOT} on http://localhost:${PORT}`);
});
