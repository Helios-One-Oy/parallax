// Parallax sink. One Bun file.
// - GET  /healthz                     liveness
// - GET  /stage2/:id                  a small "second stage" text file (records a hit)
// - POST /collect                     accepts ONLY the constant specimen JSON -> 204
// - GET  /registry/@nbd%2f<name>      npm packument (also /registry/@nbd/<name>)
// - GET  /registry/tarballs/<file>    specimen tarball
// - GET  /hits?since=<iso|ms>         recorded hits as JSON
// Nothing is stored except: time, path, specimen id, run id.
import { file } from "bun";

const DIR = import.meta.dir;
const REGISTRY = `${DIR}/registry`;
const PORT = Number(process.env.PORT || 8787);
const KNOWN = new Set(["shai-hulud", "release-gate", "fresh-host", "time-bomb", "pth"]);

type Meta = Record<string, {
  distTags: Record<string, string>;
  versions: Record<string, { manifest: any; file: string; integrity: string; shasum: string }>;
}>;

let meta: Meta = {};
try {
  meta = JSON.parse(await file(`${REGISTRY}/meta.json`).text());
} catch {
  console.warn("no registry/meta.json yet; run build.js");
}

type Hit = { time: string; path: string; specimen: string | null; run: string | null };
const hits: Hit[] = [];
function record(h: Hit) {
  hits.push(h);
  if (hits.length > 5000) hits.splice(0, hits.length - 5000);
}

function baseUrl(req: Request): string {
  if (process.env.PLX_SINK_URL) return process.env.PLX_SINK_URL.replace(/\/$/, "");
  const h = req.headers.get("host") || `127.0.0.1:${PORT}`;
  const proto = req.headers.get("x-forwarded-proto") || (h.startsWith("127.") || h.startsWith("localhost") ? "http" : "https");
  return `${proto}://${h}`;
}

function packument(name: string, req: Request): Response | null {
  const entry = meta[name];
  if (!entry) return null;
  const base = baseUrl(req);
  const versions: Record<string, any> = {};
  for (const [v, info] of Object.entries(entry.versions)) {
    versions[v] = {
      ...info.manifest,
      name,
      version: v,
      dist: {
        tarball: `${base}/registry/tarballs/${info.file}`,
        shasum: info.shasum,
        integrity: info.integrity,
      },
    };
  }
  const doc = { name, "dist-tags": entry.distTags, versions };
  return new Response(JSON.stringify(doc), {
    headers: { "content-type": "application/json" },
  });
}

const server = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  async fetch(req) {
    const url = new URL(req.url);
    const p = url.pathname;
    const now = () => new Date().toISOString();

    if (p === "/healthz") return new Response("ok\n");

    if (p === "/" ) return new Response("parallax-sink\n");

    if (req.method === "GET" && p.startsWith("/stage2/")) {
      const id = decodeURIComponent(p.slice("/stage2/".length));
      record({ time: now(), path: p, specimen: id || null, run: null });
      return new Response(`# parallax stage two for ${id}\n# harmless simulation; no code here runs\n`, {
        headers: { "content-type": "text/plain" },
      });
    }

    if (req.method === "POST" && p === "/collect") {
      let body: any;
      try { body = await req.json(); } catch { return new Response("bad json", { status: 400 }); }
      const keys = body && typeof body === "object" ? Object.keys(body).sort() : [];
      const ok = keys.length === 2 && keys[0] === "run" && keys[1] === "specimen"
        && typeof body.specimen === "string" && KNOWN.has(body.specimen)
        && typeof body.run === "string";
      if (!ok) return new Response("rejected: only the constant specimen JSON is accepted", { status: 400 });
      record({ time: now(), path: p, specimen: body.specimen, run: body.run });
      return new Response(null, { status: 204 });
    }

    if (req.method === "GET" && p === "/hits") {
      const since = url.searchParams.get("since");
      let out = hits;
      if (since) {
        const t = isNaN(Number(since)) ? Date.parse(since) : Number(since);
        if (!isNaN(t)) out = hits.filter((h) => Date.parse(h.time) > t);
      }
      return new Response(JSON.stringify(out), { headers: { "content-type": "application/json" } });
    }

    if (req.method === "GET" && p.startsWith("/registry/")) {
      const rest = decodeURIComponent(p.slice("/registry/".length));
      if (rest.startsWith("tarballs/")) {
        const name = rest.slice("tarballs/".length);
        if (name.includes("/") || name.includes("..")) return new Response("no", { status: 400 });
        const f = file(`${REGISTRY}/tarballs/${name}`);
        if (!(await f.exists())) return new Response("not found", { status: 404 });
        return new Response(f, { headers: { "content-type": "application/octet-stream" } });
      }
      const resp = packument(rest, req);
      return resp || new Response(JSON.stringify({ error: "Not found" }), { status: 404, headers: { "content-type": "application/json" } });
    }

    return new Response("not found", { status: 404 });
  },
});

console.log(`parallax-sink on :${server.port} (packages: ${Object.keys(meta).length})`);
