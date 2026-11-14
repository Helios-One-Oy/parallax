#!/usr/bin/env bun
// Parallax console: a JSON API and a static UI.
//   bun src/server.ts                       on the box: reads PLX_RUNS_DIR, re-syncs when tokens are at hand
//   PLX_MODE=public bun src/server.ts       the public app: holds what the box pushes to POST /ingest
// Env: PORT (8787), PLX_RUNS_DIR, PLX_SYNC_SECONDS (30, 0 = off), PLX_FIXTURE=1 (development only),
//      PLX_ALLOW_FENCE=1 (box only), PLX_INGEST_TOKEN (public only), CRACI_API_TOKEN (read-only, for live logs).
import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CraciClient } from "./craci.ts";
import { loadFleetRepos } from "./fleet.ts";
import { GithubClient, readGithubToken } from "./github.ts";
import { ringFence } from "./graph.ts";
import { runsDir } from "./paths.ts";
import type { JobSummary } from "./types.ts";
import {
  buildSnapshot,
  emptySnapshot,
  liveCraci,
  newMemo,
  offlineCraci,
  readJsonFile,
  snapshotHash,
  snapshotProblem,
  type Snapshot,
} from "./console/snapshot.ts";
import { newMemory, syncOnce } from "./console/sync.ts";
import { fleetView, knownJob, replayRows, ringsFor, ringsView, runView, type ReplayDef } from "./console/views.ts";

export type AppOptions = {
  mode: "box" | "public";
  fixture?: boolean;
  allowFence?: boolean;
  /** Bearer secret for POST /ingest (public mode). */
  ingestToken?: string | null;
  /** Live CRACI client: running jobs and live logs. */
  craci?: CraciClient | null;
  /** Reads finished logs from the box's API cache (box mode). */
  cacheCraci?: CraciClient | null;
  /** Only used by the fence action. */
  github?: GithubClient | null;
  replays?: ReplayDef[];
  /** Box mode: builds the snapshot from the run directory. */
  loadSnapshot?: () => Promise<Snapshot>;
  /** Start value in public mode. */
  initial?: Snapshot;
  uiDir?: string;
  now?: () => number;
  /** How long a built snapshot is served before the disk is read again (box mode). */
  ttlMs?: number;
};

const MAX_LOG_BYTES = 3_000_000;
const MAX_LOGS_TOTAL = 48_000_000;
const MAX_STREAMS = 24;
const STREAM_MAX_MS = 20 * 60_000;

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
};

const SECURITY = {
  "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

export function createApp(o: AppOptions) {
  const now = o.now ?? Date.now;
  const fixture = !!o.fixture;
  const allowFence = o.mode === "box" && !!o.allowFence && !fixture;
  const uiDir = o.uiDir ?? join(import.meta.dir, "..", "ui");
  const replays = o.replays ?? [];

  // ---------- the snapshot ----------
  let snap: Snapshot | null = o.initial ?? null;
  let builtAt = 0;
  let building: Promise<Snapshot> | null = null;
  let lastContact: string | null = null;
  const logs = new Map<string, string>();
  let logBytes = 0;

  async function current(): Promise<Snapshot> {
    if (o.mode === "public" || !o.loadSnapshot) return (snap ??= await emptySnapshot(fixture));
    if (snap && now() - builtAt < (o.ttlMs ?? 3000)) return snap;
    building ??= o
      .loadSnapshot()
      .then((s) => {
        snap = s;
        builtAt = now();
        return s;
      })
      .catch(async (e) => {
        console.error(`snapshot: ${e instanceof Error ? e.message : String(e)}`);
        return (snap ??= await emptySnapshot(fixture));
      })
      .finally(() => {
        building = null;
      });
    return building;
  }

  // ---------- running jobs, live from CRACI when a token is at hand ----------
  let live: { at: number; iso: string; jobs: JobSummary[] } | null = null;
  let liveAsked = 0;
  let liveAsking: Promise<void> | null = null;
  async function liveActive(): Promise<{ jobs: JobSummary[]; at: string } | null> {
    if (!o.craci) return null;
    // One call to CRACI every 5 s at most, however many pages are open and whether or not it answered.
    if (now() - liveAsked >= 5000) {
      liveAsking ??= o.craci
        .listActiveJobs()
        .then(({ jobs }) => {
          live = { at: now(), iso: new Date(now()).toISOString(), jobs: jobs ?? [] };
        })
        .catch(() => {})
        .finally(() => {
          liveAsked = now();
          liveAsking = null;
        });
      await liveAsking;
    }
    return live ? { jobs: live.jobs, at: live.iso } : null;
  }

  // ---------- helpers ----------
  const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...SECURITY, ...extra } });
  const problem = (status: number, error: string) => json({ error }, status);

  function authorised(req: Request): boolean {
    if (!o.ingestToken) return false;
    const got = Buffer.from((req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, ""));
    const want = Buffer.from(o.ingestToken);
    return got.length === want.length && timingSafeEqual(got, want);
  }

  async function body(req: Request): Promise<any> {
    const raw = new Uint8Array(await req.arrayBuffer());
    const bytes = req.headers.get("content-encoding") === "gzip" ? Bun.gunzipSync(raw) : raw;
    return JSON.parse(new TextDecoder().decode(bytes));
  }

  // ---------- static UI ----------
  let bundle: Promise<string> | null = null;
  const script = () =>
    (bundle ??= Bun.build({ entrypoints: [join(uiDir, "app.ts")], target: "browser", minify: !process.env.PLX_DEV }).then(async (r) => {
      if (!r.success) throw new Error(r.logs.map(String).join("\n"));
      return await r.outputs[0]!.text();
    }));

  async function staticFile(path: string): Promise<Response> {
    const headers = { ...SECURITY, "cache-control": "no-cache" };
    if (path === "/app.js") {
      if (process.env.PLX_DEV) bundle = null;
      try {
        return new Response(await script(), { headers: { ...headers, "content-type": TYPES[".js"]! } });
      } catch (e) {
        bundle = null;
        return new Response(`console.error(${JSON.stringify(String(e))})`, { status: 500, headers: { ...headers, "content-type": TYPES[".js"]! } });
      }
    }
    const ext = /\.[a-z0-9]+$/.exec(path)?.[0] ?? "";
    if (ext && TYPES[ext] && /^\/[A-Za-z0-9_./-]+$/.test(path) && !path.includes("..")) {
      const f = Bun.file(join(uiDir, path));
      if (await f.exists()) return new Response(f, { headers: { ...headers, "content-type": TYPES[ext]!, ...(ext === ".woff2" ? { "cache-control": "public, max-age=604800" } : {}) } });
      return new Response("not found", { status: 404, headers });
    }
    let html = await readFile(join(uiDir, "index.html"), "utf8");
    html = html.replace("<!--FIXTURE-->", fixture ? '<p class="fixture" role="status">Fixture data, not real. Built from test factories for development.</p>' : "");
    return new Response(html, { headers: { ...headers, "content-type": TYPES[".html"]! } });
  }

  // ---------- logs ----------
  let streams = 0;

  async function logsRoute(url: URL, req: Request): Promise<Response> {
    const repo = url.searchParams.get("repo") ?? "";
    const jobId = url.searchParams.get("job") ?? "";
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo) || !/^\d+$/.test(jobId)) return problem(400, "repo and job are needed");
    const s = await current();
    let k = knownJob(s, repo, jobId);
    if (!k.known && s.repos.includes(repo)) {
      const act = await liveActive();
      if (act?.jobs.some((j) => j.repository === repo && String(j.jobId) === jobId)) k = { known: true, running: true };
    }
    if (!k.known) return problem(404, "This job is not one the console knows.");
    const text = { ...SECURITY, "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" };

    if (url.searchParams.get("follow") === "1" && o.craci && k.running) {
      if (streams >= MAX_STREAMS) return problem(503, "Too many live logs are open. Try again in a moment.");
      const craci = o.craci;
      const ac = new AbortController();
      req.signal.addEventListener("abort", () => ac.abort());
      const enc = new TextEncoder();
      const started = now();
      let lastChunk = now();
      let idle = 0;
      streams++;
      const stream = new ReadableStream<Uint8Array>({
        async start(ctrl) {
          const send = (line: string) => {
            try {
              ctrl.enqueue(enc.encode(line));
              lastChunk = now();
            } catch {
              ac.abort();
            }
          };
          const timer = setInterval(async () => {
            if (now() - started > STREAM_MAX_MS) return ac.abort();
            if (now() - lastChunk > 15_000) send(":\n"); // keeps the connection open through quiet stretches
            // Stop a little after the job has ended: CRACI keeps a followed log open for ever.
            const cur = knownJob(await current(), repo, jobId);
            const act = await liveActive();
            const running = cur.running || !!act?.jobs.some((j) => j.repository === repo && String(j.jobId) === jobId);
            idle = running ? 0 : idle + 1;
            if (idle >= 3) ac.abort();
          }, 5000);
          try {
            for await (const line of craci.followLogs(repo, jobId, { signal: ac.signal })) send(`${line.ts ?? ""}\t${line.text}\n`);
          } catch {
            /* CRACI closed the stream or the reader went away */
          } finally {
            clearInterval(timer);
            streams--;
            try {
              ctrl.close();
            } catch {
              /* already closed */
            }
          }
        },
        cancel() {
          ac.abort();
        },
      });
      return new Response(stream, { headers: { ...text, "x-plx-log": "live" } });
    }

    const key = `${repo}#${jobId}`;
    let out: string | null = logs.get(key) ?? null;
    for (const c of [o.cacheCraci, o.craci]) {
      if (out !== null || !c) continue;
      try {
        out = (await c.getJobLogs(repo, jobId, { cache: !k.running })) || null;
      } catch {
        out = null;
      }
    }
    if (out === null) return problem(404, "CRACI has no log for this job.");
    return new Response(out, { headers: { ...text, "x-plx-log": k.running ? "so-far" : "finished" } });
  }

  // ---------- ingest (public mode) ----------
  async function ingest(req: Request): Promise<Response> {
    if (!o.ingestToken) return problem(503, "Ingest is not configured.");
    if (!authorised(req)) return problem(401, "Not authorised.");
    const state = async () => ({ ok: true, hash: snap && snap.generatedAt ? snapshotHash(snap) : null, logs: [...logs.keys()] });
    lastContact = new Date(now()).toISOString();
    if (req.method === "GET") return json(await state());
    let b: any;
    try {
      b = await body(req);
    } catch {
      return problem(400, "The body is not JSON.");
    }
    if (b?.snapshot) {
      const bad = snapshotProblem(b.snapshot);
      if (bad) return problem(422, `Not a snapshot: ${bad}.`);
      if (b.snapshot.fixture && !fixture) return problem(422, "Fixture data is not accepted here.");
      snap = b.snapshot as Snapshot;
      // Work the views out once, now, so that no page has to wait for them.
      const fresh = snap;
      setTimeout(() => {
        try {
          fleetView(fresh);
        } catch (e) {
          console.error(`warm: ${e instanceof Error ? e.message : String(e)}`);
        }
      }, 0);
      const keep = new Set(snap.logs);
      for (const k of [...logs.keys()])
        if (!keep.has(k)) {
          logBytes -= logs.get(k)!.length;
          logs.delete(k);
        }
    }
    if (b?.log) {
      const { repo, jobId, text } = b.log as { repo?: string; jobId?: string; text?: string };
      const s = await current();
      if (typeof repo !== "string" || !s.repos.includes(repo) || typeof jobId !== "string" || !/^\d+$/.test(jobId) || typeof text !== "string")
        return problem(422, "Not a log of a fleet job.");
      const key = `${repo}#${jobId}`;
      const t = text.length > MAX_LOG_BYTES ? text.slice(-MAX_LOG_BYTES) : text;
      logBytes += t.length - (logs.get(key)?.length ?? 0);
      logs.delete(key);
      logs.set(key, t);
      for (const k of logs.keys()) {
        if (logBytes <= MAX_LOGS_TOTAL) break;
        logBytes -= logs.get(k)!.length;
        logs.delete(k);
      }
    }
    return json(await state());
  }

  // ---------- the routes ----------
  async function fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      if (path === "/healthz") return json({ ok: true });

      if (path === "/ingest") {
        if (o.mode !== "public") return problem(404, "Not found.");
        if (req.method !== "POST" && req.method !== "GET") return problem(405, "Use POST.");
        return await ingest(req);
      }

      if (path === "/api/fence") {
        // The route exists only on the box, and only when it was started with PLX_ALLOW_FENCE=1.
        if (!allowFence || !o.github) return problem(404, "Not found.");
        if (req.method !== "POST" || req.headers.get("x-plx-confirm") !== "apply") return problem(400, "Confirmation is missing.");
        const b = await body(req).catch(() => null);
        if (typeof b?.seed !== "string" || !b.seed.trim()) return problem(400, "A seed is needed.");
        const s = await current();
        const act = await liveActive();
        const result = await ringFence(ringsFor(s, b.seed), { dryRun: false, github: o.github, active: act?.jobs ?? s.active, policies: s.policies });
        return json(result);
      }

      if (req.method !== "GET" && req.method !== "HEAD") return problem(405, "Read only.");

      if (path === "/api/state") {
        const s = await current();
        const act = await liveActive();
        const fleet = fleetView(s, { live: act?.jobs, liveAt: act?.at });
        const payload = {
          config: { mode: o.mode, fixture, allowFence, liveLogs: !!o.craci },
          lastContact: o.mode === "public" ? lastContact : fleet.generatedAt,
          fleet,
          replays: replayRows(s, replays),
          fixes: s.fixes ?? [],
        };
        const text = JSON.stringify(payload);
        const etag = `"${new Bun.CryptoHasher("sha1").update(text).digest("hex")}"`;
        if (req.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers: { etag, ...SECURITY } });
        return new Response(text, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-cache", etag, ...SECURITY } });
      }

      if (path === "/api/run") {
        const repo = url.searchParams.get("repo") ?? "";
        const run = url.searchParams.get("run") ?? "";
        const s = await current();
        let v = runView(s, repo, run);
        if (!v) return problem(404, "The console does not know this run.");
        // A twin CRACI lists as running right now is running, whatever the last snapshot said.
        const act = await liveActive();
        if (act) {
          const twins = { ...v.twins };
          for (const which of ["bare", "decoy"] as const) {
            const t = twins[which];
            if (t && act.jobs.some((j) => j.repository === repo && String(j.jobId) === t.jobId)) twins[which] = { ...t, running: true };
          }
          v = { ...v, twins };
        }
        return json({ ...v, liveLogs: !!o.craci });
      }

      if (path === "/api/rings") {
        const seed = (url.searchParams.get("seed") ?? "").trim();
        const s = await current();
        if (!seed) return json({ seed: "", rings: null, suggestions: (await ringsView(s, "none.invalid")).suggestions, jobs: s.jobs.length, allowFence });
        if (seed.length > 600) return problem(400, "That seed is too long.");
        return json({ ...(await ringsView(s, seed)), allowFence });
      }

      if (path === "/api/logs") return await logsRoute(url, req);
      if (path.startsWith("/api/")) return problem(404, "Not found.");
      return await staticFile(path);
    } catch (e) {
      console.error(`${req.method} ${path}: ${e instanceof Error ? e.message : String(e)}`);
      return problem(500, "Something went wrong on the server.");
    }
  }

  return {
    fetch,
    /** For tests and the sync loop: forget the built snapshot so the next request reads the disk again. */
    invalidate: () => {
      builtAt = 0;
    },
    get lastContact() {
      return lastContact;
    },
  };
}

export async function loadReplays(file = process.env.PLX_REPLAYS_FILE || join(import.meta.dir, "..", "replays.json")): Promise<ReplayDef[]> {
  const doc = await readJsonFile<{ replays?: ReplayDef[] }>(file);
  return Array.isArray(doc?.replays) ? doc!.replays : [];
}

async function main() {
  const mode = process.env.PLX_MODE === "public" ? "public" : "box";
  const fixture = process.env.PLX_FIXTURE === "1";
  if (fixture && mode === "public") {
    console.error("parallax console: PLX_FIXTURE=1 is for development only and is refused in public mode.");
    process.exit(64);
  }
  const port = Number(process.env.PORT || 8787);
  const craci = liveCraci(fixture);
  const replays = await loadReplays(fixture ? join(runsDir(), "replays.json") : undefined).then(async (r) => (r.length ? r : await loadReplays()));
  const memo = newMemo();

  let github: GithubClient | null = null;
  if (mode === "box" && !fixture) {
    try {
      github = new GithubClient({ token: readGithubToken() });
    } catch {
      github = null;
    }
  }

  const app = createApp({
    mode,
    fixture,
    allowFence: process.env.PLX_ALLOW_FENCE === "1",
    ingestToken: process.env.PLX_INGEST_TOKEN?.trim() || null,
    craci,
    cacheCraci: mode === "box" ? offlineCraci() : null,
    github,
    replays,
    loadSnapshot: mode === "box" ? () => buildSnapshot({ fixture, memo }) : undefined,
  });

  const server = Bun.serve({
    port,
    hostname: process.env.PLX_HOST || (mode === "public" ? "0.0.0.0" : "127.0.0.1"),
    idleTimeout: 255,
    maxRequestBodySize: 96 * 1024 * 1024,
    fetch: app.fetch,
  });
  console.error(
    `parallax console (${mode}${fixture ? ", FIXTURE DATA" : ""}) on http://${server.hostname}:${server.port}` +
      `, live logs ${craci ? "on" : "off"}${mode === "box" ? `, runs dir ${runsDir()}` : `, ingest ${process.env.PLX_INGEST_TOKEN ? "on" : "off"}`}`,
  );

  // The box keeps the run directory fresh by itself when it can read both CRACI and GitHub.
  const every = Number(process.env.PLX_SYNC_SECONDS ?? 30);
  if (mode === "box" && !fixture && craci && github && every > 0) {
    const memory = newMemory();
    const repos = await loadFleetRepos();
    const tick = async () => {
      try {
        const r = await syncOnce({ repos, github: github!, craci, memory, log: (l) => console.error(l) });
        if (r.verdicts.length) void Promise.all(r.verdicts).then(() => app.invalidate());
        app.invalidate();
      } catch (e) {
        console.error(`sync: ${e instanceof Error ? e.message : String(e)}`);
      }
      setTimeout(tick, every * 1000);
    };
    void tick();
    console.error(`sync every ${every} s over ${repos.length} repos`);
  } else if (mode === "box" && !fixture) {
    console.error(`sync off (${every <= 0 ? "PLX_SYNC_SECONDS=0" : !craci ? "no CRACI token" : "no GitHub token"})`);
  }
}

if (import.meta.main) void main();
