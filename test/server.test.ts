// The console server: routes, the fixture banner, ingest and the pusher, live logs, and the fence switch.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CraciClient } from "../src/craci.ts";
import type { GithubClient } from "../src/github.ts";
import { pushOnce } from "../src/console/push.ts";
import { buildSnapshot, emptySnapshot, logFile, offlineCraci, snapshotHash, type Snapshot } from "../src/console/snapshot.ts";
import type { ReplayDef } from "../src/console/views.ts";
import { createApp, loadReplays } from "../src/server.ts";
import { buildFixtureDir, RUNS, WEB } from "./console/fixture.ts";

let dir = "";
let before: string | undefined;
let fixtureSnap: Snapshot;
/** The same content as the fixture, as a box would hold it for real (so it may be pushed). */
let boxSnap: Snapshot;
let defs: ReplayDef[];
const TOKEN = "test-ingest-token-0123456789";

const get = (app: { fetch: (r: Request) => Promise<Response> }, path: string, init?: RequestInit) => app.fetch(new Request(`http://console.test${path}`, init));

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "plx-console-server-"));
  before = process.env.PLX_RUNS_DIR;
  process.env.PLX_RUNS_DIR = dir;
  await buildFixtureDir(dir);
  fixtureSnap = await buildSnapshot({ fixture: true });
  boxSnap = { ...fixtureSnap, fixture: false };
  defs = JSON.parse(await readFile(join(dir, "replays.json"), "utf8")).replays;
});

afterAll(async () => {
  if (before === undefined) delete process.env.PLX_RUNS_DIR;
  else process.env.PLX_RUNS_DIR = before;
  await rm(dir, { recursive: true, force: true });
});

const fixtureApp = () => createApp({ mode: "box", fixture: true, replays: defs, cacheCraci: offlineCraci(), loadSnapshot: () => buildSnapshot({ fixture: true }) });
const publicApp = (extra: Partial<Parameters<typeof createApp>[0]> = {}) => createApp({ mode: "public", ingestToken: TOKEN, replays: defs, ...extra });

describe("pages", () => {
  test("with PLX_FIXTURE every page carries the banner", async () => {
    for (const path of ["/", "/anything/else"]) {
      const res = await get(fixtureApp(), path);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/html");
      expect(await res.text()).toContain("Fixture data, not real.");
    }
  });

  test("without it there is no banner", async () => {
    const html = await (await get(publicApp(), "/")).text();
    expect(html).not.toContain("Fixture data");
    expect(html).not.toContain("<!--FIXTURE-->");
  });

  test("the script bundles, static files are served, and nothing outside ui/ is", async () => {
    const app = publicApp();
    const js = await get(app, "/app.js");
    expect(js.status).toBe(200);
    expect(js.headers.get("content-type")).toContain("javascript");
    expect((await js.text()).length).toBeGreaterThan(5000);
    expect((await get(app, "/style.css")).status).toBe(200);
    expect((await get(app, "/fonts/ibm-plex-sans-400.woff2")).headers.get("content-type")).toBe("font/woff2");
    expect((await get(app, "/../package.json")).headers.get("content-type")).toContain("text/html");
    expect((await get(app, "/nope.css")).status).toBe(404);
    const csp = (await get(app, "/")).headers.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'self'");
    expect(csp).not.toContain("unsafe-inline");
  });

  test("the page links to no host other than GitHub", async () => {
    const js = await (await get(publicApp(), "/app.js")).text();
    const hosts = new Set([...js.matchAll(/https?:\/\/([a-z0-9.-]+)/gi)].map((m) => m[1]!.toLowerCase()));
    hosts.delete("github.com");
    hosts.delete("www.w3.org"); // the SVG namespace, not a link
    expect([...hosts]).toEqual([]);
  });
});

describe("api", () => {
  test("/api/state gives the fleet and the replays, and answers 304 when nothing moved", async () => {
    const app = fixtureApp();
    const res = await get(app, "/api/state");
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.config).toEqual({ mode: "box", fixture: true, allowFence: false, liveLogs: false });
    expect(body.fleet.repos.length).toBe(3);
    expect(body.replays.find((r: any) => r.id === "shai-hulud").state).toBe("caught");
    const again = await get(app, "/api/state", { headers: { "if-none-match": res.headers.get("etag")! } });
    expect(again.status).toBe(304);
  });

  test("/api/run gives the twin view, and 404 for a run nobody knows", async () => {
    const app = fixtureApp();
    const v = await (await get(app, `/api/run?repo=${WEB}&run=${RUNS.shai}`)).json() as any;
    expect(v.run.verdict).toBe("divergent");
    expect(v.rows.filter((r: any) => r.state === "divergent").length).toBe(2);
    expect(v.gate.state).toBe("not_started");
    expect((await get(app, `/api/run?repo=${WEB}&run=31337`)).status).toBe(404);
  });

  test("/api/rings without a seed offers seeds; with one it gives rings and a dry run", async () => {
    const app = fixtureApp();
    const none = await (await get(app, "/api/rings")).json() as any;
    expect(none.rings).toBeNull();
    expect(none.allowFence).toBe(false);
    const r = await (await get(app, "/api/rings?seed=plx-sink.test")).json() as any;
    expect(r.rings.length).toBe(4);
    expect(r.rings[0].length).toBeGreaterThan(0);
    expect(r.fence.dryRun).toBe(true);
    expect((await get(app, `/api/rings?seed=${"x".repeat(700)}`)).status).toBe(400);
  });

  test("writes are refused", async () => {
    const app = fixtureApp();
    expect((await get(app, "/api/state", { method: "POST" })).status).toBe(405);
    expect((await get(app, "/api/unknown")).status).toBe(404);
    expect((await get(app, "/ingest", { method: "POST" })).status).toBe(404); // box mode has no ingest
  });
});

describe("the fence", () => {
  const github = {} as GithubClient;
  const post = (app: any, headers: Record<string, string> = {}) =>
    get(app, "/api/fence", { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ seed: "plx-sink.test" }) });

  test("is not reachable on the public app, whatever it is started with", async () => {
    const app = createApp({ mode: "public", ingestToken: TOKEN, allowFence: true, github, initial: boxSnap });
    expect((await post(app, { "x-plx-confirm": "apply", authorization: `Bearer ${TOKEN}` })).status).toBe(404);
    expect((await (await get(app, "/api/state")).json() as any).config.allowFence).toBe(false);
  });

  test("is not reachable on the box without PLX_ALLOW_FENCE, nor with fixture data", async () => {
    const off = createApp({ mode: "box", github, loadSnapshot: async () => boxSnap });
    expect((await post(off, { "x-plx-confirm": "apply" })).status).toBe(404);
    const fx = createApp({ mode: "box", fixture: true, allowFence: true, github, loadSnapshot: async () => fixtureSnap });
    expect((await post(fx, { "x-plx-confirm": "apply" })).status).toBe(404);
    expect((await (await get(fx, "/api/rings?seed=plx-sink.test")).json() as any).allowFence).toBe(false);
  });

  test("with PLX_ALLOW_FENCE it still wants the confirmation header", async () => {
    const on = createApp({ mode: "box", allowFence: true, github, loadSnapshot: async () => boxSnap });
    expect((await (await get(on, "/api/state")).json() as any).config.allowFence).toBe(true);
    expect((await post(on)).status).toBe(400);
    expect((await get(on, "/api/fence")).status).toBe(400);
  });
});

describe("ingest and the pusher", () => {
  test("needs the bearer secret", async () => {
    const app = publicApp();
    expect((await get(app, "/ingest")).status).toBe(401);
    expect((await get(app, "/ingest", { headers: { authorization: "Bearer wrong" } })).status).toBe(401);
    expect((await get(app, "/ingest", { method: "POST", headers: { authorization: `Bearer ${TOKEN}x` }, body: "{}" })).status).toBe(401);
    expect((await get(createApp({ mode: "public" }), "/ingest", { headers: { authorization: "Bearer " } })).status).toBe(503);
    expect(app.lastContact).toBeNull();
  });

  test("starts empty: the fleet's repos, no runs, nothing invented", async () => {
    const body = await (await get(publicApp(), "/api/state")).json() as any;
    expect(body.lastContact).toBeNull();
    expect(body.fleet.generatedAt).toBeNull();
    expect(body.fleet.repos.length).toBeGreaterThan(0);
    expect(body.fleet.repos.every((r: any) => r.runs.length === 0)).toBe(true);
    expect(body.fleet.active).toEqual([]);
    expect(body.replays.every((r: any) => r.state === "not_run" || r.state === "not_set_up")).toBe(true);
  });

  test("refuses fixture data and things that are not snapshots", async () => {
    const app = publicApp();
    const send = (payload: unknown) =>
      get(app, "/ingest", { method: "POST", headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(payload) });
    expect((await send({ snapshot: fixtureSnap })).status).toBe(422);
    expect((await send({ snapshot: { v: 1 } })).status).toBe(422);
    expect((await send({ log: { repo: "someone/else", jobId: "1", text: "x" } })).status).toBe(422);
    expect((await get(app, "/ingest", { method: "POST", headers: { authorization: `Bearer ${TOKEN}` }, body: "not json" })).status).toBe(400);
    expect((await (await get(app, "/api/state")).json() as any).fleet.repos.every((r: any) => r.runs.length === 0)).toBe(true);
  });

  test("the pusher sends the snapshot and the finished logs once, then only when something changed", async () => {
    const app = publicApp();
    const viaApp = ((input: any, init: any) => app.fetch(new Request(String(input), init))) as unknown as typeof fetch;
    const o = { url: "http://console.test/", token: TOKEN, fetch: viaApp, snapshot: async () => boxSnap };
    const first = await pushOnce(o);
    expect(first.pushedSnapshot).toBe(true);
    expect(first.pushedLogs).toBe(boxSnap.logs.length);
    expect(first.hash).toBe(snapshotHash(boxSnap));
    expect(app.lastContact).not.toBeNull();

    const state = await (await get(app, "/api/state")).json() as any;
    expect(state.fleet.repos.find((r: any) => r.repo === WEB).runs.some((r: any) => r.runId === RUNS.shai && r.verdict === "divergent")).toBe(true);
    const run = await (await get(app, `/api/run?repo=${WEB}&run=${RUNS.shai}`)).json() as any;
    const log = await get(app, `/api/logs?repo=${WEB}&job=${run.twins.decoy.jobId}`);
    expect(log.status).toBe(200);
    expect(log.headers.get("x-plx-log")).toBe("finished");
    expect(await log.text()).toBe(await readFile(logFile(WEB, run.twins.decoy.jobId), "utf8"));

    const second = await pushOnce(o);
    expect(second.pushedSnapshot).toBe(false);
    expect(second.pushedLogs).toBe(0);

    const moved = { ...boxSnap, verdicts: boxSnap.verdicts.slice(1) };
    expect((await pushOnce({ ...o, snapshot: async () => moved })).pushedSnapshot).toBe(true);
  });

  test("the pusher refuses fixture data and a wrong secret", async () => {
    const app = publicApp();
    const viaApp = ((input: any, init: any) => app.fetch(new Request(String(input), init))) as unknown as typeof fetch;
    await expect(pushOnce({ url: "http://console.test", token: TOKEN, fetch: viaApp, snapshot: async () => fixtureSnap })).rejects.toThrow("fixture");
    await expect(pushOnce({ url: "http://console.test", token: "wrong", fetch: viaApp, snapshot: async () => boxSnap })).rejects.toThrow("401");
  });
});

describe("logs", () => {
  test("only for jobs the console knows", async () => {
    const app = fixtureApp();
    expect((await get(app, `/api/logs?repo=${WEB}&job=424242`)).status).toBe(404);
    expect((await get(app, "/api/logs?repo=../etc&job=1")).status).toBe(404);
    expect((await get(app, "/api/logs?repo=a/b/c&job=1")).status).toBe(400);
    expect((await get(app, `/api/logs?repo=${WEB}&job=abc`)).status).toBe(400);
  });

  test("a finished log comes from the API cache on the box", async () => {
    const app = fixtureApp();
    const run = await (await get(app, `/api/run?repo=${WEB}&run=${RUNS.shai}`)).json() as any;
    const res = await get(app, `/api/logs?repo=${WEB}&job=${run.twins.bare.jobId}`);
    expect(res.status).toBe(200);
    expect((await res.text()).length).toBeGreaterThan(20);
  });

  test("a running twin's log is followed live from CRACI, line by line", async () => {
    const enc = new TextEncoder();
    const asked: URL[] = [];
    const craciFetch = (async (input: any) => {
      const url = new URL(String(input));
      asked.push(url);
      if (url.pathname.endsWith("/jobs")) return Response.json({ jobs: boxSnap.active });
      if (url.pathname.endsWith("/job-logs") && url.searchParams.get("follow") === "true") {
        const stream = new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(enc.encode("2026-11-14T11:58:01Z npm ci\n2026-11-14T11:58:02Z added 2 pack"));
            c.enqueue(enc.encode("ages\n2026-11-14T11:58:03Z done\n"));
            c.close();
          },
        });
        return new Response(stream, { headers: { "content-type": "text/plain" } });
      }
      return new Response(JSON.stringify({ title: "nope", status: 404 }), { status: 404, headers: { "content-type": "application/problem+json" } });
    }) as unknown as typeof fetch;
    const craci = new CraciClient({ token: "test-token", cacheDir: null, fetch: craciFetch, maxRetries: 0 });
    const app = createApp({ mode: "public", ingestToken: TOKEN, craci, initial: boxSnap });

    const run = await (await get(app, `/api/run?repo=${WEB}&run=${RUNS.live}`)).json() as any;
    expect(run.liveLogs).toBe(true);
    expect(run.twins.bare.running).toBe(true);
    const res = await get(app, `/api/logs?repo=${WEB}&job=${run.twins.bare.jobId}&follow=1`);
    expect(res.status).toBe(200);
    expect(res.headers.get("x-plx-log")).toBe("live");
    const lines = (await res.text()).split("\n").filter(Boolean);
    expect(lines.length).toBe(3);
    expect(lines[1]).toContain("added 2 packages");
    const follow = asked.find((u) => u.pathname.endsWith("/job-logs"))!;
    expect(follow.searchParams.get("repo")).toBe(WEB);
    expect(follow.searchParams.get("job_id")).toBe(run.twins.bare.jobId);

    // A finished job is never followed: its stored log is served instead.
    const done = await (await get(app, `/api/run?repo=${WEB}&run=${RUNS.shai}`)).json() as any;
    const fin = await get(app, `/api/logs?repo=${WEB}&job=${done.twins.bare.jobId}&follow=1`);
    expect(fin.headers.get("x-plx-log")).not.toBe("live");
  });
});

describe("replays.json", () => {
  test("covers the spec's replays and names no owner", async () => {
    const real = await loadReplays(join(import.meta.dir, "..", "replays.json"));
    expect(real.length).toBe(10);
    expect(new Set(real.map((r) => r.id)).size).toBe(10);
    for (const r of real) {
      expect(r.incident.length).toBeGreaterThan(3);
      if (r.repo !== null) expect(r.repo).not.toContain("/");
      // a replay with a repo says where in it: a branch, a run, a workflow, an event or a finding to look for
      const where = [r.branch, r.runId, r.workflow, r.event, r.match].filter(Boolean).length;
      expect(r.repo === null ? where === 0 : where > 0).toBe(true);
    }
    const rows = (await (await get(createApp({ mode: "public", replays: real, initial: await emptySnapshot() }), "/api/state")).json() as any).replays;
    expect(rows.every((r: any) => r.state === "not_run" || r.state === "not_set_up")).toBe(true);
  });
});
