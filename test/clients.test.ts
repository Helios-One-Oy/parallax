import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CraciClient, CraciError, parseLogLine } from "../src/craci.ts";
import { GithubClient } from "../src/github.ts";
import { npmBuild, trace } from "./factories.ts";

type Reply = { status: number; body?: unknown; text?: string; headers?: Record<string, string> };

function fakeFetch(replies: Reply[]) {
  const calls: Array<{ url: URL; method: string; auth: string | null; body: unknown }> = [];
  const impl = (async (input: any, init: any = {}) => {
    const url = new URL(String(input));
    const headers = new Headers(init.headers);
    calls.push({ url, method: init.method ?? "GET", auth: headers.get("authorization"), body: init.body ? JSON.parse(init.body) : undefined });
    const r = replies.shift();
    if (!r) throw new Error(`unexpected request ${url}`);
    return new Response(r.text ?? (r.body === undefined ? "" : JSON.stringify(r.body)), {
      status: r.status,
      headers: { "content-type": r.text !== undefined ? "text/plain" : "application/json", ...(r.headers ?? {}) },
    });
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const problem = (status: number, title: string) => ({ status, body: { type: "about:blank", title, status, detail: "synthetic" } });

function client(replies: Reply[], cacheDir: string | null = null) {
  const f = fakeFetch(replies);
  const sleeps: number[] = [];
  let clock = 0;
  const c = new CraciClient({
    token: "test-token",
    cacheDir,
    fetch: f.impl,
    sleep: async (ms) => {
      sleeps.push(ms);
      clock += ms;
    },
    now: () => clock,
  });
  return { c, sleeps, calls: f.calls };
}

describe("CraciClient", () => {
  test("lists active jobs with the bearer token", async () => {
    const { c, calls } = client([{ status: 200, body: { jobs: [] } }]);
    expect(await c.listActiveJobs()).toEqual({ jobs: [] });
    expect(calls[0]!.url.pathname).toBe("/v1preview1/jobs");
    expect(calls[0]!.url.searchParams.get("status")).toBe("active");
    expect(calls[0]!.auth).toBe("Bearer test-token");
  });

  test("retries 5xx and 429 with backoff, then gives up with a typed error that hides the token", async () => {
    const ok = client([problem(503, "Unavailable"), { status: 429, headers: { "retry-after": "2" } }, { status: 200, body: { jobs: [] } }]);
    expect(await ok.c.listActiveJobs()).toEqual({ jobs: [] });
    expect(ok.sleeps).toEqual([1000, 2000]);

    const bad = client(Array.from({ length: 6 }, () => problem(503, "Unavailable")));
    const err = await bad.c.listActiveJobs().catch((e) => e);
    expect(err).toBeInstanceOf(CraciError);
    expect(err.status).toBe(503);
    expect(String(err.message)).not.toContain("test-token");
  });

  test("waits on 404 and 409 for a fresh job's trace, then caches the finished trace on disk", async () => {
    const dir = await mkdtemp(join(tmpdir(), "plx-api-test-"));
    try {
      const t = trace(npmBuild());
      const { c, calls, sleeps } = client([problem(404, "Not Found"), problem(409, "Job is not terminal"), { status: 200, body: t }], dir);
      const got = await c.getNetworkTrace("test-org/test-web", "70001");
      expect(got!.observations).toHaveLength(t.observations.length);
      expect(sleeps.length).toBe(2);
      expect(Object.fromEntries(calls[0]!.url.searchParams)).toEqual({ provider: "github", repo: "test-org/test-web", job_id: "70001" });
      const onDisk = JSON.parse(await readFile(join(dir, "test-org/test-web/70001/trace.json"), "utf8"));
      expect(onDisk.job.jobId).toBe("70001");
      // second read: no request at all
      expect((await c.getNetworkTrace("test-org/test-web", "70001"))!.job.jobId).toBe("70001");
      expect(calls).toHaveLength(3);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("returns null when the trace never appears, and does not cache an empty trace", async () => {
    const dir = await mkdtemp(join(tmpdir(), "plx-api-test-"));
    try {
      const gone = client([problem(404, "Not Found")], dir);
      expect(await gone.c.getNetworkTrace("test-org/test-web", "1", { waitFor: 0 })).toBeNull();

      const waited = client(Array.from({ length: 50 }, () => problem(404, "Not Found")), dir);
      expect(await waited.c.getSbom("test-org/test-web", "2", { waitFor: 60_000 })).toBeNull();
      expect(waited.sleeps.reduce((a, b) => a + b, 0)).toBe(60_000);

      const empty = client([{ status: 200, body: trace([]) }, { status: 200, body: trace(npmBuild()) }], dir);
      expect((await empty.c.getNetworkTrace("test-org/test-web", "3"))!.observations).toEqual([]);
      expect((await empty.c.getNetworkTrace("test-org/test-web", "3"))!.observations.length).toBeGreaterThan(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("provenance selectors and bad input", async () => {
    const digest = "sha256:" + "0".repeat(64);
    const { c, calls } = client([{ status: 200, body: { artifact_id: "1", kind: "gha_cache", digest, jobs_created_in: [], refers: [] } }, problem(404, "Unknown artifact")]);
    expect((await c.getGhaCacheProvenance({ cacheId: 1234 }))!.kind).toBe("gha_cache");
    expect(calls[0]!.url.pathname).toBe("/v1preview1/artifact-provenance/gha_cache");
    expect(calls[0]!.url.searchParams.get("cache_id")).toBe("1234");
    expect(await c.getOciManifestProvenance(digest)).toBeNull();
    expect(calls[1]!.url.searchParams.get("digest")).toBe(digest);
    await expect(c.getOciBlobProvenance("../etc/passwd")).rejects.toThrow("bad digest");
    await expect(c.getNetworkTrace("../../x", "1")).rejects.toThrow("bad repo");
  });

  test("followLogs yields timestamped lines across chunk borders", async () => {
    const chunks = ["2026-11-14T10:00:00Z\tCache restored ", "from key: npm-linux-abc\n2026-11-14T10:00:01Z\tdone\nlast line without newline"];
    const body = new ReadableStream<Uint8Array>({
      start(ctrl) {
        for (const c of chunks) ctrl.enqueue(new TextEncoder().encode(c));
        ctrl.close();
      },
    });
    const c = new CraciClient({ token: "test-token", cacheDir: null, fetch: (async () => new Response(body, { status: 200 })) as unknown as typeof fetch });
    const lines = [];
    for await (const l of c.followLogs("test-org/test-web", "70001")) lines.push(l);
    expect(lines).toEqual([
      { ts: "2026-11-14T10:00:00Z", text: "Cache restored from key: npm-linux-abc" },
      { ts: "2026-11-14T10:00:01Z", text: "done" },
      { ts: null, text: "last line without newline" },
    ]);
    expect(parseLogLine("no tab here")).toEqual({ ts: null, text: "no tab here" });
  });
});

describe("GithubClient", () => {
  test("lists caches page by page and deletes one", async () => {
    const page = (n: number, from: number) => ({ status: 200, body: { total_count: 101, actions_caches: Array.from({ length: n }, (_, i) => ({ id: from + i, key: `k${from + i}`, ref: "refs/heads/main", created_at: "2026-11-14T10:00:00Z", size_in_bytes: 1 })) } });
    const f = fakeFetch([page(100, 0), page(1, 100), { status: 204 }]);
    const gh = new GithubClient({ token: "gh-test", fetch: f.impl, baseUrl: "https://api.github.test" });
    const caches = await gh.listCaches("test-org/test-web");
    expect(caches).toHaveLength(101);
    expect(f.calls[1]!.url.searchParams.get("page")).toBe("2");
    await gh.deleteCache("test-org/test-web", 100);
    expect(f.calls[2]!.method).toBe("DELETE");
    expect(f.calls[2]!.url.pathname).toBe("/repos/test-org/test-web/actions/caches/100");
  });

  test("branch + commit + pull request", async () => {
    const f = fakeFetch([
      { status: 200, body: { default_branch: "main" } },
      { status: 200, body: { object: { sha: "abc" } } },
      { status: 201, body: { ref: "refs/heads/parallax/fence-x" } },
      { status: 404, body: { message: "Not Found" } },
      { status: 201, body: { content: {} } },
      { status: 201, body: { number: 7, html_url: "https://github.test/pull/7" } },
    ]);
    const gh = new GithubClient({ token: "gh-test", fetch: f.impl, baseUrl: "https://api.github.test" });
    const pr = await gh.createPullRequest("test-org/test-web", {
      branch: "parallax/fence-x",
      title: "t",
      body: "b",
      message: "m",
      files: [{ path: ".github/parallax/network-policy.yml", content: "default: deny\n" }],
    });
    expect(pr).toEqual({ number: 7, html_url: "https://github.test/pull/7" });
    expect(f.calls.map((c) => `${c.method} ${c.url.pathname}`)).toEqual([
      "GET /repos/test-org/test-web",
      "GET /repos/test-org/test-web/git/ref/heads/main",
      "POST /repos/test-org/test-web/git/refs",
      "GET /repos/test-org/test-web/contents/.github/parallax/network-policy.yml",
      "PUT /repos/test-org/test-web/contents/.github/parallax/network-policy.yml",
      "POST /repos/test-org/test-web/pulls",
    ]);
    expect((f.calls[4]!.body as any).branch).toBe("parallax/fence-x");
    expect(Buffer.from((f.calls[4]!.body as any).content, "base64").toString()).toBe("default: deny\n");
    expect((f.calls[5]!.body as any).base).toBe("main");
  });
});
