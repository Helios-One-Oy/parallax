// End to end: the real CLI as a subprocess against a local stand-in for the GitHub and CRACI APIs.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "../src/cli.ts";
import type { CycloneDxBom, NetworkTrace } from "../src/types.ts";
import { ghJob, httpObs, npmBuild, sbom, trace } from "./factories.ts";

const REPO = "test-org/test-web";
const ROOT = join(import.meta.dir, "..");
const PURLS = ["pkg:npm/left-pad@1.3.0"];

let server: ReturnType<typeof Bun.serve>;
let dir: string;
const traces = new Map<string, NetworkTrace>();
const sboms = new Map<string, CycloneDxBom>();
const seenAuth = new Set<string>();

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const problem = (status: number) => json({ type: "about:blank", title: "Not Found", status, detail: "synthetic" }, status);

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "plx-cli-test-"));
  server = Bun.serve({
    port: 0,
    fetch(req) {
      const u = new URL(req.url);
      seenAuth.add(req.headers.get("authorization") ?? "");
      const p = u.pathname;
      // --- GitHub ---
      if (p === `/repos/${REPO}/actions/runs/9001/jobs`)
        return json({ jobs: [ghJob({ id: 70001, run_id: 9001, name: "build (bare)" }, 30), ghJob({ id: 70002, run_id: 9001, name: "build (decoy)" }, 30)] });
      if (p === `/repos/${REPO}/actions/runs/9000/jobs`)
        return json({ jobs: [ghJob({ id: 69001, run_id: 9000, name: "build (bare)" }, 0), ghJob({ id: 69002, run_id: 9000, name: "build (decoy)" }, 0)] });
      if (p === `/repos/${REPO}/actions/runs/8000/jobs`) return json({ jobs: [ghJob({ id: 68001, run_id: 8000, name: "lint" }, 0)] });
      if (p === `/repos/${REPO}/actions/runs/9001`)
        return json({ id: 9001, head_branch: "main", head_sha: "0123456789abcdef0123456789abcdef01234567", event: "push", status: "in_progress", conclusion: null, created_at: "2026-11-14T10:29:00Z", updated_at: "2026-11-14T10:35:00Z", html_url: "" });
      if (p === `/repos/${REPO}/actions/runs`)
        return json({ workflow_runs: [{ id: 9000, head_branch: "main", head_sha: "f".repeat(40), event: "push", status: "completed", conclusion: "success", created_at: "2026-11-14T09:59:00Z", updated_at: "2026-11-14T10:05:00Z", html_url: "" }] });
      // --- CRACI ---
      const id = u.searchParams.get("job_id") ?? "";
      if (p === "/v1preview1/network-trace") return traces.has(id) ? json(traces.get(id)) : problem(404);
      if (p === "/v1preview1/sbom") return sboms.has(id) ? json(sboms.get(id)) : problem(404);
      return problem(404);
    },
  });
});

afterAll(async () => {
  server.stop(true);
  await rm(dir, { recursive: true, force: true });
});

async function cli(runsDir: string, ...args: string[]) {
  const p = Bun.spawn(["bun", "src/cli.ts", ...args], {
    cwd: ROOT,
    stdout: "pipe",
    stderr: "pipe",
    env: {
      PATH: process.env.PATH ?? "",
      HOME: join(dir, "home"),
      CRACI_API_URL: `http://127.0.0.1:${server.port}`,
      GITHUB_API_URL: `http://127.0.0.1:${server.port}`,
      CRACI_API_TOKEN: "craci-test-token",
      GITHUB_TOKEN: "github-test-token",
      PLX_RUNS_DIR: runsDir,
    },
  });
  const [stdout, stderr, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  return { stdout, stderr, code };
}

function seed(decoyExtra: any[] = [], opts: { decoyTrace?: boolean } = {}) {
  traces.clear();
  sboms.clear();
  const meta = { repository: REPO, runId: "9001" };
  traces.set("70001", trace(npmBuild(), { ...meta, jobId: "70001", jobName: "build (bare)" }, 30));
  if (opts.decoyTrace !== false) traces.set("70002", trace([...npmBuild({ ip: "151.101.2.137" }), ...decoyExtra], { ...meta, jobId: "70002", jobName: "build (decoy)" }, 30));
  traces.set("69001", trace(npmBuild(), { repository: REPO, runId: "9000", jobId: "69001", jobName: "build (bare)" }, 0));
  for (const id of ["70001", "70002", "69001"]) sboms.set(id, sbom(PURLS));
}

const verdictArgs = (summary: string) => ["verdict", "--repo", REPO, "--run", "9001", "--json", "--wait", "0", "--wait-trace", "0", "--summary", summary];

describe("cli verdict", () => {
  test("clean run: exit 0, verdict file written, summary written, tokens never printed", async () => {
    seed();
    const runs = join(dir, "clean");
    const r = await cli(runs, ...verdictArgs(join(dir, "clean.md")));
    expect(r.code).toBe(0);
    const v = JSON.parse(r.stdout);
    expect(v.status).toBe("clean");
    expect(v.twins.bare).toMatchObject({ jobId: "70001", name: "build (bare)", status: "success" });
    expect(v.commitSha).toBe("0123456789abcdef0123456789abcdef01234567");
    expect(JSON.parse(await readFile(join(runs, "verdicts", REPO, "9001.json"), "utf8"))).toEqual(v);
    const md = await readFile(join(dir, "clean.md"), "utf8");
    expect(md).toContain("Clean");
    expect(md).toContain("Compared against 1 earlier bare run");
    // the finished traces were cached under the runs dir
    expect(JSON.parse(await readFile(join(runs, "api", REPO, "70001", "trace.json"), "utf8")).job.jobId).toBe("70001");
    expect(r.stdout + r.stderr + md).not.toContain("test-token");
    expect(seenAuth.has("Bearer craci-test-token")).toBe(true);
  }, 30_000);

  test("divergent run: exit 1, two divergences, marked new in the fleet, policy in the summary", async () => {
    seed([httpObs("https://plx-sink.test/stage2/x.txt"), httpObs("https://plx-sink.test/collect", { method: "POST" })]);
    const r = await cli(join(dir, "div"), ...verdictArgs(join(dir, "div.md")));
    expect(r.code).toBe(1);
    const v = JSON.parse(r.stdout);
    expect(v.status).toBe("divergent");
    expect(v.divergences).toHaveLength(2);
    expect(v.divergences.every((d: any) => d.side === "decoy-only" && d.novelInFleet === true)).toBe(true);
    const md = await readFile(join(dir, "div.md"), "utf8");
    expect(md).toContain("| decoy only | `http POST plx-sink.test/collect` (new in the fleet) |");
    expect(md).toContain("cracicorp/setup@v1");
    expect(md).toContain("# stays blocked: plx-sink.test");
  }, 30_000);

  test("missing decoy trace: exit 2, inconclusive", async () => {
    seed([], { decoyTrace: false });
    const r = await cli(join(dir, "inc"), ...verdictArgs(join(dir, "inc.md")));
    expect(r.code).toBe(2);
    expect(JSON.parse(r.stdout).status).toBe("inconclusive");
    expect(await readFile(join(dir, "inc.md"), "utf8")).toContain("The decoy twin has no network trace on CRACI.");
  }, 30_000);

  test("a run without twin jobs is inconclusive, not a crash", async () => {
    const r = await cli(join(dir, "none"), "verdict", "--repo", REPO, "--run", "8000", "--json", "--wait", "0", "--wait-trace", "0", "--history", "0");
    expect(r.code).toBe(2);
    const v = JSON.parse(r.stdout);
    expect(v.status).toBe("inconclusive");
    expect(v.twins.bare).toEqual({ jobId: "", name: "build (bare)", status: "missing", url: "" });
    expect(v.runId).toBe("8000");
  }, 30_000);

  test("GitHub or CRACI being down is exit 2, never a pass", async () => {
    const r = await cli(join(dir, "down"), "verdict", "--repo", REPO, "--run", "7000", "--json", "--wait", "0");
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("parallax:");
  }, 30_000);
});

describe("cli fleet commands on an empty index", () => {
  test("rings, drift, notfound and egress answer plainly", async () => {
    const runs = join(dir, "empty");
    const rings = await cli(runs, "rings", "--seed", "pkg:npm/plx-specimen@9.9.9");
    expect(rings.code).toBe(0);
    expect(rings.stdout).toContain("R0 = 0.00");
    expect((await cli(runs, "drift")).stdout).toContain("no URL changed its bytes across 0 indexed jobs");
    expect((await cli(runs, "notfound")).stdout).toContain("no registry 404");
    expect((await cli(runs, "egress")).code).toBe(0);
    expect((await cli(runs, "lineage")).stdout).toContain("no trusted job restored a cache");
    expect((await cli(runs, "images")).stdout).toContain("no job pulled an image of ours");
    const help = await cli(runs);
    expect(help.stdout).toContain("bun src/cli.ts verdict");
  }, 30_000);

  test("parseArgs", () => {
    expect(parseArgs(["verdict", "--repo", "a/b", "--json", "--run=5"])).toEqual({ _: ["verdict"], repo: "a/b", json: true, run: "5" });
  });
});

describe("verdict action", () => {
  test("action.yml is valid and wired as specified", async () => {
    const doc = Bun.YAML.parse(await readFile(join(ROOT, "verdict/action.yml"), "utf8")) as any;
    expect(doc.runs.using).toBe("composite");
    expect(Object.keys(doc.inputs)).toEqual(expect.arrayContaining(["craci-token", "github-token", "allow-inconclusive"]));
    expect(doc.runs.steps[0].uses).toBe("oven-sh/setup-bun@v2");
    const run: string = doc.runs.steps[1].run;
    expect(run).toContain('"$GITHUB_ACTION_PATH/../src/cli.ts" verdict');
    expect(run).toContain("$GITHUB_STEP_SUMMARY");
    expect(doc.runs.steps[1].env.CRACI_API_TOKEN).toBe("${{ inputs.craci-token }}");
  });
});
