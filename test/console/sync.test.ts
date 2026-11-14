// One sync cycle with fake GitHub and CRACI clients: what it reads, what it writes, and when it judges a run.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CraciClient } from "../../src/craci.ts";
import { GithubError, type GhJob, type GhRun, type GithubClient } from "../../src/github.ts";
import { buildSnapshot, readJsonFile, stateDir, type GithubState } from "../../src/console/snapshot.ts";
import { newMemory, syncOnce } from "../../src/console/sync.ts";
import { fleetView, runView } from "../../src/console/views.ts";
import { at, ghJob } from "../factories.ts";

const REPO = "test-org/test-web";
let dir = "";
let before: string | undefined;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "plx-console-sync-"));
  before = process.env.PLX_RUNS_DIR;
  process.env.PLX_RUNS_DIR = dir;
});

afterAll(async () => {
  if (before === undefined) delete process.env.PLX_RUNS_DIR;
  else process.env.PLX_RUNS_DIR = before;
  await rm(dir, { recursive: true, force: true });
});

const run = (id: number, o: Partial<GhRun> = {}): GhRun => ({
  id,
  name: "ci",
  head_branch: "main",
  head_sha: "0123456789abcdef0123456789abcdef01234567",
  event: "push",
  status: "completed",
  conclusion: "success",
  run_attempt: 1,
  created_at: at(0),
  updated_at: at(5),
  run_started_at: at(0),
  html_url: `https://github.com/${REPO}/actions/runs/${id}`,
  ...o,
});

function fakes(runs: GhRun[], jobs: Record<number, GhJob[]>) {
  const calls = { listRuns: 0, listJobs: [] as number[], getRun: [] as number[], active: 0 };
  const github = {
    listRuns: async () => (calls.listRuns++, runs),
    listJobs: async (_repo: string, id: number | string) => (calls.listJobs.push(Number(id)), jobs[Number(id)] ?? []),
    getRun: async (_repo: string, id: number | string) => {
      calls.getRun.push(Number(id));
      throw new GithubError(404, "Not Found", "synthetic");
    },
    listCaches: async () => [],
  } as unknown as GithubClient;
  const craci = {
    listActiveJobs: async () => (calls.active++, { jobs: [{ repository: REPO, jobId: "77", runId: "502", name: "build (bare)", status: "running" }, { repository: "someone/else", jobId: "1" }] }),
    getNetworkTrace: async () => null,
    getSbom: async () => null,
    getJobLogs: async () => "",
    getGhaCacheProvenance: async () => null,
    getOciManifestProvenance: async () => null,
    getOciBlobProvenance: async () => null,
  } as unknown as CraciClient;
  return { github, craci, calls };
}

describe("syncOnce", () => {
  test("reads GitHub cheaply, writes the state, and judges only runs whose two twins have finished", async () => {
    const jobs = {
      501: [ghJob({ id: 11, run_id: 501, name: "build (bare)" }), ghJob({ id: 12, run_id: 501, name: "build (decoy)" }), ghJob({ id: 13, run_id: 501, name: "release", conclusion: "skipped" })],
      502: [ghJob({ id: 21, run_id: 502, name: "build (bare)", status: "in_progress", conclusion: null, completed_at: null }), ghJob({ id: 22, run_id: 502, name: "build (decoy)" })],
    };
    const f = fakes([run(502, { status: "in_progress", conclusion: null }), run(501)], jobs);
    const judged: string[] = [];
    const memory = newMemory();
    let clock = Date.parse(at(10));
    const o = { repos: [REPO], github: f.github, craci: f.craci, memory, runVerdict: async (repo: string, id: string) => void judged.push(`${repo}#${id}`), now: () => clock };

    const first = await syncOnce(o);
    await Promise.all(first.verdicts);
    expect(first.errors).toEqual([]);
    expect(judged).toEqual([`${REPO}#501`]);
    expect(first.fleetSynced).toEqual([REPO]);

    const state = (await readJsonFile<GithubState>(join(stateDir(), "github.json")))!;
    expect(state.repos[REPO]!.runs.map((r) => r.id)).toEqual(["502", "501"]);
    expect(state.repos[REPO]!.jobs["501"]!.map((j) => j.name)).toEqual(["build (bare)", "build (decoy)", "release"]);
    expect(state.repos[REPO]!.complete).toBe(true);
    const active = (await readJsonFile<{ jobs: { repository: string }[] }>(join(stateDir(), "active.json")))!;
    expect(active.jobs.map((j) => j.repository)).toEqual([REPO]); // other people's jobs are dropped

    // The next cycle, seconds later: the finished run is not read again, the running one is, and nothing is judged twice.
    f.calls.listJobs.length = 0;
    clock += 5000;
    const second = await syncOnce(o);
    await Promise.all(second.verdicts);
    expect(f.calls.listJobs).toEqual([502]);
    expect(judged.length).toBe(1);
    expect(second.fleetSynced).toEqual([]);

    // What the console then shows is exactly that state: one run without a verdict yet, one running.
    const snap = await buildSnapshot();
    expect(snap.github.repos[REPO]!.runs.length).toBe(2);
    const rv = runView({ ...snap, repos: [REPO] }, REPO, "501")!;
    expect(rv.run.verdict).toBeNull();
    expect(rv.gate.job?.conclusion).toBe("skipped");
    const fv = fleetView({ ...snap, repos: [REPO], active: active.jobs as any });
    expect(fv.repos[0]!.runs.map((r) => r.runId)).toEqual(["502", "501"]);
  });

  test("a GitHub failure is reported, not hidden, and the last known runs stay", async () => {
    const f = fakes([run(501)], {});
    const broken = { ...f.github, listRuns: async () => Promise.reject(new Error("rate limited")) } as unknown as GithubClient;
    const r = await syncOnce({ repos: [REPO], github: broken, craci: f.craci, memory: newMemory(), runVerdict: async () => {}, now: () => Date.parse(at(20)) });
    expect(r.errors.join(" ")).toContain("rate limited");
    expect(r.github.repos[REPO]!.error).toContain("rate limited");
    expect(r.github.repos[REPO]!.runs.map((x) => x.id)).toEqual(["502", "501"]);
  });
});
