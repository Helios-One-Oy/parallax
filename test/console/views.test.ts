// The console's views over a fixture run directory: everything shown is what the core computed.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildSnapshot, emptySnapshot, snapshotHash, snapshotProblem, type Snapshot } from "../../src/console/snapshot.ts";
import { fleetView, knownJob, replayRows, ringsView, runView, type ReplayDef } from "../../src/console/views.ts";
import { buildFixtureDir, REPOS, RUNS, WEB } from "./fixture.ts";

let dir = "";
let before: string | undefined;
let snap: Snapshot;
let defs: ReplayDef[];

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "plx-console-views-"));
  before = process.env.PLX_RUNS_DIR;
  process.env.PLX_RUNS_DIR = dir;
  await buildFixtureDir(dir);
  snap = await buildSnapshot({ fixture: true });
  defs = JSON.parse(await readFile(join(dir, "replays.json"), "utf8")).replays;
});

afterAll(async () => {
  if (before === undefined) delete process.env.PLX_RUNS_DIR;
  else process.env.PLX_RUNS_DIR = before;
  await rm(dir, { recursive: true, force: true });
});

describe("snapshot", () => {
  test("is read from the run directory and marked as fixture", () => {
    expect(snap.fixture).toBe(true);
    expect(snap.repos).toEqual(REPOS);
    expect(snap.jobs.length).toBeGreaterThan(10);
    expect(snap.verdicts.length).toBeGreaterThan(3);
    expect(snapshotProblem(snap)).toBeNull();
    expect(snapshotProblem(JSON.parse(JSON.stringify(snap)))).toBeNull();
  });

  test("the hash ignores the clock and follows the content", () => {
    const later = { ...snap, generatedAt: "2031-01-01T00:00:00Z", activeAt: "2031-01-01T00:00:00Z" };
    expect(snapshotHash(later)).toBe(snapshotHash(snap));
    expect(snapshotHash({ ...snap, verdicts: snap.verdicts.slice(1) })).not.toBe(snapshotHash(snap));
  });

  test("rejects things that are not snapshots", () => {
    expect(snapshotProblem(null)).not.toBeNull();
    expect(snapshotProblem({ ...snap, v: 2 })).not.toBeNull();
    expect(snapshotProblem({ ...snap, repos: ["not a repo"] })).not.toBeNull();
    expect(snapshotProblem({ ...snap, jobs: "x" })).not.toBeNull();
  });

  test("an empty snapshot has the fleet's repos and nothing else", async () => {
    const e = await emptySnapshot();
    expect(e.repos.length).toBeGreaterThan(0);
    expect(e.jobs).toEqual([]);
    expect(e.verdicts).toEqual([]);
    const f = fleetView(e);
    expect(f.repos.every((r) => r.runs.length === 0)).toBe(true);
    expect(f.active).toEqual([]);
    expect(f.alerts.egress).toEqual([]);
    expect(runView(e, e.repos[0]!, "1")).toBeNull();
  });
});

describe("fleet view", () => {
  test("lists every repo with its runs and their verdicts", () => {
    const f = fleetView(snap);
    expect(f.repos.map((r) => r.repo)).toEqual(REPOS);
    const web = f.repos.find((r) => r.repo === WEB)!;
    const byId = new Map(web.runs.map((r) => [r.runId, r]));
    expect(byId.get(RUNS.clean)!.verdict).toBe("clean");
    expect(byId.get(RUNS.shai)!.verdict).toBe("divergent");
    expect(byId.get(RUNS.shai)!.divergences).toBe(2);
    expect(byId.get(RUNS.shai)!.pr?.number).toBe(4);
    expect(byId.get(RUNS.live)!.live).toBe(true);
    expect(byId.get(RUNS.live)!.verdict).toBeNull();
  });

  test("shows the CRACI jobs running right now", () => {
    const f = fleetView(snap);
    expect(f.active.length).toBe(2);
    expect(f.active.every((a) => a.repo === WEB && a.runId === RUNS.live)).toBe(true);
    // A live list from CRACI replaces the one in the snapshot.
    expect(fleetView(snap, { live: [], liveAt: "2026-11-14T12:00:00Z" }).active).toEqual([]);
  });

  test("carries the alerts the core computes", () => {
    const a = fleetView(snap).alerts;
    expect(a.egress.length).toBeGreaterThan(0);
    expect(a.lineage.length).toBe(1);
    expect(a.drift.length).toBe(1);
    expect(a.images.length).toBe(1);
    expect(a.notFound.length).toBe(1);
  });
});

describe("twin view", () => {
  test("a divergent run: shared rows quiet, the decoy-only rows carry a sentence", () => {
    const v = runView(snap, WEB, RUNS.shai)!;
    expect(v.run.verdict).toBe("divergent");
    const div = v.rows.filter((r) => r.state === "divergent");
    expect(div.length).toBe(2);
    for (const r of div) {
      expect(r.bare).toBeNull();
      expect(r.decoy).not.toBeNull();
      expect(r.host).toBe("plx-sink.test");
      expect(r.why).toContain("Only the decoy twin");
    }
    const shared = v.rows.filter((r) => r.state === "shared");
    expect(shared.length).toBeGreaterThan(5);
    expect(shared.every((r) => r.bare && r.decoy && r.why === null)).toBe(true);
    // CRACI's order is kept: the divergent rows come where the decoy made them, at the end.
    expect(v.rows.slice(-2).every((r) => r.state === "divergent")).toBe(true);
    expect(v.twins.bare?.hasLog).toBe(true);
    expect(v.twins.decoy?.hasLog).toBe(true);
  });

  test("the gate is the real state of the release job", () => {
    const bad = runView(snap, WEB, RUNS.shai)!.gate;
    expect(bad.state).toBe("not_started");
    expect(bad.job?.conclusion).toBe("skipped");
    const good = runView(snap, WEB, RUNS.clean)!.gate;
    expect(good.state).toBe("ran");
    expect(good.job?.conclusion).toBe("success");
    const live = runView(snap, WEB, RUNS.live)!;
    expect(live.gate.state).toBe("waiting");
    expect(live.twins.bare?.running).toBe(true);
    expect(live.twins.decoy?.running).toBe(true);
    expect(live.rows).toEqual([]);
  });

  test("an unknown run is not invented", () => {
    expect(runView(snap, WEB, "123456789")).toBeNull();
    expect(runView(snap, "someone/else", RUNS.shai)).toBeNull();
  });

  test("only jobs the snapshot holds are known", () => {
    const v = runView(snap, WEB, RUNS.shai)!;
    expect(knownJob(snap, WEB, v.twins.decoy!.jobId)).toEqual({ known: true, running: false });
    expect(knownJob(snap, WEB, runView(snap, WEB, RUNS.live)!.twins.bare!.jobId)).toEqual({ known: true, running: true });
    expect(knownJob(snap, WEB, "999999999").known).toBe(false);
  });
});

describe("rings", () => {
  test("a divergence's seeds lead to the job that fetched it, and the fence is a dry run", async () => {
    const seeds = runView(snap, WEB, RUNS.shai)!.seeds;
    expect(seeds.length).toBeGreaterThan(0);
    const r = await ringsView(snap, seeds[0]!.seed);
    expect(r.rings).not.toBeNull();
    expect(r.rings!.length).toBe(4);
    expect(r.rings![0]!.some((m) => m.runId === RUNS.shai)).toBe(true);
    expect(r.fence?.dryRun).toBe(true);
    expect(r.fence!.actions.every((a) => a.executed === false)).toBe(true);
  });

  test("a seed nothing touched gives empty rings", async () => {
    const r = await ringsView(snap, "never-seen.invalid");
    expect((r.rings ?? []).flat()).toEqual([]);
  });
});

describe("replay scoreboard", () => {
  test("every row comes from a real run and its verdict, or says it has not run", () => {
    const rows = replayRows(snap, defs);
    const by = new Map(rows.map((r) => [r.id, r]));
    const shai = by.get("shai-hulud")!;
    expect(shai.state).toBe("caught");
    expect(shai.organs).toContain("twins");
    expect(shai.seconds).toBeGreaterThan(0);
    expect(by.get("cache-poison")!.organs).toEqual(["cache lineage"]);
    expect(by.get("tag-repoint")!.organs).toEqual(["URL-hash drift"]);
    expect(by.get("slopsquat")!.organs).toEqual(["registry 404s"]);
    expect(by.get("release-gate")!.state).toBe("not_run");
    expect(by.get("pth")!.state).toBe("not_set_up");
    for (const r of rows.filter((x) => x.state === "not_run" || x.state === "not_set_up")) {
      expect(r.organs).toEqual([]);
      expect(r.seconds).toBeNull();
    }
  });

  test("with nothing run, nothing is caught", async () => {
    const rows = replayRows(await emptySnapshot(), defs);
    expect(rows.every((r) => r.state === "not_run" || r.state === "not_set_up")).toBe(true);
  });
});
