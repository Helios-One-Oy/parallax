import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildFleetJob, FleetIndex, syncFleet } from "../src/fleet.ts";
import { ghJob, httpObs, npmBuild, sbom, trace } from "./factories.ts";
import { API, BASE, buildFixture, SPECIMEN, STAGE2_HASH, WEB } from "./fixture-fleet.ts";

const job = (repo: string, id: number, run: number, minute: number, obs: any[], purls: string[] = []) =>
  buildFleetJob({
    repo,
    job: ghJob({ id, run_id: run, name: "build (bare)" }, minute),
    trace: trace(obs, { repository: repo, jobId: String(id), runId: String(run) }, minute),
    sbom: sbom(purls),
  });

describe("fleet index", () => {
  test("firstSeen for a host, a package and a body hash", async () => {
    const { index } = await buildFixture();
    expect(index.firstSeen("plx-sink.test")).toMatchObject({ repo: WEB, jobId: "101" });
    expect(index.firstSeen(SPECIMEN)).toMatchObject({ repo: WEB, jobId: "101" });
    expect(index.firstSeen("pkg:npm/plx-specimen")).toMatchObject({ jobId: "101" });
    expect(index.firstSeen(STAGE2_HASH)).toMatchObject({ jobId: "101" });
    expect(index.firstSeen("ghcr.io")).toMatchObject({ jobId: "102" });
    expect(index.firstSeen("never-seen.test")).toBeNull();
    expect(index.jobsWith(SPECIMEN).map((j) => j.jobId)).toEqual(["101", "102"]);
    expect(index.seenBefore("host", "plx-sink.test", { excludeRunId: "11" })).toBe(false);
    expect(index.seenBefore("host", "registry.npmjs.org", { excludeRunId: "13" })).toBe(true);
  });

  test("urlHashDrift: same URL, different bytes; packuments and index pages are left out", async () => {
    const { index } = await buildFixture();
    const script = "https://raw.githubusercontent.com/test-org/tool/v1/install.sh";
    const packument = "https://registry.npmjs.org/left-pad";
    await index.addJob(job(WEB, 110, 40, 60, [httpObs(script, { bodyHash: { sha256: "a".repeat(64) } }), httpObs(packument, { bodyHash: { sha256: "c".repeat(64) } })]));
    await index.addJob(job(API, 210, 41, 70, [httpObs(script + "?token=1", { bodyHash: { sha256: "a".repeat(64) } })]));
    await index.addJob(job(BASE, 310, 42, 80, [httpObs(script, { bodyHash: { sha256: "b".repeat(64) } }), httpObs(packument, { bodyHash: { sha256: "d".repeat(64) } })]));

    const drift = index.urlHashDrift();
    expect(drift).toHaveLength(1);
    expect(drift[0]!.url).toBe("raw.githubusercontent.com/test-org/tool/v1/install.sh");
    expect(drift[0]!.mutable).toBeNull();
    expect(drift[0]!.versions.map((v) => [v.sha256[0], v.jobs, v.firstSeen.jobId])).toEqual([["a", 2, "110"], ["b", 1, "310"]]);

    const all = index.urlHashDrift({ includeMutable: true });
    expect(all.find((d) => d.url === "registry.npmjs.org/left-pad")!.mutable).toBe("npm-packument");
  });

  test("notFound pools registry 404s across repos", async () => {
    const { index } = await buildFixture();
    const miss = (url: string) => httpObs(url, { statusCode: 404, bodyHash: null });
    await index.addJob(job(WEB, 120, 50, 60, [miss("https://registry.npmjs.org/plx-hallucinated-pkg"), miss("https://registry.npmjs.org/left-pad/-/left-pad-0.0.0.tgz")]));
    await index.addJob(job(API, 220, 51, 70, [miss("https://registry.npmjs.org/plx-hallucinated-pkg"), miss("https://pypi.org/simple/plx-ghost/"), miss("https://example-docs.test/missing.html")]));
    const nf = index.notFound();
    expect(nf.map((n) => `${n.registry} ${n.name} ${n.jobs.length}`)).toEqual(["npm plx-hallucinated-pkg 2", "pypi plx-ghost 1"]);
    expect(nf[0]!.repos).toEqual([API, WEB].sort());
  });

  test("newEgress: hosts no earlier job of the repo contacted; twins of one run do not hide each other", async () => {
    const { index } = await buildFixture();
    const fresh = [...npmBuild(), httpObs("https://fresh-host.test/beacon", { method: "POST" })];
    const bare = job(WEB, 130, 60, 60, fresh);
    const decoy = job(WEB, 131, 60, 61, fresh);
    await index.addJob(bare);
    await index.addJob(decoy);
    expect(index.newEgress(bare).hosts).toEqual(["fresh-host.test"]);
    expect(index.newEgress(decoy).hosts).toEqual(["fresh-host.test"]);
    expect(index.newEgress(decoy).earlierJobs).toBe(3);
    // the first job of a repo has no baseline
    expect(index.newEgress({ repo: WEB, jobId: "101" }).earlierJobs).toBe(0);
    expect(index.newEgress(index.getJob(WEB, 103)!).hosts).toEqual([]);
  });

  test("persists as JSON lines and loads back", async () => {
    const dir = await mkdtemp(join(tmpdir(), "plx-fleet-test-"));
    try {
      const { index } = await buildFixture(dir);
      const lines = (await readFile(join(dir, "jobs.jsonl"), "utf8")).trim().split("\n");
      expect(lines).toHaveLength(6);
      expect(JSON.parse(lines[0]!).jobId).toBe("101");
      const again = await FleetIndex.load(dir);
      expect(again.jobs.size).toBe(6);
      expect(again.caches.size).toBe(2);
      expect(again.artifacts.size).toBe(2);
      expect(again.getJob(WEB, 101)).toEqual(index.getJob(WEB, 101)!);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("syncFleet indexes finished jobs once, keeps going when CRACI has no trace", async () => {
    const t = trace(npmBuild(), { repository: WEB, jobId: "101", runId: "11" });
    let traceCalls = 0;
    const craci = {
      getNetworkTrace: async (_r: string, id: string) => (traceCalls++, id === "101" ? t : null),
      getSbom: async () => sbom(["pkg:npm/left-pad@1.3.0"]),
      getJobLogs: async () => "",
      getGhaCacheProvenance: async () => null,
      getOciManifestProvenance: async () => null,
      getOciBlobProvenance: async () => null,
    } as any;
    const github = {
      listRuns: async () => [{ id: 11, event: "push", head_branch: "main", name: "ci" }],
      listJobs: async () => [ghJob({ id: 101, run_id: 11, name: "build (bare)" }), ghJob({ id: 102, run_id: 11, name: "build (decoy)" }), ghJob({ id: 103, run_id: 11, name: "later", status: "in_progress", conclusion: null })],
      listCaches: async () => [{ id: 501, key: "k", ref: "refs/heads/main", created_at: "2026-11-14T10:03:00Z", size_in_bytes: 1 }],
    } as any;
    const index = new FleetIndex(null);
    const now = () => Date.parse("2026-11-14T12:00:00Z");
    const first = await syncFleet({ repos: [WEB], craci, github, index, now });
    expect(first.repos[0]).toMatchObject({ runs: 1, jobsNew: 1, jobsWithoutTrace: 1, caches: 1 });
    expect(index.getJob(WEB, 101)!.hasTrace).toBe(true);
    expect(index.getJob(WEB, 102)!.hasTrace).toBe(false);
    expect(index.hasJob(WEB, 103)).toBe(false);
    const second = await syncFleet({ repos: [WEB], craci, github, index, now });
    expect(second.repos[0]).toMatchObject({ jobsNew: 0, jobsWithoutTrace: 0 });
    expect(traceCalls).toBe(2);
  });
});
