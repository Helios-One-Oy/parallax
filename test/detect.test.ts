// Every detector other than the twin diff, asked about one run (src/detect.ts).
import { describe, expect, test } from "bun:test";
import { detectContext, detectRun, judge } from "../src/detect.ts";
import { buildFleetJob, FleetIndex, ghaCachesOfSbom, syncCaches, unknownArtifact } from "../src/fleet.ts";
import { ringFence, rings, buildGraph } from "../src/graph.ts";
import type { NetworkObservation, PreviewArtifactProvenance } from "../src/types.ts";
import { ghJob, httpObs, logLines, npmBuild, sbom, sha, trace } from "./factories.ts";

const REPO = "test-org/test-web";
const ENTRY = "6629298651489501712"; // larger than a JS number can hold exactly, like CRACI's real entry ids
const CACHE_PURL = `pkg:ghacache/7493989779944505418/7493989779944505563@v1hash?entry_id=${ENTRY}&key=npm-linux-abc`;

type J = { id: number; run: number; name?: string; event?: string; minute: number; obs?: NetworkObservation[]; purls?: string[]; logs?: string };

async function fleet(jobs: J[]): Promise<FleetIndex> {
  const index = new FleetIndex(null);
  for (const j of jobs)
    await index.addJob(
      buildFleetJob({
        repo: REPO,
        job: ghJob({ id: j.id, run_id: j.run, name: j.name ?? "build (bare)" }, j.minute),
        run: { event: j.event ?? "push" },
        trace: trace(j.obs ?? npmBuild(), { repository: REPO, runId: String(j.run), jobId: String(j.id) }, j.minute),
        sbom: sbom(j.purls ?? ["pkg:npm/left-pad@1.3.0"]),
        logs: j.logs ?? "",
      }),
    );
  return index;
}

/** Three earlier runs of merged code, two twins each. */
const history = (extra: NetworkObservation[] = []): J[] =>
  [1, 2, 3].flatMap((n) => [
    { id: n * 10 + 1, run: n, name: "build (bare)", minute: n * 10, obs: [...npmBuild(), ...extra] },
    { id: n * 10 + 2, run: n, name: "build (decoy)", minute: n * 10, obs: [...npmBuild(), ...extra] },
  ]);

const beacon = httpObs("https://fresh-host.test/ping", { method: "POST" });

describe("new egress", () => {
  test("fresh-host: both twins call a host no earlier run called, so the twins agree and new egress catches it", async () => {
    const index = await fleet([
      ...history(),
      { id: 91, run: 9, name: "build (bare)", event: "pull_request", minute: 60, obs: [...npmBuild(), beacon] },
      { id: 92, run: 9, name: "build (decoy)", event: "pull_request", minute: 60, obs: [...npmBuild(), beacon] },
    ]);
    const d = detectRun(detectContext(index), REPO, "9");
    expect(d.findings.map((f) => [f.organ, f.jobName, f.key, f.fails])).toEqual([
      ["new egress", "build (bare)", "fresh-host.test", true],
      ["new egress", "build (decoy)", "fresh-host.test", true],
    ]);
    expect(d.findings[0]!.policy).toContain("fresh-host.test");
    expect(d.checks.find((c) => c.organ === "new egress")).toMatchObject({ state: "checked" });
    // the twin diff alone calls this run clean
    expect(judge("clean", d.findings)).toEqual({ result: "fail", caughtBy: ["new egress"] });
  });

  test("too little history: nothing is called new, and the check says so", async () => {
    const index = await fleet([...history().slice(0, 4), { id: 91, run: 9, minute: 60, obs: [...npmBuild(), beacon] }]);
    const d = detectRun(detectContext(index), REPO, "9");
    expect(d.findings).toEqual([]);
    const c = d.checks.find((x) => x.organ === "new egress")!;
    expect(c.state).toBe("too_little_history");
    expect(c.note).toContain("2 earlier runs");
    expect(judge("clean", d.findings)).toEqual({ result: "pass", caughtBy: [] });
  });

  test("a pull request cannot vouch for itself: only runs of merged code count as earlier", async () => {
    const index = await fleet([
      ...history(),
      { id: 81, run: 8, event: "pull_request", minute: 50, obs: [...npmBuild(), beacon] }, // the same pull request, pushed before
      { id: 91, run: 9, event: "pull_request", minute: 60, obs: [...npmBuild(), beacon] },
    ]);
    expect(detectRun(detectContext(index), REPO, "9").findings.map((f) => f.key)).toEqual(["fresh-host.test"]);
    // once merged code has called it, it is no longer new
    const merged = await fleet([...history([beacon]), { id: 91, run: 9, event: "pull_request", minute: 60, obs: [...npmBuild(), beacon] }]);
    expect(detectRun(detectContext(merged), REPO, "9").findings).toEqual([]);
  });

  test("runner plumbing that CRACI always allows is never new", async () => {
    const plumbing = [httpObs("https://cache.blob.core.windows.net/x/y"), httpObs("https://run-actions-7-azure-westus.actions.githubusercontent.com/a/b")];
    const index = await fleet([...history(), { id: 91, run: 9, minute: 60, obs: [...npmBuild(), ...plumbing] }]);
    expect(detectRun(detectContext(index), REPO, "9").findings).toEqual([]);
  });
});

describe("cache lineage from CRACI's own records", () => {
  const provenance = (writerJob: string): PreviewArtifactProvenance => ({
    artifact_id: "a1",
    kind: "gha_cache",
    digest: `sha256:${sha("cache-archive")}`,
    cache_id: ENTRY,
    refers: [],
    jobs_created_in: [
      { provider: { provider: "github", repository: REPO, job_id: writerJob }, accepted_at: "2026-11-14T10:41:00Z", metadata: { kind: "gha_cache", cache_key: "npm-linux-abc", version: "v1hash", size_bytes: 17270436 } } as any,
    ],
  });

  test("the SBOM names the cache entry", () => {
    expect(ghaCachesOfSbom(sbom(["pkg:npm/left-pad@1.3.0", CACHE_PURL]))).toEqual([{ entryId: ENTRY, key: "npm-linux-abc", version: "v1hash" }]);
  });

  test("a release job restored a cache that a pull_request_target job wrote", async () => {
    const index = await fleet([
      { id: 41, run: 4, name: "warm cache", event: "pull_request_target", minute: 40, purls: [CACHE_PURL], logs: logLines("Cache saved with key: npm-linux-abc") },
      { id: 51, run: 5, name: "build (bare)", minute: 50 },
      { id: 52, run: 5, name: "release", minute: 55, purls: ["pkg:npm/left-pad@1.3.0", CACHE_PURL], logs: logLines("Cache restored from key: npm-linux-abc") },
    ]);
    const asked: string[] = [];
    const craci = { getGhaCacheProvenance: async (q: any) => (asked.push(q.cacheId), provenance("41")) };
    for (const j of index.jobs.values()) await syncCaches(index, craci as any, REPO, j.ghaCaches ?? []);
    expect(asked).toEqual([ENTRY]); // asked once, by entry id, kept as a string
    expect([...index.caches.values()][0]).toMatchObject({ id: ENTRY, key: "npm-linux-abc", size_in_bytes: 17270436 });

    const d = detectRun(detectContext(index), REPO, "5");
    expect(d.findings).toHaveLength(1);
    expect(d.findings[0]).toMatchObject({ organ: "cache lineage", jobName: "release", key: "npm-linux-abc", fails: true, policy: null });
    expect(d.findings[0]!.why).toContain("pull request target");
    expect(d.checks.find((c) => c.organ === "cache lineage")!.note).toContain("1 cache restore");
    // the writer's own run restored nothing
    expect(detectRun(detectContext(index), REPO, "4").findings).toEqual([]);

    // the fence cannot delete from CRACI's cache store through GitHub: it says so instead of planning a delete
    const fence = await ringFence(rings(buildGraph(index), "job:41"), { dryRun: true });
    expect(fence.actions.filter((x) => x.type === "delete_cache")).toEqual([]);
    expect(fence.manual.join(" ")).toContain("held by CRACI's cache store");
  });

  test("a cache written by a trusted job is not a finding", async () => {
    const index = await fleet([
      { id: 41, run: 4, name: "release", minute: 40, purls: [CACHE_PURL] },
      { id: 52, run: 5, name: "release", minute: 55, purls: [CACHE_PURL] },
    ]);
    for (const j of index.jobs.values()) await syncCaches(index, { getGhaCacheProvenance: async () => provenance("41") } as any, REPO, j.ghaCaches ?? []);
    const d = detectRun(detectContext(index), REPO, "5");
    expect(d.findings).toEqual([]);
    expect(d.checks.find((c) => c.organ === "cache lineage")).toMatchObject({ state: "checked" });
  });
});

describe("same URL, new bytes", () => {
  const script = (seed: string) => httpObs("https://get.tool.test/install.sh", { bodyHash: { sha256: sha(seed) } });

  test("fails the run when the old bytes were seen by two earlier jobs", async () => {
    const index = await fleet([...history([script("v1")]), { id: 91, run: 9, minute: 60, obs: [...npmBuild(), script("v2")] }]);
    const d = detectRun(detectContext(index), REPO, "9");
    expect(d.findings).toHaveLength(1);
    expect(d.findings[0]).toMatchObject({ organ: "same URL, new bytes", key: "get.tool.test/install.sh", host: "get.tool.test", fails: true });
    expect(judge("clean", d.findings).caughtBy).toEqual(["same URL, new bytes"]);
    // the runs that saw the old bytes are not blamed
    expect(detectRun(detectContext(index), REPO, "3").findings).toEqual([]);
  });

  test("is only reported when a single earlier job saw the old bytes", async () => {
    const index = await fleet([
      ...history(),
      { id: 81, run: 8, minute: 50, obs: [...npmBuild(), script("v1")] },
      { id: 91, run: 9, minute: 60, obs: [...npmBuild(), script("v2")] },
    ]);
    const f = detectRun(detectContext(index), REPO, "9").findings.filter((x) => x.organ === "same URL, new bytes");
    expect(f.map((x) => x.fails)).toEqual([false]);
    expect(judge("clean", f)).toEqual({ result: "pass", caughtBy: ["same URL, new bytes"] });
  });
});

describe("registry 404 and image provenance", () => {
  test("a package name the registry does not know", async () => {
    const index = await fleet([...history(), { id: 91, run: 9, minute: 60, obs: [...npmBuild(), httpObs("https://registry.npmjs.org/react-codemod-utils", { statusCode: 404 })] }]);
    const d = detectRun(detectContext(index), REPO, "9");
    expect(d.findings).toHaveLength(1);
    expect(d.findings[0]).toMatchObject({ organ: "registry 404", key: "npm:react-codemod-utils", host: "registry.npmjs.org", fails: true });
    // a failed build makes the twin diff inconclusive; the finding still names the cause
    expect(judge("inconclusive", d.findings)).toEqual({ result: "fail", caughtBy: ["registry 404"] });
  });

  test("our own image tag returns bytes no job of ours produced, judged only after CRACI was asked", async () => {
    const moved = sha("repointed");
    const pull = httpObs("https://ghcr.io/v2/test-org/base/manifests/22", { bodyHash: { sha256: moved } });
    const before = httpObs("https://ghcr.io/v2/test-org/base/manifests/21", { bodyHash: { sha256: sha("ours") } });
    const index = await fleet([...history([before]), { id: 91, run: 9, minute: 60, obs: [...npmBuild(), pull] }]);
    expect(detectRun(detectContext(index), REPO, "9").findings).toEqual([]);
    await index.addArtifact(unknownArtifact(`sha256:${moved}`));
    const d = detectRun(detectContext(index), REPO, "9");
    expect(d.findings.map((f) => [f.organ, f.key, f.fails])).toEqual([["image provenance", "ghcr.io/test-org/base:22", true]]);
  });
});
