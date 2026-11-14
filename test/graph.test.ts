import { describe, expect, test } from "bun:test";
import { buildFleetJob } from "../src/fleet.ts";
import { buildGraph, cacheEventsFromLog, cacheLineageAlerts, cacheNodeId, deriveCacheRestores, foreignImagePulls, jobNodeId, ociRefsFromTrace, r0, ringFence, rings } from "../src/graph.ts";
import type { JobSummary } from "../src/types.ts";
import { at, ghJob, httpObs, jobMeta, logLines, trace } from "./factories.ts";
import { API, B1, buildFixture, M1, SPECIMEN, STAGE2_HASH, WEB } from "./fixture-fleet.ts";

const ids = (ring: Array<{ id: string }>) => ring.map((m) => m.id).sort();

describe("derivations", () => {
  test("cache keys from actions/cache log lines", () => {
    const ev = cacheEventsFromLog(logLines("Cache restored from key: npm-linux-abc", "\x1b[36mCache saved with key: npm-linux-def\x1b[0m", "nothing here"));
    expect(ev).toEqual({ restored: ["npm-linux-abc"], saved: ["npm-linux-def"] });
  });

  test("image pulls and pushes from registry calls in the trace", () => {
    const refs = ociRefsFromTrace(
      trace([
        httpObs("https://registry-1.docker.io/v2/library/node/manifests/22", { bodyHash: { sha256: M1.slice(7) } }),
        httpObs(`https://registry-1.docker.io/v2/library/node/blobs/${B1}`),
        httpObs("https://ghcr.io/v2/test-org/web/manifests/v2", { method: "PUT", statusCode: 201 }),
        httpObs("https://ghcr.io/v2/test-org/web/manifests/denied", { statusCode: 403, policyDenied: true }),
      ]),
    );
    expect(refs.manifests).toEqual([
      { registry: "docker.io", name: "library/node", ref: "22", digest: M1, op: "pull" },
      { registry: "ghcr.io", name: "test-org/web", ref: "v2", digest: null, op: "push" },
    ]);
    expect(refs.blobs).toEqual([{ registry: "docker.io", name: "library/node", digest: B1, op: "pull" }]);
  });

  test("cache restores: by log key, by digest in the trace, and unresolved keys are kept", async () => {
    const { index, caches } = await buildFixture();
    const j102 = index.getJob(WEB, 102)!;
    expect(deriveCacheRestores(j102, caches).map((r) => r.nodeId)).toEqual([cacheNodeId(WEB, 501)]);
    // the job that wrote the cache did not restore it
    expect(deriveCacheRestores(index.getJob(WEB, 101)!, caches)).toEqual([]);
    // digest match in the trace
    const byDigest = { ...index.getJob(WEB, 103)!, urlHashes: [["x.test/blob", caches[0]!.digest!.slice(7)]] as Array<[string, string]> };
    expect(deriveCacheRestores(byDigest, caches)[0]!.evidence).toContain("digest");
    // key with no known cache
    const lost = { ...j102, cache: { restored: ["gone-key"], saved: [] } };
    expect(deriveCacheRestores(lost, caches)[0]!.nodeId).toBe(`cache:${WEB}#key=gone-key`);
  });
});

describe("rings on a fleet of 6 jobs, 2 caches, 1 image", () => {
  test("package seed: fetched -> cache -> restorer -> image", async () => {
    const { index } = await buildFixture();
    const g = buildGraph(index);
    expect([...g.nodes.values()].filter((n) => n.type === "job")).toHaveLength(6);
    expect([...g.nodes.values()].filter((n) => n.type === "cache")).toHaveLength(2);

    const r = rings(g, SPECIMEN);
    expect(r.seedKind).toBe("package");
    expect(ids(r.rings[0])).toEqual([jobNodeId(WEB, 101)]);
    expect(ids(r.rings[1])).toEqual([cacheNodeId(WEB, 501)]);
    // #102 has the package only through the cache: ring 2, not ring 0
    expect(ids(r.rings[2])).toEqual([jobNodeId(WEB, 102)]);
    expect(ids(r.rings[3])).toEqual([`blob:${B1}`, `manifest:${M1}`].sort());
    expect(r.r0).toBe(1);
    expect(r0(g, SPECIMEN)).toBe(1);

    // every membership is explained by a path that starts at the seed
    const two = r.rings[2][0]!;
    expect(two.path).toEqual([SPECIMEN, jobNodeId(WEB, 101), cacheNodeId(WEB, 501), jobNodeId(WEB, 102)]);
    expect(two.why).toContain("Restored cache npm-linux-abc");
    expect(r.rings[1][0]!.why).toContain("CRACI cache provenance");
    for (const m of r.rings.flat()) expect(m.path[m.path.length - 1]).toBe(m.id);
  });

  test("host seed and url-hash seed find the same first job", async () => {
    const g = buildGraph((await buildFixture()).index);
    expect(ids(rings(g, "plx-sink.test").rings[0])).toEqual([jobNodeId(WEB, 101)]);
    const h = rings(g, STAGE2_HASH);
    expect(h.seedKind).toBe("url-hash");
    expect(ids(h.rings[0])).toEqual([jobNodeId(WEB, 101)]);
    expect(ids(rings(g, "never-seen.test").rings[0])).toEqual([]);
    expect(rings(g, "never-seen.test").r0).toBe(0);
  });

  test("job seed crosses repos through the image", async () => {
    const g = buildGraph((await buildFixture()).index);
    const r = rings(g, "job:102");
    expect(ids(r.rings[0])).toEqual([jobNodeId(WEB, 102)]);
    expect(ids(r.rings[1])).toEqual([`blob:${B1}`, `manifest:${M1}`].sort());
    expect(ids(r.rings[2])).toEqual([jobNodeId(API, 201)]);
    expect(ids(r.rings[3])).toEqual([cacheNodeId(API, 502)]);
    expect(r.rings[2][0]!.why).toMatch(/^Pulled /);
    // #202 restored cache 502 but that is one step past ring 3
    expect(r.rings.flat().some((m) => m.id === jobNodeId(API, 202))).toBe(false);
    expect(r.r0).toBe(1);
  });

  test("ringFence lists concrete actions, dry run by default, and executes through the GitHub client when asked", async () => {
    const g = buildGraph((await buildFixture()).index);
    const r = rings(g, SPECIMEN);
    const active: JobSummary[] = [{ ...jobMeta({ repository: WEB, runId: "14", jobId: "104", status: "running" }), startedAt: at(55), url: "https://github.com/x" }];
    const calls: string[] = [];
    const github = {
      cancelRun: async (repo: string, id: string) => void calls.push(`cancel ${repo} ${id}`),
      deleteCache: async (repo: string, id: number) => void calls.push(`delete ${repo} ${id}`),
      rerunRun: async (repo: string, id: string) => {
        calls.push(`rerun ${repo} ${id}`);
        throw new Error("403 not allowed");
      },
      createPullRequest: async (repo: string, pr: any) => {
        calls.push(`pr ${repo} ${pr.branch} ${pr.files[0].path}`);
        return { number: 7, html_url: "https://github.com/x/pull/7" };
      },
    } as any;

    const plan = await ringFence(r, { active, policies: { [WEB]: "default: deny\npresets: [npm]\n" }, github });
    expect(plan.dryRun).toBe(true);
    expect(calls).toEqual([]);
    expect(plan.actions.map((a) => a.type)).toEqual(["cancel_run", "delete_cache", "rerun_run", "open_pr"]);
    expect(plan.actions.every((a) => a.executed === false)).toBe(true);
    expect(plan.actions[1]).toMatchObject({ type: "delete_cache", repo: WEB, cacheId: 501, key: "npm-linux-abc" });
    expect(plan.actions[2]).toMatchObject({ type: "rerun_run", repo: WEB, runId: "12" });
    expect(plan.manual.join(" ")).toContain("by hand");

    const done = await ringFence(r, { dryRun: false, active, policies: { [WEB]: "default: deny\npresets: [npm]\n" }, github });
    expect(calls).toEqual([`cancel ${WEB} 14`, `delete ${WEB} 501`, `rerun ${WEB} 12`, `pr ${WEB} parallax/fence-pkg-npm-plx-specimen-9-9-9 .github/parallax/network-policy.yml`]);
    expect(done.actions.map((a) => a.ok)).toEqual([true, true, false, true]);
    expect(done.actions[2]!.detail).toContain("403");
    expect(done.actions[3]!.detail).toBe("https://github.com/x/pull/7");
    await expect(ringFence(r, { dryRun: false })).rejects.toThrow();
  });
});

describe("detectors on the same graph", () => {
  test("cache lineage: a trusted job restored a cache written by a pull-request job", async () => {
    const calm = cacheLineageAlerts(buildGraph((await buildFixture()).index));
    expect(calm).toEqual([]);
    const { index } = await buildFixture(null, { firstJobEvent: "pull_request_target" });
    const alerts = cacheLineageAlerts(buildGraph(index));
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ repo: WEB, writer: { jobId: "101", event: "pull_request_target" }, reader: { jobId: "102", runId: "12", event: "push" } });
    expect(alerts[0]!.cache.key).toBe("npm-linux-abc");
    expect(alerts[0]!.why).toContain("Anyone can trigger that kind of run.");
  });

  test("image provenance: a pull of our own tag that returns bytes no job of ours produced", async () => {
    const { index } = await buildFixture();
    expect(foreignImagePulls(index)).toEqual([]);
    const moved = "sha256:" + "e".repeat(64);
    await index.addJob(
      buildFleetJob({
        repo: API,
        job: ghJob({ id: 203, run_id: 23, name: "build (bare)" }, 60),
        trace: trace([httpObs("https://ghcr.io/v2/test-org/web/manifests/v1", { bodyHash: { sha256: moved.slice(7) } }), httpObs("https://registry-1.docker.io/v2/library/node/manifests/22", { bodyHash: { sha256: "f".repeat(64) } })], {}, 60),
        sbom: null,
      }),
    );
    const alerts = foreignImagePulls(index);
    expect(alerts).toHaveLength(1); // the public node image is not ours, so it is not judged
    expect(alerts[0]).toMatchObject({ repo: API, jobId: "203", image: "ghcr.io/test-org/web:v1", digest: moved, ours: [M1] });
  });
});
