// A synthetic run directory for developing and testing the console. Built from test/factories.ts.
// Nothing here is real. The console shows it only with PLX_FIXTURE=1, under a visible banner.
//   bun test/console/fixture.ts [dir]     (default /bulk3/runs/craci/dev-fixture)
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { diffTwinsDetailed } from "../../src/diff.ts";
import { buildFleetJob, FleetIndex } from "../../src/fleet.ts";
import type { GhJob } from "../../src/github.ts";
import type { JobSummary, NetworkObservation, PreviewArtifactProvenance, Verdict } from "../../src/types.ts";
import type { GhJobLite, GhRunLite, GithubState } from "../../src/console/snapshot.ts";
import { at, cacheRecord, ghJob, httpObs, logLines, npmBuild, sbom, sha, trace } from "../factories.ts";

export const WEB = "test-org/test-web";
export const API = "test-org/test-api";
export const BASE = "test-org/test-base";
export const REPOS = [WEB, API, BASE];
export const SPECIMEN = "pkg:npm/plx-specimen@9.9.9";
const CLEAN = ["pkg:npm/left-pad@1.3.0", "pkg:npm/%40types/node@22.9.0"];
const STAGE2 = "https://plx-sink.test/stage2/shai-hulud";
const COLLECT = "https://plx-sink.test/collect";
const IMG = `sha256:${sha("our-image")}`;
const FOREIGN = sha("someone-elses-image");

export const RUNS = { clean: "9001", shai: "9002", fresh: "9003", poisonPr: "9004", poisonPush: "9005", drift: "9006", image: "9007", slop: "9008", live: "9009", imagePush: "9010" };

type Step = { repo: string; run: string; branch: string; event: string; minute: number; pr?: number; title: string };

export async function buildFixtureDir(dir: string): Promise<{ dir: string }> {
  await rm(dir, { recursive: true, force: true });
  const index = new FleetIndex(join(dir, "fleet"));
  const github: GithubState = { fetchedAt: at(120), repos: {} };
  for (const r of REPOS) github.repos[r] = { runs: [], jobs: {}, gone: [], complete: true };
  const verdicts: Verdict[] = [];
  let nextJob = 70000;

  const put = async (file: string, text: string) => {
    await mkdir(join(file, ".."), { recursive: true });
    await writeFile(file, text);
  };
  const lite = (j: GhJob): GhJobLite => ({ id: String(j.id), name: j.name, status: j.status, conclusion: j.conclusion, startedAt: j.started_at, completedAt: j.completed_at, url: j.html_url ?? "" });

  async function job(s: Step, name: string, obs: NetworkObservation[] | null, purls: string[], logs: string, o: { offset?: number; conclusion?: string | null; status?: string } = {}) {
    const id = ++nextJob;
    const minute = s.minute + (o.offset ?? 0);
    const gh = ghJob({ id, run_id: Number(s.run), name, head_branch: s.branch, html_url: `https://github.com/${s.repo}/actions/runs/${s.run}/job/${id}`, ...(o.status ? { status: o.status, completed_at: null } : {}), ...(o.conclusion !== undefined ? { conclusion: o.conclusion } : {}) }, minute);
    if (o.conclusion === "skipped") {
      gh.started_at = null;
      gh.completed_at = at(minute);
    }
    github.repos[s.repo]!.jobs[s.run] = [...(github.repos[s.repo]!.jobs[s.run] ?? []), lite(gh)];
    if (!obs) return { gh, trace: null, sbom: null };
    const t = trace(obs, { repository: s.repo, jobId: String(id), runId: s.run, jobName: name, branch: s.branch }, minute);
    const b = sbom(purls);
    const base = join(dir, "api", s.repo, String(id));
    await put(join(base, "trace.json"), JSON.stringify(t));
    await put(join(base, "sbom.json"), JSON.stringify(b));
    await put(join(base, "logs.txt"), logs);
    await index.addJob(buildFleetJob({ repo: s.repo, job: gh, run: { event: s.event, head_branch: s.branch, name: "ci" }, trace: t, sbom: b, logs, now: at(minute + 4) }));
    return { gh, trace: t, sbom: b };
  }

  function run(s: Step, status = "completed", conclusion: string | null = "success") {
    const r: GhRunLite = {
      id: s.run, workflow: "ci", title: s.title, branch: s.branch, sha: sha(`commit-${s.run}`).slice(0, 40), event: s.event, status, conclusion,
      createdAt: at(s.minute), startedAt: at(s.minute), updatedAt: at(s.minute + 5), url: `https://github.com/${s.repo}/actions/runs/${s.run}`, attempt: 1, prs: s.pr ? [s.pr] : [],
    };
    github.repos[s.repo]!.runs.unshift(r);
    return r;
  }

  const buildLog = (twin: string, extra: string[] = []) =>
    logLines(`Run plx-run npm ci`, `twin: ${twin}`, "npm warn deprecated left-pad@1.3.0", "added 2 packages in 3s", ...extra, "Run plx-run npm test", "ok 12 tests", "Run plx-run npm run build", "built dist/ in 1.2s");

  /** Both twins, the verdict the core gives for them, and the release job GitHub would show. */
  async function twins(s: Step, o: { both?: NetworkObservation[]; decoyOnly?: NetworkObservation[]; purls?: string[]; decoyPurls?: string[]; logs?: string }) {
    const common = [...npmBuild(), ...(o.both ?? [])];
    const purls = o.purls ?? CLEAN;
    const bare = await job(s, "build (bare)", common, purls, o.logs ?? buildLog("bare"));
    const decoy = await job(s, "build (decoy)", [...common, ...(o.decoyOnly ?? [])], o.decoyPurls ?? purls, o.logs ?? buildLog("decoy"));
    const ref = (j: GhJob) => ({ jobId: String(j.id), name: j.name, status: j.conclusion ?? "", url: j.html_url ?? "" });
    const mem = new FleetIndex(null);
    for (const j of index.jobs.values()) mem.jobs.set(`${j.repo}#${j.jobId}`, j);
    const d = diffTwinsDetailed(
      { job: ref(bare.gh), trace: bare.trace, sbom: bare.sbom, conclusion: "success", reachedBuild: true },
      { job: ref(decoy.gh), trace: decoy.trace, sbom: decoy.sbom, conclusion: "success", reachedBuild: true },
      { fleet: mem, now: at(s.minute + 4) },
    );
    d.verdict.commitSha = sha(`commit-${s.run}`).slice(0, 40);
    verdicts.push(d.verdict);
    await put(join(dir, "verdicts", s.repo, `${s.run}.json`), JSON.stringify(d.verdict, null, 2));
    const failed = d.verdict.status !== "clean";
    await job(s, "verdict", null, [], "", { offset: 4, conclusion: failed ? "failure" : "success" });
    return { verdict: d.verdict, failed };
  }

  // 1. A clean push to main: the release job runs and saves the cache.
  let s: Step = { repo: WEB, run: RUNS.clean, branch: "main", event: "push", minute: 0, title: "Shipment list: sort by ETA" };
  await twins(s, {});
  await job(s, "release", npmBuild(), CLEAN, logLines("Run actions/cache@v4", "Cache not found for input keys: npm-linux-abc", "Run npm ci", "Cache saved with key: npm-linux-abc"), { offset: 5 });
  run(s);

  // 2. shai-hulud: only the decoy twin, which carries a fake npm token, fetches a second stage and posts.
  s = { repo: WEB, run: RUNS.shai, branch: "deps/telemetry-utils-2.1.1", event: "pull_request", minute: 12, pr: 4, title: "deps: bump @nbd/telemetry-utils to 2.1.1" };
  await twins(s, { decoyOnly: [httpObs(STAGE2), httpObs(COLLECT, { method: "POST" })], purls: [...CLEAN, SPECIMEN] });
  await job(s, "release", null, [], "", { offset: 5, conclusion: "skipped" });
  run(s, "completed", "failure");

  // 3. fresh-host: both twins call a host no earlier job of the repo contacted. The twins agree; new egress catches it.
  s = { repo: WEB, run: RUNS.fresh, branch: "deps/add-retry-fetch", event: "pull_request", minute: 24, pr: 5, title: "deps: add @nbd/retry-fetch" };
  await twins(s, { both: [httpObs("https://feed.carrier-status.test/v1/ping")] });
  await job(s, "release", null, [], "", { offset: 5, conclusion: "skipped" });
  run(s);

  // 4 + 5. cache-poison: a pull-request job saves a cache, a push job on main restores it.
  s = { repo: API, run: RUNS.poisonPr, branch: "perf/faster-ci", event: "pull_request", minute: 36, pr: 9, title: "ci: warm the pip cache" };
  const writer = await job(s, "warm cache", npmBuild(), ["pkg:pypi/requests@2.32.3"], logLines("Run actions/cache@v4", "Cache saved with key: pip-linux-xyz"));
  run(s);
  await index.addCache(cacheRecord({ repo: API, id: 601, key: "pip-linux-xyz", createdMinute: 38, createdByJob: String(writer.gh.id) }));
  s = { repo: API, run: RUNS.poisonPush, branch: "main", event: "push", minute: 48, title: "Rate limits per carrier" };
  await job(s, "release", npmBuild(), ["pkg:pypi/requests@2.32.3"], logLines("Run actions/cache@v4", "Cache restored from key: pip-linux-xyz", "Run pip install"));
  run(s);

  // 6. tag-repoint: the same URL returns different bytes than it did in run 9001.
  const SCRIPT = "https://raw.githubusercontent.com/some-org/setup-thing/v2/install.sh";
  s = { repo: BASE, run: "9000", branch: "main", event: "push", minute: -20, title: "Base image: node 22" };
  await job(s, "build base", [...npmBuild(), httpObs(SCRIPT)], CLEAN, logLines("Run curl install.sh | sh"));
  run(s);
  s = { repo: BASE, run: RUNS.drift, branch: "ci/pin-setup", event: "push", minute: 60, title: "ci: refresh setup script" };
  await job(s, "build base", [...npmBuild(), httpObs(SCRIPT, { bodyHash: { sha256: sha("repointed bytes") } })], CLEAN, logLines("Run curl install.sh | sh"));
  run(s);

  // 7. image-repoint: our job pushed ghcr.io/test-org/base:22; a later job pulls that tag and gets bytes nobody of ours made.
  s = { repo: BASE, run: RUNS.imagePush, branch: "main", event: "push", minute: 66, title: "Publish base image" };
  const pusher = await job(s, "publish image", [...npmBuild().slice(0, 4), httpObs("https://ghcr.io/v2/test-org/base/manifests/22", { method: "PUT", statusCode: 201 })], CLEAN, logLines("Run docker push"));
  run(s);
  const art: PreviewArtifactProvenance = {
    artifact_id: "9101", kind: "oci_image_manifest", digest: IMG, media_type: "application/vnd.oci.image.manifest.v1+json", refers: [],
    jobs_created_in: [{ craci_job_id: "500001", provider: { kind: "github", repository: BASE, job_id: String(pusher.gh.id) }, accepted_at: at(67), metadata: { kind: "oci", registry: "ghcr.io", repository: "test-org/base", reference: "22" } }],
  };
  await index.addArtifact(art);
  s = { repo: API, run: RUNS.image, branch: "ci/base-22", event: "push", minute: 72, title: "Build on the shared base image" };
  await job(s, "build image", [...npmBuild().slice(0, 4), httpObs("https://ghcr.io/v2/test-org/base/manifests/22", { bodyHash: { sha256: FOREIGN } })], ["pkg:pypi/requests@2.32.3"], logLines("Run docker build"));
  run(s);

  // 8. slopsquat: an install asks npm for a name that does not exist.
  s = { repo: WEB, run: RUNS.slop, branch: "feat/eta-model", event: "pull_request", minute: 84, pr: 6, title: "ETA model: add helper package" };
  await twins(s, { both: [httpObs("https://registry.npmjs.org/fast-eta-utils-pro", { statusCode: 404 })] });
  await job(s, "release", null, [], "", { offset: 5, conclusion: "skipped" });
  run(s);

  // 9. A run in progress: CRACI lists both twins as running; nothing is known about them yet.
  s = { repo: WEB, run: RUNS.live, branch: "main", event: "push", minute: 118, title: "Carrier feed: retry on 503" };
  const a = await job(s, "build (bare)", null, [], "", { status: "in_progress", conclusion: null });
  const b = await job(s, "build (decoy)", null, [], "", { status: "in_progress", conclusion: null });
  run(s, "in_progress", null);
  const active: JobSummary[] = [a.gh, b.gh].map((j) => ({
    provider: "github", repository: WEB, runId: s.run, jobId: String(j.id), runAttempt: 1, commitSha: sha(`commit-${s.run}`).slice(0, 40), branch: "main", workflow: "ci", jobName: j.name, status: "running", startedAt: at(118), url: j.html_url ?? "",
  }));

  await index.compact();
  await put(join(dir, "console", "state", "github.json"), JSON.stringify(github));
  await put(join(dir, "console", "state", "active.json"), JSON.stringify({ at: at(120), jobs: active }));
  await put(join(dir, "fleet.json"), JSON.stringify(REPOS));
  await put(
    join(dir, "replays.json"),
    JSON.stringify({
      replays: [
        { id: "shai-hulud", incident: "Shai-Hulud npm worm, Sep and Nov 2025", how: "A dependency update whose code fires only if an npm token is present.", expected: "twins", repo: "test-web", branch: "deps/telemetry-utils-2.1.1" },
        { id: "release-gate", incident: "Nx s1ngularity, Aug 2025", how: "Fires only when the ref is a tag and the event is a release.", expected: "twins", repo: "test-web", branch: "deps/release-notes-1.4.1" },
        { id: "fresh-host", incident: "axios, 31 Mar 2026", how: "A new dependency that calls a never-seen host on every build.", expected: "new egress", repo: "test-web", branch: "deps/add-retry-fetch" },
        { id: "cache-poison", incident: "TanStack, 11 May 2026; Ultralytics, Dec 2024", how: "A pull-request job saves a cache under the key the release job restores.", expected: "cache lineage", repo: "test-api", branch: "perf/faster-ci" },
        { id: "tag-repoint", incident: "tj-actions, Mar 2025; Trivy action, Mar 2026", how: "A script fetched by a mutable URL returns new bytes.", expected: "URL-hash drift", repo: "test-base", branch: "ci/pin-setup" },
        { id: "image-repoint", incident: "KICS image, 22 Apr 2026", how: "A base image tag moves to a digest no job of ours produced.", expected: "image provenance", repo: "test-api", branch: "ci/base-22" },
        { id: "slopsquat", incident: "Hallucinated package names, 2026", how: "An install asks the registry for a name that does not exist.", expected: "registry 404s", repo: "test-web", branch: "feat/eta-model" },
        { id: "pth", incident: "LiteLLM, 24 Mar 2026", how: "A Python package with a .pth file that fires at interpreter start if cloud keys are present.", expected: "twins", repo: null, branch: null },
      ],
    }),
  );
  await put(join(dir, "README.md"), "Synthetic console fixture built by parallax/test/console/fixture.ts from test factories. Not real data. Safe to delete.\n");
  return { dir };
}

if (import.meta.main) {
  const dir = process.argv[2] || "/bulk3/runs/craci/dev-fixture";
  await buildFixtureDir(dir);
  console.log(`fixture written to ${dir}\nrun: PLX_FIXTURE=1 PLX_RUNS_DIR=${dir} bun src/server.ts`);
}
