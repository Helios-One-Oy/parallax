// A hand-built synthetic fleet for the graph and fleet tests: 6 jobs in 3 repos, 2 caches, 1 image.
//
//   web #101  downloads the specimen package, calls the sink, saves cache 501
//   web #102  restores cache 501 (so its SBOM carries the specimen), pushes image M1 (layer B1)
//   web #103  clean, unrelated
//   api #201  pulls image M1, saves cache 502
//   api #202  restores cache 502
//   base #301 clean, unrelated
import { buildFleetJob, FleetIndex, type CacheRecord } from "../src/fleet.ts";
import type { PreviewArtifactProvenance } from "../src/types.ts";
import { at, cacheRecord, ghJob, httpObs, logLines, npmBuild, sbom, sha, trace } from "./factories.ts";

export const WEB = "test-org/test-web";
export const API = "test-org/test-api";
export const BASE = "test-org/test-base";
export const SPECIMEN = "pkg:npm/plx-specimen@9.9.9";
export const CLEAN_PURLS = ["pkg:npm/left-pad@1.3.0", "pkg:npm/%40types/node@22.9.0"];
export const M1 = `sha256:${sha("manifest-1")}`;
export const B1 = `sha256:${sha("layer-1")}`;
export const STAGE2_URL = "https://plx-sink.test/stage2/x.txt";
export const STAGE2_HASH = `sha256:${sha(STAGE2_URL)}`;

export async function buildFixture(dir: string | null = null, opts: { firstJobEvent?: string } = {}): Promise<{ index: FleetIndex; caches: CacheRecord[]; artifacts: PreviewArtifactProvenance[] }> {
  const index = new FleetIndex(dir);
  const add = (repo: string, id: number, run: number, minute: number, name: string, obs: any[], purls: string[], logs: string, event = "push") =>
    index.addJob(
      buildFleetJob({
        repo,
        job: ghJob({ id, run_id: run, name }, minute),
        run: { event, head_branch: "main", name: "ci" },
        trace: trace(obs, { repository: repo, jobId: String(id), runId: String(run), jobName: name }, minute),
        sbom: sbom(purls),
        logs,
        now: at(minute + 4),
      }),
    );

  await add(
    WEB, 101, 11, 0, "build (bare)",
    [...npmBuild(), httpObs("https://plx-registry.test/plx-specimen/-/plx-specimen-9.9.9.tgz"), httpObs(STAGE2_URL), httpObs("https://plx-sink.test/collect", { method: "POST" })],
    [...CLEAN_PURLS, SPECIMEN],
    logLines("Run actions/cache@v4", "Cache not found for input keys: npm-linux-abc", "Post job cleanup.", "Cache saved with key: npm-linux-abc"),
    opts.firstJobEvent ?? "push",
  );
  await add(
    WEB, 102, 12, 10, "release",
    [
      ...npmBuild().slice(0, 4),
      httpObs(`https://ghcr.io/v2/test-org/web/blobs/uploads/9f8e7d6c-1111-2222-3333-444444444444?digest=${encodeURIComponent(B1)}`, { method: "PUT", statusCode: 201 }),
      httpObs("https://ghcr.io/v2/test-org/web/manifests/v1", { method: "PUT", statusCode: 201 }),
    ],
    [...CLEAN_PURLS, SPECIMEN],
    logLines("Run actions/cache@v4", "Cache hit for: npm-linux-abc", "Cache restored from key: npm-linux-abc"),
  );
  await add(WEB, 103, 13, 20, "lint", npmBuild(), CLEAN_PURLS, logLines("Run npm ci"));
  await add(
    API, 201, 21, 30, "build (bare)",
    [
      ...npmBuild().slice(0, 4),
      httpObs("https://ghcr.io/v2/test-org/web/manifests/v1", { bodyHash: { sha256: M1.slice(7) } }),
      httpObs(`https://ghcr.io/v2/test-org/web/blobs/${B1}`),
    ],
    ["pkg:pypi/requests@2.32.3"],
    logLines("Cache saved with key: pip-linux-xyz"),
  );
  await add(API, 202, 22, 40, "test", npmBuild().slice(0, 4), ["pkg:pypi/requests@2.32.3"], logLines("Cache restored from key: pip-linux-xyz"));
  await add(BASE, 301, 31, 50, "build (bare)", npmBuild(), CLEAN_PURLS, logLines("Run npm ci"));

  const caches = [
    cacheRecord({ repo: WEB, id: 501, key: "npm-linux-abc", createdMinute: 3, createdByJob: "101" }),
    cacheRecord({ repo: API, id: 502, key: "pip-linux-xyz", createdMinute: 33, createdByJob: "201" }),
  ];
  for (const c of caches) await index.addCache(c);

  const createdBy102 = (reference: string) => ({
    craci_job_id: "500102",
    provider: { kind: "github" as const, repository: WEB, job_id: "102" },
    accepted_at: at(12),
    metadata: { kind: "oci" as const, registry: "ghcr.io", repository: "test-org/web", reference },
  });
  const artifacts: PreviewArtifactProvenance[] = [
    {
      artifact_id: "9001",
      kind: "oci_image_manifest",
      digest: M1,
      media_type: "application/vnd.oci.image.manifest.v1+json",
      jobs_created_in: [createdBy102("v1")],
      refers: [
        {
          kind: "oci_blob",
          role: "layer",
          digest: B1,
          media_type: "application/vnd.oci.image.layer.v1.tar+gzip",
          size_bytes: 2048,
          position: 0,
          ref: `/v1preview1/artifact-provenance/oci_blob?digest=${B1}`,
        },
      ],
    },
    { artifact_id: "9002", kind: "oci_blob", digest: B1, jobs_created_in: [createdBy102(B1)], refers: [] },
  ];
  for (const a of artifacts) await index.addArtifact(a);
  return { index, caches, artifacts };
}
