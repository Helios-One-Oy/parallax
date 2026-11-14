// Synthetic CRACI data for tests only. Shapes follow research/dl/openapi.json exactly.
// Nothing built here is real and nothing here may be shown as if it were.
import type { GhJob } from "../src/github.ts";
import type { CacheRecord } from "../src/fleet.ts";
import type {
  CycloneDxBom,
  DnsNetworkObservation,
  HttpNetworkObservation,
  HttpObservation,
  JobMetadata,
  JobRef,
  NetworkObservation,
  NetworkTrace,
  PreviewArtifactProvenance,
  SshGitNetworkObservation,
  SshGitObservation,
  TcpNetworkObservation,
  TcpObservation,
} from "../src/types.ts";

export const T0 = Date.parse("2026-11-14T10:00:00Z");
export const at = (minutes: number) => new Date(T0 + minutes * 60_000).toISOString().replace(".000Z", "Z");
export const sha = (seed: string) => new Bun.CryptoHasher("sha256").update(seed).digest("hex");

export function httpObs(originUrl: string, o: Partial<HttpObservation> = {}): HttpNetworkObservation {
  const method = o.method ?? "GET";
  return {
    sequence: 0,
    observedAt: at(0),
    protocol: "http",
    http: {
      method,
      originUrl,
      ipAddress: "104.16.0.35",
      statusCode: 200,
      bodySizeBytes: "1024",
      policyDenied: false,
      bodyHash: method === "GET" ? { sha256: sha(originUrl.split("?")[0]!), sha512: null, md5: null } : null,
      denyReason: null,
      matchedRule: null,
      ...o,
    },
  };
}

export function dnsObs(name: string, type = "A", response = "104.16.0.35"): DnsNetworkObservation {
  return { sequence: 0, observedAt: at(0), protocol: "dns", dns: { nameserverIp: "10.0.0.2", record: `${name} ${type}`, response } };
}

export function tcpObs(sni: string | null, port = 443, o: Partial<TcpObservation> = {}): TcpNetworkObservation {
  return {
    sequence: 0,
    observedAt: at(0),
    protocol: "tcp",
    tcp: {
      remoteIp: "104.16.0.35",
      resolvedHosts: sni ? [sni] : [],
      port,
      bytesToRemote: "517",
      bytesFromRemote: "4096",
      allowed: true,
      tlsAlpn: sni ? ["h2", "http/1.1"] : [],
      tlsServerName: sni,
      denyReason: null,
      duration: "120ms",
      error: null,
      matchedRule: null,
      ...o,
    },
  };
}

export function sshGitObs(host: string, repoPath: string, o: Partial<SshGitObservation> = {}): SshGitNetworkObservation {
  return {
    sequence: 0,
    observedAt: at(0),
    protocol: "ssh_git",
    sshGit: {
      host,
      port: 22,
      user: "git",
      service: "git-upload-pack",
      repoPath,
      originUrl: `git@${host}:${repoPath}`,
      allowed: true,
      bytesToUpstream: "300",
      bytesFromUpstream: "90000",
      depthForced: false,
      denyReason: null,
      duration: "1s",
      exitStatus: 0,
      matchedRule: null,
      ...o,
    },
  };
}

export function jobMeta(o: Partial<JobMetadata> = {}): JobMetadata {
  return {
    provider: "github",
    repository: "test-org/test-web",
    runId: "9001",
    jobId: "70001",
    runAttempt: 1,
    commitSha: "0123456789abcdef0123456789abcdef01234567",
    branch: "main",
    workflow: "ci",
    jobName: "build (bare)",
    status: "success",
    ...o,
  };
}

/** A trace whose observations get their sequence numbers and times in the order given. */
export function trace(observations: NetworkObservation[], job: Partial<JobMetadata> = {}, startMinute = 0): NetworkTrace {
  return {
    schemaVersion: "1",
    job: jobMeta(job),
    observations: observations.map((o, i) => ({ ...o, sequence: i, observedAt: new Date(T0 + startMinute * 60_000 + i * 250).toISOString() })) as NetworkObservation[],
  };
}

/** What an ordinary small npm build does on the network. */
export function npmBuild(opts: { ip?: string; token?: string; guid?: string } = {}): NetworkObservation[] {
  const ip = opts.ip ?? "104.16.0.35";
  const token = opts.token ?? "sig-aaaa";
  const guid = opts.guid ?? "11111111-2222-3333-4444-555555555555";
  return [
    dnsObs("github.com", "A", "140.82.121.3"),
    tcpObs("github.com", 443, { remoteIp: "140.82.121.3" }),
    httpObs("https://github.com/test-org/test-web/info/refs?service=git-upload-pack", { ipAddress: "140.82.121.3", matchedRule: "github" }),
    httpObs("https://github.com/test-org/test-web/git-upload-pack", { method: "POST", ipAddress: "140.82.121.3", matchedRule: "github" }),
    dnsObs("registry.npmjs.org", "A", ip),
    dnsObs("registry.npmjs.org", "AAAA", ""),
    tcpObs("registry.npmjs.org", 443, { remoteIp: ip }),
    httpObs("https://registry.npmjs.org/left-pad", { ipAddress: ip, matchedRule: "npm" }),
    httpObs("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", { ipAddress: ip, matchedRule: "npm" }),
    httpObs("https://registry.npmjs.org/@types%2fnode", { ipAddress: ip, matchedRule: "npm" }),
    httpObs("https://registry.npmjs.org/@types/node/-/node-22.9.0.tgz", { ipAddress: ip, matchedRule: "npm" }),
    httpObs(`https://results-receiver.actions.githubusercontent.com/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL`, { method: "POST" }),
    httpObs(`https://productionresultssa7.blob.core.windows.net/actions-cache/${guid}/cache.tzst?sv=2025-01-05&sig=${token}`, { ipAddress: "20.60.1.1" }),
    httpObs("https://example-docs.test/guide/index.html", { ipAddress: ip }),
  ];
}

export function sbom(purls: string[]): CycloneDxBom {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    components: purls.map((purl) => {
      const m = /^pkg:[^/]+\/(.+)@(.+)$/.exec(purl);
      return { type: "library", name: m?.[1] ?? purl, version: m?.[2] ?? "", purl, "bom-ref": purl };
    }),
  };
}

export const jobRef = (jobId: string, name: string, status = "success"): JobRef => ({
  jobId,
  name,
  status,
  url: `https://github.com/test-org/test-web/actions/runs/9001/job/${jobId}`,
});

export function ghJob(o: Partial<GhJob> & { id: number; run_id: number; name: string }, startMinute = 0): GhJob {
  return {
    status: "completed",
    conclusion: "success",
    started_at: at(startMinute),
    completed_at: at(startMinute + 3),
    html_url: `https://github.com/x/actions/runs/${o.run_id}/job/${o.id}`,
    head_sha: "0123456789abcdef0123456789abcdef01234567",
    head_branch: "main",
    workflow_name: "ci",
    ...o,
  };
}

export function cacheRecord(o: { repo: string; id: number; key: string; createdMinute: number; createdByJob?: string; digest?: string }): CacheRecord {
  const digest = o.digest ?? `sha256:${sha(`cache-${o.id}`)}`;
  const provenance: PreviewArtifactProvenance | null = o.createdByJob
    ? {
        artifact_id: String(1000 + o.id),
        kind: "gha_cache",
        digest,
        cache_id: String(o.id),
        refers: [],
        jobs_created_in: [
          {
            craci_job_id: String(500000 + Number(o.createdByJob)),
            provider: { kind: "github", repository: o.repo, job_id: o.createdByJob },
            accepted_at: at(o.createdMinute),
            metadata: { kind: "gha_cache", cache_key: o.key, version: "v1", size_bytes: 4096 },
          },
        ],
      }
    : null;
  return {
    repo: o.repo,
    id: o.id,
    key: o.key,
    ref: "refs/heads/main",
    version: "v1",
    created_at: at(o.createdMinute),
    size_in_bytes: 4096,
    digest: provenance ? digest : null,
    provenance,
  };
}

export const logLines = (...texts: string[]) => texts.map((t, i) => `${new Date(T0 + i * 1000).toISOString()}\t${t}`).join("\n") + "\n";
