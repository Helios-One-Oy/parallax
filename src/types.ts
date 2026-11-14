// Types for the CRACI API, hand-written from research/dl/openapi.json (exact field names),
// plus the Verdict contract from SPEC.md. Unknown extra fields are always tolerated.

// ---------- CRACI: network trace ----------

export type HashValue = { md5?: string | null; sha256?: string | null; sha512?: string | null };

export type HttpObservation = {
  method: string;
  originUrl: string;
  ipAddress: string;
  statusCode: number;
  bodySizeBytes: string; // decimal string
  policyDenied: boolean;
  bodyHash?: HashValue | null;
  denyReason?: string | null;
  matchedRule?: string | null;
  [extra: string]: unknown;
};

export type DnsObservation = {
  nameserverIp: string;
  record: string; // "DNS record name and type requested by the job" (exact format not specified)
  response: string;
  [extra: string]: unknown;
};

export type TcpObservation = {
  remoteIp: string;
  resolvedHosts: string[];
  port: number;
  bytesToRemote: string;
  bytesFromRemote: string;
  allowed: boolean;
  tlsAlpn: string[];
  tlsServerName?: string | null;
  denyReason?: string | null;
  duration?: string | null;
  error?: string | null;
  matchedRule?: string | null;
  [extra: string]: unknown;
};

export type SshGitObservation = {
  host: string;
  port: number;
  user: string;
  service: string;
  repoPath: string;
  originUrl: string;
  allowed: boolean;
  bytesToUpstream: string;
  bytesFromUpstream: string;
  depthForced: boolean;
  denyReason?: string | null;
  duration?: string | null;
  exitStatus?: number | null;
  matchedRule?: string | null;
  [extra: string]: unknown;
};

type ObsBase = { sequence: number; observedAt: string; [extra: string]: unknown };
export type HttpNetworkObservation = ObsBase & { protocol: "http"; http: HttpObservation };
export type DnsNetworkObservation = ObsBase & { protocol: "dns"; dns: DnsObservation };
export type TcpNetworkObservation = ObsBase & { protocol: "tcp"; tcp: TcpObservation };
export type SshGitNetworkObservation = ObsBase & { protocol: "ssh_git"; sshGit: SshGitObservation };
export type NetworkObservation =
  | HttpNetworkObservation
  | DnsNetworkObservation
  | TcpNetworkObservation
  | SshGitNetworkObservation;

export type JobMetadata = {
  provider: string;
  repository: string;
  runId: string;
  jobId: string;
  runAttempt: number;
  commitSha: string;
  branch: string;
  workflow: string;
  jobName: string;
  status: string;
  [extra: string]: unknown;
};

export type NetworkTrace = {
  schemaVersion: string;
  job: JobMetadata;
  observations: NetworkObservation[];
  [extra: string]: unknown;
};

// ---------- CRACI: jobs, usage, problem ----------

export type JobSummary = JobMetadata & { startedAt: string; url: string };
export type Jobs = { jobs: JobSummary[] };
export type Usage = { start: string; end: string; total: { vcpuSeconds: number } };
export type Problem = { type: string; title: string; status: number; detail: string };

// ---------- CRACI: artifact provenance ----------

export type PreviewArtifactKind =
  | "oci_image_manifest"
  | "oci_image_index"
  | "oci_unknown_manifest"
  | "oci_manifest"
  | "oci_blob"
  | "gha_cache";

export type PreviewGithubJobIdentity = { kind: "github"; repository: string; job_id: string };
export type PreviewOciPublicationMetadata = { kind: "oci"; registry: string; repository: string; reference: string };
export type PreviewGhaCachePublicationMetadata = {
  kind: "gha_cache";
  cache_key: string;
  version: string;
  size_bytes: number;
};
export type PreviewPublicationMetadata = PreviewOciPublicationMetadata | PreviewGhaCachePublicationMetadata;

export type PreviewCreatingJob = {
  craci_job_id: string;
  provider: PreviewGithubJobIdentity;
  accepted_at: string;
  metadata: PreviewPublicationMetadata;
};

export type PreviewPlatform = {
  os: string;
  architecture: string;
  os_features?: string[];
  os_version?: string | null;
  variant?: string | null;
};

export type PreviewReference = {
  kind: PreviewArtifactKind;
  role: "config" | "layer" | "manifest";
  digest: string;
  media_type: string;
  size_bytes: number;
  ref: string;
  platform?: PreviewPlatform | null;
  position?: number | null;
  urls?: string[];
};

export type PreviewDescriptor = { media_type: string; digest: string; size_bytes: number };

export type PreviewArtifactProvenance = {
  artifact_id: string;
  kind: PreviewArtifactKind;
  digest: string;
  jobs_created_in: PreviewCreatingJob[];
  refers: PreviewReference[];
  annotations?: Record<string, string>;
  artifact_type?: string | null;
  cache_id?: string | null;
  media_type?: string | null;
  purl?: string;
  subject?: PreviewDescriptor | null;
  [extra: string]: unknown;
};

// ---------- CycloneDX (only what we read) ----------

export type CdxComponent = {
  type?: string;
  name?: string;
  version?: string;
  purl?: string;
  "bom-ref"?: string;
  components?: CdxComponent[];
  [extra: string]: unknown;
};
export type CycloneDxBom = {
  bomFormat?: string;
  specVersion?: string;
  metadata?: Record<string, unknown>;
  components?: CdxComponent[];
  [extra: string]: unknown;
};

// ---------- Verdict (SPEC.md, exact) ----------

export type JobRef = { jobId: string; name: string; status: string; url: string };

export type Divergence = {
  side: "decoy-only" | "bare-only";
  kind: "http" | "dns" | "tcp" | "ssh_git" | "package";
  key: string;
  host: string;
  sample: unknown;
  novelInFleet: boolean;
  why: string;
};

/** The detectors, by the name shown everywhere. "twins" findings are the `divergences`. */
export type Organ = "twins" | "twin downloads" | "new egress" | "cache lineage" | "same URL, new bytes" | "image provenance" | "registry 404";

/** Something a detector other than the twin diff found for one job of the run. */
export type Finding = {
  organ: Exclude<Organ, "twins">;
  /** The job of this run it was found in. */
  jobId: string;
  jobName: string;
  /** What it is about: a host, a cache key, a URL, an image tag or a package name. */
  key: string;
  host: string;
  /** One plain sentence. */
  why: string;
  /** Which CRACI or GitHub record shows it. */
  evidence: string;
  /** True when this finding fails the verdict job. */
  fails: boolean;
  /** Would a CRACI `network:` policy have stopped it, in one sentence. Null when no network rule can. */
  policy: string | null;
};

/** Whether a detector could say anything for this run, and on how much data. */
export type Check = {
  organ: Organ;
  state: "checked" | "too_little_history" | "nothing_to_check";
  note: string;
};

export type Verdict = {
  repo: string;
  runId: string;
  commitSha: string;
  branch: string;
  twins: { bare: JobRef; decoy: JobRef };
  /** The twin diff alone. */
  status: "clean" | "divergent" | "inconclusive";
  divergences: Divergence[];
  ignored: { count: number; rules: string[] };
  stats: { bare: number; decoy: number; shared: number };
  createdAt: string;
  // ---- added 14 Nov: one verdict, all detectors. Absent in verdict files written before. ----
  /** What the other detectors found for the jobs of this run. Empty when they found nothing. */
  findings?: Finding[];
  /** One line per detector: did it have enough to go on. */
  checks?: Check[];
  /** Every job of the run that was looked at, and whether CRACI had a trace for it. */
  jobs?: Array<JobRef & { traced: boolean }>;
  /** What the verdict job does: fail = the twins diverged or a finding that fails was made. */
  result?: "pass" | "fail" | "inconclusive";
  /** The detectors that caught something, in the order above. */
  caughtBy?: Organ[];
};
