// Every normalisation and noise rule lives here, as data. One surprise in a real trace = one new line.
//
// Order of work for one observation (see normalize.ts):
//   1. HOST_RULES   rewrite the host name (rotating shards -> one canonical name), all protocols
//   2. RULES        first match wins: either `noise` (dropped, with a reason) or a canonical path (HTTP only)
//   3. SEGMENT_RULES  when no rule decided the path, volatile path segments are replaced one by one
//
// The lists below were written from the OpenAPI schema and public knowledge of the tools, before any
// real CRACI trace existed. Check them against the first real trace.

export type Kind = "http" | "dns" | "tcp" | "ssh_git";

export type HostRule = { name: string; match: RegExp; to: string };

export type Rule = {
  name: string;
  /** Protocols this rule applies to. Default: all. */
  proto?: Kind[];
  /** Tested against the canonical host (lower case, no port). */
  host: RegExp;
  /** HTTP only: tested against the cleaned path (no query). */
  path?: RegExp;
  /** HTTP only: canonical path; `$1`… refer to groups of `path`. Omitted = keep the path exactly as it is. */
  to?: string;
  /** Present = the observation is noise; the text says why. */
  noise?: string;
};

export type SegmentRule = { name: string; match: RegExp; to: string };

// Our own sink (sink/): it serves the specimen packages as an npm registry under /registry and takes
// the specimens' calls on /stage2/:id and /collect. One place for its address, like everywhere else.
export const SINK_URL = (process.env.PLX_SINK_URL || "https://parallax-sink.fly.dev").replace(/\/+$/, "");
export const SINK_HOST = new URL(SINK_URL).host;
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// 1. Hosts whose name itself rotates between runs.
export const HOST_RULES: HostRule[] = [
  // Only GitHub's own result/cache storage accounts are folded together; any other storage account keeps its name.
  { name: "gha-results-storage", match: /^productionresultssa\d+\.blob\.core\.windows\.net$/, to: "productionresultssa*.blob.core.windows.net" },
  { name: "gha-pipelines-shard", match: /^pipelines[a-z0-9-]*\.actions\.githubusercontent\.com$/, to: "pipelines*.actions.githubusercontent.com" },
  // Seen in the first real fleet runs: run-actions-1-azure-eastus, run-actions-2-azure-eastus, ...
  { name: "gha-run-shard", match: /^run-actions-\d+-[a-z0-9-]+\.actions\.githubusercontent\.com$/, to: "run-actions-*.actions.githubusercontent.com" },
  { name: "gha-vstoken-shard", match: /^vstoken[a-z0-9-]*\.actions\.githubusercontent\.com$/, to: "vstoken*.actions.githubusercontent.com" },
  { name: "s3-regional", match: /^([a-z0-9.-]+)\.s3[.-][a-z0-9-]+\.amazonaws\.com$/, to: "$1.s3.amazonaws.com" },
  { name: "cloudfront-node", match: /^d[a-z0-9]{12,14}\.cloudfront\.net$/, to: "*.cloudfront.net" },
  { name: "quay-cdn-shard", match: /^cdn\d+\.quay\.io$/, to: "cdn*.quay.io" },
];

// 2. Named rules, first match wins.
export const RULES: Rule[] = [
  // --- noise: plumbing of the runner itself, not of the build ---
  {
    name: "runner-telemetry",
    host: /(^|\.)(applicationinsights\.azure\.com|in\.applicationinsights\.azure\.com|services\.visualstudio\.com|events\.data\.microsoft\.com)$/,
    noise: "telemetry sent by the GitHub Actions runner program, not by the build",
  },
  {
    name: "craci-control-plane",
    host: /(^|\.)craci\.com$/,
    noise: "the CRACI runner talking to CRACI itself",
  },

  // --- GitHub Actions job plumbing: one key per service, the ids inside the path change every run ---
  { name: "gha-service", proto: ["http"], host: /(^|\.)actions\.githubusercontent\.com$/, path: /^\/.*$/, to: "/*" },
  { name: "gha-results-blob", proto: ["http"], host: /^productionresultssa\*\.blob\.core\.windows\.net$/, path: /^\/([^/]+)\/.*$/, to: "/$1/*" },

  // --- package registries: the path names a package version, keep it ---
  { name: "npm-registry", proto: ["http"], host: /^(registry\.npmjs\.org|registry\.yarnpkg\.com)$/ },
  { name: "pypi-files", proto: ["http"], host: /^files\.pythonhosted\.org$/, path: /^\/packages\/.*\/([^/]+)$/, to: "/packages/*/$1" },
  { name: "pypi-index", proto: ["http"], host: /^pypi\.org$/ },
  { name: "crates", proto: ["http"], host: /^(index|static)\.crates\.io$/ },
  { name: "go-proxy", proto: ["http"], host: /^proxy\.golang\.org$/ },
  { name: "rubygems", proto: ["http"], host: /^(index\.)?rubygems\.org$/ },

  // --- OCI registries: digests and tags identify content, upload sessions do not ---
  { name: "oci-upload-session", proto: ["http"], host: /./, path: /^(\/v2\/.+\/blobs\/uploads)\/.*$/, to: "$1/*" },
  { name: "oci-content", proto: ["http"], host: /./, path: /^\/v2\/.+\/(blobs|manifests)\/[^/]+$/ },
  { name: "docker-cdn-blob", proto: ["http"], host: /^production\.cloudflare\.docker\.com$/, path: /^\/registry-v2\/.*\/(sha256\/[0-9a-f]{2}\/[0-9a-f]{64})\/data$/, to: "/registry-v2/*/$1/data" },

  // --- GitHub: release downloads are redirected to signed, one-time URLs ---
  { name: "github-release-asset", proto: ["http"], host: /^(objects|release-assets)\.githubusercontent\.com$/, path: /^\/([^/]+)\/.*$/, to: "/$1/*" },
  { name: "github-raw", proto: ["http"], host: /^raw\.githubusercontent\.com$/ },
  { name: "github-codeload", proto: ["http"], host: /^codeload\.github\.com$/ },
];

// 3. Generic scrubbing of one path segment (used only when no rule in RULES fixed the path).
export const SEGMENT_RULES: SegmentRule[] = [
  { name: "guid", match: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, to: "{guid}" },
  { name: "hex-digest", match: /^[0-9a-f]{32,}$/i, to: "{hex}" },
  { name: "epoch-time", match: /^1\d{9}(\d{3})?$/, to: "{time}" },
  { name: "iso-time", match: /^\d{4}-\d\d-\d\d(T[\d:.Z+-]+)?$/, to: "{time}" },
  { name: "long-number", match: /^\d{7,}$/, to: "{id}" },
  { name: "opaque-token", match: /^[A-Za-z0-9_~-]{48,}$/, to: "{token}" },
];

// URLs whose bytes change by design: never reported as "same URL, different bytes" (fleet.urlHashDrift).
// Tested against "host/path" (no scheme, no query).
export const MUTABLE_URL_RULES: Array<{ name: string; match: RegExp }> = [
  { name: "npm-packument", match: /^(registry\.npmjs\.org|registry\.yarnpkg\.com)\/(?!.*\/-\/)/ },
  { name: "sink-registry-packument", match: new RegExp(`^${esc(SINK_HOST)}/registry/(?!tarballs/)`) },
  { name: "pypi-index-page", match: /^pypi\.org\/(simple|pypi)\// },
  { name: "apt-index", match: /\/(dists\/.*|InRelease|Release(\.gpg)?|Packages(\.(gz|xz|bz2))?|APKINDEX\.tar\.gz)$/ },
  { name: "go-proxy-list", match: /^proxy\.golang\.org\/.*\/@(v\/list|latest)$/ },
  { name: "crates-index", match: /^index\.crates\.io\// },
  { name: "rubygems-index", match: /^(index\.)?rubygems\.org\/(versions|info\/|names|api\/)/ },
  { name: "oci-tag-or-token", match: /\/v2\/.+\/manifests\/(?!sha(256|512):)[^/]+$|\/v2\/?$|\/token$/ },
  { name: "git-refs", match: /\/info\/refs$|\/git-upload-pack$/ },
  { name: "github-api", match: /^api\.github\.com\// },
  { name: "gha-service", match: /(^|\.)actions\.githubusercontent\.com\// },
];

// Registry "this name does not exist" answers (fleet.notFound). Group 1 = the package name.
export const REGISTRY_404_RULES: Array<{ name: string; registry: string; match: RegExp }> = [
  { name: "npm", registry: "npm", match: /^(?:registry\.npmjs\.org|registry\.yarnpkg\.com)\/((?:@[^/]+\/)?[^/]+)$/ },
  { name: "sink-registry", registry: "npm", match: new RegExp(`^${esc(SINK_HOST)}/registry/(?!tarballs/)((?:@[^/]+/)?[^/]+)$`) },
  { name: "pypi", registry: "pypi", match: /^pypi\.org\/simple\/([^/]+)\/?$/ },
  { name: "crates", registry: "cargo", match: /^index\.crates\.io\/(?:[^/]+\/){1,2}([^/]+)$/ },
  { name: "go", registry: "golang", match: /^proxy\.golang\.org\/(.+)\/@v\/list$/ },
  { name: "rubygems", registry: "gem", match: /^(?:index\.)?rubygems\.org\/info\/([^/]+)$/ },
];

// Hosts covered by a built-in CRACI network preset (policySuggestion). `matchedRule` in the trace wins
// over this table when it names a preset.
export const PRESET_HOSTS: Array<{ preset: string; host: RegExp }> = [
  { preset: "npm", host: /^(registry\.npmjs\.org|registry\.yarnpkg\.com)$/ },
  { preset: "pypi", host: /^(pypi\.org|files\.pythonhosted\.org)$/ },
  { preset: "rubygems", host: /^(index\.)?rubygems\.org$/ },
  { preset: "alpine", host: /^dl-cdn\.alpinelinux\.org$/ },
  { preset: "debian", host: /^(deb|security)\.debian\.org$/ },
  { preset: "ubuntu", host: /^(([a-z0-9-]+\.)?archive|security|ports|snapshot)\.ubuntu\.com$/ },
  { preset: "cargo", host: /^((index|static)\.)?crates\.io$/ },
  { preset: "golang", host: /^proxy\.golang\.org$/ },
  { preset: "fonts", host: /^(fonts\.googleapis\.com|fonts\.gstatic\.com|use\.typekit\.net|fonts\.bunny\.net|api\.fontshare\.com)$/ },
  { preset: "cache-nixos-org", host: /^(cache\.nixos\.org|[a-z0-9-]+\.cachix\.org)$/ },
  { preset: "dockerhub", host: /^(registry-1\.docker\.io|auth\.docker\.io|index\.docker\.io|production\.cloudflare\.docker\.com)$/ },
  { preset: "ghcr", host: /^(ghcr\.io|pkg-containers\.githubusercontent\.com)$/ },
  { preset: "quay", host: /^(quay\.io|cdn\*\.quay\.io)$/ },
  { preset: "gcr", host: /^([a-z0-9-]+\.)?gcr\.io$/ },
  { preset: "ecr-public", host: /^public\.ecr\.aws$/ },
  { preset: "github", host: /^(github\.com|api\.github\.com|codeload\.github\.com|raw\.githubusercontent\.com|objects\.githubusercontent\.com|release-assets\.githubusercontent\.com)$/ },
  { preset: "gitlab", host: /^gitlab\.com$/ },
  { preset: "docker-apt", host: /^download\.docker\.com$/ },
  { preset: "nodesource", host: /^deb\.nodesource\.com$/ },
  { preset: "bitbucket", host: /^bitbucket\.org$/ },
];

// Private package registries: allowed as a CRACI package `source` (a URL prefix, still inspected),
// never as a whole-host connection. `path` = the part of the host that is the registry.
export const SOURCE_HOSTS: Array<{ source: "npm" | "pypi"; host: RegExp; path: RegExp; url: string }> = [
  { source: "npm", host: new RegExp(`^${esc(SINK_HOST)}$`), path: /^\/registry(\/|$)/, url: `${SINK_URL}/registry` },
];

/** Complete list of preset names CRACI accepts (guides_setup-action-network.md). */
export const PRESET_NAMES = [
  "pypi", "npm", "rubygems", "alpine", "debian", "ubuntu", "cargo", "golang", "fonts", "cache-nixos-org",
  "dockerhub", "ghcr", "quay", "gcr", "ecr-public", "github", "gitlab", "docker-apt", "nodesource",
  "raspbian", "yocto", "openembedded", "bitbucket", "googlesource",
];

// "CRACI always allows CI job and cache management traffic to GitHub services": no policy line needed.
export const PLATFORM_HOSTS: RegExp[] = [
  /(^|\.)actions\.githubusercontent\.com$/,
  /^productionresultssa\*\.blob\.core\.windows\.net$/,
  /(^|\.)craci\.com$/,
  // CRACI's own store for GitHub Actions caches (matchedRule "github-actions-cache-…" in real traces).
  /^cache\.blob\.core\.windows\.net$/,
];

// Lines printed by actions/cache and the setup-* actions. Group 1 = the cache key.
export const CACHE_RESTORE_LOG_PATTERNS: RegExp[] = [
  /Cache restored from key:\s*(\S.*?)\s*$/,
  /Cache hit for:\s*(\S.*?)\s*$/,
  /Cache hit for restore-key:\s*(\S.*?)\s*$/,
];
export const CACHE_SAVE_LOG_PATTERNS: RegExp[] = [/Cache saved with (?:the )?key:\s*(\S.*?)\s*$/];

// A twin "reached the build" when a step with such a name actually ran (diff.ts, cli.ts).
export const BUILD_STEP_PATTERN = /\b(build|install|test|compile|lint|npm|pnpm|yarn|bun|pip|poetry|uv|cargo|go|make|docker|plx-run)\b/i;

// The verdict looks for these two jobs in a run.
export const TWIN_JOB_PATTERNS = { bare: /\(bare\)\s*$/, decoy: /\(decoy\)\s*$/ };

// The step that dresses a twin. Until it starts, the two twins are the same code with the same inputs,
// so a difference seen earlier cannot have been caused by the decoy credentials (diff.BEFORE_DRESS_RULE).
export const DRESS_STEP_PATTERN = /(^|[\s/])dress(\s|@|$)/i;

// Steps that are never "the build": runner bookkeeping and `uses:` steps (default name "Run owner/repo@ref").
export const SETUP_STEP_PATTERN = /^(Set up job|Complete job|Post |Pre |Run [\w.-]+\/[\w./-]+@|Initialize containers|Stop containers)/;

// Workflow events anyone outside the team can trigger. A cache written by such a job and restored by a
// job of a trusted event is the cache-poisoning pattern (graph.cacheLineageAlerts).
export const UNTRUSTED_EVENTS = ["pull_request", "pull_request_target", "issue_comment", "issues", "discussion", "discussion_comment", "fork", "watch"];

// New egress means something only against some history: this many earlier runs of the repo with a CRACI trace.
export const MIN_EGRESS_RUNS = 3;

// "Same URL, new bytes" fails the verdict only when the old bytes were seen by at least this many earlier jobs.
export const MIN_STABLE_JOBS = 2;
