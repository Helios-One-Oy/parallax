// Contact tracing: a graph of jobs, packages, fetched bytes, caches and image layers, and the rings
// around a seed (who fetched it, what they wrote, who read that, what those wrote).
import type { CacheRecord, FleetIndex, FleetJob } from "./fleet.ts";
import type { GithubClient } from "./github.ts";
import { splitUrl } from "./normalize.ts";
import { CACHE_RESTORE_LOG_PATTERNS, CACHE_SAVE_LOG_PATTERNS, UNTRUSTED_EVENTS } from "./rules.ts";
import type { JobSummary, NetworkTrace, PreviewArtifactProvenance } from "./types.ts";

// ---------- derivations from raw CRACI data (the parts that will need tuning) ----------

export type OciRefs = {
  manifests: Array<{ registry: string; name: string; ref: string; digest: string | null; op: "pull" | "push" }>;
  blobs: Array<{ registry: string; name: string; digest: string; op: "pull" | "push" }>;
};

const DIGEST = /^sha(256:[0-9a-f]{64}|512:[0-9a-f]{128})$/;

export function canonRegistry(host: string): string {
  return /^(registry-1|index)\.docker\.io$/.test(host) ? "docker.io" : host;
}

/** Image pulls and pushes visible in a trace as registry API calls (`/v2/<name>/manifests|blobs/...`). */
export function ociRefsFromTrace(trace: Pick<NetworkTrace, "observations"> | null | undefined): OciRefs {
  const out: OciRefs = { manifests: [], blobs: [] };
  const seen = new Set<string>();
  const push = <T>(list: T[], id: string, item: T) => {
    if (!seen.has(id)) {
      seen.add(id);
      list.push(item);
    }
  };
  for (const o of trace?.observations ?? []) {
    if (o?.protocol !== "http" || !o.http) continue;
    const h = o.http;
    const u = splitUrl(h.originUrl);
    if (!u) continue;
    const method = String(h.method ?? "").toUpperCase();
    const ok = h.statusCode >= 200 && h.statusCode < 300 && !h.policyDenied;
    const registry = canonRegistry(u.hostPort);
    const m = /^\/v2\/(.+)\/(manifests|blobs)\/([^/]+)$/.exec(u.path);
    if (m && ok && (method === "GET" || method === "PUT")) {
      const [, name, what, ref] = m as unknown as [string, string, string, string];
      const op = method === "GET" ? "pull" : "push";
      if (what === "manifests") {
        // By tag: the digest of a manifest is the SHA-256 of its bytes, which is the response body hash of a pull.
        const digest = DIGEST.test(ref) ? ref : op === "pull" && h.bodyHash?.sha256 ? `sha256:${h.bodyHash.sha256.toLowerCase()}` : null;
        push(out.manifests, `m ${op} ${registry}/${name}:${ref}`, { registry, name, ref, digest, op });
      } else if (DIGEST.test(ref) && op === "pull") {
        push(out.blobs, `b pull ${ref}`, { registry, name, digest: ref, op });
      }
      continue;
    }
    // Blob upload: PUT /v2/<name>/blobs/uploads/<session>?digest=sha256:...
    const up = /^\/v2\/(.+)\/blobs\/uploads(\/.*)?$/.exec(u.path);
    if (up && ok && method === "PUT") {
      let digest: string | null = null;
      try {
        digest = new URL(h.originUrl).searchParams.get("digest");
      } catch {
        digest = null;
      }
      if (digest && DIGEST.test(digest)) push(out.blobs, `b push ${digest}`, { registry, name: up[1]!, digest, op: "push" });
    }
  }
  return out;
}

/** Cache keys a job restored and saved, read from the lines actions/cache prints. */
export function cacheEventsFromLog(logText: string): { restored: string[]; saved: string[] } {
  const restored = new Set<string>();
  const saved = new Set<string>();
  for (const raw of logText.split("\n")) {
    const tab = raw.indexOf("\t");
    const line = (tab >= 0 ? raw.slice(tab + 1) : raw).replace(/\r$/, "").replace(/\x1b\[[0-9;]*m/g, "");
    for (const re of CACHE_RESTORE_LOG_PATTERNS) {
      const m = re.exec(line);
      if (m) restored.add(m[1]!);
    }
    for (const re of CACHE_SAVE_LOG_PATTERNS) {
      const m = re.exec(line);
      if (m) saved.add(m[1]!);
    }
  }
  return { restored: [...restored], saved: [...saved] };
}

export const jobNodeId = (repo: string, jobId: string | number) => `job:${repo}#${jobId}`;
export const cacheNodeId = (repo: string, id: string | number) => `cache:${repo}#${id}`;
const unresolvedCacheId = (repo: string, key: string) => `cache:${repo}#key=${key}`;

function cacheCreators(c: CacheRecord): Array<{ repo: string; jobId: string }> {
  return (c.provenance?.jobs_created_in ?? []).map((j) => ({ repo: j.provider.repository, jobId: String(j.provider.job_id) }));
}

/**
 * Which caches did this job restore? Two sources:
 *  1. log lines of actions/cache ("Cache restored from key: K"), matched to the newest cache with key K
 *     in the same repo that existed before the job ended and was not written by the job itself;
 *  2. the trace: a download whose body hash equals a cache archive digest known to CRACI.
 * A key that matches no known cache still gives an (unresolved) cache node, so the edge is not lost.
 */
export function deriveCacheRestores(
  job: FleetJob,
  caches: CacheRecord[],
): Array<{ nodeId: string; key: string; evidence: string; record: CacheRecord | null }> {
  const out = new Map<string, { nodeId: string; key: string; evidence: string; record: CacheRecord | null }>();
  const mine = caches.filter((c) => c.repo === job.repo);
  const selfMade = (c: CacheRecord) => cacheCreators(c).some((j) => j.repo === job.repo && j.jobId === job.jobId);
  const end = job.completedAt ?? job.startedAt;

  // 0. CRACI's own record: the job's SBOM lists the cache entry, and cache provenance names another job as its writer.
  for (const g of job.ghaCaches ?? []) {
    const rec = mine.find((c) => String(c.id) === g.entryId) ?? null;
    const wroteIt = rec ? selfMade(rec) : false;
    const knownWriter = !!rec && cacheCreators(rec).length > 0;
    // Without provenance only the job's own log can tell a restore from a save.
    if (wroteIt || (!knownWriter && !job.cache.restored.includes(g.key))) continue;
    const nodeId = cacheNodeId(job.repo, g.entryId);
    out.set(nodeId, {
      nodeId,
      key: g.key || rec?.key || g.entryId,
      evidence: knownWriter ? "CRACI lists the cache entry in this job's SBOM and names another job as its writer" : `CRACI lists the cache entry in this job's SBOM; job log: "Cache restored from key: ${g.key}"`,
      record: rec,
    });
  }
  const viaSbom = new Set([...out.values()].map((r) => r.key));
  for (const key of job.cache.restored) {
    if (viaSbom.has(key)) continue;
    const candidates = mine
      .filter((c) => c.key === key && !selfMade(c) && (!end || !c.created_at || c.created_at <= end))
      .sort((a, b) => b.created_at.localeCompare(a.created_at));
    const pick = candidates.find((c) => !job.startedAt || c.created_at <= job.startedAt) ?? candidates[0] ?? null;
    const nodeId = pick ? cacheNodeId(job.repo, pick.id) : unresolvedCacheId(job.repo, key);
    out.set(nodeId, { nodeId, key, evidence: `job log: "Cache restored from key: ${key}"`, record: pick });
  }
  const hashes = new Set(job.urlHashes.map(([, sha]) => `sha256:${sha}`));
  for (const c of mine) {
    if (!c.digest || !hashes.has(c.digest) || selfMade(c)) continue;
    const nodeId = cacheNodeId(job.repo, c.id);
    if (!out.has(nodeId)) out.set(nodeId, { nodeId, key: c.key, evidence: `trace: downloaded bytes with the cache's digest ${c.digest}`, record: c });
  }
  return [...out.values()];
}

/** Does the trace show the job downloading this package itself (as opposed to inheriting it from a cache)? */
export function fetchedPackage(purl: string, keys: string[]): boolean {
  const m = /^pkg:[^/]+\/(.+?)@([^?#]+)/.exec(purl);
  if (!m) return false;
  const norm = (s: string) => decodeURIComponent(s).toLowerCase().replace(/[_.]/g, "-");
  const name = norm(m[1]!.split("/").pop()!);
  const version = decodeURIComponent(m[2]!).toLowerCase();
  return keys.some((k) => {
    if (!k.startsWith("http GET ")) return false;
    const low = k.toLowerCase();
    return low.replace(/[_.]/g, "-").includes(name) && low.includes(version);
  });
}

// ---------- graph ----------

export type NodeType = "job" | "package" | "url" | "host" | "cache" | "blob" | "manifest" | "repo";
export type EdgeType = "in_repo" | "fetched" | "has_package" | "contacted" | "created" | "refers" | "restored" | "pulled";
export type GNode = { id: string; type: NodeType; label: string; repo?: string; data?: unknown };
export type GEdge = { from: string; to: string; type: EdgeType; evidence: string };

export class Graph {
  readonly nodes = new Map<string, GNode>();
  readonly edges: GEdge[] = [];
  private readonly outIx = new Map<string, GEdge[]>();
  private readonly inIx = new Map<string, GEdge[]>();
  private readonly seen = new Set<string>();

  node(n: GNode): GNode {
    const have = this.nodes.get(n.id);
    if (have) {
      if (n.data !== undefined && have.data === undefined) have.data = n.data;
      return have;
    }
    this.nodes.set(n.id, n);
    return n;
  }
  edge(from: string, to: string, type: EdgeType, evidence: string) {
    const k = `${from}\n${to}\n${type}`;
    if (this.seen.has(k)) return;
    this.seen.add(k);
    const e = { from, to, type, evidence };
    this.edges.push(e);
    (this.outIx.get(from) ?? this.outIx.set(from, []).get(from)!).push(e);
    (this.inIx.get(to) ?? this.inIx.set(to, []).get(to)!).push(e);
  }
  out(id: string, type?: EdgeType): GEdge[] {
    const l = this.outIx.get(id) ?? [];
    return type ? l.filter((e) => e.type === type) : l;
  }
  in(id: string, type?: EdgeType): GEdge[] {
    const l = this.inIx.get(id) ?? [];
    return type ? l.filter((e) => e.type === type) : l;
  }
  toJSON() {
    return { nodes: [...this.nodes.values()], edges: this.edges };
  }
}

export type GraphInput = Pick<FleetIndex, "jobs" | "caches" | "artifacts"> | {
  jobs: Iterable<FleetJob>;
  caches: Iterable<CacheRecord>;
  artifacts: Iterable<PreviewArtifactProvenance>;
};

const values = <T>(x: Iterable<T> | Map<string, T>): T[] => (x instanceof Map ? [...x.values()] : [...(x as Iterable<T>)]);

export function buildGraph(input: GraphInput): Graph {
  const g = new Graph();
  const jobs = values<FleetJob>(input.jobs as any);
  const caches = values<CacheRecord>(input.caches as any);
  const artifacts = values<PreviewArtifactProvenance>(input.artifacts as any);

  const jobNode = (repo: string, jobId: string, j?: FleetJob) => {
    g.node({ id: `repo:${repo}`, type: "repo", label: repo, repo });
    const n = g.node({ id: jobNodeId(repo, jobId), type: "job", label: j ? `${j.name} #${jobId}` : `job #${jobId}`, repo, data: j });
    g.edge(n.id, `repo:${repo}`, "in_repo", "GitHub");
    return n.id;
  };

  for (const j of jobs) {
    const id = jobNode(j.repo, j.jobId, j);
    for (const h of j.hosts) {
      g.node({ id: `host:${h}`, type: "host", label: h });
      g.edge(id, `host:${h}`, "contacted", "CRACI network trace");
    }
    for (const p of j.purls) {
      g.node({ id: p, type: "package", label: p });
      g.edge(id, p, "has_package", fetchedPackage(p, j.keys) ? "CRACI SBOM, download seen in the trace" : "CRACI SBOM");
    }
    for (const [url, sha] of j.urlHashes) {
      const uid = `url:${url}@sha256:${sha}`;
      g.node({ id: uid, type: "url", label: url, data: { url, sha256: sha } });
      g.edge(id, uid, "fetched", "CRACI network trace (URL and body hash)");
    }
  }

  // caches: who created them
  for (const c of caches) {
    const cid = cacheNodeId(c.repo, c.id);
    g.node({ id: cid, type: "cache", label: c.key, repo: c.repo, data: c });
    const creators = cacheCreators(c);
    for (const cr of creators) g.edge(jobNode(cr.repo, cr.jobId), cid, "created", "CRACI cache provenance");
    if (creators.length === 0) {
      // No provenance: fall back to the "Cache saved with key" log line of a job that ended around the cache's creation.
      const t = Date.parse(c.created_at);
      const saver = jobs
        .filter((j) => j.repo === c.repo && j.cache.saved.includes(c.key))
        .filter((j) => !Number.isFinite(t) || (Date.parse(j.startedAt) <= t && t <= Date.parse(j.completedAt ?? j.startedAt) + 10 * 60_000))
        .sort((a, b) => b.startedAt.localeCompare(a.startedAt))[0];
      if (saver) g.edge(jobNodeId(saver.repo, saver.jobId), cid, "created", `job log: "Cache saved with key: ${c.key}"`);
    }
  }

  // caches: who restored them
  for (const j of jobs) {
    for (const r of deriveCacheRestores(j, caches)) {
      g.node({ id: r.nodeId, type: "cache", label: r.key, repo: j.repo, data: r.record ?? { key: r.key, unresolved: true } });
      g.edge(jobNodeId(j.repo, j.jobId), r.nodeId, "restored", r.evidence);
    }
  }

  // OCI artifacts: creators and references
  const ociId = (kind: string, digest: string) => `${kind === "oci_blob" ? "blob" : "manifest"}:${digest}`;
  const tagIndex = new Map<string, Array<{ digest: string; at: string }>>();
  for (const a of artifacts) {
    if (a.kind === "gha_cache" || a.unknown_to_craci) continue;
    const id = ociId(a.kind, a.digest);
    g.node({ id, type: a.kind === "oci_blob" ? "blob" : "manifest", label: a.digest.slice(0, 19), data: a });
    for (const cr of a.jobs_created_in ?? []) {
      g.edge(jobNode(cr.provider.repository, String(cr.provider.job_id)), id, "created", "CRACI artifact provenance");
      if (cr.metadata?.kind === "oci" && a.kind !== "oci_blob") {
        const k = `${canonRegistry(cr.metadata.registry)}/${cr.metadata.repository}:${cr.metadata.reference}`;
        (tagIndex.get(k) ?? tagIndex.set(k, []).get(k)!).push({ digest: a.digest, at: cr.accepted_at });
      }
    }
    for (const r of a.refers ?? []) {
      const rid = ociId(r.kind, r.digest);
      g.node({ id: rid, type: r.kind === "oci_blob" ? "blob" : "manifest", label: r.digest.slice(0, 19) });
      g.edge(id, rid, "refers", `manifest lists it as ${r.role}`);
    }
  }

  // OCI: who pulled what
  for (const j of jobs) {
    const id = jobNodeId(j.repo, j.jobId);
    for (const m of j.oci?.manifests ?? []) {
      const tagKey = `${m.registry}/${m.name}:${m.ref}`;
      if (m.op === "push") {
        if (m.digest) {
          g.node({ id: `manifest:${m.digest}`, type: "manifest", label: tagKey });
          g.edge(id, `manifest:${m.digest}`, "created", `trace: PUT ${tagKey}`);
        }
        continue;
      }
      let digest = m.digest;
      if (!digest) {
        const end = j.completedAt ?? j.startedAt;
        digest =
          (tagIndex.get(tagKey) ?? [])
            .filter((t) => !end || t.at <= end)
            .sort((a, b) => b.at.localeCompare(a.at))[0]?.digest ?? null;
      }
      const mid = digest ? `manifest:${digest}` : `manifest:${tagKey}`;
      g.node({ id: mid, type: "manifest", label: tagKey, data: digest ? undefined : { unresolved: true } });
      g.edge(id, mid, "pulled", `trace: GET ${m.registry}/v2/${m.name}/manifests/${m.ref}`);
    }
    for (const b of j.oci?.blobs ?? []) {
      g.node({ id: `blob:${b.digest}`, type: "blob", label: b.digest.slice(0, 19) });
      if (b.op === "pull") g.edge(id, `blob:${b.digest}`, "pulled", `trace: GET ${b.registry}/v2/${b.name}/blobs/${b.digest.slice(0, 19)}…`);
      else g.edge(id, `blob:${b.digest}`, "created", `trace: blob upload to ${b.registry}/${b.name}`);
    }
  }
  return g;
}

// ---------- rings ----------

export type RingMember = {
  id: string;
  type: NodeType;
  ring: 0 | 1 | 2 | 3;
  label: string;
  repo?: string;
  /** Node ids from a ring-0 job (or the seed) to this member. */
  path: string[];
  /** The same path in plain words. */
  why: string;
};

export type Rings = {
  seed: string;
  seedKind: "package" | "host" | "url-hash" | "job";
  rings: [RingMember[], RingMember[], RingMember[], RingMember[]];
  /** Mean number of ring-2 jobs per ring-0 job. */
  r0: number;
};

const ARTIFACT_TYPES = new Set<NodeType>(["cache", "blob", "manifest"]);
const ringJobs = new WeakMap<Rings, Map<string, FleetJob>>();

export function rings(g: Graph, seed: string): Rings {
  const seedKind: Rings["seedKind"] = seed.startsWith("job:")
    ? "job"
    : seed.startsWith("pkg:")
      ? "package"
      : /^sha256:[0-9a-f]{64}$/i.test(seed)
        ? "url-hash"
        : "host";
  const member = new Map<string, RingMember>();
  const put = (id: string, ring: RingMember["ring"], path: string[], why: string): boolean => {
    if (member.has(id)) return false;
    const n = g.nodes.get(id);
    if (!n) return false;
    member.set(id, { id, type: n.type, ring, label: n.label, repo: n.repo, path, why });
    return true;
  };
  const label = (id: string) => {
    const n = g.nodes.get(id);
    return n ? `${n.type} ${n.label}` : id;
  };

  // ring 0
  const weak: Array<{ id: string; why: string }> = [];
  if (seedKind === "job") {
    const want = seed.slice(4);
    for (const n of g.nodes.values())
      if (n.type === "job" && (n.id === seed || n.id.endsWith(`#${want}`))) put(n.id, 0, [n.id], "This job is the seed.");
  } else if (seedKind === "package") {
    const exact = seed.split("?")[0]!;
    const versioned = exact.lastIndexOf("@") > exact.indexOf("/");
    for (const n of g.nodes.values()) {
      if (n.type !== "package" || !(n.id === exact || (!versioned && n.id.startsWith(`${exact}@`)))) continue;
      for (const e of g.in(n.id, "has_package")) {
        if (e.evidence.includes("download seen")) put(e.from, 0, [n.id, e.from], `Downloaded ${n.id} itself (CRACI SBOM and trace).`);
        else weak.push({ id: e.from, why: `Has ${n.id} in its SBOM; no download of it in its own trace.` });
      }
    }
  } else if (seedKind === "url-hash") {
    const sha = seed.toLowerCase();
    for (const n of g.nodes.values()) {
      if (n.type !== "url" || !n.id.endsWith(`@${sha}`)) continue;
      for (const e of g.in(n.id, "fetched")) put(e.from, 0, [n.id, e.from], `Fetched ${n.label} and got these exact bytes (${sha.slice(0, 19)}…).`);
    }
  } else {
    const hid = `host:${seed.toLowerCase()}`;
    for (const e of g.in(hid, "contacted")) put(e.from, 0, [hid, e.from], `Contacted ${seed} (CRACI network trace).`);
  }

  // A layer that was pulled from a place none of our jobs push to (the public base image under our own) is
  // not our jobs' work, whoever pushed it on. Neither is a layer the same job pulled before it pushed it.
  const ours = new Set<string>();
  for (const e of g.edges) {
    if (e.type !== "created") continue;
    const up = /blob upload to (\S+)/.exec(e.evidence)?.[1] ?? /trace: PUT (\S+):[^:\s]+$/.exec(e.evidence)?.[1];
    if (up) ours.add(up);
  }
  const from = (evidence: string) => /GET (\S+?)\/v2\/(\S+)\/blobs\//.exec(evidence)?.slice(1, 3).join("/") ?? "";
  const inherited = (jobId: string, blobId: string): boolean => {
    if (!blobId.startsWith("blob:")) return false;
    const pulls = g.in(blobId, "pulled");
    return pulls.some((p) => p.from === jobId || (ours.size > 0 && from(p.evidence) !== "" && !ours.has(from(p.evidence))));
  };

  const spread = (fromRing: 0 | 2, toRing: 1 | 3) => {
    for (const m of [...member.values()].filter((x) => x.ring === fromRing && x.type === "job")) {
      for (const e of g.out(m.id, "created")) {
        if (inherited(m.id, e.to)) continue;
        if (!put(e.to, toRing, [...m.path, e.to], `Written by ${label(m.id)} (${e.evidence}).`)) continue;
        // An image that lists a tainted layer or manifest is tainted too.
        const stack = [e.to];
        while (stack.length) {
          const cur = stack.pop()!;
          for (const r of g.in(cur, "refers")) {
            const base = member.get(cur)!;
            if (put(r.from, toRing, [...base.path, r.from], `Its manifest lists ${label(cur)} (${r.evidence}).`)) stack.push(r.from);
          }
        }
      }
    }
  };

  // Jobs that only inherited the package are ring 0 only if nothing else explains them; decide after ring 2.
  spread(0, 1);
  const ring2 = () => {
    for (const a of [...member.values()].filter((x) => x.ring === 1 && ARTIFACT_TYPES.has(x.type))) {
      for (const e of [...g.in(a.id, "restored"), ...g.in(a.id, "pulled")]) {
        put(e.from, 2, [...a.path, e.from], `${e.type === "restored" ? "Restored" : "Pulled"} ${label(a.id)} (${e.evidence}).`);
      }
    }
  };
  ring2();
  let added = false;
  for (const w of weak) added = put(w.id, 0, [w.id], w.why) || added;
  if (added) {
    spread(0, 1);
    ring2();
  }
  spread(2, 3);

  const by = (r: number) => [...member.values()].filter((m) => m.ring === r).sort((a, b) => a.id.localeCompare(b.id));
  const out: Rings = { seed, seedKind, rings: [by(0), by(1), by(2), by(3)], r0: 0 };
  out.r0 = r0Of(out);
  // Remember the job records behind the members (run ids, workflow, branch) for ringFence, outside the JSON.
  const records = new Map<string, FleetJob>();
  for (const m of member.values()) {
    const d = g.nodes.get(m.id)?.data as FleetJob | undefined;
    if (m.type === "job" && d && typeof d === "object" && "runId" in d) records.set(m.id, d);
  }
  ringJobs.set(out, records);
  return out;
}

function r0Of(r: Rings): number {
  const zero = r.rings[0].filter((m) => m.type === "job");
  if (zero.length === 0) return 0;
  const per = new Map<string, Set<string>>(zero.map((m) => [m.id, new Set<string>()]));
  for (const m of r.rings[2]) {
    const origin = m.path.find((id) => per.has(id));
    if (origin) per.get(origin)!.add(m.id);
  }
  let sum = 0;
  for (const s of per.values()) sum += s.size;
  return sum / zero.length;
}

/** Mean number of ring-2 jobs per ring-0 job: how far one contaminated job spreads. */
export function r0(g: Graph, seed: string): number {
  return rings(g, seed).r0;
}

// ---------- ring fence ----------

export type FenceAction =
  | { type: "cancel_run"; repo: string; runId: string; reason: string }
  | { type: "delete_cache"; repo: string; cacheId: number; key: string; reason: string }
  | { type: "rerun_run"; repo: string; runId: string; reason: string }
  | { type: "open_pr"; repo: string; branch: string; title: string; body: string; path: string; content: string; reason: string };

export type FenceResult = {
  dryRun: boolean;
  actions: Array<FenceAction & { executed: boolean; ok?: boolean; detail?: string }>;
  /** Things Parallax cannot do through GitHub, in plain words. */
  manual: string[];
};

export type FenceOptions = {
  /** Default true: only list the actions. */
  dryRun?: boolean;
  github?: GithubClient;
  /** Jobs running right now (CRACI `GET /v1preview1/jobs?status=active`). */
  active?: JobSummary[];
  /** Network policy YAML per repo (from policySuggestion) for the pull request. */
  policies?: Record<string, string>;
};

/**
 * The concrete containment steps for a set of rings. Order matters: stop what is running, delete the
 * contaminated caches, then re-run (the re-run then finds no cache), then propose the network policy.
 */
export async function ringFence(r: Rings, o: FenceOptions = {}): Promise<FenceResult> {
  const dryRun = o.dryRun !== false;
  const actions: FenceAction[] = [];
  const manual: string[] = [];
  const all = r.rings.flat();
  const artifacts = all.filter((m) => ARTIFACT_TYPES.has(m.type));
  const hotRepos = new Set(all.map((m) => m.repo).filter(Boolean) as string[]);

  const cancelled = new Set<string>();
  for (const j of o.active ?? []) {
    if (!hotRepos.has(j.repository) || cancelled.has(`${j.repository}#${j.runId}`)) continue;
    cancelled.add(`${j.repository}#${j.runId}`);
    actions.push({
      type: "cancel_run",
      repo: j.repository,
      runId: String(j.runId),
      reason: `Run is in progress in a repo with contaminated caches or images; it could restore one (seed ${r.seed}).`,
    });
  }

  for (const m of artifacts) {
    const cm = /^cache:(.+)#(\d+)$/.exec(m.id);
    if (cm && !Number.isSafeInteger(Number(cm[2]))) {
      // An entry id of CRACI's cache store, not a GitHub cache id.
      manual.push(`Cache "${m.label}" in ${cm[1]} is held by CRACI's cache store, which GitHub's API cannot delete from. Change the cache key in the workflow so no job restores it again.`);
    } else if (cm) {
      actions.push({ type: "delete_cache", repo: cm[1]!, cacheId: Number(cm[2]), key: m.label, reason: m.why });
    } else if (m.type === "cache") {
      manual.push(`Cache with key "${m.label}" in ${m.repo ?? "?"} is not in GitHub's cache list any more; nothing to delete.`);
    } else {
      manual.push(`Image ${m.type} ${m.id.split(":").slice(1).join(":")} must be retired in its registry by hand.`);
    }
  }

  // Re-run the newest affected run per repo, workflow and branch.
  const newest = new Map<string, { repo: string; runId: string; at: string; name: string }>();
  for (const m of r.rings[2]) {
    const j = ringJobs.get(r)?.get(m.id);
    if (!j?.runId) continue;
    const k = `${j.repo}\n${j.workflow}\n${j.branch}`;
    const have = newest.get(k);
    if (!have || have.at < j.startedAt) newest.set(k, { repo: j.repo, runId: j.runId, at: j.startedAt, name: j.name });
  }
  for (const n of newest.values()) {
    if (cancelled.has(`${n.repo}#${n.runId}`)) continue;
    actions.push({
      type: "rerun_run",
      repo: n.repo,
      runId: n.runId,
      reason: `Job "${n.name}" used a contaminated cache or image; run it again now that the cache is gone.`,
    });
  }

  for (const repo of new Set(r.rings[0].map((m) => m.repo).filter(Boolean) as string[])) {
    const policy = o.policies?.[repo];
    if (!policy) {
      manual.push(`No network policy was supplied for ${repo}; no pull request planned.`);
      continue;
    }
    const slug = r.seed.replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40);
    actions.push({
      type: "open_pr",
      repo,
      branch: `parallax/fence-${slug}`,
      title: `Parallax: block network access outside what the build needs`,
      body: [
        `Parallax traced \`${r.seed}\` through this repo's jobs.`,
        "",
        "This pull request adds the network policy the clean build needs and nothing more.",
        "Paste the block from `.github/parallax/network-policy.yml` into the `network:` input of the `cracicorp/setup@v1` step.",
      ].join("\n"),
      path: ".github/parallax/network-policy.yml",
      content: policy,
      reason: `Jobs of ${repo} are ring 0 for ${r.seed}.`,
    });
  }

  const result: FenceResult = { dryRun, actions: actions.map((a) => ({ ...a, executed: false })), manual };
  if (dryRun) return result;
  if (!o.github) throw new Error("ringFence: a GithubClient is needed when dryRun is false");
  for (const a of result.actions) {
    try {
      if (a.type === "cancel_run") await o.github.cancelRun(a.repo, a.runId);
      else if (a.type === "delete_cache") await o.github.deleteCache(a.repo, a.cacheId);
      else if (a.type === "rerun_run") await o.github.rerunRun(a.repo, a.runId);
      else {
        const pr = await o.github.createPullRequest(a.repo, {
          branch: a.branch,
          title: a.title,
          body: a.body,
          message: a.title,
          files: [{ path: a.path, content: a.content }],
        });
        a.detail = pr.html_url;
      }
      a.ok = true;
    } catch (e) {
      a.ok = false;
      a.detail = e instanceof Error ? e.message : String(e);
    }
    a.executed = true;
  }
  return result;
}

// ---------- two detectors that read the same graph data ----------

export type LineageAlert = {
  repo: string;
  cache: { id: string; key: string };
  writer: { jobId: string; name: string; event: string; branch: string };
  reader: { jobId: string; runId: string; name: string; event: string; branch: string };
  evidence: string;
  why: string;
};

/**
 * Cache lineage: a cache written by a job anyone can trigger (a pull request, an issue comment) and
 * restored by a job of a trusted event (push, release, schedule). The Ultralytics and TanStack pattern.
 */
export function cacheLineageAlerts(g: Graph): LineageAlert[] {
  const out: LineageAlert[] = [];
  const untrusted = (event: string) => UNTRUSTED_EVENTS.includes(event);
  for (const e of g.edges) {
    if (e.type !== "restored") continue;
    const reader = g.nodes.get(e.from)?.data as FleetJob | undefined;
    const cache = g.nodes.get(e.to);
    if (!reader?.event || !cache || untrusted(reader.event)) continue;
    for (const c of g.in(e.to, "created")) {
      const writer = g.nodes.get(c.from)?.data as FleetJob | undefined;
      if (!writer?.event || !untrusted(writer.event)) continue;
      out.push({
        repo: reader.repo,
        cache: { id: cache.id, key: cache.label },
        writer: { jobId: writer.jobId, name: writer.name, event: writer.event, branch: writer.branch },
        reader: { jobId: reader.jobId, runId: reader.runId, name: reader.name, event: reader.event, branch: reader.branch },
        evidence: `${c.evidence}; ${e.evidence}`,
        why: `Job "${reader.name}" (${reader.event} on ${reader.branch || "?"}) restored the cache "${cache.label}", which was written by job "${writer.name}" of a ${writer.event.replace(/_/g, " ")} run on ${writer.branch || "?"}. Anyone can trigger that kind of run.`,
      });
    }
  }
  return out.sort((a, b) => a.reader.jobId.localeCompare(b.reader.jobId));
}

/**
 * Is this image repository one of ours? Yes when one of our jobs pushed to it (seen in its trace), or
 * when it sits under the GitHub organisation of a fleet repo on ghcr.io (ghcr.io/<org>/…).
 */
export function ourImageRepos(jobs: Iterable<FleetJob>): (registry: string, name: string) => boolean {
  const pushed = new Set<string>();
  const orgs = new Set<string>();
  for (const j of jobs) {
    orgs.add(j.repo.split("/")[0]!.toLowerCase());
    for (const m of j.oci?.manifests ?? []) if (m.op === "push") pushed.add(`${m.registry}/${m.name}`);
  }
  return (registry, name) => pushed.has(`${registry}/${name}`) || (registry === "ghcr.io" && orgs.has(name.split("/")[0]!.toLowerCase()));
}

export type ImageAlert = {
  repo: string;
  jobId: string;
  name: string;
  image: string;
  digest: string;
  /** Digests our own jobs pushed under the same tag, newest first. */
  ours: string[];
  why: string;
};

/**
 * Image provenance: a job pulled an image from a repository our own jobs push to, but the bytes it got
 * were not produced by any of our jobs (CRACI has no creating job for that digest). The tag was moved.
 */
export function foreignImagePulls(input: GraphInput): ImageAlert[] {
  const jobs = values<FleetJob>(input.jobs as any);
  const artifacts = values<PreviewArtifactProvenance>(input.artifacts as any);
  const ourRepos = new Set<string>();
  const made = new Set<string>();
  const asked = new Set(artifacts.map((a) => a.digest));
  const byTag = new Map<string, Array<{ digest: string; at: string }>>();
  for (const a of artifacts) {
    if (a.kind === "gha_cache" || a.kind === "oci_blob") continue;
    for (const cr of a.jobs_created_in ?? []) {
      made.add(a.digest);
      if (cr.metadata?.kind !== "oci") continue;
      const repo = `${canonRegistry(cr.metadata.registry)}/${cr.metadata.repository}`;
      ourRepos.add(repo);
      const k = `${repo}:${cr.metadata.reference}`;
      (byTag.get(k) ?? byTag.set(k, []).get(k)!).push({ digest: a.digest, at: cr.accepted_at });
    }
  }
  const isOurs = ourImageRepos(jobs);
  const out: ImageAlert[] = [];
  for (const j of jobs) {
    // Docker asks for the tag (HEAD) and then fetches the manifest by digest: one pull, one row per job and
    // digest, and the row that names the tag is the one kept.
    const mine = new Map<string, { alert: ImageAlert; byDigest: boolean }>();
    const keep = (repo: string, alert: ImageAlert, byDigest: boolean) => {
      const k = `${repo}\n${alert.digest}`;
      const had = mine.get(k);
      if (!had || (had.byDigest && !byDigest)) mine.set(k, { alert, byDigest });
    };
    for (const m of j.oci?.manifests ?? []) {
      const repo = `${m.registry}/${m.name}`;
      // Only a digest CRACI was asked about can be called foreign: unknown stays unknown.
      if (m.op !== "pull" || !m.digest || !(ourRepos.has(repo) || isOurs(m.registry, m.name)) || made.has(m.digest) || !asked.has(m.digest)) continue;
      const byDigest = DIGEST.test(m.ref);
      // Pulled by tag: what our jobs pushed under that tag. Pulled by digest: what our jobs pushed to that repository at all.
      const pushed = byDigest ? [...byTag].filter(([k]) => k.startsWith(`${repo}:`)).flatMap(([, v]) => v) : (byTag.get(`${repo}:${m.ref}`) ?? []);
      const ours = [...new Set(pushed.sort((a, b) => b.at.localeCompare(a.at)).map((x) => x.digest))];
      const image = byDigest ? `${repo}@${m.digest.slice(0, 19)}…` : `${repo}:${m.ref}`;
      keep(
        repo,
        {
          repo: j.repo,
          jobId: j.jobId,
          name: j.name,
          image,
          digest: m.digest,
          ours,
          why: `Job "${j.name}" pulled ${byDigest ? repo : image} and got ${m.digest.slice(0, 19)}…. CRACI knows no job of ours that produced those bytes${ours.length ? ` (the newest image our jobs pushed there is ${ours[0]!.slice(0, 19)}…)` : ""}.`,
        },
        byDigest,
      );
    }
    for (const x of mine.values()) out.push(x.alert);
  }
  return out;
}
