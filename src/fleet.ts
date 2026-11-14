// Fleet index: one record per finished job of the fleet repos, persisted as JSON lines.
// Answers: when was a host / package / body hash first seen, which URLs changed their bytes,
// which registry names did not exist, which hosts are new for a repo.
import { appendFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CraciClient } from "./craci.ts";
import { sbomPurls, type FleetLookup } from "./diff.ts";
import type { GhCache, GhJob, GhRun, GithubClient } from "./github.ts";
import { cacheEventsFromLog, ociRefsFromTrace, type OciRefs } from "./graph.ts";
import { hostsOf, normalizeTrace, splitUrl } from "./normalize.ts";
import { fleetDir } from "./paths.ts";
import { MUTABLE_URL_RULES, PLATFORM_HOSTS, REGISTRY_404_RULES, UNTRUSTED_EVENTS } from "./rules.ts";
import type { CycloneDxBom, NetworkTrace, PreviewArtifactProvenance } from "./types.ts";

export type FleetJob = {
  repo: string;
  runId: string;
  jobId: string;
  runAttempt: number;
  name: string;
  workflow: string;
  branch: string;
  commitSha: string;
  event: string;
  status: string;
  conclusion: string | null;
  startedAt: string;
  completedAt: string | null;
  url: string;
  hasTrace: boolean;
  hasSbom: boolean;
  /** Normalised observation keys (noise excluded). */
  keys: string[];
  hosts: string[];
  purls: string[];
  /** GET 200 responses with a body hash: [host/path, sha256]. */
  urlHashes: Array<[string, string]>;
  /** host/path of every 404 answer. */
  notFound: string[];
  /** Keys CRACI's network policy blocked. */
  denied: Array<{ key: string; reason: string | null }>;
  cache: { restored: string[]; saved: string[] };
  /**
   * GitHub Actions cache entries CRACI lists in the job's SBOM (`pkg:ghacache/…?entry_id=N&key=K`):
   * caches the job restored or wrote. CRACI's cache provenance says which (by entry id).
   */
  ghaCaches?: GhaCacheRef[];
  oci: OciRefs;
  indexedAt: string;
  /** Version of the rules this record was derived with (INDEX_VERSION). Older records are derived again. */
  v?: number;
};

export type GhaCacheRef = { entryId: string; key: string; version: string };

/** Bump when normalisation rules or the derived fields change: records are then rebuilt from the API cache. */
export const INDEX_VERSION = 2;

/** Cache entries named in a CRACI SBOM. */
export function ghaCachesOfSbom(bom: CycloneDxBom | null | undefined): GhaCacheRef[] {
  const out = new Map<string, GhaCacheRef>();
  const walk = (list: CycloneDxBom["components"]) => {
    for (const c of list ?? []) {
      const purl = typeof c?.purl === "string" ? c.purl : "";
      if (purl.startsWith("pkg:ghacache/")) {
        const [head, query = ""] = purl.split("?");
        const q = new URLSearchParams(query);
        const entryId = q.get("entry_id") ?? "";
        if (/^\d+$/.test(entryId)) out.set(entryId, { entryId, key: q.get("key") ?? "", version: head!.split("@")[1] ?? "" });
      }
      if (Array.isArray(c?.components)) walk(c.components);
    }
  };
  walk(Array.isArray(bom?.components) ? bom!.components : []);
  return [...out.values()];
}

export type CacheRecord = Omit<GhCache, "id"> & {
  /** GitHub's cache id, or CRACI's cache entry id (a number too large for a JS number, so a string). */
  id: number | string;
  repo: string;
  /** CRACI digest of the cache archive, when CRACI knows the cache. */
  digest: string | null;
  provenance: PreviewArtifactProvenance | null;
};

export type Seen = { at: string; repo: string; runId: string; jobId: string; name: string };

const jobKey = (repo: string, jobId: string) => `${repo}#${jobId}`;

/** Build the index record of one finished job from what GitHub and CRACI returned. */
export function buildFleetJob(input: {
  repo: string;
  job: Pick<GhJob, "id" | "run_id" | "name" | "status" | "conclusion" | "started_at" | "completed_at" | "html_url" | "head_sha"> & Partial<GhJob>;
  run?: Partial<GhRun> | null;
  trace: NetworkTrace | null;
  sbom: CycloneDxBom | null;
  logs?: string | null;
  now?: string;
}): FleetJob {
  const { repo, job, run, trace, sbom } = input;
  const nt = normalizeTrace(trace);
  const urlHashes = new Map<string, [string, string]>();
  const notFound = new Set<string>();
  const denied = new Map<string, string | null>();
  for (const [key, list] of nt.keys) {
    for (const n of list) {
      const o = n.raw as any;
      if (n.kind === "http") {
        const u = splitUrl(o.http.originUrl);
        const url = u ? `${u.hostPort}${u.path}` : String(o.http.originUrl).split("?")[0]!;
        const method = String(o.http.method ?? "").toUpperCase();
        const sha = o.http.bodyHash?.sha256;
        if (method === "GET" && o.http.statusCode === 200 && typeof sha === "string" && sha) urlHashes.set(`${url} ${sha}`, [url, sha.toLowerCase()]);
        if (o.http.statusCode === 404 && (method === "GET" || method === "HEAD")) notFound.add(url);
        if (o.http.policyDenied) denied.set(key, o.http.denyReason ?? null);
      } else if (n.kind === "tcp" && o.tcp.allowed === false) denied.set(key, o.tcp.denyReason ?? null);
      else if (n.kind === "ssh_git" && o.sshGit.allowed === false) denied.set(key, o.sshGit.denyReason ?? null);
    }
  }
  const firstObs = trace?.observations?.map((o) => o.observedAt).filter(Boolean).sort()[0];
  const events = cacheEventsFromLog(input.logs ?? "");
  return {
    repo,
    runId: String(job.run_id ?? trace?.job.runId ?? ""),
    jobId: String(job.id),
    runAttempt: Number(job.run_attempt ?? trace?.job.runAttempt ?? 1),
    name: job.name,
    workflow: String(job.workflow_name ?? run?.name ?? trace?.job.workflow ?? ""),
    branch: String(job.head_branch ?? run?.head_branch ?? trace?.job.branch ?? ""),
    commitSha: String(job.head_sha ?? trace?.job.commitSha ?? ""),
    event: String(run?.event ?? ""),
    status: job.status,
    conclusion: job.conclusion ?? null,
    startedAt: job.started_at ?? firstObs ?? "",
    completedAt: job.completed_at ?? null,
    url: job.html_url ?? "",
    hasTrace: !!trace,
    hasSbom: !!sbom,
    keys: [...nt.keys.keys()].sort(),
    hosts: hostsOf(nt),
    purls: [...sbomPurls(sbom).keys()].sort(),
    urlHashes: [...urlHashes.values()],
    notFound: [...notFound].sort(),
    denied: [...denied].map(([key, reason]) => ({ key, reason })),
    cache: events,
    ghaCaches: ghaCachesOfSbom(sbom),
    oci: ociRefsFromTrace(trace),
    indexedAt: input.now ?? new Date().toISOString(),
    v: INDEX_VERSION,
  };
}

export class FleetIndex implements FleetLookup {
  readonly jobs = new Map<string, FleetJob>();
  readonly caches = new Map<string, CacheRecord>();
  readonly artifacts = new Map<string, PreviewArtifactProvenance>();

  /** `dir: null` = memory only (tests). */
  constructor(readonly dir: string | null = fleetDir()) {}

  static async load(dir: string | null = fleetDir()): Promise<FleetIndex> {
    const ix = new FleetIndex(dir);
    if (!dir) return ix;
    for (const j of await readLines<FleetJob>(join(dir, "jobs.jsonl"))) ix.jobs.set(jobKey(j.repo, j.jobId), j);
    for (const c of await readLines<CacheRecord>(join(dir, "caches.jsonl"))) ix.caches.set(`${c.repo}#${c.id}`, c);
    for (const a of await readLines<PreviewArtifactProvenance>(join(dir, "artifacts.jsonl"))) ix.artifacts.set(a.digest, a);
    return ix;
  }

  hasJob(repo: string, jobId: string | number) {
    return this.jobs.has(jobKey(repo, String(jobId)));
  }
  getJob(repo: string, jobId: string | number) {
    return this.jobs.get(jobKey(repo, String(jobId)));
  }
  async addJob(j: FleetJob) {
    this.jobs.set(jobKey(j.repo, j.jobId), j);
    await this.append("jobs.jsonl", j);
  }
  async addCache(c: CacheRecord) {
    this.caches.set(`${c.repo}#${c.id}`, c);
    await this.append("caches.jsonl", c);
  }
  async addArtifact(a: PreviewArtifactProvenance) {
    this.artifacts.set(a.digest, a);
    await this.append("artifacts.jsonl", a);
  }

  /**
   * Rewrite the files with one line per record (appends leave old versions behind). Several processes
   * write this index (the console's sync, `cli sync`), so what another one appended since this one
   * loaded is read back first and kept: for a record both hold, the newer one wins.
   */
  async compact() {
    if (!this.dir) return;
    await mkdir(this.dir, { recursive: true });
    for (const j of await readLines<FleetJob>(join(this.dir, "jobs.jsonl"))) {
      const mine = this.jobs.get(jobKey(j.repo, j.jobId));
      if (!mine || ((j.v ?? 0) >= (mine.v ?? 0) && j.indexedAt > mine.indexedAt)) this.jobs.set(jobKey(j.repo, j.jobId), j);
    }
    for (const c of await readLines<CacheRecord>(join(this.dir, "caches.jsonl"))) {
      const mine = this.caches.get(`${c.repo}#${c.id}`);
      if (!mine || (!mine.provenance && c.provenance)) this.caches.set(`${c.repo}#${c.id}`, c);
    }
    for (const a of await readLines<PreviewArtifactProvenance>(join(this.dir, "artifacts.jsonl"))) {
      const mine = this.artifacts.get(a.digest);
      if (!mine || (mine.unknown_to_craci && !a.unknown_to_craci)) this.artifacts.set(a.digest, a);
    }
    const dump = (rows: Iterable<unknown>) => [...rows].map((r) => JSON.stringify(r) + "\n").join("");
    const put = async (file: string, text: string) => {
      const tmp = join(this.dir!, `.${file}.${process.pid}.tmp`);
      await writeFile(tmp, text);
      await rename(tmp, join(this.dir!, file));
    };
    await put("jobs.jsonl", dump(this.jobs.values()));
    await put("caches.jsonl", dump(this.caches.values()));
    await put("artifacts.jsonl", dump(this.artifacts.values()));
  }

  private async append(file: string, row: unknown) {
    if (!this.dir) return;
    await mkdir(this.dir, { recursive: true });
    await appendFile(join(this.dir, file), JSON.stringify(row) + "\n");
  }

  /** Jobs oldest first. */
  sorted(): FleetJob[] {
    return [...this.jobs.values()].sort((a, b) => a.startedAt.localeCompare(b.startedAt) || a.jobId.localeCompare(b.jobId));
  }

  // ---------- queries ----------

  /** First job that saw a host, a package (`pkg:...`) or a body hash (`sha256:...`). */
  firstSeen(what: string): Seen | null {
    const has = matcher(what);
    for (const j of this.sorted()) if (has(j)) return seen(j);
    return null;
  }

  /** Every job that saw it, oldest first. */
  jobsWith(what: string): FleetJob[] {
    const has = matcher(what);
    return this.sorted().filter(has);
  }

  seenBefore(kind: "host" | "purl", value: string, o: { before?: string; excludeRunId?: string } = {}): boolean {
    for (const j of this.jobs.values()) {
      if (o.excludeRunId && j.runId === o.excludeRunId) continue;
      if (o.before && j.startedAt && j.startedAt >= o.before) continue;
      if (kind === "host" ? j.hosts.includes(value) : j.purls.includes(value)) return true;
    }
    return false;
  }

  /** "Same URL, different bytes": URLs whose body hash changed between jobs. Mutable-by-nature URLs are left out. */
  urlHashDrift(o: { includeMutable?: boolean } = {}): Array<{
    url: string;
    mutable: string | null;
    versions: Array<{ sha256: string; firstSeen: Seen; jobs: number }>;
  }> {
    const byUrl = new Map<string, Map<string, { firstSeen: Seen; jobs: number }>>();
    for (const j of this.sorted()) {
      const mine = new Set<string>();
      for (const [url, sha] of j.urlHashes) {
        if (mine.has(`${url} ${sha}`)) continue;
        mine.add(`${url} ${sha}`);
        const m = byUrl.get(url) ?? byUrl.set(url, new Map()).get(url)!;
        const v = m.get(sha);
        if (v) v.jobs++;
        else m.set(sha, { firstSeen: seen(j), jobs: 1 });
      }
    }
    const out = [];
    for (const [url, m] of byUrl) {
      if (m.size < 2) continue;
      const mutable = MUTABLE_URL_RULES.find((r) => r.match.test(url))?.name ?? null;
      if (mutable && !o.includeMutable) continue;
      out.push({
        url,
        mutable,
        versions: [...m].map(([sha256, v]) => ({ sha256, ...v })).sort((a, b) => a.firstSeen.at.localeCompare(b.firstSeen.at)),
      });
    }
    return out.sort((a, b) => a.url.localeCompare(b.url));
  }

  /** Registry 404s pooled across the fleet: names somebody asked for that do not exist. */
  notFound(): Array<{ registry: string; name: string; url: string; jobs: Seen[]; repos: string[] }> {
    const pool = new Map<string, { registry: string; name: string; url: string; jobs: Seen[] }>();
    for (const j of this.sorted()) {
      for (const url of j.notFound) {
        for (const r of REGISTRY_404_RULES) {
          const m = r.match.exec(url);
          if (!m) continue;
          const name = decodeURIComponent(m[1]!);
          const k = `${r.registry} ${name}`;
          const e = pool.get(k) ?? pool.set(k, { registry: r.registry, name, url, jobs: [] }).get(k)!;
          if (!e.jobs.some((s) => s.jobId === j.jobId && s.repo === j.repo)) e.jobs.push(seen(j));
          break;
        }
      }
    }
    return [...pool.values()]
      .map((e) => ({ ...e, repos: [...new Set(e.jobs.map((s) => s.repo))].sort() }))
      .sort((a, b) => b.jobs.length - a.jobs.length || a.name.localeCompare(b.name));
  }

  /**
   * Hosts this job contacted that no earlier job of the same repo did. Other jobs of the same run do
   * not count as earlier. A job of a run anyone can trigger (a pull request) is compared only with what
   * jobs of trusted runs did before: unmerged code cannot vouch for itself. Runner plumbing that CRACI
   * always allows (GitHub Actions services, the cache store) is never "new".
   */
  newEgress(job: FleetJob | { repo: string; jobId: string }): { hosts: string[]; earlierJobs: number; earlierRuns: number } {
    const j = "hosts" in job ? job : this.getJob(job.repo, job.jobId);
    if (!j) return { hosts: [], earlierJobs: 0, earlierRuns: 0 };
    const untrusted = UNTRUSTED_EVENTS.includes(j.event);
    const known = new Set<string>();
    const runs = new Set<string>();
    let earlierJobs = 0;
    for (const e of this.jobs.values()) {
      if (e.repo !== j.repo || e.runId === j.runId || !e.hasTrace) continue;
      if (!(e.startedAt < j.startedAt)) continue;
      if (untrusted && UNTRUSTED_EVENTS.includes(e.event)) continue;
      earlierJobs++;
      runs.add(e.runId);
      for (const h of e.hosts) known.add(h);
    }
    return {
      hosts: j.hosts.filter((h) => !known.has(h) && !PLATFORM_HOSTS.some((re) => re.test(h))),
      earlierJobs,
      earlierRuns: runs.size,
    };
  }
}

function seen(j: FleetJob): Seen {
  return { at: j.startedAt, repo: j.repo, runId: j.runId, jobId: j.jobId, name: j.name };
}

function matcher(what: string): (j: FleetJob) => boolean {
  if (what.startsWith("pkg:")) {
    const exact = what.split("?")[0]!;
    // Without a version the seed matches every version of the package.
    return exact.lastIndexOf("@") > exact.indexOf("/")
      ? (j) => j.purls.includes(exact)
      : (j) => j.purls.some((p) => p === exact || p.startsWith(`${exact}@`));
  }
  if (/^sha256:[0-9a-f]{64}$/i.test(what)) {
    const sha = what.slice(7).toLowerCase();
    return (j) => j.urlHashes.some(([, h]) => h === sha);
  }
  const host = what.toLowerCase();
  return (j) => j.hosts.includes(host);
}

async function readLines<T>(file: string): Promise<T[]> {
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch {
    return [];
  }
  const out: T[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as T);
    } catch {
      /* a torn last line: skip */
    }
  }
  return out;
}

// ---------- sync ----------

export async function loadFleetRepos(file = process.env.PLX_FLEET_FILE || join(import.meta.dir, "..", "fleet.json")): Promise<string[]> {
  for (const f of [file, join(import.meta.dir, "fleet.json")]) {
    try {
      const v = JSON.parse(await readFile(f, "utf8"));
      if (Array.isArray(v)) return v.map(String);
    } catch {
      /* try the next place */
    }
  }
  throw new Error("fleet.json not found (a JSON list of OWNER/REPO)");
}

export type SyncReport = {
  repos: Array<{ repo: string; runs: number; jobsNew: number; jobsWithoutTrace: number; caches: number; error?: string }>;
  artifacts: number;
};

/** Index every finished job of the fleet that is not indexed yet, the repos' caches and the OCI artifacts they touch. */
export async function syncFleet(o: {
  repos: string[];
  craci: CraciClient;
  github: GithubClient;
  index: FleetIndex;
  maxRuns?: number;
  /** Ask CRACI again for jobs that had no trace last time. */
  retryMissing?: boolean;
  log?: (line: string) => void;
  now?: () => number;
}): Promise<SyncReport> {
  const now = o.now ?? Date.now;
  const log = o.log ?? (() => {});
  const report: SyncReport = { repos: [], artifacts: 0 };

  for (const repo of o.repos) {
    const row = { repo, runs: 0, jobsNew: 0, jobsWithoutTrace: 0, caches: 0 } as SyncReport["repos"][number];
    report.repos.push(row);
    try {
      const runs = await o.github.listRuns(repo, { max: o.maxRuns ?? 100 });
      row.runs = runs.length;
      for (const run of runs) {
        const jobs = await o.github.listJobs(repo, run.id, { filter: "all" });
        const todo = jobs.filter((j) => j.status === "completed" && !(o.index.getJob(repo, j.id)?.hasTrace));
        for (let i = 0; i < todo.length; i += 4) {
          await Promise.all(
            todo.slice(i, i + 4).map(async (job) => {
              const ageMs = now() - Date.parse(job.completed_at ?? "") || 0;
              const fresh = ageMs < 10 * 60_000;
              const known = o.index.getJob(repo, job.id);
              if (known && !fresh && !o.retryMissing) return; // asked before, CRACI has nothing for it (not a CRACI job)
              const waitFor = fresh ? 60_000 : 0;
              const trace = await o.craci.getNetworkTrace(repo, String(job.id), { waitFor });
              const sbom = trace ? await o.craci.getSbom(repo, String(job.id), { waitFor }) : null;
              let logs = "";
              if (trace) logs = await o.craci.getJobLogs(repo, String(job.id), { cache: true }).catch(() => "");
              if (!trace && fresh) return; // may still appear: ask again on the next sync
              const record = buildFleetJob({ repo, job, run, trace, sbom, logs });
              // What CRACI knows about the caches this job touched goes in before the job itself.
              await syncCaches(o.index, o.craci, repo, record.ghaCaches ?? []);
              await o.index.addJob(record);
              if (trace) row.jobsNew++;
              else row.jobsWithoutTrace++;
              log(`${repo} job ${job.id} "${job.name}": ${trace ? `${trace.observations.length} observations` : "no CRACI trace"}`);
            }),
          );
        }
      }
      // Cache entries of jobs indexed earlier whose provenance CRACI did not have yet.
      for (const j of [...o.index.jobs.values()]) if (j.repo === repo) await syncCaches(o.index, o.craci, repo, j.ghaCaches ?? []);
      for (const c of await o.github.listCaches(repo)) {
        const prov = await o.craci.getGhaCacheProvenance({ cacheId: c.id }).catch(() => null);
        await o.index.addCache({ ...c, repo, digest: prov?.digest ?? null, provenance: prov });
        row.caches++;
      }
    } catch (e) {
      row.error = e instanceof Error ? e.message : String(e);
      log(`${repo}: ${row.error}`);
    }
  }

  // OCI artifacts named in the traces, then whatever they refer to (three levels are enough for index -> manifest -> layer).
  const queue: Array<{ digest: string; kind: "manifest" | "blob"; depth: number }> = [];
  for (const j of o.index.jobs.values()) {
    for (const m of j.oci.manifests) if (m.digest) queue.push({ digest: m.digest, kind: "manifest", depth: 0 });
    for (const b of j.oci.blobs) queue.push({ digest: b.digest, kind: "blob", depth: 0 });
  }
  const done = new Set<string>();
  while (queue.length) {
    const { digest, kind, depth } = queue.shift()!;
    if (done.has(digest)) continue;
    done.add(digest);
    try {
      const prov =
        kind === "manifest"
          ? ((await o.craci.getOciManifestProvenance(digest)) ?? (await o.craci.getOciBlobProvenance(digest)))
          : await o.craci.getOciBlobProvenance(digest);
      if (!prov) {
        // Remember that CRACI was asked and knows no job that produced it: only then can a pull of it be called foreign.
        if (kind === "manifest" && !o.index.artifacts.has(digest)) await o.index.addArtifact(unknownArtifact(digest));
        continue;
      }
      await o.index.addArtifact(prov);
      report.artifacts++;
      if (depth < 3)
        for (const r of prov.refers ?? []) queue.push({ digest: r.digest, kind: r.kind === "oci_blob" ? "blob" : "manifest", depth: depth + 1 });
    } catch (e) {
      log(`artifact ${digest}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  await o.index.compact();
  return report;
}

/** The record kept for a manifest CRACI was asked about and knows no producing job for. */
export function unknownArtifact(digest: string): PreviewArtifactProvenance {
  return { artifact_id: "", kind: "oci_manifest", digest, jobs_created_in: [], refers: [], unknown_to_craci: true };
}

/** Ask CRACI who wrote these cache entries and keep the answers. Entries CRACI already answered for are skipped. */
export async function syncCaches(index: FleetIndex, craci: Pick<CraciClient, "getGhaCacheProvenance">, repo: string, refs: GhaCacheRef[]): Promise<void> {
  for (const c of refs) {
    if (index.caches.get(`${repo}#${c.entryId}`)?.provenance) continue;
    const prov = await craci.getGhaCacheProvenance({ cacheId: c.entryId }).catch(() => null);
    if (!prov) continue;
    const made = prov.jobs_created_in?.[0];
    const meta = made?.metadata?.kind === "gha_cache" ? made.metadata : null;
    await index.addCache({
      repo,
      id: c.entryId,
      key: meta?.cache_key || c.key,
      ref: "",
      version: meta?.version || c.version,
      created_at: made?.accepted_at ?? "",
      size_in_bytes: meta?.size_bytes ?? 0,
      digest: prov.digest ?? null,
      provenance: prov,
    });
  }
}

/**
 * Derive again, from the on-disk API cache, every record that was built with older rules. No job is
 * asked for twice: a record whose trace is not on disk is left as it is.
 */
export async function reindexStale(index: FleetIndex, craci: Pick<CraciClient, "getNetworkTrace" | "getSbom" | "getJobLogs">): Promise<number> {
  let n = 0;
  for (const j of [...index.jobs.values()]) {
    if (!j.hasTrace || j.v === INDEX_VERSION) continue;
    const trace = await craci.getNetworkTrace(j.repo, j.jobId, { waitFor: 0 }).catch(() => null);
    if (!trace) continue;
    const sbom = await craci.getSbom(j.repo, j.jobId, { waitFor: 0 }).catch(() => null);
    const logs = await craci.getJobLogs(j.repo, j.jobId, { cache: true }).catch(() => "");
    const fresh = buildFleetJob({
      repo: j.repo,
      job: {
        id: Number(j.jobId), run_id: Number(j.runId), run_attempt: j.runAttempt, name: j.name, status: j.status, conclusion: j.conclusion,
        started_at: j.startedAt || null, completed_at: j.completedAt, html_url: j.url, head_sha: j.commitSha, head_branch: j.branch, workflow_name: j.workflow,
      },
      run: { event: j.event },
      trace,
      sbom,
      logs,
    });
    index.jobs.set(jobKey(j.repo, j.jobId), fresh);
    n++;
  }
  if (n) await index.compact();
  return n;
}
