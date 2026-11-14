// Fleet index: one record per finished job of the fleet repos, persisted as JSON lines.
// Answers: when was a host / package / body hash first seen, which URLs changed their bytes,
// which registry names did not exist, which hosts are new for a repo.
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CraciClient } from "./craci.ts";
import { sbomPurls, type FleetLookup } from "./diff.ts";
import type { GhCache, GhJob, GhRun, GithubClient } from "./github.ts";
import { cacheEventsFromLog, ociRefsFromTrace, type OciRefs } from "./graph.ts";
import { hostsOf, normalizeTrace, splitUrl } from "./normalize.ts";
import { fleetDir } from "./paths.ts";
import { MUTABLE_URL_RULES, REGISTRY_404_RULES } from "./rules.ts";
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
  oci: OciRefs;
  indexedAt: string;
};

export type CacheRecord = GhCache & {
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
    oci: ociRefsFromTrace(trace),
    indexedAt: input.now ?? new Date().toISOString(),
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

  /** Rewrite the files with one line per record (appends leave old versions behind). */
  async compact() {
    if (!this.dir) return;
    await mkdir(this.dir, { recursive: true });
    const dump = (rows: Iterable<unknown>) => [...rows].map((r) => JSON.stringify(r) + "\n").join("");
    await writeFile(join(this.dir, "jobs.jsonl"), dump(this.jobs.values()));
    await writeFile(join(this.dir, "caches.jsonl"), dump(this.caches.values()));
    await writeFile(join(this.dir, "artifacts.jsonl"), dump(this.artifacts.values()));
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

  /** Hosts this job contacted that no earlier job of the same repo did (other jobs of the same run do not count as earlier). */
  newEgress(job: FleetJob | { repo: string; jobId: string }): { hosts: string[]; earlierJobs: number } {
    const j = "hosts" in job ? job : this.getJob(job.repo, job.jobId);
    if (!j) return { hosts: [], earlierJobs: 0 };
    const known = new Set<string>();
    let earlierJobs = 0;
    for (const e of this.jobs.values()) {
      if (e.repo !== j.repo || e.runId === j.runId || !e.hasTrace) continue;
      if (!(e.startedAt < j.startedAt)) continue;
      earlierJobs++;
      for (const h of e.hosts) known.add(h);
    }
    return { hosts: j.hosts.filter((h) => !known.has(h)), earlierJobs };
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
              await o.index.addJob(buildFleetJob({ repo, job, run, trace, sbom, logs }));
              if (trace) row.jobsNew++;
              else row.jobsWithoutTrace++;
              log(`${repo} job ${job.id} "${job.name}": ${trace ? `${trace.observations.length} observations` : "no CRACI trace"}`);
            }),
          );
        }
      }
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
      if (!prov) continue;
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
