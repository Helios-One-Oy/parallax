// What each page shows, derived from a snapshot with the core's own functions. Pure: no disk, no network.
import { detectContext, detectRun, judge, type DetectContext, type RunDetection } from "../detect.ts";
import { FleetIndex, type FleetJob } from "../fleet.ts";
import { buildGraph, cacheLineageAlerts, cacheNodeId, foreignImagePulls, ringFence, rings, type FenceResult, type Graph, type RingMember } from "../graph.ts";
import { MIN_EGRESS_RUNS, MUTABLE_URL_RULES, SOURCE_HOSTS, TWIN_JOB_PATTERNS, UNTRUSTED_EVENTS } from "../rules.ts";
import type { Check, Divergence, Finding, JobSummary, Organ, Verdict } from "../types.ts";
import { runKey, type GhJobLite, type Snapshot, type TwinConn, type TwinDetail } from "./snapshot.ts";

// ---------- shared ----------

const derived = new WeakMap<Snapshot, { index: FleetIndex; graph: Graph }>();

export function coreOf(s: Snapshot): { index: FleetIndex; graph: Graph } {
  let d = derived.get(s);
  if (!d) {
    const index = new FleetIndex(null);
    for (const j of s.jobs) index.jobs.set(`${j.repo}#${j.jobId}`, j);
    for (const c of s.caches) index.caches.set(`${c.repo}#${c.id}`, c);
    for (const a of s.artifacts) index.artifacts.set(a.digest, a);
    d = { index, graph: buildGraph(index) };
    derived.set(s, d);
  }
  return d;
}

const detectCtx = new WeakMap<Snapshot, DetectContext>();
const detections = new WeakMap<Snapshot, Map<string, RunDetection>>();

/** What the detectors other than the twin diff say about one run, from the snapshot as it is now. */
export function detectionOf(s: Snapshot, repo: string, runId: string): RunDetection {
  let ctx = detectCtx.get(s);
  if (!ctx) {
    const { index, graph } = coreOf(s);
    ctx = detectContext(index, graph);
    detectCtx.set(s, ctx);
  }
  const map = detections.get(s) ?? detections.set(s, new Map()).get(s)!;
  const k = runKey(repo, runId);
  let d = map.get(k);
  if (!d) map.set(k, (d = detectRun(ctx, repo, runId)));
  return d;
}

const RELEASE_JOB = new RegExp(process.env.PLX_RELEASE_JOB || "^release\\b", "i");
const isTwin = (name: string) => TWIN_JOB_PATTERNS.bare.test(name) || TWIN_JOB_PATTERNS.decoy.test(name);

// ---------- runs ----------

export type RunRow = {
  repo: string;
  runId: string;
  branch: string;
  sha: string;
  event: string;
  workflow: string;
  title: string;
  startedAt: string;
  url: string;
  /** GitHub's own words; null when GitHub has not been read for this run. */
  status: string | null;
  conclusion: string | null;
  /** CRACI lists a job of this run as running right now. */
  live: boolean;
  hasTwins: boolean;
  verdict: Verdict["status"] | null;
  divergences: number;
  /** All detectors together. null = nothing judged this run (no verdict and no finding). */
  result: "pass" | "fail" | "inconclusive" | null;
  /** The detectors that found something in this run, the twin diff included. */
  caughtBy: Organ[];
  findings: number;
  pr: { number: number; url: string } | null;
  /** GitHub no longer has this run (it was deleted there). */
  gone: boolean;
};

const runsCache = new WeakMap<Snapshot, Map<string, RunRow>>();

export function runsOf(s: Snapshot): Map<string, RunRow> {
  const hit = runsCache.get(s);
  if (hit) return hit;
  const out = new Map<string, RunRow>();
  const row = (repo: string, runId: string): RunRow => {
    const k = runKey(repo, runId);
    let r = out.get(k);
    if (!r) {
      r = {
        repo, runId, branch: "", sha: "", event: "", workflow: "", title: "", startedAt: "",
        url: `https://github.com/${repo}/actions/runs/${runId}`,
        status: null, conclusion: null, live: false, hasTwins: false, verdict: null, divergences: 0, result: null, caughtBy: [], findings: 0, pr: null, gone: false,
      };
      out.set(k, r);
    }
    return r;
  };

  for (const [repo, st] of Object.entries(s.github.repos)) {
    for (const g of st.runs) {
      const r = row(repo, g.id);
      r.branch = g.branch;
      r.sha = g.sha;
      r.event = g.event;
      r.workflow = g.workflow;
      r.title = g.title;
      r.startedAt = g.startedAt || g.createdAt;
      r.url = g.url || r.url;
      r.status = g.status;
      r.conclusion = g.conclusion;
      if (g.prs[0]) r.pr = { number: g.prs[0], url: `https://github.com/${repo}/pull/${g.prs[0]}` };
      if ((st.jobs[g.id] ?? []).some((j) => isTwin(j.name))) r.hasTwins = true;
    }
    for (const id of st.gone ?? []) row(repo, id).gone = true;
  }
  for (const j of s.jobs) {
    if (!j.runId) continue;
    const r = row(j.repo, j.runId);
    r.branch ||= j.branch;
    r.sha ||= j.commitSha;
    r.event ||= j.event;
    r.workflow ||= j.workflow;
    if (j.startedAt && (!r.startedAt || j.startedAt < r.startedAt) && r.status === null) r.startedAt = j.startedAt;
    if (isTwin(j.name)) r.hasTwins = true;
  }
  for (const a of s.active) {
    if (!a.runId) continue;
    const r = row(a.repository, String(a.runId));
    r.live = true;
    r.branch ||= a.branch;
    r.sha ||= a.commitSha;
    r.workflow ||= a.workflow;
    r.startedAt ||= a.startedAt;
    if (isTwin(a.jobName)) r.hasTwins = true;
  }
  for (const v of s.verdicts) {
    const r = row(v.repo, v.runId);
    if (r.verdict) continue; // verdicts are newest first
    r.verdict = v.status;
    r.divergences = v.divergences.length;
    r.branch ||= v.branch;
    r.sha ||= v.commitSha;
    r.startedAt ||= v.createdAt;
    r.hasTwins = true;
  }
  const tracedRuns = new Set(s.jobs.filter((j) => j.hasTrace && j.runId).map((j) => runKey(j.repo, j.runId)));
  for (const [k, r] of out) {
    const findings = tracedRuns.has(k) ? detectionOf(s, r.repo, r.runId).findings : [];
    r.findings = findings.length;
    if (!r.verdict && !findings.length) continue;
    const j = judge(r.verdict ?? "clean", findings);
    r.caughtBy = j.caughtBy;
    r.result = r.verdict || j.result === "fail" ? j.result : null;
  }
  runsCache.set(s, out);
  return out;
}

const newestFirst = (a: RunRow, b: RunRow) => b.startedAt.localeCompare(a.startedAt) || Number(b.runId) - Number(a.runId);

// ---------- fleet (home) ----------

export type ActiveRow = { repo: string; runId: string; jobId: string; name: string; status: string; startedAt: string; branch: string; url: string };

export type Alerts = {
  /** Jobs the checks ran over. Zero means nothing could be checked yet. */
  jobs: number;
  egress: Array<{ repo: string; runId: string; jobId: string; name: string; at: string; hosts: string[] }>;
  lineage: Array<{ repo: string; runId: string; cacheKey: string; seed: string; why: string; evidence: string }>;
  drift: Array<{ url: string; versions: Array<{ sha256: string; at: string; repo: string; runId: string; jobs: number }> }>;
  images: Array<{ repo: string; runId: string; jobId: string; image: string; digest: string; why: string }>;
  notFound: Array<{ registry: string; name: string; jobs: number; repos: string[]; runs: Array<{ repo: string; runId: string }> }>;
};

export type FleetView = {
  generatedAt: string | null;
  fixture: boolean;
  repos: Array<{ repo: string; url: string; runs: RunRow[]; totalRuns: number; error: string | null }>;
  active: ActiveRow[];
  activeAt: string | null;
  alerts: Alerts;
  counts: { jobs: number; traced: number; caches: number; images: number; verdicts: number };
};

export function alertsOf(s: Snapshot): Alerts {
  const { index, graph } = coreOf(s);
  const traced = index.sorted().filter((j) => j.hasTrace);
  const egress = traced
    .map((j) => ({ repo: j.repo, runId: j.runId, jobId: j.jobId, name: j.name, at: j.startedAt, ...index.newEgress(j) }))
    .filter((r) => r.earlierRuns >= MIN_EGRESS_RUNS && r.hosts.length > 0)
    .map(({ earlierJobs: _e, earlierRuns: _r, ...r }) => r)
    .reverse();
  return {
    jobs: traced.length,
    egress,
    lineage: cacheLineageAlerts(graph).map((a) => ({
      repo: a.repo,
      runId: a.reader.runId,
      cacheKey: a.cache.key,
      seed: a.cache.id,
      why: a.why,
      evidence: a.evidence,
    })),
    drift: index.urlHashDrift().map((d) => ({
      url: d.url,
      versions: d.versions.map((v) => ({ sha256: v.sha256, at: v.firstSeen.at, repo: v.firstSeen.repo, runId: v.firstSeen.runId, jobs: v.jobs })),
    })),
    images: foreignImagePulls(index).map((a) => ({
      repo: a.repo,
      runId: index.getJob(a.repo, a.jobId)?.runId ?? "",
      jobId: a.jobId,
      image: a.image,
      digest: a.digest,
      why: a.why,
    })),
    notFound: index.notFound().map((n) => ({
      registry: n.registry,
      name: n.name,
      jobs: n.jobs.length,
      repos: n.repos,
      runs: n.jobs.map((j) => ({ repo: j.repo, runId: j.runId })),
    })),
  };
}

export function activeOf(s: Snapshot, live?: JobSummary[] | null): ActiveRow[] {
  return (live ?? s.active)
    .filter((j) => s.repos.includes(j.repository))
    .map((j) => ({
      repo: j.repository,
      runId: String(j.runId),
      jobId: String(j.jobId),
      name: j.jobName,
      status: j.status,
      startedAt: j.startedAt,
      branch: j.branch,
      url: j.url,
    }));
}

export function fleetView(s: Snapshot, o: { runsPerRepo?: number; live?: JobSummary[] | null; liveAt?: string | null } = {}): FleetView {
  const all = [...runsOf(s).values()];
  return {
    generatedAt: s.generatedAt || null,
    fixture: s.fixture,
    repos: s.repos.map((repo) => {
      const mine = all.filter((r) => r.repo === repo).sort(newestFirst);
      return {
        repo,
        url: `https://github.com/${repo}`,
        runs: mine.slice(0, o.runsPerRepo ?? 6),
        totalRuns: mine.length,
        error: s.github.repos[repo]?.error ?? null,
      };
    }),
    active: activeOf(s, o.live),
    activeAt: o.live ? (o.liveAt ?? null) : s.activeAt,
    alerts: alertsOf(s),
    counts: {
      jobs: s.jobs.length,
      traced: s.jobs.filter((j) => j.hasTrace).length,
      caches: s.caches.length,
      images: s.artifacts.length,
      verdicts: s.verdicts.length,
    },
  };
}

// ---------- twin view ----------

export type TwinJob = { jobId: string; name: string; status: string; url: string; running: boolean; hasLog: boolean };

/** One line of the side-by-side list: the same connection in both twins, or a gap on one side. */
export type TwinRow = {
  key: string;
  kind: string;
  host: string;
  bare: TwinConn | null;
  decoy: TwinConn | null;
  /** shared = both did it; divergent = counted in the verdict; alone = one twin only, but not counted (see `note`). */
  state: "shared" | "divergent" | "alone";
  why: string | null;
  novel: boolean;
  note: string | null;
};

export type Gate = {
  /** The release job as GitHub reports it; null when the run has none (yet). */
  job: GhJobLite | null;
  state: "ran" | "running" | "waiting" | "not_started" | "none" | "unknown";
  sentence: string;
};

export type RunView = {
  run: RunRow;
  verdict: Verdict | null;
  twins: { bare: TwinJob | null; decoy: TwinJob | null };
  rows: TwinRow[];
  sides: { bare: { hasTrace: boolean; observations: number; noise: number } | null; decoy: { hasTrace: boolean; observations: number; noise: number } | null };
  packages: Divergence[];
  /** What the detectors other than the twin diff found for any job of this run (also the release job). */
  findings: Finding[];
  /** Per detector: did it have anything to look at. */
  checks: Check[];
  /** Every job of the run as GitHub lists them, for the pipeline strip. */
  jobs: GhJobLite[];
  gate: Gate;
  seeds: Seed[];
};

export type Seed = { seed: string; label: string; kind: "package" | "host" | "bytes" | "cache" };

function jobsOfRun(s: Snapshot, repo: string, runId: string): GhJobLite[] {
  const gh = s.github.repos[repo]?.jobs[runId];
  if (gh?.length) return gh;
  // GitHub was not read for this run: fall back to what the fleet index and CRACI's active list hold.
  const out = new Map<string, GhJobLite>();
  for (const j of s.jobs)
    if (j.repo === repo && j.runId === runId)
      out.set(j.jobId, { id: j.jobId, name: j.name, status: j.status, conclusion: j.conclusion, startedAt: j.startedAt || null, completedAt: j.completedAt, url: j.url });
  for (const a of s.active)
    if (a.repository === repo && String(a.runId) === runId && !out.has(String(a.jobId)))
      out.set(String(a.jobId), { id: String(a.jobId), name: a.jobName, status: "in_progress", conclusion: null, startedAt: a.startedAt, completedAt: null, url: a.url });
  return [...out.values()];
}

function mergeRows(v: Verdict | null, t: TwinDetail | null): TwinRow[] {
  if (!t) return [];
  const div = new Map<string, Divergence>();
  for (const d of v?.divergences ?? []) if (d.kind !== "package") div.set(`${d.side} ${d.key}`, d);
  const decoyBy = new Map(t.decoy.conns.map((c) => [c.key, c]));
  const bareKeys = new Set(t.bare.conns.map((c) => c.key));
  const note = (side: "bare" | "decoy"): string =>
    !v
      ? ""
      : v.status === "inconclusive"
        ? "Not judged: the verdict is inconclusive."
        : side === "decoy"
          ? "Not counted: earlier bare runs of this repo did this too."
          : "Not counted: it comes and goes between earlier bare runs, or the decoy twin stopped early.";
  const make = (c: TwinConn, side: "bare" | "decoy" | "both"): TwinRow => {
    if (side === "both") return { key: c.key, kind: c.kind, host: c.host, bare: c, decoy: decoyBy.get(c.key)!, state: "shared", why: null, novel: false, note: null };
    const d = div.get(`${side}-only ${c.key}`);
    return {
      key: c.key, kind: c.kind, host: c.host,
      bare: side === "bare" ? c : null,
      decoy: side === "decoy" ? c : null,
      state: d ? "divergent" : "alone",
      why: d?.why ?? null,
      novel: !!d?.novelInFleet,
      note: d ? null : note(side) || null,
    };
  };
  // The bare twin's order is the spine. A connection only the decoy made goes right after the last
  // shared connection that came before it in the decoy's own order.
  const rows: TwinRow[] = [];
  const after = new Map<string, TwinRow[]>();
  const head: TwinRow[] = [];
  let last: string | null = null;
  for (const c of t.decoy.conns) {
    if (bareKeys.has(c.key)) last = c.key;
    else if (last === null) head.push(make(c, "decoy"));
    else (after.get(last) ?? after.set(last, []).get(last)!).push(make(c, "decoy"));
  }
  rows.push(...head);
  for (const c of t.bare.conns) {
    rows.push(make(c, decoyBy.has(c.key) ? "both" : "bare"));
    rows.push(...(after.get(c.key) ?? []));
  }
  return rows;
}

function gateOf(run: RunRow, v: Verdict | null, jobs: GhJobLite[], fromGithub: boolean): Gate {
  const job = jobs.find((j) => RELEASE_JOB.test(j.name)) ?? null;
  if (!fromGithub) return { job: null, state: "unknown", sentence: "GitHub has not been read for this run yet." };
  if (!job) {
    if (run.status !== "completed") return { job: null, state: "waiting", sentence: "The release job has not started. It waits for the verdict." };
    return { job: null, state: "none", sentence: "This run has no release job." };
  }
  if (job.status !== "completed") {
    if (job.status === "in_progress") return { job, state: "running", sentence: "The release job is running." };
    return { job, state: "waiting", sentence: "The release job has not started. It waits for the verdict." };
  }
  if (job.conclusion === "skipped" || job.conclusion === "cancelled" || !job.startedAt) {
    const because = v?.status === "divergent" ? "The twins diverged, so the release job did not start." : v?.status === "inconclusive" ? "The verdict is inconclusive, so the release job did not start." : "The release job did not start in this run.";
    return { job, state: "not_started", sentence: because };
  }
  const ended = job.conclusion && job.conclusion !== "success" ? ` It ended in ${job.conclusion}.` : "";
  const ran = v?.status === "clean" ? "The verdict was clean, so the release job ran." : v?.status === "divergent" ? "The twins diverged, and the release job ran anyway." : "The release job ran.";
  return { job, state: "ran", sentence: ran + ended };
}

const mergedBytes = new WeakMap<Snapshot, Set<string>>();

/**
 * Downloads of a caught pull request whose exact bytes no job of merged code ever fetched: the package it
 * brought in. Both twins fetch it, so the twin diff does not name it; CRACI's body hashes do.
 */
function ownDownloads(s: Snapshot, v: Verdict): Seed[] {
  const { index } = coreOf(s);
  let merged = mergedBytes.get(s);
  if (!merged) {
    merged = new Set();
    for (const j of s.jobs) if (!UNTRUSTED_EVENTS.includes(j.event)) for (const [url, sha] of j.urlHashes) merged.add(`${url}@${sha}`);
    mergedBytes.set(s, merged);
  }
  const out: Seed[] = [];
  for (const id of [v.twins.decoy.jobId, v.twins.bare.jobId]) {
    const j = index.getJob(v.repo, id);
    if (!j || !UNTRUSTED_EVENTS.includes(j.event)) continue;
    for (const [url, sha] of j.urlHashes) {
      if (merged.has(`${url}@${sha}`) || MUTABLE_URL_RULES.some((r) => r.match.test(url)) || out.some((x) => x.seed === `sha256:${sha}`)) continue;
      out.push({ seed: `sha256:${sha}`, label: `bytes of ${url}`, kind: "bytes" });
    }
  }
  return out.slice(0, 4);
}

export function seedsOf(s: Snapshot, only?: Verdict | null): Seed[] {
  const out = new Map<string, Seed>();
  const add = (x: Seed) => {
    if (!out.has(x.seed)) out.set(x.seed, x);
  };
  for (const v of only ? [only] : s.verdicts) {
    if (v.status === "divergent" || detectionOf(s, v.repo, v.runId).findings.some((f) => f.fails)) for (const x of ownDownloads(s, v)) add(x);
    for (const d of v.divergences) {
      if (d.kind === "package") add({ seed: d.key, label: d.key, kind: "package" });
      else {
        const sha = (d.sample as any)?.http?.bodyHash?.sha256;
        if (typeof sha === "string" && /^[0-9a-f]{64}$/i.test(sha)) add({ seed: `sha256:${sha.toLowerCase()}`, label: `bytes of ${d.key.split(" ").slice(2).join(" ") || d.host}`, kind: "bytes" });
        if (d.host) add({ seed: d.host, label: d.host, kind: "host" });
      }
    }
  }
  if (!only) {
    const caches = [...s.caches].sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, 6);
    for (const c of caches) add({ seed: cacheNodeId(c.repo, c.id), label: `cache ${c.key}`, kind: "cache" });
  }
  return [...out.values()].slice(0, 14);
}

export function runView(s: Snapshot, repo: string, runId: string): RunView | null {
  const run = runsOf(s).get(runKey(repo, runId));
  if (!run) return null;
  const verdict = s.verdicts.find((v) => v.repo === repo && v.runId === runId) ?? null;
  const detail = s.twins[runKey(repo, runId)] ?? null;
  const fromGithub = !!s.github.repos[repo]?.jobs[runId]?.length;
  const jobs = jobsOfRun(s, repo, runId);
  const logs = new Set(s.logs);
  const twinJob = (which: "bare" | "decoy"): TwinJob | null => {
    const gh = jobs.find((j) => TWIN_JOB_PATTERNS[which].test(j.name));
    const ref = verdict?.twins[which];
    const jobId = gh?.id || ref?.jobId || "";
    if (!jobId) return null;
    const active = s.active.some((a) => a.repository === repo && String(a.jobId) === jobId);
    const running = active || (!!gh && gh.status !== "completed");
    return {
      jobId,
      name: gh?.name ?? ref?.name ?? `build (${which})`,
      status: gh ? (gh.status === "completed" ? (gh.conclusion ?? "completed") : gh.status) : (ref?.status ?? ""),
      url: gh?.url || ref?.url || "",
      running,
      hasLog: logs.has(`${repo}#${jobId}`),
    };
  };
  const detection = detectionOf(s, repo, runId);
  const side = (x: TwinDetail["bare"] | undefined) => (x ? { hasTrace: x.hasTrace, observations: x.observations, noise: x.noise } : null);
  return {
    run,
    verdict,
    twins: { bare: twinJob("bare"), decoy: twinJob("decoy") },
    rows: mergeRows(verdict, detail),
    sides: { bare: side(detail?.bare), decoy: side(detail?.decoy) },
    packages: (verdict?.divergences ?? []).filter((d) => d.kind === "package"),
    findings: detection.findings,
    checks: [...(verdict?.checks ?? []).filter((c) => c.organ === "twins"), ...detection.checks],
    jobs,
    gate: gateOf(run, verdict, jobs, fromGithub),
    seeds: verdict ? seedsOf(s, verdict) : [],
  };
}

/** Is this job one the console knows (so its log may be asked for)? */
export function knownJob(s: Snapshot, repo: string, jobId: string): { known: boolean; running: boolean } {
  if (!s.repos.includes(repo)) return { known: false, running: false };
  if (s.active.some((a) => a.repository === repo && String(a.jobId) === jobId)) return { known: true, running: true };
  for (const list of Object.values(s.github.repos[repo]?.jobs ?? {})) {
    const j = list.find((x) => x.id === jobId);
    if (j) return { known: true, running: j.status !== "completed" };
  }
  if (s.jobs.some((j) => j.repo === repo && j.jobId === jobId)) return { known: true, running: false };
  if (s.verdicts.some((v) => v.repo === repo && (v.twins.bare.jobId === jobId || v.twins.decoy.jobId === jobId))) return { known: true, running: false };
  return { known: false, running: false };
}

// ---------- rings ----------

export type RingsView = {
  seed: string;
  seedKind: string;
  /** Set when the seed was a cache: the job that wrote it is the real seed. */
  resolved: string | null;
  note: string | null;
  rings: Array<Array<RingMember & { runId: string | null }>>;
  r0: number;
  fence: FenceResult;
  jobs: number;
  suggestions: Seed[];
};

export const RING_NAMES = ["Jobs that fetched it", "Caches and image layers they wrote", "Jobs that read those", "What those jobs wrote"];

function resolveSeed(s: Snapshot, seed: string): { seed: string; resolved: string | null; note: string | null } {
  if (!seed.startsWith("cache:")) return { seed, resolved: null, note: null };
  const { graph } = coreOf(s);
  const writers = graph.in(seed, "created").map((e) => e.from);
  if (!graph.nodes.has(seed)) return { seed, resolved: null, note: "This cache is not in the fleet index." };
  if (writers.length === 0) return { seed, resolved: null, note: "Neither CRACI's cache provenance nor a job log says which job wrote this cache." };
  return {
    seed: writers[0]!,
    resolved: writers[0]!,
    note: writers.length > 1 ? `${writers.length} jobs wrote this cache. The rings start from the first one.` : "The rings start from the job that wrote this cache.",
  };
}

export async function ringsView(s: Snapshot, rawSeed: string): Promise<RingsView> {
  const { index, graph } = coreOf(s);
  const seed = rawSeed.trim();
  const res = resolveSeed(s, seed);
  const r = rings(graph, res.seed);
  const fence = await ringFence(r, { dryRun: true, active: s.active, policies: s.policies });
  const withRun = (m: RingMember) => {
    const jm = /^job:(.+)#(\d+)$/.exec(m.id);
    const j: FleetJob | undefined = jm ? index.getJob(jm[1]!, jm[2]!) : undefined;
    return { ...m, runId: j?.runId || null };
  };
  return {
    seed,
    seedKind: seed.startsWith("cache:") ? "cache" : r.seedKind,
    resolved: res.resolved,
    note:
      res.note ??
      (r.seedKind === "host" && SOURCE_HOSTS.some((h) => h.host.test(seed.toLowerCase()))
        ? `${seed} also serves this fleet's own packages, so every build contacts it. To follow one bad package, start from its bytes instead.`
        : null),
    rings: r.rings.map((ring) => ring.map(withRun)),
    r0: r.r0,
    fence,
    jobs: index.jobs.size,
    suggestions: seedsOf(s),
  };
}

/** The rings and the fence plan the core computes for a seed (for the apply action). */
export function ringsFor(s: Snapshot, rawSeed: string) {
  const { graph } = coreOf(s);
  return rings(graph, resolveSeed(s, rawSeed.trim()).seed);
}

// ---------- replay scoreboard ----------

/**
 * Where a replay runs. `repo` plus at least one of:
 *  - `runId`: exactly this run (also one GitHub has deleted since);
 *  - `branch`, `workflow`, `event`: the newest judged run that matches all that are given;
 *  - `match`: among those runs, the newest one with a finding that names this text (a host, a URL, a package, or a detector name).
 * A replay with a `repo` only, or none, is "not set up".
 */
export type ReplayDef = {
  id: string;
  incident: string;
  how: string;
  expected: string;
  repo: string | null;
  branch?: string | null;
  runId?: string | null;
  workflow?: string | null;
  event?: string | null;
  match?: string | null;
};

export type ReplayRow = ReplayDef & {
  /** Full OWNER/REPO from the fleet list, when the replay's repo is in the fleet. */
  fullRepo: string | null;
  state: "not_set_up" | "not_run" | "not_seen" | "running" | "no_verdict" | "caught" | "missed";
  run: RunRow | null;
  organs: string[];
  saw: string[];
  /** From the start of the run to the end of the job that settled it (the verdict job, or the job that holds the finding). */
  seconds: number | null;
  /** Did the run's own verdict job fail, so the release never started? null = the run has no finished verdict job. */
  stopped: boolean | null;
  /** The job on a CRACI runner whose record shows it. */
  job: { name: string; url: string } | null;
};

export function replayRows(s: Snapshot, defs: ReplayDef[]): ReplayRow[] {
  const { index } = coreOf(s);
  const runs = [...runsOf(s).values()];
  type Hit = { organ: string; key: string; why: string; jobId: string; fails: boolean };
  const hitsOf = (r: RunRow): Hit[] => {
    const v = s.verdicts.find((x) => x.repo === r.repo && x.runId === r.runId);
    const out: Hit[] = [];
    if (v?.status === "divergent")
      for (const d of v.divergences) out.push({ organ: "twins", key: d.key, why: d.why, jobId: d.side === "decoy-only" ? v.twins.decoy.jobId : v.twins.bare.jobId, fails: true });
    for (const f of detectionOf(s, r.repo, r.runId).findings) out.push({ organ: f.organ, key: f.key, why: f.why, jobId: f.jobId, fails: f.fails });
    // A cache this run wrote that a trusted job restored later: the finding sits on the reader's run, the replay is the writer.
    for (const a of detectCtx.get(s)?.lineage ?? []) {
      const w = index.getJob(a.repo, a.writer.jobId);
      if (a.repo === r.repo && w?.runId === r.runId && a.reader.runId !== r.runId) out.push({ organ: "cache lineage", key: a.cache.key, why: a.why, jobId: a.reader.jobId, fails: true });
    }
    return out;
  };

  return defs.map((def): ReplayRow => {
    const fullRepo = def.repo ? (s.repos.find((r) => r === def.repo || r.endsWith(`/${def.repo}`)) ?? null) : null;
    const base: ReplayRow = { ...def, fullRepo, state: "not_set_up", run: null, organs: [], saw: [], seconds: null, stopped: null, job: null };
    if (!fullRepo || !(def.branch || def.runId || def.workflow || def.event || def.match)) return base;
    const mine = runs
      .filter((r) => r.repo === fullRepo && (!def.runId || r.runId === def.runId) && (!def.branch || r.branch === def.branch) && (!def.workflow || r.workflow === def.workflow) && (!def.event || r.event === def.event))
      .sort(newestFirst);
    if (mine.length === 0) return { ...base, state: "not_run" };

    const traced = (r: RunRow) => s.jobs.some((j) => j.repo === fullRepo && j.runId === r.runId && j.hasTrace);
    const named = (h: Hit) => !def.match || h.organ === def.match || h.key.includes(def.match) || h.why.includes(def.match);
    let run: RunRow;
    let judged = true;
    if (def.match && !def.runId) {
      const found = mine.find((r) => hitsOf(r).some(named));
      // Without a run id nothing says which run was the replay, so a miss cannot be told from "not run".
      if (!found) return { ...base, state: "not_seen" };
      run = found;
    } else {
      const j = mine.find((r) => r.verdict || traced(r));
      judged = !!j;
      run = j ?? mine[0]!;
    }
    const row: ReplayRow = { ...base, run };
    const jobs = index.sorted().filter((j) => j.repo === fullRepo && j.runId === run.runId);
    const hits = hitsOf(run).filter(named);
    // The same thing seen in both twins is one line.
    const seen = new Map<string, { why: string; n: number }>();
    for (const h of hits) {
      const organ = h.fails ? h.organ : `${h.organ} (reported, did not stop the run)`;
      if (!row.organs.includes(organ)) row.organs.push(organ);
      const k = `${h.organ}\n${h.key}`;
      const g = seen.get(k);
      if (g) g.n++;
      else seen.set(k, { why: h.why, n: 1 });
    }
    for (const g of seen.values())
      if (row.saw.length < 3) row.saw.push(g.n > 1 ? `${g.why} The same in ${g.n - 1} more job${g.n === 2 ? "" : "s"} of this run.` : g.why);
    const tracedJobs = jobs.filter((j) => j.hasTrace);
    if (run.gone && tracedJobs.length) {
      const n = tracedJobs.reduce((sum, j) => sum + j.keys.length, 0);
      row.organs.push("CRACI trace");
      row.saw.unshift(`GitHub no longer has this run. CRACI still holds ${n} connection${n === 1 ? "" : "s"} it made.`);
      row.saw.length = Math.min(row.saw.length, 3);
    }

    // Time and the job that shows it.
    const ghJobs = s.github.repos[fullRepo]?.jobs[run.runId] ?? [];
    const vj = ghJobs.find((j) => /^verdict\b/i.test(j.name) && j.status === "completed" && j.conclusion !== "skipped");
    row.stopped = vj ? vj.conclusion === "failure" : null;
    const hitJobs = [...new Set(hits.map((h) => h.jobId))].map((id) => index.getJob(fullRepo, id)).filter((j): j is FleetJob => !!j);
    const first = hitJobs[0] ?? (run.gone ? tracedJobs[0] : undefined);
    if (first) row.job = { name: first.name, url: first.url };
    const lastHit = hitJobs.map((j) => j.completedAt ?? "").sort().pop() || "";
    const end = vj?.completedAt && lastHit <= vj.completedAt ? vj.completedAt : lastHit || vj?.completedAt || "";
    if (end && run.startedAt) {
      const sec = Math.round((Date.parse(end) - Date.parse(run.startedAt)) / 1000);
      if (Number.isFinite(sec) && sec >= 0) row.seconds = sec;
    }

    const verdict = s.verdicts.find((v) => v.repo === fullRepo && v.runId === run.runId) ?? null;
    if (hits.some((h) => h.fails) || (run.gone && tracedJobs.length)) row.state = "caught";
    else if (!judged && (run.live || (run.status !== null && run.status !== "completed"))) row.state = "running";
    else if ((verdict && verdict.status !== "inconclusive") || (def.runId && tracedJobs.length)) row.state = "missed";
    else row.state = "no_verdict";
    return row;
  });
}
