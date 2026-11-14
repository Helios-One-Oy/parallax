// One place where every detector other than the twin diff is asked about one run. The verdict action
// (index built from the API) and the console (index from the snapshot) both call detectRun, so a run
// shows the same findings everywhere.
import type { FleetIndex, FleetJob } from "./fleet.ts";
import { buildGraph, cacheLineageAlerts, canonRegistry, foreignImagePulls, ourImageRepos, type Graph, type ImageAlert, type LineageAlert } from "./graph.ts";
import { MIN_EGRESS_RUNS, MIN_STABLE_JOBS, MUTABLE_URL_RULES, TWIN_JOB_PATTERNS, UNTRUSTED_EVENTS } from "./rules.ts";
import type { Check, Finding, Organ, Verdict } from "./types.ts";

export const ORGANS: Organ[] = ["twins", "twin downloads", "new egress", "cache lineage", "same URL, new bytes", "image provenance", "registry 404"];

type Drift = ReturnType<FleetIndex["urlHashDrift"]>[number];

export type DetectContext = {
  index: FleetIndex;
  graph: Graph;
  lineage: LineageAlert[];
  images: ImageAlert[];
  drift: Map<string, Drift>;
  notFound: ReturnType<FleetIndex["notFound"]>;
  ourRepos: (registry: string, name: string) => boolean;
};

/** Everything that is computed once per index, however many runs are asked about. */
export function detectContext(index: FleetIndex, graph: Graph = buildGraph(index)): DetectContext {
  const ours = ourImageRepos(index.jobs.values());
  const made = new Set<string>();
  for (const a of index.artifacts.values())
    for (const cr of a.jobs_created_in ?? []) if (cr.metadata?.kind === "oci") made.add(`${canonRegistry(cr.metadata.registry)}/${cr.metadata.repository}`);
  const ourRepos = (registry: string, name: string) => ours(registry, name) || made.has(`${registry}/${name}`);
  return {
    index,
    graph,
    lineage: cacheLineageAlerts(graph),
    images: foreignImagePulls(index),
    drift: new Map(index.urlHashDrift().map((d) => [d.url, d])),
    notFound: index.notFound(),
    ourRepos,
  };
}

const short = (sha: string) => sha.replace(/^sha256:/, "").slice(0, 12);
const plural = (n: number, one: string, many = one + "s") => `${n} ${n === 1 ? one : many}`;
const hostOf = (url: string) => url.split("/")[0]!.replace(/:\d+$/, "");

export type RunDetection = { findings: Finding[]; checks: Check[]; jobs: FleetJob[] };

/** What the detectors say about the jobs of one run. `checks` says, per detector, whether it had anything to look at. */
export function detectRun(ctx: DetectContext, repo: string, runId: string): RunDetection {
  const { index } = ctx;
  // A run that was run again holds two jobs with one name: the newest one stands for the run.
  const all = index.sorted().filter((j) => j.repo === repo && j.runId === runId);
  const newest = new Map<string, FleetJob>();
  for (const j of all) if (!newest.has(j.name) || newest.get(j.name)!.startedAt < j.startedAt) newest.set(j.name, j);
  const jobs = all.filter((j) => newest.get(j.name) === j);
  const traced = jobs.filter((j) => j.hasTrace);
  const ids = new Set(jobs.map((j) => j.jobId));
  const findings: Finding[] = [];
  const checks: Check[] = [];
  const untrusted = jobs.some((j) => UNTRUSTED_EVENTS.includes(j.event));

  // ---- new egress ----
  if (!traced.length) checks.push({ organ: "new egress", state: "nothing_to_check", note: "No job of this run has a CRACI network trace yet." });
  else {
    let runs = Infinity;
    for (const j of traced) {
      const e = index.newEgress(j);
      runs = Math.min(runs, e.earlierRuns);
      if (e.earlierRuns < MIN_EGRESS_RUNS) continue;
      for (const h of e.hosts)
        findings.push({
          organ: "new egress",
          jobId: j.jobId,
          jobName: j.name,
          key: h,
          host: h,
          why: `Job "${j.name}" contacted ${h}. No job of the ${plural(e.earlierRuns, "earlier run")} ${untrusted ? "of merged code " : ""}in this repo did.`,
          evidence: `CRACI network trace of job ${j.jobId}, compared with the traces of ${plural(e.earlierJobs, "earlier job")}`,
          fails: true,
          policy: `Yes. A \`network:\` policy that lists only what earlier builds used has no line for ${h}, so CRACI refuses the connection.`,
        });
    }
    const of = untrusted ? "earlier runs of merged code" : "earlier runs";
    if (runs < MIN_EGRESS_RUNS)
      checks.push({
        organ: "new egress",
        state: "too_little_history",
        note: `Too little history: ${runs} ${of} of this repo have a CRACI trace, ${MIN_EGRESS_RUNS} are needed before a host can be called new.`,
      });
    else checks.push({ organ: "new egress", state: "checked", note: `Every host the ${plural(traced.length, "job")} contacted was compared with ${runs} or more ${of} of this repo.` });
  }

  // ---- cache lineage ----
  const restores = jobs.flatMap((j) => ctx.graph.out(`job:${j.repo}#${j.jobId}`, "restored").map((e) => ({ j, e })));
  for (const a of ctx.lineage) {
    if (a.repo !== repo || !ids.has(a.reader.jobId)) continue;
    findings.push({
      organ: "cache lineage",
      jobId: a.reader.jobId,
      jobName: a.reader.name,
      key: a.cache.key,
      host: "",
      why: a.why,
      evidence: a.evidence,
      fails: true,
      policy: null,
    });
  }
  if (!restores.length) checks.push({ organ: "cache lineage", state: "nothing_to_check", note: "No job of this run restored a cache." });
  else {
    const known = restores.filter(({ e }) => ctx.graph.in(e.to, "created").some((c) => (ctx.graph.nodes.get(c.from)?.data as FleetJob | undefined)?.event)).length;
    checks.push({
      organ: "cache lineage",
      state: "checked",
      note: `${plural(restores.length, "cache restore")}; the job that wrote the cache is known for ${known}${known < restores.length ? " (the others cannot be judged)" : ""}.`,
    });
  }

  // ---- same URL, new bytes ----
  let urls = 0;
  for (const j of traced) {
    const mine = new Set<string>();
    for (const [url, sha] of j.urlHashes) {
      urls++;
      const d = ctx.drift.get(url);
      if (!d || mine.has(url)) continue;
      const v = d.versions.find((x) => x.sha256 === sha);
      if (!v || v.firstSeen.runId !== runId || v.firstSeen.repo !== repo) continue;
      const before = d.versions.filter((x) => x.firstSeen.at < v.firstSeen.at && !(x.firstSeen.runId === runId && x.firstSeen.repo === repo));
      if (!before.length) continue;
      mine.add(url);
      const old = before[before.length - 1]!;
      const oldJobs = before.reduce((n, x) => n + x.jobs, 0);
      findings.push({
        organ: "same URL, new bytes",
        jobId: j.jobId,
        jobName: j.name,
        key: url,
        host: hostOf(url),
        why: `Job "${j.name}" fetched ${url} and got bytes (sha256 ${short(sha)}…) that differ from what ${plural(oldJobs, "earlier job")} got from the same address (sha256 ${short(old.sha256)}…, first in job ${old.firstSeen.jobId}).`,
        evidence: `CRACI body hashes in the network traces of job ${j.jobId} and job ${old.firstSeen.jobId}`,
        fails: oldJobs >= MIN_STABLE_JOBS,
        policy: null,
      });
    }
  }
  checks.push(
    urls
      ? { organ: "same URL, new bytes", state: "checked", note: `${plural(urls, "download")} with a CRACI body hash compared with every earlier job in the fleet.` }
      : { organ: "same URL, new bytes", state: "nothing_to_check", note: "No download with a CRACI body hash in this run." },
  );

  // ---- twin downloads: the same address, fetched by both twins, answered with different bytes ----
  const bare = traced.find((j) => TWIN_JOB_PATTERNS.bare.test(j.name));
  const decoy = traced.find((j) => TWIN_JOB_PATTERNS.decoy.test(j.name));
  if (!bare || !decoy) checks.push({ organ: "twin downloads", state: "nothing_to_check", note: "This run does not have two twins with a CRACI trace." });
  else {
    const by = (j: FleetJob) => {
      const m = new Map<string, Set<string>>();
      for (const [u, h] of j.urlHashes) m.set(u, (m.get(u) ?? new Set<string>()).add(h));
      return m;
    };
    const b = by(bare);
    let both = 0;
    for (const [url, hs] of by(decoy)) {
      const other = b.get(url);
      // Addresses whose bytes change by design (index pages, health checks) say nothing.
      if (!other || MUTABLE_URL_RULES.some((r) => r.match.test(url))) continue;
      both++;
      if ([...hs].some((h) => other.has(h))) continue;
      findings.push({
        organ: "twin downloads",
        jobId: decoy.jobId,
        jobName: decoy.name,
        key: url,
        host: hostOf(url),
        why: `Both twins fetched ${url}. The decoy twin, which carries fake credentials, got different bytes (sha256 ${short([...hs][0]!)}…) than the bare twin (sha256 ${short([...other][0]!)}…).`,
        evidence: `CRACI body hashes in the network traces of job ${bare.jobId} and job ${decoy.jobId}`,
        fails: true,
        policy: null,
      });
    }
    checks.push({ organ: "twin downloads", state: "checked", note: `${plural(both, "download")} that both twins made compared byte for byte (CRACI body hashes).` });
  }

  // ---- image provenance ----
  const pulls = traced.flatMap((j) => (j.oci?.manifests ?? []).filter((m) => m.op === "pull" && m.digest && ctx.ourRepos(m.registry, m.name)));
  for (const a of ctx.images) {
    if (a.repo !== repo || !ids.has(a.jobId)) continue;
    findings.push({
      organ: "image provenance",
      jobId: a.jobId,
      jobName: a.name,
      key: a.image,
      host: a.image.split("/")[0]!,
      why: a.why,
      evidence: `CRACI network trace of job ${a.jobId} (the manifest it pulled) and CRACI image provenance (no producing job for ${a.digest.slice(0, 19)}…)`,
      fails: true,
      policy: null,
    });
  }
  checks.push(
    pulls.length
      ? { organ: "image provenance", state: "checked", note: `${plural(pulls.length, "pull")} of our own images compared with what CRACI says our jobs pushed.` }
      : { organ: "image provenance", state: "nothing_to_check", note: "No job of this run pulled an image from a registry our jobs push to." },
  );

  // ---- registry 404 ----
  for (const n of ctx.notFound) {
    for (const s of n.jobs) {
      if (s.repo !== repo || !ids.has(s.jobId)) continue;
      findings.push({
        organ: "registry 404",
        jobId: s.jobId,
        jobName: s.name,
        key: `${n.registry}:${n.name}`,
        host: hostOf(n.url),
        why: `Job "${s.name}" asked the ${n.registry} registry for "${n.name}" and the registry answered that no such package exists. Whoever registers that name next decides what this build installs.`,
        evidence: `CRACI network trace of job ${s.jobId}: 404 for ${n.url}`,
        fails: true,
        policy: null,
      });
    }
  }
  checks.push(
    traced.length
      ? { organ: "registry 404", state: "checked", note: `Registry answers of ${plural(traced.length, "job")} read; "no such package" answers: ${findings.filter((f) => f.organ === "registry 404").length}.` }
      : { organ: "registry 404", state: "nothing_to_check", note: "No job of this run has a CRACI network trace yet." },
  );

  return { findings, checks, jobs };
}

/** The twin diff and the other detectors folded into one result. A failing finding wins over "inconclusive". */
export function judge(status: Verdict["status"], findings: Finding[]): { result: NonNullable<Verdict["result"]>; caughtBy: Organ[] } {
  const organs = new Set<Organ>(findings.map((f) => f.organ));
  if (status === "divergent") organs.add("twins");
  const fail = status === "divergent" || findings.some((f) => f.fails);
  return { result: fail ? "fail" : status === "inconclusive" ? "inconclusive" : "pass", caughtBy: ORGANS.filter((o) => organs.has(o)) };
}

/** The verdict with what the other detectors found added to it. */
export function withFindings(v: Verdict, d: RunDetection): Verdict {
  const twinCheck: Check =
    v.status === "inconclusive"
      ? { organ: "twins", state: "nothing_to_check", note: "The two twins could not be compared." }
      : { organ: "twins", state: "checked", note: `${v.stats.shared} connections seen in both twins, ${v.divergences.length} in only one.` };
  const twinIds = new Set([v.twins.bare.jobId, v.twins.decoy.jobId]);
  // The verdict object itself is extended: diff.ts keeps a hidden link from it to the traces (policySuggestion).
  return Object.assign(v, {
    findings: d.findings,
    checks: [twinCheck, ...d.checks],
    jobs: d.jobs
      .filter((j) => !twinIds.has(j.jobId))
      .map((j) => ({ jobId: j.jobId, name: j.name, status: j.conclusion ?? j.status, url: j.url, traced: j.hasTrace })),
    ...judge(v.status, d.findings),
  });
}
