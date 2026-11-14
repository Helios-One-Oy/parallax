#!/usr/bin/env bun
// Parallax command line: bun src/cli.ts <sync|verdict|rings|drift|notfound|egress> ...
import { mkdir, readdir, readFile, writeFile, appendFile } from "node:fs/promises";
import { join } from "node:path";
import { CraciClient } from "./craci.ts";
import { diffTwinsDetailed, policySuggestion, type DiffDetail, type TwinInput } from "./diff.ts";
import { detectContext, detectRun, withFindings } from "./detect.ts";
import { buildFleetJob, FleetIndex, loadFleetRepos, reindexStale, syncCaches, syncFleet, unknownArtifact, type FleetJob } from "./fleet.ts";
import { GithubClient, type GhJob, type GhRun } from "./github.ts";
import { buildGraph, cacheLineageAlerts, foreignImagePulls, ourImageRepos, ringFence, rings } from "./graph.ts";
import { assertRepo, verdictsDir } from "./paths.ts";
import { BUILD_STEP_PATTERN, DRESS_STEP_PATTERN, SETUP_STEP_PATTERN, MIN_EGRESS_RUNS, TWIN_JOB_PATTERNS, UNTRUSTED_EVENTS } from "./rules.ts";
import type { JobRef, Verdict } from "./types.ts";

type Args = { _: string[]; [k: string]: string | boolean | string[] };

export function parseArgs(argv: string[]): Args {
  const a: Args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i]!;
    if (!t.startsWith("--")) {
      a._.push(t);
      continue;
    }
    const eq = t.indexOf("=");
    if (eq > 0) a[t.slice(2, eq)] = t.slice(eq + 1);
    else if (i + 1 < argv.length && !argv[i + 1]!.startsWith("--")) a[t.slice(2)] = argv[++i]!;
    else a[t.slice(2)] = true;
  }
  return a;
}
const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** false = the job ended without any build step having run. undefined = cannot tell. */
export function reachedBuild(job: Pick<GhJob, "conclusion" | "steps">): boolean | undefined {
  if (job.conclusion === "success") return true;
  if (!job.steps?.length) return undefined;
  return job.steps.some(
    (s) => !SETUP_STEP_PATTERN.test(s.name) && BUILD_STEP_PATTERN.test(s.name) && (s.conclusion === "success" || s.conclusion === "failure"),
  );
}

/** Start of the step that dresses the twin, or null when the job has no such step. */
export function dressedAt(job: Pick<GhJob, "steps">): string | null {
  return job.steps?.find((s) => DRESS_STEP_PATTERN.test(s.name))?.started_at ?? null;
}

const jobRef = (j: GhJob | undefined, fallbackName: string): JobRef =>
  j
    ? { jobId: String(j.id), name: j.name, status: j.status === "completed" ? (j.conclusion ?? "completed") : j.status, url: j.html_url ?? "" }
    : { jobId: "", name: fallbackName, status: "missing", url: "" };

const HEAD = {
  pass: "✅ Passed: the twins behaved the same and no other detector found anything",
  fail: "❌ Stopped",
  inconclusive: "⚠️ Inconclusive: Parallax could not compare the twins",
};
const TWIN_HEAD = {
  clean: "✅ Clean: both twins behaved the same",
  divergent: "❌ Divergent: the twins did not behave the same",
  inconclusive: "⚠️ Inconclusive: Parallax could not compare the twins",
};
const CHECK_STATE = { checked: "checked", too_little_history: "not judged", nothing_to_check: "nothing to check" };

export function renderMarkdown(d: DiffDetail): string {
  const v = d.verdict;
  const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");
  const link = (j: JobRef) => (j.url ? `[${j.name}](${j.url})` : j.name);
  const out: string[] = [];
  const findings = v.findings ?? [];
  const result = v.result ?? (v.status === "clean" ? "pass" : v.status === "divergent" ? "fail" : "inconclusive");
  out.push(`## Parallax verdict`, "");
  if (v.result) out.push(`**${HEAD[result]}${result === "fail" ? `. Caught by: ${(v.caughtBy ?? []).join(", ")}` : ""}**`, "");
  out.push(`${v.result ? "Twins: " : ""}**${TWIN_HEAD[v.status]}**`, "");
  out.push(`Run ${v.runId || "?"}${v.branch ? ` on \`${v.branch}\`` : ""}${v.commitSha ? ` at \`${v.commitSha.slice(0, 7)}\`` : ""}. Bare twin: ${link(v.twins.bare)} (${v.twins.bare.status}). Decoy twin: ${link(v.twins.decoy)} (${v.twins.decoy.status}).`, "");
  if (v.divergences.length) {
    out.push("| Side | What | Why |", "|---|---|---|");
    for (const x of v.divergences)
      out.push(`| ${x.side === "decoy-only" ? "decoy only" : "bare only"} | \`${cell(x.key)}\`${x.novelInFleet ? " (new in the fleet)" : ""} | ${cell(x.why)} |`);
    out.push("");
  }
  out.push(
    `Seen in both twins: ${v.stats.shared} (bare ${v.stats.bare}, decoy ${v.stats.decoy}). Ignored as noise: ${v.ignored.count}${v.ignored.rules.length ? ` (rules: ${v.ignored.rules.join(", ")})` : ""}.`,
  );
  if (findings.length) {
    out.push("", "### What the other detectors found", "", "| Detector | Job | What | Why | Stops the run | Would a CRACI network policy have blocked it |", "|---|---|---|---|---|---|");
    for (const f of findings)
      out.push(`| ${f.organ} | ${cell(f.jobName)} | \`${cell(f.key)}\` | ${cell(f.why)} | ${f.fails ? "yes" : "no, reported only"} | ${cell(f.policy ?? "No. No network rule tells this apart from normal traffic.")} |`);
  }
  if (v.checks?.length) {
    out.push("", "### What was checked", "", "| Detector | State | |", "|---|---|---|");
    for (const c of v.checks) out.push(`| ${c.organ} | ${CHECK_STATE[c.state]} | ${cell(c.note)} |`);
  }
  if (d.notes.length) out.push("", ...d.notes.map((n) => `- ${n}`));
  return out.join("\n") + "\n";
}

function renderText(d: DiffDetail): string {
  const v = d.verdict;
  const out = [`${(v.result ?? v.status).toUpperCase()}  ${v.repo} run ${v.runId} ${v.branch} ${v.commitSha.slice(0, 7)}${v.caughtBy?.length ? `  caught by: ${v.caughtBy.join(", ")}` : ""}`];
  out.push(`  twins: ${v.status}`);
  for (const x of v.divergences) out.push(`  ${x.side.padEnd(10)} ${x.key}${x.novelInFleet ? "  [new in the fleet]" : ""}\n             ${x.why}`);
  out.push(`  shared ${v.stats.shared}, bare ${v.stats.bare}, decoy ${v.stats.decoy}, ignored ${v.ignored.count}${v.ignored.rules.length ? ` (${v.ignored.rules.join(", ")})` : ""}`);
  for (const f of v.findings ?? []) out.push(`  ${f.organ}${f.fails ? "" : " (reported only)"}: ${f.key}  [${f.jobName}]\n             ${f.why}`);
  for (const c of v.checks ?? []) out.push(`  check ${c.organ}: ${CHECK_STATE[c.state]}. ${c.note}`);
  for (const n of d.notes) out.push(`  note: ${n}`);
  return out.join("\n");
}

export async function writeVerdict(v: Verdict): Promise<string | null> {
  try {
    const dir = join(verdictsDir(), assertRepo(v.repo));
    await mkdir(dir, { recursive: true });
    const file = join(dir, `${v.runId}.json`);
    await writeFile(file, JSON.stringify(v, null, 2) + "\n");
    return file;
  } catch {
    return null;
  }
}

async function cmdVerdict(a: Args): Promise<number> {
  const repo = assertRepo(str(a.repo) ?? "");
  const runId = str(a.run);
  if (!runId) throw new Error("verdict needs --repo OWNER/REPO --run RUN_ID");
  const gh = new GithubClient();
  const craci = new CraciClient();
  const waitJobsMs = Number(str(a.wait) ?? 900) * 1000;
  const waitTraceMs = Number(str(a["wait-trace"]) ?? 300) * 1000;
  const historyN = Number(str(a.history) ?? 5);
  const say = (s: string) => {
    if (!a.json) console.error(s);
  };

  // 1. the two twins
  let bare: GhJob | undefined;
  let decoy: GhJob | undefined;
  let jobs: GhJob[] = [];
  const deadline = Date.now() + waitJobsMs;
  for (;;) {
    jobs = await gh.listJobs(repo, runId);
    bare = jobs.find((j) => TWIN_JOB_PATTERNS.bare.test(j.name));
    decoy = jobs.find((j) => TWIN_JOB_PATTERNS.decoy.test(j.name));
    if (bare?.status === "completed" && decoy?.status === "completed") break;
    if (Date.now() >= deadline) break;
    say(`waiting for the twins to finish (bare: ${bare?.status ?? "not found"}, decoy: ${decoy?.status ?? "not found"})`);
    await sleep(10_000);
  }
  const run: GhRun | null = await gh.getRun(repo, runId).catch(() => null);
  const meta = { repo, runId, commitSha: run?.head_sha ?? bare?.head_sha ?? "", branch: run?.head_branch ?? "" };

  // 2. traces and SBOMs (a trace can appear a little after the job ends)
  const fetchTwin = async (j: GhJob | undefined, name: string): Promise<TwinInput> => {
    if (!j || j.status !== "completed") return { job: jobRef(j, name), trace: null, sbom: null, meta };
    const trace = await craci.getNetworkTrace(repo, String(j.id), { waitFor: waitTraceMs });
    const sbom = await craci.getSbom(repo, String(j.id), { waitFor: trace ? Math.min(waitTraceMs, 60_000) : 0 });
    return { job: jobRef(j, name), trace, sbom, conclusion: j.conclusion, reachedBuild: reachedBuild(j), dressedAt: dressedAt(j), meta };
  };
  const [tb, td] = await Promise.all([fetchTwin(bare, "build (bare)"), fetchTwin(decoy, "build (decoy)")]);

  // 3. every job of this run CRACI has a trace for, and the history of the repo
  const index = await FleetIndex.load().catch(() => new FleetIndex(null));
  const mem = new FleetIndex(null);
  for (const [k, j] of index.jobs) mem.jobs.set(k, j);
  for (const [k, c] of index.caches) mem.caches.set(k, c);
  for (const [k, x] of index.artifacts) mem.artifacts.set(k, x);
  const put = (j: FleetJob) => mem.jobs.set(`${j.repo}#${j.jobId}`, j);
  const logsOf = (id: string) => craci.getJobLogs(repo, id, { cache: true }).catch(() => "");
  const mine: FleetJob[] = [];
  for (const [gj, t] of [[bare, tb], [decoy, td]] as const) {
    if (!gj || gj.status !== "completed") continue;
    mine.push(buildFleetJob({ repo, job: gj, run, trace: t.trace ?? null, sbom: t.sbom ?? null, logs: t.trace ? await logsOf(String(gj.id)) : "" }));
  }
  for (const gj of jobs.filter((j) => j.status === "completed" && j !== bare && j !== decoy)) {
    const trace = await craci.getNetworkTrace(repo, String(gj.id), { waitFor: 0 }).catch(() => null);
    if (!trace) continue; // not a CRACI job (the verdict job itself), or nothing recorded
    const sbom = await craci.getSbom(repo, String(gj.id), { waitFor: 0 }).catch(() => null);
    mine.push(buildFleetJob({ repo, job: gj, run, trace, sbom, logs: await logsOf(String(gj.id)) }));
  }
  for (const j of mine) put(j);

  const cutoff = bare?.started_at ?? run?.created_at ?? new Date().toISOString();
  const earlierBare = () =>
    [...mem.jobs.values()]
      .filter((j) => j.repo === repo && j.hasTrace && j.runId !== runId && TWIN_JOB_PATTERNS.bare.test(j.name) && j.conclusion === "success" && j.startedAt < cutoff)
      .sort((x, y) => y.startedAt.localeCompare(x.startedAt))
      .slice(0, historyN);
  if (historyN > 0) {
    try {
      const runs = (await gh.listRuns(repo, { max: 40, status: "completed" })).filter((r) => String(r.id) !== runId && r.created_at < cutoff);
      // The newest runs, and enough runs of merged code for "new egress" to have something to compare a pull request with.
      const pick = new Set([...runs.slice(0, Math.max(historyN, 8)), ...runs.filter((r) => !UNTRUSTED_EVENTS.includes(r.event)).slice(0, 8)]);
      const known = new Set([...mem.jobs.values()].filter((j) => j.repo === repo && j.hasTrace).map((j) => j.runId));
      for (const r of pick) {
        if (known.has(String(r.id))) continue;
        const done = (await gh.listJobs(repo, r.id)).filter((x) => x.status === "completed");
        await Promise.all(
          done.map(async (j) => {
            const trace = await craci.getNetworkTrace(repo, String(j.id), { waitFor: 0 });
            if (!trace) return;
            const sbom = await craci.getSbom(repo, String(j.id), { waitFor: 0 });
            put(buildFleetJob({ repo, job: j, run: r, trace, sbom }));
          }),
        );
      }
    } catch (e) {
      say(`history not available: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  const bareRuns = earlierBare().map((j) => j.keys);

  // 4. what CRACI knows about the caches and our own images these jobs touched
  try {
    for (const j of mine) await syncCaches(mem, craci, repo, j.ghaCaches ?? []);
    const entries = new Set(mine.flatMap((j) => (j.ghaCaches ?? []).map((c) => c.entryId)));
    for (const c of mem.caches.values()) {
      if (c.repo !== repo || !entries.has(String(c.id))) continue;
      for (const cr of c.provenance?.jobs_created_in ?? []) {
        const wRepo = cr.provider.repository;
        const wId = String(cr.provider.job_id);
        if (mem.getJob(wRepo, wId)) continue;
        // The job that wrote the cache: its run's event says whether anyone could have triggered it.
        try {
          const wj = await gh.getJob(wRepo, wId);
          const wr = await gh.getRun(wRepo, wj.run_id);
          put(buildFleetJob({ repo: wRepo, job: wj, run: wr, trace: null, sbom: null }));
        } catch {
          /* GitHub no longer has the writer's job: the restore is then not judged, and the check says so */
        }
      }
    }
    const ours = ourImageRepos(mem.jobs.values());
    for (const j of mine)
      for (const m of j.oci.manifests) {
        if (m.op !== "pull" || !m.digest || !ours(m.registry, m.name) || mem.artifacts.has(m.digest)) continue;
        const prov = await craci.getOciManifestProvenance(m.digest);
        mem.artifacts.set(m.digest, prov ?? unknownArtifact(m.digest));
      }
  } catch (e) {
    say(`cache or image provenance not available: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 5. the twin diff, then every other detector on the same jobs
  const detail = diffTwinsDetailed(tb, td, { bareRuns, fleet: mem.jobs.size > mine.length ? mem : undefined });
  if (mem.jobs.size <= mine.length) detail.notes.push("No earlier jobs are known, so nothing is marked as new in the fleet.");
  else detail.notes.push(`Compared against ${bareRuns.length} earlier bare run${bareRuns.length === 1 ? "" : "s"} of this repo.`);
  const v = withFindings(detail.verdict, detectRun(detectContext(mem), repo, runId));
  const result = v.result ?? "inconclusive";

  // 6. output
  const file = await writeVerdict(v);
  const denyHosts = (v.findings ?? []).filter((f) => f.organ === "new egress").map((f) => f.host);
  let policy: string | null = null;
  if (result === "fail" && tb.trace && (v.divergences.length || denyHosts.length)) {
    try {
      policy = policySuggestion(v, v.status === "inconclusive" ? tb.trace : undefined, { denyHosts }).step;
    } catch {
      policy = null;
    }
  }
  if (a.json) console.log(JSON.stringify(v, null, 2));
  else {
    console.log(renderText(detail));
    if (file) console.error(`verdict written to ${file}`);
    if (policy) console.log("\nSuggested network policy:\n" + policy);
  }
  const summary = str(a.summary) ?? process.env.GITHUB_STEP_SUMMARY;
  if (summary && (a.summary || process.env.GITHUB_ACTIONS)) {
    let md = renderMarkdown(detail);
    if (policy) md += `\n<details><summary>Network policy that keeps the clean build working and blocks the rest</summary>\n\n\`\`\`yaml\n${policy}\`\`\`\n\n</details>\n`;
    await appendFile(summary, md).catch(() => {});
  }
  if (process.env.GITHUB_OUTPUT && process.env.GITHUB_ACTIONS)
    await appendFile(process.env.GITHUB_OUTPUT, `status=${v.status}\ncaught_by=${(v.caughtBy ?? []).join(", ")}\n`).catch(() => {});
  return result === "pass" ? 0 : result === "fail" ? 1 : 2;
}

async function cmdReindex(a: Args): Promise<number> {
  const index = await FleetIndex.load();
  const n = await reindexStale(index, new CraciClient());
  if (a.json) console.log(JSON.stringify({ rebuilt: n, jobs: index.jobs.size }));
  else console.log(`${n} job records rebuilt from the stored CRACI answers; index holds ${index.jobs.size} jobs`);
  return 0;
}

async function cmdSync(a: Args): Promise<number> {
  const repos = str(a.repo) ? [assertRepo(str(a.repo)!)] : await loadFleetRepos();
  const index = await FleetIndex.load();
  const report = await syncFleet({
    repos,
    craci: new CraciClient(),
    github: new GithubClient(),
    index,
    maxRuns: Number(str(a["max-runs"]) ?? 100),
    retryMissing: !!a["retry-missing"],
    log: (l) => console.error(l),
  });
  if (a.json) console.log(JSON.stringify(report, null, 2));
  else {
    for (const r of report.repos)
      console.log(`${r.repo}: ${r.runs} runs, ${r.jobsNew} jobs indexed, ${r.jobsWithoutTrace} without a CRACI trace, ${r.caches} caches${r.error ? `, error: ${r.error}` : ""}`);
    console.log(`${report.artifacts} image artifacts; index now holds ${index.jobs.size} jobs`);
  }
  return report.repos.some((r) => r.error) ? 1 : 0;
}

async function latestPolicy(repo: string, craci: CraciClient): Promise<string | null> {
  try {
    const dir = join(verdictsDir(), assertRepo(repo));
    const files = (await readdir(dir)).filter((f) => f.endsWith(".json")).sort((x, y) => Number(y.slice(0, -5)) - Number(x.slice(0, -5)));
    for (const f of files) {
      const v = JSON.parse(await readFile(join(dir, f), "utf8")) as Verdict;
      if (v.status === "inconclusive" || !v.twins.bare.jobId) continue;
      const trace = await craci.getNetworkTrace(repo, v.twins.bare.jobId, { waitFor: 0 });
      if (trace) return policySuggestion(v, trace).yaml;
    }
  } catch {
    /* no verdicts for this repo */
  }
  return null;
}

async function cmdRings(a: Args): Promise<number> {
  const seed = str(a.seed);
  if (!seed) throw new Error("rings needs --seed <purl | host | sha256:… | job:ID>");
  const index = await FleetIndex.load();
  const g = buildGraph(index);
  const r = rings(g, seed);
  let fence = null;
  if (a.fence || a.execute) {
    const craci = new CraciClient();
    const active = await craci.listActiveJobs().then((x) => x.jobs).catch(() => []);
    const policies: Record<string, string> = {};
    for (const repo of new Set(r.rings[0].map((m) => m.repo).filter(Boolean) as string[])) {
      const p = await latestPolicy(repo, craci);
      if (p) policies[repo] = p;
    }
    fence = await ringFence(r, { dryRun: !a.execute, github: a.execute ? new GithubClient() : undefined, active, policies });
  }
  if (a.json) {
    console.log(JSON.stringify({ ...r, fence }, null, 2));
    return 0;
  }
  const names = ["fetched it directly", "caches and image layers they wrote", "jobs that read those", "what those jobs wrote"];
  console.log(`seed ${seed} (${r.seedKind}), ${index.jobs.size} jobs in the index`);
  r.rings.forEach((ring, i) => {
    console.log(`\nring ${i}: ${names[i]} (${ring.length})`);
    for (const m of ring) console.log(`  ${m.id}\n      ${m.why}`);
  });
  console.log(`\nR0 = ${r.r0.toFixed(2)} (ring-2 jobs per ring-0 job)`);
  if (fence) {
    console.log(`\nring fence${fence.dryRun ? " (dry run, nothing was changed; add --execute to act)" : ""}:`);
    for (const x of fence.actions) {
      const what =
        x.type === "delete_cache" ? `delete cache ${x.cacheId} "${x.key}" in ${x.repo}`
        : x.type === "cancel_run" ? `cancel run ${x.runId} in ${x.repo}`
        : x.type === "rerun_run" ? `re-run run ${x.runId} in ${x.repo}`
        : `open a pull request in ${x.repo} (${x.branch})`;
      console.log(`  ${x.executed ? (x.ok ? "done  " : "FAILED") : "plan  "} ${what}${x.detail ? `: ${x.detail}` : ""}`);
    }
    for (const m of fence.manual) console.log(`  by hand: ${m}`);
  }
  return 0;
}

async function cmdDrift(a: Args): Promise<number> {
  const index = await FleetIndex.load();
  const rows = index.urlHashDrift({ includeMutable: !!a.all });
  if (a.json) console.log(JSON.stringify(rows, null, 2));
  else if (!rows.length) console.log(`no URL changed its bytes across ${index.jobs.size} indexed jobs`);
  else
    for (const r of rows) {
      console.log(`${r.url}${r.mutable ? `  [mutable by nature: ${r.mutable}]` : ""}`);
      for (const v of r.versions) console.log(`  sha256:${v.sha256}  first ${v.firstSeen.at} in ${v.firstSeen.repo} job ${v.firstSeen.jobId}, ${v.jobs} job${v.jobs === 1 ? "" : "s"}`);
    }
  return 0;
}

async function cmdNotFound(a: Args): Promise<number> {
  const index = await FleetIndex.load();
  const rows = index.notFound();
  if (a.json) console.log(JSON.stringify(rows, null, 2));
  else if (!rows.length) console.log(`no registry 404 across ${index.jobs.size} indexed jobs`);
  else for (const r of rows) console.log(`${r.registry} ${r.name}: asked by ${r.jobs.length} job${r.jobs.length === 1 ? "" : "s"} in ${r.repos.join(", ")} (${r.url})`);
  return 0;
}

async function cmdEgress(a: Args): Promise<number> {
  const index = await FleetIndex.load();
  const repo = str(a.repo);
  const rows = index
    .sorted()
    .filter((j) => j.hasTrace && (!repo || j.repo === repo))
    .map((j) => ({ repo: j.repo, runId: j.runId, jobId: j.jobId, name: j.name, at: j.startedAt, ...index.newEgress(j) }))
    .filter((r) => r.earlierRuns >= MIN_EGRESS_RUNS && r.hosts.length > 0);
  if (a.json) console.log(JSON.stringify(rows, null, 2));
  else if (!rows.length) console.log("no job contacted a host that earlier jobs of its repo had not");
  else for (const r of rows) console.log(`${r.at} ${r.repo} job ${r.jobId} "${r.name}": new hosts ${r.hosts.join(", ")}`);
  return 0;
}

async function cmdLineage(a: Args): Promise<number> {
  const index = await FleetIndex.load();
  const rows = cacheLineageAlerts(buildGraph(index));
  if (a.json) console.log(JSON.stringify(rows, null, 2));
  else if (!rows.length) console.log(`no trusted job restored a cache written by an untrusted one (${index.jobs.size} jobs, ${index.caches.size} caches)`);
  else for (const r of rows) console.log(`${r.repo} job ${r.reader.jobId}: ${r.why}\n    ${r.evidence}`);
  return 0;
}

async function cmdImages(a: Args): Promise<number> {
  const index = await FleetIndex.load();
  const rows = foreignImagePulls(index);
  if (a.json) console.log(JSON.stringify(rows, null, 2));
  else if (!rows.length) console.log(`no job pulled an image of ours that our jobs did not produce (${index.artifacts.size} image artifacts known)`);
  else for (const r of rows) console.log(`${r.repo} job ${r.jobId}: ${r.why}`);
  return 0;
}

const HELP = `Parallax
  bun src/cli.ts sync [--repo O/R] [--max-runs N] [--retry-missing]   index all finished jobs of the fleet
  bun src/cli.ts verdict --repo O/R --run ID [--json]        judge a run: twin diff plus every other detector (exit 0 pass, 1 fail, 2 inconclusive)
          [--history N] [--wait SEC] [--wait-trace SEC] [--summary FILE]
  bun src/cli.ts reindex                                     rebuild index records made with older rules, from stored CRACI answers
  bun src/cli.ts rings --seed <purl|host|sha256:…|job:ID>    contact tracing [--json] [--fence] [--execute]
  bun src/cli.ts drift [--all] [--json]                      URLs whose bytes changed between jobs
  bun src/cli.ts notfound [--json]                           registry names that did not exist
  bun src/cli.ts egress [--repo O/R] [--json]                hosts that were new for their repo
  bun src/cli.ts lineage [--json]                            caches written by untrusted jobs and restored by trusted ones
  bun src/cli.ts images [--json]                             pulls of our own images whose bytes no job of ours produced`;

export async function main(argv: string[]): Promise<number> {
  const a = parseArgs(argv);
  switch (a._[0]) {
    case "sync": return cmdSync(a);
    case "verdict": return cmdVerdict(a);
    case "reindex": return cmdReindex(a);
    case "rings": return cmdRings(a);
    case "drift": return cmdDrift(a);
    case "notfound": return cmdNotFound(a);
    case "egress": return cmdEgress(a);
    case "lineage": return cmdLineage(a);
    case "images": return cmdImages(a);
    default:
      console.log(HELP);
      return a._[0] ? 64 : 0;
  }
}

if (import.meta.main) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(`parallax: ${e instanceof Error ? e.message : String(e)}`);
      process.exit(e?.name === "CraciError" || e?.name === "GithubError" ? 2 : 70);
    },
  );
}
