// One sync cycle on the box: read GitHub (cheaply), index new jobs with the core's syncFleet, ask CRACI
// what is running, and have `cli verdict` judge every run whose two twins have finished.
// What it learns is written under <runs dir>/console/state/ for the snapshot builder.
import { join } from "node:path";
import type { CraciClient } from "../craci.ts";
import { FleetIndex, reindexStale, syncFleet } from "../fleet.ts";
import { GithubError, type GhJob, type GhRun, type GithubClient } from "../github.ts";
import { TWIN_JOB_PATTERNS } from "../rules.ts";
import type { Verdict } from "../types.ts";
import { emptyGithub, readJsonFile, readVerdicts, stateDir, writeJsonFile, type GhJobLite, type GhRunLite, type GithubState } from "./snapshot.ts";

export const liteRun = (r: GhRun): GhRunLite => ({
  id: String(r.id),
  workflow: String(r.name ?? ""),
  title: String((r as any).display_title ?? ""),
  branch: r.head_branch ?? "",
  sha: r.head_sha,
  event: r.event,
  status: r.status ?? "",
  conclusion: r.conclusion,
  createdAt: r.created_at,
  startedAt: r.run_started_at ?? r.created_at,
  updatedAt: r.updated_at,
  url: r.html_url,
  attempt: r.run_attempt ?? 1,
  prs: Array.isArray((r as any).pull_requests) ? (r as any).pull_requests.map((p: any) => Number(p?.number)).filter((n: number) => Number.isFinite(n)) : [],
});

export const liteJob = (j: GhJob): GhJobLite => ({
  id: String(j.id),
  name: j.name,
  status: j.status,
  conclusion: j.conclusion,
  startedAt: j.started_at,
  completedAt: j.completed_at,
  url: j.html_url ?? "",
});

export type SyncMemory = {
  /** When syncFleet last ran per repo (ms). */
  fleetAt: Record<string, number>;
  /** Verdict attempts per `repo#runId`: when, and whether one is running. */
  verdictAt: Record<string, number>;
  verdictBusy: Set<string>;
  /** Runs GitHub confirmed it still has, although they are off the short list. */
  alive: Set<string>;
  first: boolean;
};

export const newMemory = (): SyncMemory => ({ fleetAt: {}, verdictAt: {}, verdictBusy: new Set(), alive: new Set(), first: true });

export type SyncOptions = {
  repos: string[];
  github: GithubClient;
  craci: CraciClient;
  memory: SyncMemory;
  /** Judge one run and write its verdict file. Default: `bun src/cli.ts verdict` as its own process. */
  runVerdict?: (repo: string, runId: string) => Promise<void>;
  /** Runs looked at per repo in each cycle. */
  maxRuns?: number;
  /** Runs handed to syncFleet on the first cycle (backfill). */
  backfillRuns?: number;
  log?: (line: string) => void;
  now?: () => number;
};

export type SyncResult = { github: GithubState; fleetSynced: string[]; verdicts: Promise<void>[]; errors: string[] };

/** `bun src/cli.ts verdict` in a child process, exactly as a person would run it. */
export async function spawnVerdict(repo: string, runId: string): Promise<void> {
  const cli = join(import.meta.dir, "..", "cli.ts");
  const p = Bun.spawn([process.execPath, cli, "verdict", "--repo", repo, "--run", runId, "--json", "--wait", "0", "--wait-trace", "120"], {
    stdout: "ignore",
    stderr: "ignore",
    env: process.env,
  });
  await p.exited;
}

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

export async function syncOnce(o: SyncOptions): Promise<SyncResult> {
  const now = o.now ?? Date.now;
  const log = o.log ?? (() => {});
  const mem = o.memory;
  const file = join(stateDir(), "github.json");
  const prev = (await readJsonFile<GithubState>(file)) ?? emptyGithub();
  const next: GithubState = { fetchedAt: new Date(now()).toISOString(), repos: {} };
  const errors: string[] = [];
  const changed = new Set<string>();
  const index = await FleetIndex.load();
  // Records made with older rules are rebuilt once from the CRACI answers already on disk.
  if (mem.first) await reindexStale(index, o.craci).then((n) => n && log(`fleet index: ${n} records rebuilt with the current rules`), () => {});

  // 1. GitHub: the newest runs of every repo; jobs only for runs that moved since the last look.
  for (const repo of o.repos) {
    const old = prev.repos[repo] ?? { runs: [], jobs: {}, gone: [], complete: false };
    const st = { runs: old.runs, jobs: { ...old.jobs }, gone: [...(old.gone ?? [])], complete: old.complete } as GithubState["repos"][string];
    next.repos[repo] = st;
    try {
      const max = o.maxRuns ?? 20;
      const runs = (await o.github.listRuns(repo, { max })).map(liteRun);
      st.complete = runs.length < max;
      const oldById = new Map(old.runs.map((r) => [r.id, r]));
      let watched = 0;
      for (const r of runs) {
        const before = oldById.get(r.id);
        const moved = !before || before.updatedAt !== r.updatedAt || before.status !== r.status || before.attempt !== r.attempt;
        // Runs in progress are read again every cycle (the three newest per repo), the rest only when they moved.
        const watch = r.status === "in_progress" && watched++ < 3;
        if (moved || watch || !st.jobs[r.id]) {
          st.jobs[r.id] = (await o.github.listJobs(repo, r.id)).map(liteJob);
          if (moved && r.status === "completed") changed.add(repo);
        }
      }
      // Keep runs that fell off the short list, so their rows do not vanish from the console.
      const listed = new Set(runs.map((r) => r.id));
      st.runs = [...runs, ...old.runs.filter((r) => !listed.has(r.id))].slice(0, 200);
      // Runs the fleet index knows that GitHub no longer lists: were they deleted there?
      const indexed = new Set([...index.jobs.values()].filter((j) => j.repo === repo && j.hasTrace && j.runId).map((j) => j.runId));
      for (const id of indexed) {
        if (listed.has(id) || st.gone.includes(id)) continue;
        let gone = st.complete; // the list is everything GitHub has, and the run is not in it
        if (!gone) {
          const k = `${repo}#${id}`;
          if (mem.alive.has(k)) continue;
          try {
            const r = liteRun(await o.github.getRun(repo, id));
            mem.alive.add(k);
            if (!st.runs.some((x) => x.id === id)) st.runs.push(r);
          } catch (e) {
            gone = e instanceof GithubError && e.status === 404;
          }
        }
        if (gone) st.gone.push(id);
      }
      delete st.error;
    } catch (e) {
      st.error = msg(e);
      errors.push(`${repo}: ${st.error}`);
      log(`github ${repo}: ${st.error}`);
    }
  }
  await writeJsonFile(file, next);

  // 2. CRACI: what is running right now.
  try {
    const { jobs } = await o.craci.listActiveJobs();
    await writeJsonFile(join(stateDir(), "active.json"), { at: new Date(now()).toISOString(), jobs: (jobs ?? []).filter((j) => o.repos.includes(j.repository)) });
  } catch (e) {
    errors.push(`craci active jobs: ${msg(e)}`);
    log(`craci active jobs: ${msg(e)}`);
  }

  // 3. Verdicts: every run whose two twins are finished and that has no settled verdict yet.
  const have = new Map<string, Verdict>();
  for (const v of await readVerdicts()) if (!have.has(`${v.repo}#${v.runId}`)) have.set(`${v.repo}#${v.runId}`, v);
  const runVerdict = o.runVerdict ?? spawnVerdict;
  const verdicts: Promise<void>[] = [];
  for (const repo of o.repos) {
    const st = next.repos[repo]!;
    for (const r of st.runs) {
      const jobs = st.jobs[r.id] ?? [];
      const bare = jobs.find((j) => TWIN_JOB_PATTERNS.bare.test(j.name));
      const decoy = jobs.find((j) => TWIN_JOB_PATTERNS.decoy.test(j.name));
      if (bare?.status !== "completed" || decoy?.status !== "completed") continue;
      const k = `${repo}#${r.id}`;
      const v = have.get(k);
      const done = Math.max(Date.parse(bare.completedAt ?? ""), Date.parse(decoy.completedAt ?? "")) || 0;
      // An inconclusive verdict may only mean the trace was late: try again for a while.
      const retry = v?.status === "inconclusive" && now() - done < 20 * 60_000 && now() - (mem.verdictAt[k] ?? 0) > 60_000;
      const stale = !!v && (v.twins.bare.jobId !== bare.id || v.twins.decoy.jobId !== decoy.id); // the run was run again
      if ((v && !retry && !stale) || mem.verdictBusy.has(k)) continue;
      if (!v && now() - (mem.verdictAt[k] ?? 0) < 60_000) continue;
      mem.verdictAt[k] = now();
      mem.verdictBusy.add(k);
      verdicts.push(
        runVerdict(repo, r.id)
          .catch((e) => log(`verdict ${k}: ${msg(e)}`))
          .finally(() => mem.verdictBusy.delete(k)),
      );
    }
  }

  // 4. The fleet index. syncFleet lists every run's jobs again, so it runs only when there is a reason:
  //    the first cycle, a run that just finished, or finished jobs whose CRACI trace has not arrived.
  const fleetSynced: string[] = [];
  for (const repo of o.repos) {
    const st = next.repos[repo]!;
    if (st.error) continue;
    const pending = st.runs.some((r) =>
      (st.jobs[r.id] ?? []).some((j) => {
        if (j.status !== "completed" || j.conclusion === "skipped") return false;
        if (index.getJob(repo, j.id)?.hasTrace) return false;
        return now() - Date.parse(j.completedAt ?? "") < 15 * 60_000;
      }),
    );
    const due = now() - (mem.fleetAt[repo] ?? 0) > 60_000;
    if (!(mem.first || changed.has(repo) || (pending && due))) continue;
    mem.fleetAt[repo] = now();
    try {
      const rep = await syncFleet({ repos: [repo], craci: o.craci, github: o.github, index, maxRuns: mem.first ? (o.backfillRuns ?? 50) : (o.maxRuns ?? 20), log });
      fleetSynced.push(repo);
      for (const r of rep.repos) if (r.error) errors.push(`${r.repo}: ${r.error}`);
    } catch (e) {
      errors.push(`${repo}: ${msg(e)}`);
    }
  }
  mem.first = false;
  return { github: next, fleetSynced, verdicts, errors };
}
