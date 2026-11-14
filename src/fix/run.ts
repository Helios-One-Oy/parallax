// A fix that has to prove itself:
//   propose: CRACI's bill of materials for a job → the advisories → an agent writes the change → the gate → a pull request
//   verify:  the pull request's build on CRACI → its bill of materials → which advisories are really gone → a comment
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CraciClient } from "../craci.ts";
import type { GhJob, GhRun, GithubClient } from "../github.ts";
import { readGithubToken } from "../github.ts";
import { assertRepo, runsDir } from "../paths.ts";
import type { Scope } from "./advisories.ts";
import { advisoriesOf, compareAdvisories, countBySeverity, inScope } from "./advisories.ts";
import type { Agent } from "./agent.ts";
import { FIX_MAY_CHANGE, lockDiff, lockPackages, newRegistries, outsideTheFix, porcelainPaths } from "./lockfile.ts";
import type { Change, FixRecord, JobPoint, Proof, Target } from "./report.ts";
import { DEFAULT_MIN_AGE_HOURS, buildBrief, judgeChange, judgeProof, renderPrBody, renderProof } from "./report.ts";
import { agesOf, fetchOsv, fixedVersion } from "./sources.ts";

export const fixesDir = () => join(runsDir(), "fixes");
export const fixesFile = () => join(fixesDir(), "fixes.jsonl");

/** The job whose bill of materials is read: the twin that is not dressed up. */
export const MEASURED_JOB = "build (bare)";
export const VERDICT_JOB = /verdict/i;

type Gh = Pick<GithubClient, "defaultBranch" | "listRuns" | "listJobs" | "getRun">;
type Craci = Pick<CraciClient, "getSbom">;
type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

/** The checkout the agent works in. Tests replace it with a directory of their own. */
export type Workspace = {
  /** A fresh copy of the repository's branch in `dir`. */
  checkout(repo: string, branch: string, dir: string): Promise<void>;
  /** The commit that was checked out, when the workspace can tell. */
  head?(dir: string): Promise<string>;
  /** Paths that differ from the checked-out commit. */
  changedPaths(dir: string): Promise<string[]>;
  /** Commit the given paths on a new branch and push it. */
  push(dir: string, branch: string, paths: string[], message: string): Promise<void>;
};

async function sh(cmd: string[], cwd?: string): Promise<string> {
  const p = Bun.spawn(cmd, { cwd, stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
  if (code !== 0) throw new Error(`${cmd.slice(0, 3).join(" ")} failed (${code}): ${err.trim().slice(0, 300)}`);
  return out;
}

export const gitWorkspace: Workspace = {
  async checkout(repo, branch, dir) {
    await sh(["gh", "repo", "clone", assertRepo(repo), dir, "--", "--depth", "1", "--branch", branch]);
  },
  async head(dir) {
    return (await sh(["git", "rev-parse", "HEAD"], dir)).trim();
  },
  async changedPaths(dir) {
    return porcelainPaths(await sh(["git", "status", "--porcelain"], dir));
  },
  async push(dir, branch, paths, message) {
    await sh(["git", "checkout", "-b", branch], dir);
    await sh(["git", "add", "--", ...paths], dir);
    await sh(["git", "commit", "-m", message], dir);
    await sh(["git", "push", "origin", branch], dir);
  },
};

export type FixDeps = {
  gh: Gh;
  craci: Craci;
  agent: Agent;
  workspace?: Workspace;
  fetch?: FetchLike;
  now?: () => number;
  /** Where the record is appended; null = nowhere (tests). */
  recordFile?: string | null;
  /** Root for throwaway checkouts. */
  workDir?: string;
  log?: (line: string) => void;
};

const jobPoint = (run: Pick<GhRun, "head_branch" | "head_sha" | "id">, job: Pick<GhJob, "id" | "name" | "html_url">): JobPoint => ({
  branch: run.head_branch ?? "",
  commitSha: run.head_sha,
  runId: String(run.id),
  jobId: String(job.id),
  jobName: job.name,
  jobUrl: job.html_url ?? "",
});

/** The newest finished run of the branch that has the measured job, passed. */
async function latestMeasured(gh: Gh, repo: string, branch: string): Promise<{ run: GhRun; job: GhJob } | null> {
  for (const run of await gh.listRuns(repo, { branch, status: "completed", max: 15 })) {
    const job = (await gh.listJobs(repo, run.id)).find((j) => j.name === MEASURED_JOB && j.conclusion === "success");
    if (job) return { run, job };
  }
  return null;
}

async function save(r: FixRecord, file: string | null | undefined): Promise<void> {
  if (file === null) return;
  const f = file ?? fixesFile();
  await mkdir(join(f, ".."), { recursive: true });
  await appendFile(f, JSON.stringify(r) + "\n");
}

/** Every fix, the latest state of each (the file is append-only: a later line replaces an earlier one with the same id). */
export async function readFixes(file: string = fixesFile()): Promise<FixRecord[]> {
  let text = "";
  try {
    text = await readFile(file, "utf8");
  } catch {
    return [];
  }
  const byId = new Map<string, FixRecord>();
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line) as FixRecord;
      byId.set(r.id, r);
    } catch {
      /* a torn line */
    }
  }
  return [...byId.values()];
}

export async function proposeFix(
  o: { repo: string; scope?: Scope; minAgeHours?: number; craciPrompt?: string | null; dryRun?: boolean },
  deps: FixDeps,
): Promise<FixRecord> {
  const { gh, craci, agent } = deps;
  const ws = deps.workspace ?? gitWorkspace;
  const now = deps.now ?? Date.now;
  const log = deps.log ?? (() => {});
  const scope = o.scope ?? "high";
  const minAgeHours = o.minAgeHours ?? DEFAULT_MIN_AGE_HOURS;
  const repo = assertRepo(o.repo);

  const branch = await gh.defaultBranch(repo);
  const found = await latestMeasured(gh, repo, branch);
  if (!found) throw new Error(`No finished "${MEASURED_JOB}" job on ${branch} of ${repo}`);
  const base = jobPoint(found.run, found.job);
  const sbom = await craci.getSbom(repo, base.jobId);
  if (!sbom) throw new Error(`CRACI has no bill of materials for job ${base.jobId}`);
  const all = advisoriesOf(sbom);
  const wanted = inScope(all, scope).filter((a) => a.purl.startsWith("pkg:npm/"));
  log(`${all.length} advisories in the bill of materials of ${base.jobName} @ ${base.commitSha.slice(0, 7)}, ${wanted.length} in scope`);

  const stamp = new Date(now()).toISOString().replace(/[-:]/g, "").slice(0, 13);
  const record: FixRecord = {
    id: `${repo}#${stamp}`,
    repo,
    createdAt: new Date(now()).toISOString(),
    scope,
    minAgeHours,
    base,
    before: countBySeverity(all),
    targeted: [],
    craciPrompt: !!o.craciPrompt,
    agent: null,
    change: null,
    status: "nothing-to-fix",
    why: [],
    pr: null,
    proof: null,
  };
  if (!wanted.length) {
    await save(record, deps.recordFile);
    return record;
  }

  const root = workRoot(deps, record);
  const dir = join(root, "repo");
  await mkdir(root, { recursive: true });
  await ws.checkout(repo, branch, dir);
  const head = await ws.head?.(dir);
  if (head && head !== base.commitSha) {
    // The advisories were read from one commit and the fix would be written on another: not a measured fix.
    throw new Error(`${branch} is at ${head.slice(0, 7)} but its newest finished build is of ${base.commitSha.slice(0, 7)}. Run again when that build is done.`);
  }
  const manifestBefore = JSON.parse(await readFile(join(dir, "package.json"), "utf8")) as Record<string, Record<string, string> | undefined>;
  const lockBefore = lockPackages(await readFile(join(dir, "package-lock.json"), "utf8"));
  const direct = new Set([...Object.keys(manifestBefore.dependencies ?? {}), ...Object.keys(manifestBefore.devDependencies ?? {})]);

  const osv = await fetchOsv(wanted.map((a) => a.id), deps.fetch);
  const targets: Target[] = wanted.map((a) => ({ ...a, fixedIn: fixedVersion(osv.get(a.id), a.package, a.version), direct: direct.has(a.package) }));
  record.targeted = targets;

  log(`agent at work in ${dir}`);
  const res = await agent({ cwd: dir, home: join(root, "home"), prompt: buildBrief({ repo, job: base, targets, minAgeHours, craciPrompt: o.craciPrompt }) });
  record.agent = { model: res.model, turns: res.turns, seconds: res.seconds, report: res.report };
  if (!res.ok) {
    record.status = "agent-failed";
    record.why = [res.error ?? "The agent did not finish."];
    await save(record, deps.recordFile);
    return record;
  }

  // The gate: read what the agent left behind, not what it says it did.
  const changed = await ws.changedPaths(dir);
  const lockText = await readFile(join(dir, "package-lock.json"), "utf8");
  const lockAfter = lockPackages(lockText);
  const diff = lockDiff(lockBefore, lockAfter);
  const lockRaw = JSON.parse(lockText) as { packages?: Record<string, { hasInstallScript?: boolean }> };
  const broughtIn = [...diff.changed.flatMap((c) => c.to.filter((v) => !c.from.includes(v)).map((version) => ({ name: c.name, version }))), ...diff.added.flatMap((a) => a.versions.map((version) => ({ name: a.name, version })))];
  const touched = new Set(broughtIn.map((b) => b.name));
  const change: Change = {
    diff,
    outside: outsideTheFix(changed),
    newRegistries: newRegistries(lockBefore, lockAfter),
    ages: (await agesOf(broughtIn, now(), deps.fetch)).sort((a, b) => (a.ageHours ?? Infinity) - (b.ageHours ?? Infinity)),
    installScripts: Object.entries(lockRaw.packages ?? {})
      .filter(([path, p]) => p.hasInstallScript && touched.has(path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length)))
      .map(([path]) => path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length)),
  };
  record.change = change;
  const verdict = judgeChange(change, minAgeHours);
  if (verdict.refuse.length) {
    record.status = "refused";
    record.why = verdict.refuse;
    await save(record, deps.recordFile);
    return record;
  }
  if (!changed.includes("package-lock.json")) {
    record.status = "no-change";
    record.why = ["The agent left the lockfile as it was."];
    await save(record, deps.recordFile);
    return record;
  }

  record.status = "proposed";
  await save(record, deps.recordFile);
  return o.dryRun ? record : publishFix({ record }, deps);
}

const workRoot = (deps: Pick<FixDeps, "workDir">, r: Pick<FixRecord, "repo" | "id">) =>
  join(deps.workDir ?? join(fixesDir(), "work"), r.repo.replace("/", "__"), r.id.slice(r.id.indexOf("#") + 1));

/** Push a proposed change (one that passed the gate) and open its pull request. */
export async function publishFix(
  o: { record?: FixRecord; id?: string },
  deps: Pick<FixDeps, "workspace" | "fetch" | "recordFile" | "workDir" | "log">,
): Promise<FixRecord> {
  const ws = deps.workspace ?? gitWorkspace;
  const record = o.record ?? (await readFixes(deps.recordFile ?? undefined)).find((r) => r.id === o.id);
  if (!record || record.status !== "proposed" || !record.change || record.pr) throw new Error("No proposed fix without a pull request matches");
  const { repo, base, targeted: targets, change } = record;
  const dir = join(workRoot(deps, record), "repo");
  const stamp = record.id.slice(record.id.indexOf("#") + 1);
  const prBranch = `parallax/fix-${stamp.toLowerCase()}`;
  const title = `deps: clear known advisories in ${[...new Set(targets.map((t) => t.package))].join(", ")}`;
  await ws.push(
    dir,
    prBranch,
    (await ws.changedPaths(dir)).filter((p) => FIX_MAY_CHANGE.includes(p)),
    `${title}\n\nFrom CRACI's bill of materials of ${base.jobName} at ${base.commitSha.slice(0, 7)}.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`,
  );
  const body = renderPrBody(record, judgeChange(change, record.minAgeHours ?? DEFAULT_MIN_AGE_HOURS).notes);
  const made = await openPullRequest(repo, { head: prBranch, base: base.branch, title, body }, deps.fetch);
  const done: FixRecord = { ...record, pr: { number: made.number, url: made.html_url, branch: prBranch } };
  (deps.log ?? (() => {}))(`opened ${made.html_url}`);
  await save(done, deps.recordFile);
  return done;
}

// ---------- verify ----------

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function verifyFix(
  o: { id?: string; repo?: string; pr?: number; waitMs?: number; comment?: boolean; records?: FixRecord[] },
  deps: Omit<FixDeps, "agent" | "workspace">,
): Promise<FixRecord> {
  const { gh, craci } = deps;
  const now = deps.now ?? Date.now;
  const log = deps.log ?? (() => {});
  const records = o.records ?? (await readFixes(deps.recordFile ?? undefined));
  const record = records.find((r) => (o.id ? r.id === o.id : r.repo === o.repo && r.pr?.number === o.pr));
  if (!record?.pr) throw new Error("No proposed fix with a pull request matches");
  const repo = record.repo;

  const deadline = now() + (o.waitMs ?? 12 * 60_000);
  // The newest run of the fix branch that has the measured job (other workflows may run on the branch too).
  let run: GhRun | null = null;
  let jobs: GhJob[] = [];
  for (;;) {
    run = null;
    for (const r of await gh.listRuns(repo, { branch: record.pr.branch, max: 10 })) {
      jobs = await gh.listJobs(repo, r.id);
      if (jobs.some((j) => j.name === MEASURED_JOB)) {
        run = r;
        break;
      }
    }
    if (run?.status === "completed") break;
    if (now() >= deadline) throw new Error(`The build of ${record.pr.url} did not finish in time`);
    log(run ? `run ${run.id} is ${run.status}` : "no run yet");
    await sleep(15_000);
  }
  const measured = jobs.find((j) => j.name === MEASURED_JOB)!;
  const sbom = await craci.getSbom(repo, String(measured.id), { waitFor: 3 * 60_000 });
  if (!sbom) throw new Error(`CRACI has no bill of materials for job ${measured.id}`);
  const after = advisoriesOf(sbom);
  const baseSbom = await craci.getSbom(repo, record.base.jobId);
  const cmp = compareAdvisories(advisoriesOf(baseSbom), after);
  const verdictJob = jobs.find((j) => VERDICT_JOB.test(j.name));
  const proof: Proof = {
    at: new Date(now()).toISOString(),
    job: jobPoint(run, measured),
    run: { url: run.html_url, conclusion: run.conclusion },
    jobs: Object.fromEntries(jobs.map((j) => [j.name, j.conclusion])),
    twins: verdictJob?.conclusion === "success" ? "clean" : verdictJob?.conclusion === "failure" ? "blocked" : null,
    ...cmp,
    after: countBySeverity(after),
  };
  const judged = judgeProof(record, proof);
  const done: FixRecord = { ...record, proof, status: judged.status, why: judged.why };
  if (o.comment !== false) await commentOnPullRequest(repo, record.pr.number, renderProof(done), deps.fetch);
  await save(done, deps.recordFile);
  return done;
}

// ---------- the two GitHub calls only a fix makes ----------

async function github<T>(path: string, body: unknown, fetchImpl: FetchLike = fetch): Promise<T> {
  const res = await fetchImpl(`${process.env.GITHUB_API_URL ?? "https://api.github.com"}${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${readGithubToken()}`, accept: "application/vnd.github+json", "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`GitHub POST ${path} failed: ${res.status} ${(await res.text()).slice(0, 200)}`);
  return (await res.json()) as T;
}

export const openPullRequest = (repo: string, pr: { head: string; base: string; title: string; body: string }, f?: FetchLike) =>
  github<{ number: number; html_url: string }>(`/repos/${assertRepo(repo)}/pulls`, pr, f);

export const commentOnPullRequest = (repo: string, number: number, body: string, f?: FetchLike) =>
  github<{ html_url: string }>(`/repos/${assertRepo(repo)}/issues/${number}/comments`, { body }, f);
