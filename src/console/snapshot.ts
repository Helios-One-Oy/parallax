// The console's data: one JSON-serialisable snapshot of everything the core knows.
// The box builds it from the run directory through the core; the public app receives it over /ingest.
// Nothing in here is made up: every field is read from the fleet index, a verdict file, a CRACI trace
// in the API cache, or the GitHub state the sync wrote.
import { mkdir, readdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { CraciClient, readCraciToken } from "../craci.ts";
import { policySuggestion } from "../diff.ts";
import { FleetIndex, loadFleetRepos, type CacheRecord, type FleetJob } from "../fleet.ts";
import { readFixes } from "../fix/run.ts";
import { fixRows, type FixRow } from "../fix/view.ts";
import { normalizeTrace } from "../normalize.ts";
import { apiCacheDir, assertId, assertRepo, fleetDir, runsDir, verdictsDir } from "../paths.ts";
import type { JobSummary, NetworkTrace, PreviewArtifactProvenance, Verdict } from "../types.ts";

export type GhRunLite = {
  id: string;
  workflow: string;
  title: string;
  branch: string;
  sha: string;
  event: string;
  status: string;
  conclusion: string | null;
  createdAt: string;
  startedAt: string;
  updatedAt: string;
  url: string;
  attempt: number;
  prs: number[];
};

export type GhJobLite = {
  id: string;
  name: string;
  status: string;
  conclusion: string | null;
  startedAt: string | null;
  completedAt: string | null;
  url: string;
};

export type GithubRepoState = {
  runs: GhRunLite[];
  /** Jobs per run id. */
  jobs: Record<string, GhJobLite[]>;
  /** Run ids GitHub answered 404 for (the run was deleted there). */
  gone: string[];
  /** True when the run list above is everything GitHub has for the repo. */
  complete: boolean;
  error?: string;
};

export type GithubState = { fetchedAt: string | null; repos: Record<string, GithubRepoState> };

export type TwinConn = {
  key: string;
  kind: string;
  host: string;
  /** How many raw observations folded into this key. */
  count: number;
  /** Sequence number of the first one (CRACI's order). */
  seq: number;
  at: string | null;
  httpStatus: number | null;
  denied: boolean;
};

export type TwinSide = { jobId: string; hasTrace: boolean; observations: number; noise: number; conns: TwinConn[] };
export type TwinDetail = { bare: TwinSide; decoy: TwinSide };

export type Snapshot = {
  v: 1;
  generatedAt: string;
  fixture: boolean;
  repos: string[];
  jobs: FleetJob[];
  caches: CacheRecord[];
  artifacts: PreviewArtifactProvenance[];
  verdicts: Verdict[];
  /** Ordered connections of both twins, by `repo#runId`. */
  twins: Record<string, TwinDetail>;
  github: GithubState;
  active: JobSummary[];
  activeAt: string | null;
  /** Network policy per repo, from its newest judged run (for the ring-fence pull request). */
  policies: Record<string, string>;
  /** `repo#jobId` of finished job logs the box holds. */
  logs: string[];
  /** Dependency fixes an agent proposed, and what each one's own build proved. Absent in older snapshots. */
  fixes?: FixRow[];
};

export const runKey = (repo: string, runId: string | number) => `${repo}#${runId}`;
export const stateDir = () => join(runsDir(), "console", "state");
export const emptyGithub = (): GithubState => ({ fetchedAt: null, repos: {} });

/** A client that never leaves the machine: it only answers from the on-disk API cache. */
export function offlineCraci(): CraciClient {
  const notFound = async () =>
    new Response(JSON.stringify({ title: "offline", status: 404 }), { status: 404, headers: { "content-type": "application/problem+json" } });
  return new CraciClient({ token: "offline", maxRetries: 0, fetch: notFound as unknown as typeof fetch });
}

/** A real client when a token is at hand, else null. Never in fixture mode. */
export function liveCraci(fixture: boolean): CraciClient | null {
  if (fixture) return null;
  try {
    return new CraciClient({ token: readCraciToken() });
  } catch {
    return null;
  }
}

export async function readJsonFile<T>(file: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as T;
  } catch {
    return null;
  }
}

export async function writeJsonFile(file: string, value: unknown): Promise<void> {
  await mkdir(dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(value));
  await rename(tmp, file);
}

async function ls(dir: string): Promise<string[]> {
  try {
    return await readdir(dir);
  } catch {
    return [];
  }
}

export async function readVerdicts(): Promise<Verdict[]> {
  const out: Verdict[] = [];
  const root = verdictsDir();
  for (const owner of await ls(root))
    for (const repo of await ls(join(root, owner)))
      for (const f of await ls(join(root, owner, repo))) {
        if (!f.endsWith(".json")) continue;
        const v = await readJsonFile<Verdict>(join(root, owner, repo, f));
        if (v && typeof v.repo === "string" && typeof v.runId === "string" && v.twins) out.push(v);
      }
  return out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function twinSide(jobId: string, trace: NetworkTrace | null): TwinSide {
  const nt = normalizeTrace(trace);
  let noise = 0;
  for (const list of nt.noise.values()) noise += list.length;
  const conns: TwinConn[] = [];
  for (const [key, list] of nt.keys) {
    const first = list.reduce((a, b) => (Number(b.raw.sequence) < Number(a.raw.sequence) ? b : a));
    const raw = first.raw as any;
    conns.push({
      key,
      kind: first.kind,
      host: first.host,
      count: list.length,
      seq: Number(raw.sequence) || 0,
      at: typeof raw.observedAt === "string" ? raw.observedAt : null,
      httpStatus: first.kind === "http" && typeof raw.http?.statusCode === "number" ? raw.http.statusCode : null,
      denied: list.some((n) => {
        const o = n.raw as any;
        return o.http?.policyDenied === true || o.tcp?.allowed === false || o.sshGit?.allowed === false;
      }),
    });
  }
  conns.sort((a, b) => a.seq - b.seq || a.key.localeCompare(b.key));
  return { jobId, hasTrace: !!trace, observations: nt.total, noise, conns };
}

export async function twinDetail(craci: CraciClient, v: Verdict): Promise<TwinDetail> {
  const get = async (jobId: string) => {
    if (!jobId) return null;
    try {
      return await craci.getNetworkTrace(v.repo, jobId, { waitFor: 0 });
    } catch {
      return null;
    }
  };
  const [bare, decoy] = await Promise.all([get(v.twins.bare.jobId), get(v.twins.decoy.jobId)]);
  return { bare: twinSide(v.twins.bare.jobId, bare), decoy: twinSide(v.twins.decoy.jobId, decoy) };
}

async function exists(file: string): Promise<boolean> {
  try {
    return (await stat(file)).isFile();
  } catch {
    return false;
  }
}

export function logFile(repo: string, jobId: string): string {
  return join(apiCacheDir(), assertRepo(repo), assertId(jobId), "logs.txt");
}

export type BuildOptions = {
  fixture?: boolean;
  /** Reads traces (disk cache first). Default: an offline client, so building a snapshot never needs a token. */
  craci?: CraciClient;
  /** How many of the newest verdicts get their twin connections attached. */
  maxTwins?: number;
  /** Keeps parsed traces between builds, so a rebuild every few seconds does not read them again. */
  memo?: BuildMemo;
  now?: () => Date;
};

export type BuildMemo = { twins: Map<string, TwinDetail>; policies: Map<string, string> };
export const newMemo = (): BuildMemo => ({ twins: new Map(), policies: new Map() });

/** Read the run directory through the core and return the whole snapshot. */
export async function buildSnapshot(o: BuildOptions = {}): Promise<Snapshot> {
  const fixture = !!o.fixture;
  const craci = o.craci ?? offlineCraci();
  const dir = runsDir();
  const repos = await loadFleetRepos(fixture ? join(dir, "fleet.json") : undefined);
  const index = await FleetIndex.load(fleetDir());
  const verdicts = await readVerdicts();
  const github = (await readJsonFile<GithubState>(join(stateDir(), "github.json"))) ?? emptyGithub();
  const activeDoc = await readJsonFile<{ at: string; jobs: JobSummary[] }>(join(stateDir(), "active.json"));

  const twins: Record<string, TwinDetail> = {};
  const logs = new Set<string>();
  const policies: Record<string, string> = {};
  for (const v of verdicts.slice(0, o.maxTwins ?? 80)) {
    const mk = `${runKey(v.repo, v.runId)} ${v.createdAt}`;
    let td = o.memo?.twins.get(mk);
    if (!td) {
      td = await twinDetail(craci, v);
      if (td.bare.hasTrace && td.decoy.hasTrace) o.memo?.twins.set(mk, td);
    }
    twins[runKey(v.repo, v.runId)] = td;
    for (const t of [v.twins.bare, v.twins.decoy]) {
      if (!t.jobId) continue;
      try {
        if (await exists(logFile(v.repo, t.jobId))) logs.add(`${v.repo}#${t.jobId}`);
      } catch {
        /* a verdict with a broken repo or job id: no log */
      }
    }
  }
  for (const v of verdicts) {
    if (policies[v.repo] || v.status === "inconclusive" || !v.twins.bare.jobId) continue;
    const mk = `${runKey(v.repo, v.runId)} ${v.createdAt}`;
    const known = o.memo?.policies.get(mk);
    if (known) {
      policies[v.repo] = known;
      continue;
    }
    try {
      const trace = await craci.getNetworkTrace(v.repo, v.twins.bare.jobId, { waitFor: 0 });
      if (trace) {
        policies[v.repo] = policySuggestion(v, trace).yaml;
        o.memo?.policies.set(mk, policies[v.repo]!);
      }
    } catch {
      /* no policy for this repo */
    }
  }

  return {
    v: 1,
    generatedAt: (o.now?.() ?? new Date()).toISOString(),
    fixture,
    repos,
    jobs: index.sorted(),
    caches: [...index.caches.values()],
    artifacts: [...index.artifacts.values()],
    verdicts,
    twins,
    github,
    active: (activeDoc?.jobs ?? []).filter((j) => repos.includes(j.repository)),
    activeAt: activeDoc?.at ?? null,
    policies,
    logs: [...logs].sort(),
    fixes: await Promise.all(
      fixRows(await readFixes(join(runsDir(), "fixes", "fixes.jsonl")))
        .filter((f) => repos.includes(f.repo))
        .map(async (f) => ({ ...f, prompt: f.craciPrompt ? await fixPrompt(f.base.jobUrl) : null })),
    ),
  };
}

/** The fix prompt copied from the CRACI page of this job, as the box saved it. */
async function fixPrompt(jobUrl: string): Promise<string | null> {
  const id = /\/job\/(\d+)/.exec(jobUrl)?.[1];
  if (!id) return null;
  try {
    return (await readFile(join(runsDir(), "aifix", `job-${id}-fix-prompt.txt`), "utf8")).trim().slice(0, 8000) || null;
  } catch {
    return null;
  }
}

/** A snapshot for "nothing known yet": the fleet's repos and nothing else. */
export async function emptySnapshot(fixture = false): Promise<Snapshot> {
  let repos: string[] = [];
  try {
    repos = await loadFleetRepos();
  } catch {
    repos = [];
  }
  return {
    v: 1,
    generatedAt: "",
    fixture,
    repos,
    jobs: [],
    caches: [],
    artifacts: [],
    verdicts: [],
    twins: {},
    github: emptyGithub(),
    active: [],
    activeAt: null,
    policies: {},
    logs: [],
  };
}

/** Identity of a snapshot's content; clock fields that move on every build are left out. */
export function snapshotHash(s: Snapshot): string {
  const stable = { ...s, generatedAt: "", activeAt: null, github: { ...s.github, fetchedAt: null } };
  return new Bun.CryptoHasher("sha256").update(JSON.stringify(stable)).digest("hex");
}

/** Shape check for a snapshot that arrived over the network. Returns the reason it is not one, or null. */
export function snapshotProblem(x: unknown): string | null {
  const s = x as Partial<Snapshot> | null;
  if (!s || typeof s !== "object") return "not an object";
  if (s.v !== 1) return "unknown version";
  for (const k of ["repos", "jobs", "caches", "artifacts", "verdicts", "active", "logs"] as const)
    if (!Array.isArray(s[k])) return `${k} is not a list`;
  if (!s.repos!.every((r) => typeof r === "string" && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(r))) return "bad repo name";
  for (const k of ["twins", "github", "policies"] as const) if (!s[k] || typeof s[k] !== "object") return `${k} is missing`;
  if (!s.github!.repos || typeof s.github!.repos !== "object") return "github.repos is missing";
  return null;
}
