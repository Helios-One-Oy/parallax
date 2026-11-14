// GitHub REST client: runs, jobs, Actions caches, cancel, re-run, branch + commit + pull request.
// Token: GITHUB_TOKEN, then GH_TOKEN, then `gh auth token`. Never printed.
import { assertId, assertRepo } from "./paths.ts";

export type GhRun = {
  id: number;
  name?: string | null;
  path?: string;
  head_branch: string | null;
  head_sha: string;
  event: string;
  status: string | null;
  conclusion: string | null;
  run_attempt?: number;
  created_at: string;
  updated_at: string;
  run_started_at?: string;
  html_url: string;
  workflow_id?: number;
  [extra: string]: unknown;
};

export type GhStep = {
  name: string;
  status: string;
  conclusion: string | null;
  number: number;
  started_at?: string | null;
  completed_at?: string | null;
};

export type GhJob = {
  id: number;
  run_id: number;
  run_attempt?: number;
  name: string;
  status: string;
  conclusion: string | null;
  started_at: string | null;
  completed_at: string | null;
  html_url: string | null;
  head_sha: string;
  head_branch?: string | null;
  workflow_name?: string | null;
  labels?: string[];
  runner_name?: string | null;
  steps?: GhStep[];
  [extra: string]: unknown;
};

export type GhCache = {
  id: number;
  key: string;
  ref: string;
  version?: string;
  created_at: string;
  last_accessed_at?: string;
  size_in_bytes: number;
};

export type PullRequestInput = {
  branch: string;
  base?: string; // default: the repository's default branch
  title: string;
  body: string;
  message: string;
  files: Array<{ path: string; content: string }>;
};

export class GithubError extends Error {
  constructor(
    readonly status: number,
    readonly path: string,
    readonly body: string,
  ) {
    super(`GitHub ${path} failed: ${status} ${body.slice(0, 300)}`);
    this.name = "GithubError";
  }
}

export function readGithubToken(): string {
  const env = (process.env.GITHUB_TOKEN || process.env.GH_TOKEN || "").trim();
  if (env) return env;
  try {
    const p = Bun.spawnSync(["gh", "auth", "token"], { stdout: "pipe", stderr: "ignore" });
    const t = p.stdout.toString().trim();
    if (p.exitCode === 0 && t) return t;
  } catch {
    /* gh not installed */
  }
  throw new Error("No GitHub token: set GITHUB_TOKEN or GH_TOKEN, or log in with `gh auth login`");
}

export type GithubOptions = {
  token?: string;
  baseUrl?: string;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
};

export class GithubClient {
  private token: string | undefined;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(o: GithubOptions = {}) {
    this.token = o.token;
    this.baseUrl = o.baseUrl ?? process.env.GITHUB_API_URL ?? "https://api.github.com";
    this.fetchImpl = o.fetch ?? fetch;
    this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  // ---------- read ----------

  async getRun(repo: string, runId: string | number): Promise<GhRun> {
    return this.api<GhRun>("GET", `/repos/${assertRepo(repo)}/actions/runs/${assertId(runId)}`);
  }

  /** Newest first. `max` caps the number of runs returned. */
  async listRuns(
    repo: string,
    o: { max?: number; branch?: string; status?: string; event?: string; created?: string } = {},
  ): Promise<GhRun[]> {
    const q = new URLSearchParams();
    for (const k of ["branch", "status", "event", "created"] as const) if (o[k]) q.set(k, o[k]!);
    return this.paged<GhRun>(`/repos/${assertRepo(repo)}/actions/runs?${q}`, "workflow_runs", o.max ?? 200);
  }

  /** Jobs of a run. `filter: "latest"` = latest attempt only (GitHub default); "all" = every attempt. */
  async listJobs(repo: string, runId: string | number, o: { filter?: "latest" | "all" } = {}): Promise<GhJob[]> {
    return this.paged<GhJob>(
      `/repos/${assertRepo(repo)}/actions/runs/${assertId(runId)}/jobs?filter=${o.filter ?? "latest"}`,
      "jobs",
      1000,
    );
  }

  async listCaches(repo: string, o: { key?: string; ref?: string } = {}): Promise<GhCache[]> {
    const q = new URLSearchParams();
    if (o.key) q.set("key", o.key);
    if (o.ref) q.set("ref", o.ref);
    return this.paged<GhCache>(`/repos/${assertRepo(repo)}/actions/caches?${q}`, "actions_caches", 5000);
  }

  // ---------- write ----------

  async deleteCache(repo: string, cacheId: string | number): Promise<void> {
    await this.api("DELETE", `/repos/${assertRepo(repo)}/actions/caches/${assertId(cacheId)}`);
  }

  async cancelRun(repo: string, runId: string | number): Promise<void> {
    await this.api("POST", `/repos/${assertRepo(repo)}/actions/runs/${assertId(runId)}/cancel`);
  }

  /** Re-runs every job of the run. For "without cache", delete the caches first: GitHub has no such switch. */
  async rerunRun(repo: string, runId: string | number): Promise<void> {
    await this.api("POST", `/repos/${assertRepo(repo)}/actions/runs/${assertId(runId)}/rerun`);
  }

  async defaultBranch(repo: string): Promise<string> {
    return (await this.api<{ default_branch: string }>("GET", `/repos/${assertRepo(repo)}`)).default_branch;
  }

  /** Create a branch from `base`, commit the files onto it (one commit per file), open a pull request. */
  async createPullRequest(repo: string, pr: PullRequestInput): Promise<{ number: number; html_url: string }> {
    assertRepo(repo);
    const base = pr.base ?? (await this.defaultBranch(repo));
    const ref = await this.api<{ object: { sha: string } }>(
      "GET",
      `/repos/${repo}/git/ref/heads/${encodeURIComponent(base).replaceAll("%2F", "/")}`,
    );
    try {
      await this.api("POST", `/repos/${repo}/git/refs`, { ref: `refs/heads/${pr.branch}`, sha: ref.object.sha });
    } catch (e) {
      // 422 = the branch already exists: reuse it.
      if (!(e instanceof GithubError && e.status === 422)) throw e;
    }
    for (const f of pr.files) {
      const path = f.path.split("/").map(encodeURIComponent).join("/");
      let sha: string | undefined;
      try {
        sha = (
          await this.api<{ sha: string }>(
            "GET",
            `/repos/${repo}/contents/${path}?ref=${encodeURIComponent(pr.branch)}`,
          )
        ).sha;
      } catch (e) {
        if (!(e instanceof GithubError && e.status === 404)) throw e;
      }
      await this.api("PUT", `/repos/${repo}/contents/${path}`, {
        message: pr.message,
        content: Buffer.from(f.content, "utf8").toString("base64"),
        branch: pr.branch,
        ...(sha ? { sha } : {}),
      });
    }
    const made = await this.api<{ number: number; html_url: string }>("POST", `/repos/${repo}/pulls`, {
      title: pr.title,
      body: pr.body,
      head: pr.branch,
      base,
    });
    return { number: made.number, html_url: made.html_url };
  }

  // ---------- internals ----------

  private async paged<T>(path: string, field: string, max: number): Promise<T[]> {
    const out: T[] = [];
    const sep = path.includes("?") ? (path.endsWith("?") ? "" : "&") : "?";
    for (let page = 1; out.length < max && page <= 100; page++) {
      const body = await this.api<Record<string, unknown>>("GET", `${path}${sep}per_page=100&page=${page}`);
      const items = (Array.isArray(body) ? body : (body[field] as T[] | undefined)) ?? [];
      out.push(...(items as T[]));
      if (items.length < 100) break;
    }
    return out.slice(0, max);
  }

  private async api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
    this.token ??= readGithubToken();
    for (let attempt = 0; ; attempt++) {
      let res: Response | null = null;
      try {
        res = await this.fetchImpl(`${this.baseUrl}${path}`, {
          method,
          headers: {
            authorization: `Bearer ${this.token}`,
            accept: "application/vnd.github+json",
            "x-github-api-version": "2022-11-28",
            "user-agent": "parallax",
            ...(body === undefined ? {} : { "content-type": "application/json" }),
          },
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(30_000),
        });
      } catch (e) {
        if (attempt >= 3) throw e;
      }
      if (res?.ok) {
        if (res.status === 204 || res.status === 202 || res.status === 201) {
          const text = await res.text();
          return (text ? JSON.parse(text) : undefined) as T;
        }
        return (await res.json()) as T;
      }
      const status = res?.status ?? 0;
      const limited = status === 429 || (status === 403 && res?.headers.get("x-ratelimit-remaining") === "0");
      if ((!res || status >= 500 || limited) && attempt < 3) {
        const retryAfter = Number(res?.headers.get("retry-after"));
        await res?.body?.cancel().catch(() => {});
        await this.sleep(retryAfter > 0 ? Math.min(retryAfter * 1000, 60_000) : 1000 * 2 ** attempt);
        continue;
      }
      throw new GithubError(status, `${method} ${path.split("?")[0]}`, res ? await res.text() : "network error");
    }
  }
}
