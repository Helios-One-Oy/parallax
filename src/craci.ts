// Typed client for the CRACI API (research/dl/openapi.json, nine endpoints).
// - token from CRACI_API_TOKEN or ~/.config/crashtest/craci.token (never printed)
// - retries with backoff on network errors, 429 and 5xx
// - `waitFor`: keep polling on 404/409 for trace and SBOM while a job is fresh
// - on-disk cache of immutable responses under <runsDir>/api/<owner>/<repo>/<jobId>/...
import { readFileSync } from "node:fs";
import { mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { apiCacheDir, assertDigest, assertId, assertRepo } from "./paths.ts";
import type {
  CycloneDxBom,
  Jobs,
  NetworkTrace,
  PreviewArtifactProvenance,
  Problem,
  Usage,
} from "./types.ts";

export const DEFAULT_WAIT_MS = 5 * 60_000;

export class CraciError extends Error {
  constructor(
    readonly status: number,
    readonly path: string,
    readonly problem: Partial<Problem> | null,
    cause?: unknown,
  ) {
    super(
      `CRACI ${path} failed: ${status || "network error"}${problem?.title ? ` ${problem.title}` : ""}${problem?.detail ? ` (${problem.detail})` : ""}`,
      cause ? { cause } : undefined,
    );
    this.name = "CraciError";
  }
  get notFound() {
    return this.status === 404;
  }
  get notTerminal() {
    return this.status === 409;
  }
}

export type CraciOptions = {
  token?: string;
  baseUrl?: string;
  /** Directory for cached responses; null disables the cache. */
  cacheDir?: string | null;
  fetch?: typeof fetch;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  maxRetries?: number;
  pollMs?: number;
  /** Per-request timeout in ms (not applied to followLogs). Default 60 s. */
  timeoutMs?: number;
};

export type WaitOptions = {
  /** How long to keep polling on 404/409, in ms. Default 5 minutes. 0 = one try. */
  waitFor?: number;
  /** Skip the disk cache for this call. */
  fresh?: boolean;
  signal?: AbortSignal;
};

export type LogLine = { ts: string | null; text: string };

type Query = Record<string, string | number | boolean | string[] | undefined>;

export function readCraciToken(): string {
  const env = process.env.CRACI_API_TOKEN?.trim();
  if (env) return env;
  const file = process.env.CRACI_TOKEN_FILE || join(homedir(), ".config/crashtest/craci.token");
  try {
    const t = readFileSync(file, "utf8").trim();
    if (t) return t;
  } catch {
    /* fall through */
  }
  throw new Error("No CRACI token: set CRACI_API_TOKEN or create ~/.config/crashtest/craci.token");
}

export function parseLogLine(line: string): LogLine {
  const clean = line.endsWith("\r") ? line.slice(0, -1) : line;
  const tab = clean.indexOf("\t");
  if (tab > 0 && /^\d{4}-\d\d-\d\dT/.test(clean)) return { ts: clean.slice(0, tab), text: clean.slice(tab + 1) };
  return { ts: null, text: clean };
}

export class CraciClient {
  readonly baseUrl: string;
  readonly cacheDir: string | null;
  private token: string | undefined;
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly now: () => number;
  private readonly maxRetries: number;
  private readonly pollMs: number;
  private readonly timeoutMs: number;

  constructor(o: CraciOptions = {}) {
    this.baseUrl = o.baseUrl ?? process.env.CRACI_API_URL ?? "https://api.craci.com";
    this.cacheDir = o.cacheDir === undefined ? apiCacheDir() : o.cacheDir;
    this.token = o.token;
    this.fetchImpl = o.fetch ?? fetch;
    this.sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.now = o.now ?? Date.now;
    this.maxRetries = o.maxRetries ?? 5;
    this.pollMs = o.pollMs ?? 5_000;
    this.timeoutMs = o.timeoutMs ?? 60_000;
  }

  // ---------- the nine endpoints ----------

  /** GET /v1preview1/jobs?status=active */
  async listActiveJobs(since?: string): Promise<Jobs> {
    return this.json<Jobs>("/v1preview1/jobs", { status: "active", since });
  }

  /** GET /v1preview1/job-logs (whole stored log as text). `cache: true` only for finished jobs. */
  async getJobLogs(repo: string, jobId: string, o: { tail?: number; cache?: boolean } & WaitOptions = {}): Promise<string> {
    const file = o.cache && !o.tail ? this.jobFile(repo, jobId, "logs.txt") : null;
    if (file && !o.fresh) {
      const hit = await readText(file);
      if (hit !== null) return hit;
    }
    const res = await this.request(
      "/v1preview1/job-logs",
      { provider: "github", repo, job_id: jobId, tail: o.tail || undefined },
      { accept: "text/plain", waitForMs: o.waitFor ?? 0, waitStatuses: [404], signal: o.signal },
    );
    const text = await res.text();
    if (file && text) await writeAtomic(file, text);
    return text;
  }

  /** GET /v1preview1/job-logs?follow=true as an async iterator of lines. Ends when the server closes or the signal aborts. */
  async *followLogs(
    repo: string,
    jobId: string,
    o: { tail?: number; signal?: AbortSignal; waitFor?: number } = {},
  ): AsyncGenerator<LogLine> {
    const res = await this.request(
      "/v1preview1/job-logs",
      { provider: "github", repo, job_id: jobId, follow: true, tail: o.tail || undefined },
      { accept: "text/plain", waitForMs: o.waitFor ?? 0, waitStatuses: [404], signal: o.signal, noTimeout: true },
    );
    if (!res.body) return;
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    try {
      for (;;) {
        let chunk: Awaited<ReturnType<typeof reader.read>>;
        try {
          chunk = await reader.read();
        } catch (e) {
          if (o.signal?.aborted) return;
          throw e;
        }
        if (chunk.done) break;
        buf += dec.decode(chunk.value, { stream: true });
        let nl: number;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          yield parseLogLine(line);
        }
      }
      if (buf) yield parseLogLine(buf);
    } finally {
      reader.cancel().catch(() => {});
    }
  }

  /** GET /v1preview1/network-trace. Waits on 404 (unknown yet) and 409 (not terminal). Returns null when still absent. */
  async getNetworkTrace(repo: string, jobId: string, o: WaitOptions = {}): Promise<NetworkTrace | null> {
    return this.jobDoc<NetworkTrace>("/v1preview1/network-trace", repo, jobId, "trace.json", "application/json", o, (t) =>
      // An empty trace may just be early: keep asking for it next time.
      Array.isArray(t?.observations) && t.observations.length > 0,
    );
  }

  /** GET /v1preview1/sbom (CycloneDX 1.7). Returns null when still absent. */
  async getSbom(repo: string, jobId: string, o: WaitOptions = {}): Promise<CycloneDxBom | null> {
    return this.jobDoc<CycloneDxBom>(
      "/v1preview1/sbom",
      repo,
      jobId,
      "sbom.json",
      "application/vnd.cyclonedx+json; version=1.7, application/json",
      o,
      (b) => !!b && typeof b === "object",
    );
  }

  /** GET /v1preview1/artifact-provenance/gha_cache by cache id, or by digest + repository. */
  async getGhaCacheProvenance(
    sel: { cacheId: string | number } | { digest: string; repository: string },
    o: { fresh?: boolean; ttlMs?: number } = {},
  ): Promise<PreviewArtifactProvenance | null> {
    const q: Query =
      "cacheId" in sel
        ? { cache_id: assertId(sel.cacheId) }
        : { digest: assertDigest(sel.digest), repository: assertRepo(sel.repository) };
    const name = "cacheId" in sel ? `id-${assertId(sel.cacheId)}` : `${sel.repository.replace("/", "__")}-${sel.digest.replace(":", "_")}`;
    return this.artifact("gha_cache", name, q, o);
  }

  /** GET /v1preview1/artifact-provenance/oci_blob */
  async getOciBlobProvenance(digest: string, o: { fresh?: boolean; ttlMs?: number } = {}) {
    return this.artifact("oci_blob", assertDigest(digest).replace(":", "_"), { digest }, o);
  }

  /** GET /v1preview1/artifact-provenance/oci_manifest */
  async getOciManifestProvenance(digest: string, o: { fresh?: boolean; ttlMs?: number } = {}) {
    return this.artifact("oci_manifest", assertDigest(digest).replace(":", "_"), { digest }, o);
  }

  /** GET /v1experimental1/sbom/oci_manifest. 409 = a contributing job has not finished (waited on). */
  async getOciManifestSbom(
    digest: string,
    o: { jobInvolvement?: Array<"any" | "manifest" | "config-blob" | "layer-blob"> } & WaitOptions = {},
  ): Promise<CycloneDxBom | null> {
    try {
      const res = await this.request(
        "/v1experimental1/sbom/oci_manifest",
        { digest: assertDigest(digest), job_involvement: o.jobInvolvement },
        {
          accept: "application/vnd.cyclonedx+json; version=1.7, application/json",
          waitForMs: o.waitFor ?? 0,
          waitStatuses: [409],
          signal: o.signal,
        },
      );
      return (await res.json()) as CycloneDxBom;
    } catch (e) {
      if (e instanceof CraciError && (e.notFound || e.notTerminal)) return null;
      throw e;
    }
  }

  /** GET /v1preview1/usage */
  async getUsage(start: string, end: string): Promise<Usage> {
    return this.json<Usage>("/v1preview1/usage", { start, end });
  }

  // ---------- internals ----------

  private jobFile(repo: string, jobId: string, name: string): string | null {
    if (!this.cacheDir) return null;
    return join(this.cacheDir, assertRepo(repo), assertId(jobId), name);
  }

  private async jobDoc<T>(
    path: string,
    repo: string,
    jobId: string,
    fileName: string,
    accept: string,
    o: WaitOptions,
    cacheable: (doc: T) => boolean,
  ): Promise<T | null> {
    const file = this.jobFile(repo, jobId, fileName);
    if (file && !o.fresh) {
      const hit = await readJson<T>(file);
      if (hit !== null) return hit;
    }
    let doc: T;
    try {
      const res = await this.request(
        path,
        { provider: "github", repo: assertRepo(repo), job_id: assertId(jobId) },
        { accept, waitForMs: o.waitFor ?? DEFAULT_WAIT_MS, waitStatuses: [404, 409], signal: o.signal },
      );
      doc = (await res.json()) as T;
    } catch (e) {
      if (e instanceof CraciError && (e.notFound || e.notTerminal)) return null;
      throw e;
    }
    // A 200 means the job is terminal (the API answers 409 otherwise), so the document is immutable.
    if (file && cacheable(doc)) await writeAtomic(file, JSON.stringify(doc));
    return doc;
  }

  private async artifact(
    kind: "gha_cache" | "oci_blob" | "oci_manifest",
    name: string,
    q: Query,
    o: { fresh?: boolean; ttlMs?: number },
  ): Promise<PreviewArtifactProvenance | null> {
    // `jobs_created_in` can grow when a later job produces the same bytes, so this cache has a short life.
    const ttl = o.ttlMs ?? 10 * 60_000;
    const file = this.cacheDir ? join(this.cacheDir, "_artifacts", kind, `${name}.json`) : null;
    if (file && !o.fresh) {
      const hit = await readJson<PreviewArtifactProvenance>(file, ttl, this.now());
      if (hit !== null) return hit;
    }
    try {
      const doc = await this.json<PreviewArtifactProvenance>(`/v1preview1/artifact-provenance/${kind}`, q);
      if (file) await writeAtomic(file, JSON.stringify(doc));
      return doc;
    } catch (e) {
      if (e instanceof CraciError && e.notFound) return null;
      throw e;
    }
  }

  private async json<T>(path: string, q: Query): Promise<T> {
    const res = await this.request(path, q, { accept: "application/json" });
    return (await res.json()) as T;
  }

  private async request(
    path: string,
    q: Query,
    o: { accept?: string; waitForMs?: number; waitStatuses?: number[]; signal?: AbortSignal; noTimeout?: boolean } = {},
  ): Promise<Response> {
    const url = new URL(path, this.baseUrl);
    for (const [k, v] of Object.entries(q)) {
      if (v === undefined) continue;
      if (Array.isArray(v)) for (const x of v) url.searchParams.append(k, x);
      else url.searchParams.set(k, String(v));
    }
    this.token ??= readCraciToken();
    const deadline = this.now() + (o.waitForMs ?? 0);
    let transientTries = 0;
    let polls = 0;
    for (;;) {
      let res: Response | null = null;
      let netErr: unknown = null;
      try {
        res = await this.fetchImpl(url, {
          headers: { authorization: `Bearer ${this.token}`, accept: o.accept ?? "application/json" },
          signal: o.noTimeout ? o.signal : o.signal ? AbortSignal.any([o.signal, AbortSignal.timeout(this.timeoutMs)]) : AbortSignal.timeout(this.timeoutMs),
        });
      } catch (e) {
        if (o.signal?.aborted) throw e;
        netErr = e; // includes our own timeout: retried like any network error
      }
      if (res?.ok) return res;
      const status = res?.status ?? 0;
      const transient = !res || status === 429 || status >= 500;
      if (transient && transientTries < this.maxRetries) {
        transientTries++;
        const retryAfter = Number(res?.headers.get("retry-after"));
        const wait = retryAfter > 0 ? Math.min(retryAfter * 1000, 60_000) : Math.min(30_000, 500 * 2 ** transientTries);
        await res?.body?.cancel().catch(() => {});
        await this.sleep(wait);
        continue;
      }
      if (res && (o.waitStatuses ?? []).includes(status) && this.now() < deadline) {
        polls++;
        await res.body?.cancel().catch(() => {});
        await this.sleep(Math.max(1, Math.min(this.pollMs * Math.min(polls, 3), deadline - this.now())));
        continue;
      }
      let problem: Partial<Problem> | null = null;
      if (res) {
        try {
          problem = (await res.json()) as Partial<Problem>;
        } catch {
          problem = null;
        }
      }
      throw new CraciError(status, path, problem, netErr ?? undefined);
    }
  }
}

// ---------- small file helpers ----------

async function readText(file: string): Promise<string | null> {
  try {
    return await readFile(file, "utf8");
  } catch {
    return null;
  }
}

async function readJson<T>(file: string, ttlMs?: number, now = Date.now()): Promise<T | null> {
  try {
    if (ttlMs !== undefined) {
      const s = await stat(file);
      if (now - s.mtimeMs > ttlMs) return null;
    }
    return JSON.parse(await readFile(file, "utf8")) as T;
  } catch {
    return null;
  }
}

async function writeAtomic(file: string, data: string): Promise<void> {
  try {
    await mkdir(dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    await writeFile(tmp, data);
    await rename(tmp, file);
  } catch {
    // The cache is best effort: a read-only or missing disk must not break a verdict.
  }
}
