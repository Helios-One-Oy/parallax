#!/usr/bin/env bun
// Pushes what the box knows to the public console: bun src/console/push.ts [--once] [--sync]
//   PLX_CONSOLE_URL   the public app (default https://parallax-console.fly.dev)
//   PLX_PUSH_SECONDS  interval (default 10)
//   token             PLX_INGEST_TOKEN, or the file ~/.config/crashtest/parallax-ingest.token (never printed)
// --sync also runs the sync cycle itself (for when no box console is running).
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { loadFleetRepos } from "../fleet.ts";
import { GithubClient, readGithubToken } from "../github.ts";
import { buildSnapshot, liveCraci, logFile, newMemo, snapshotHash, type BuildMemo, type Snapshot } from "./snapshot.ts";
import { newMemory, syncOnce } from "./sync.ts";

export function readIngestToken(): string {
  const env = process.env.PLX_INGEST_TOKEN?.trim();
  if (env) return env;
  const file = process.env.PLX_INGEST_TOKEN_FILE || join(homedir(), ".config/crashtest/parallax-ingest.token");
  try {
    const t = readFileSync(file, "utf8").trim();
    if (t) return t;
  } catch {
    /* fall through */
  }
  throw new Error("No ingest token: set PLX_INGEST_TOKEN or create ~/.config/crashtest/parallax-ingest.token");
}

export type PushOptions = {
  url: string;
  token: string;
  fetch?: typeof fetch;
  /** Default: read the run directory. */
  snapshot?: () => Promise<Snapshot>;
  readLog?: (repo: string, jobId: string) => Promise<string | null>;
  memo?: BuildMemo;
};

export type PushResult = { pushedSnapshot: boolean; pushedLogs: number; hash: string; jobs: number; verdicts: number };

/** One push: the snapshot when the app does not hold this exact one, and every finished log it lacks. */
export async function pushOnce(o: PushOptions): Promise<PushResult> {
  const f = o.fetch ?? fetch;
  const base = o.url.replace(/\/+$/, "");
  const call = async (method: "GET" | "POST", payload?: unknown): Promise<{ hash: string | null; logs: string[] }> => {
    const headers: Record<string, string> = { authorization: `Bearer ${o.token}` };
    let body: Uint8Array | undefined;
    if (payload !== undefined) {
      body = Bun.gzipSync(new TextEncoder().encode(JSON.stringify(payload)));
      headers["content-type"] = "application/json";
      headers["content-encoding"] = "gzip";
    }
    const res = await f(`${base}/ingest`, { method, headers, body, signal: AbortSignal.timeout(60_000) });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`ingest ${method} failed: ${res.status} ${detail.slice(0, 200)}`);
    }
    return (await res.json()) as { hash: string | null; logs: string[] };
  };

  const snap = await (o.snapshot ?? (() => buildSnapshot({ memo: o.memo })))();
  if (snap.fixture) throw new Error("refusing to push fixture data");
  const hash = snapshotHash(snap);
  let state = await call("GET");
  const pushedSnapshot = state.hash !== hash;
  if (pushedSnapshot) state = await call("POST", { snapshot: snap });

  const have = new Set(state.logs);
  const readLog = o.readLog ?? ((repo, jobId) => readFile(logFile(repo, jobId), "utf8").catch(() => null));
  let pushedLogs = 0;
  for (const key of snap.logs) {
    if (have.has(key)) continue;
    const at = key.lastIndexOf("#");
    const repo = key.slice(0, at);
    const jobId = key.slice(at + 1);
    const text = await readLog(repo, jobId);
    if (!text) continue;
    await call("POST", { log: { repo, jobId, text } });
    pushedLogs++;
  }
  return { pushedSnapshot, pushedLogs, hash, jobs: snap.jobs.length, verdicts: snap.verdicts.length };
}

async function main() {
  const argv = process.argv.slice(2);
  const once = argv.includes("--once");
  const withSync = argv.includes("--sync");
  if (process.env.PLX_FIXTURE === "1") throw new Error("PLX_FIXTURE=1 is for development only; the pusher does not run with it");
  const url = process.env.PLX_CONSOLE_URL || "https://parallax-console.fly.dev";
  const token = readIngestToken();
  const every = Math.max(2, Number(process.env.PLX_PUSH_SECONDS ?? 10));
  const memo = newMemo();
  const say = (s: string) => console.error(`${new Date().toISOString()} ${s}`);

  let sync: (() => Promise<void>) | null = null;
  if (withSync) {
    const craci = liveCraci(false);
    if (!craci) throw new Error("--sync needs a CRACI token");
    const github = new GithubClient({ token: readGithubToken() });
    const repos = await loadFleetRepos();
    const memory = newMemory();
    const gap = Math.max(5, Number(process.env.PLX_SYNC_SECONDS ?? 30)) * 1000;
    let last = 0;
    let busy = false;
    // Never awaited by the push loop: a sync may wait a minute for a late trace, and what it has
    // already written (GitHub state, verdicts) should reach the public app meanwhile.
    sync = async () => {
      if (busy || Date.now() - last < gap) return;
      busy = true;
      last = Date.now();
      try {
        const r = await syncOnce({ repos, github, craci, memory, log: say });
        for (const e of r.errors) say(`sync: ${e}`);
        await Promise.all(r.verdicts);
      } catch (e) {
        say(`sync failed: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        busy = false;
      }
    };
  }

  let quiet = "";
  for (;;) {
    try {
      if (sync) {
        if (once) await sync();
        else void sync();
      }
      const r = await pushOnce({ url, token, memo });
      const line = `${r.jobs} jobs, ${r.verdicts} verdicts`;
      if (r.pushedSnapshot || r.pushedLogs || line !== quiet || once)
        say(`${r.pushedSnapshot ? "pushed" : "up to date"}: ${line}${r.pushedLogs ? `, ${r.pushedLogs} logs` : ""} -> ${url}`);
      quiet = line;
    } catch (e) {
      say(`push failed: ${e instanceof Error ? e.message : String(e)}`);
      if (once) process.exit(1);
    }
    if (once) return;
    await new Promise((r) => setTimeout(r, every * 1000));
  }
}

if (import.meta.main)
  main().catch((e) => {
    console.error(`parallax push: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
