import { join } from "node:path";

/** Root for run output (traces, SBOMs, fleet index, verdicts). Never inside the repo. */
export function runsDir(): string {
  return process.env.PLX_RUNS_DIR || "/bulk3/runs/craci";
}
export const apiCacheDir = () => join(runsDir(), "api");
export const fleetDir = () => join(runsDir(), "fleet");
export const verdictsDir = () => join(runsDir(), "verdicts");

const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
export function assertRepo(repo: string): string {
  if (!REPO_RE.test(repo) || repo.includes("..")) throw new Error(`bad repo name: ${JSON.stringify(repo)}`);
  return repo;
}
export function assertId(id: string | number): string {
  const s = String(id);
  if (!/^-?[0-9]+$/.test(s)) throw new Error(`bad numeric id: ${JSON.stringify(s)}`);
  return s;
}
export function assertDigest(d: string): string {
  if (!/^sha(256:[0-9a-f]{64}|512:[0-9a-f]{128})$/.test(d)) throw new Error(`bad digest: ${JSON.stringify(d)}`);
  return d;
}
