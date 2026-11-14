// What the console shows of a fix. Built from the fix records only; nothing here is computed from the agent's own words.
import type { Severity } from "./advisories.ts";
import { SEVERITIES } from "./advisories.ts";
import type { FixRecord, FixStatus } from "./report.ts";
import { youngest } from "./report.ts";

export type FixOutcome = "gone" | "still_there" | "not_measured";

export type FixRow = {
  id: string;
  repo: string;
  createdAt: string;
  status: FixStatus;
  /** One plain sentence: where this fix stands. */
  headline: string;
  base: { jobName: string; jobUrl: string; commit: string };
  pr: { number: number; url: string } | null;
  /** True when the agent's brief quoted the prompt copied from the CRACI job page. */
  craciPrompt: boolean;
  /** That prompt, word for word, when the box still has the copy. */
  prompt?: string | null;
  agent: { model: string; seconds: number } | null;
  /** Known advisories of the build by severity: before, and after once the fix's own build was measured. */
  counts: Array<{ severity: Severity; before: number; after: number | null }>;
  advisories: Array<{ package: string; version: string; id: string; url: string; severity: Severity; title: string; fixedIn: string | null; outcome: FixOutcome }>;
  change: {
    changed: number;
    added: number;
    removed: number;
    /** The packages the advisories are about: from → to (to is empty when the package is gone). */
    moved: Array<{ name: string; from: string; to: string }>;
    youngest: { name: string; version: string; ageHours: number } | null;
  } | null;
  proof: { jobUrl: string; runUrl: string; twins: "clean" | "blocked" | null; at: string } | null;
  why: string[];
};

function headline(r: FixRecord): string {
  const n = r.targeted.length;
  const targeted = new Set(r.targeted.map((t) => `${t.id} ${t.package}`));
  const still = r.proof ? r.proof.remaining.filter((a) => targeted.has(`${a.id} ${a.package}`)).length : 0;
  switch (r.status) {
    case "nothing-to-fix":
      return "Nothing critical or high in the build.";
    case "agent-failed":
      return "The agent did not finish. Nothing was pushed.";
    case "no-change":
      return "The agent left the lockfile as it was.";
    case "refused":
      return "Refused at the gate. Nothing was pushed.";
    case "proposed":
      return r.pr ? "Passed the gate. Waiting for its build." : "Passed the gate. Not pushed yet.";
    case "proven":
      return `Proven: all ${n} are gone from the build.`;
    case "partly-proven":
      return `Proven for ${n - still} of ${n}. ${still} still in the build.`;
    case "not-proven":
      return "Not proven.";
  }
}

export function fixRow(r: FixRecord): FixRow {
  const stillThere = new Set((r.proof?.remaining ?? []).map((a) => `${a.id} ${a.package}`));
  const names = [...new Set(r.targeted.map((t) => t.package))];
  const d = r.change?.diff;
  const y = r.change ? youngest(r.change.ages) : null;
  return {
    id: r.id,
    repo: r.repo,
    createdAt: r.createdAt,
    status: r.status,
    headline: headline(r),
    base: { jobName: r.base.jobName, jobUrl: r.base.jobUrl, commit: r.base.commitSha },
    pr: r.pr ? { number: r.pr.number, url: r.pr.url } : null,
    craciPrompt: r.craciPrompt,
    agent: r.agent ? { model: r.agent.model, seconds: r.agent.seconds } : null,
    counts: SEVERITIES.filter((s) => r.before[s] || r.proof?.after[s]).map((s) => ({ severity: s, before: r.before[s], after: r.proof ? r.proof.after[s] : null })),
    advisories: r.targeted.map((t) => ({
      package: t.package,
      version: t.version,
      id: t.id,
      url: t.url,
      severity: t.severity,
      title: t.title,
      fixedIn: t.fixedIn,
      outcome: !r.proof ? "not_measured" : stillThere.has(`${t.id} ${t.package}`) ? "still_there" : "gone",
    })),
    change: d
      ? {
          changed: d.changed.length,
          added: d.added.length,
          removed: d.removed.length,
          moved: names.flatMap((name) => {
            const c = d.changed.find((x) => x.name === name);
            if (c) return [{ name, from: c.from.join(", "), to: c.to.join(", ") }];
            const gone = d.removed.find((x) => x.name === name);
            return gone ? [{ name, from: gone.versions.join(", "), to: "" }] : [];
          }),
          youngest: y && y.ageHours !== null ? { name: y.name, version: y.version, ageHours: y.ageHours } : null,
        }
      : null,
    proof: r.proof ? { jobUrl: r.proof.job.jobUrl, runUrl: r.proof.run.url, twins: r.proof.twins, at: r.proof.at } : null,
    why: r.why,
  };
}

/** Newest first. A dry run that was never pushed is left out once a later fix of the same repo has a pull request. */
export function fixRows(records: FixRecord[]): FixRow[] {
  const pushed = new Set(records.filter((r) => r.pr).map((r) => r.repo));
  return records
    .filter((r) => !(r.status === "proposed" && !r.pr && pushed.has(r.repo)))
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .map(fixRow);
}
