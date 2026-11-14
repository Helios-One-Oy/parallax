// The fix record, the brief the agent gets, the gate a change must pass, and the texts written to the pull request.
import type { Advisory, Scope, Severity } from "./advisories.ts";
import { SEVERITIES, countBySeverity } from "./advisories.ts";
import type { LockDiff } from "./lockfile.ts";
import type { Age } from "./sources.ts";

export type Target = Advisory & { fixedIn: string | null; direct: boolean };

export type Change = {
  diff: LockDiff;
  /** Changed files outside package.json and package-lock.json. */
  outside: string[];
  newRegistries: string[];
  /** Publish time of every version the fix brings in, youngest first. */
  ages: Age[];
  /** Packages the fix adds or changes that run a script at install. */
  installScripts: string[];
};

export type JobPoint = { branch: string; commitSha: string; runId: string; jobId: string; jobName: string; jobUrl: string };

export type Proof = {
  at: string;
  job: JobPoint;
  run: { url: string; conclusion: string | null };
  /** Conclusion of each job of the run, by job name. */
  jobs: Record<string, string | null>;
  /** The twins' verdict, read from the verdict job. null = the run has no verdict job or it did not finish. */
  twins: "clean" | "blocked" | null;
  cleared: Advisory[];
  remaining: Advisory[];
  introduced: Advisory[];
  after: Record<Severity, number>;
};

export type FixStatus = "nothing-to-fix" | "agent-failed" | "no-change" | "refused" | "proposed" | "proven" | "partly-proven" | "not-proven";

export type FixRecord = {
  id: string;
  repo: string;
  createdAt: string;
  scope: Scope;
  /** No version younger than this may come in. */
  minAgeHours: number;
  base: JobPoint;
  /** Every advisory CRACI lists for the base job, by severity. */
  before: Record<Severity, number>;
  targeted: Target[];
  /** True when the brief quoted the prompt copied from the CRACI job page. */
  craciPrompt: boolean;
  agent: { model: string; turns: number; seconds: number; report: string } | null;
  change: Change | null;
  status: FixStatus;
  why: string[];
  pr: { number: number; url: string; branch: string } | null;
  proof: Proof | null;
};

export const DEFAULT_MIN_AGE_HOURS = 72;

// ---------- the brief ----------

export function buildBrief(o: {
  repo: string;
  job: JobPoint;
  targets: Target[];
  minAgeHours: number;
  /** The prompt copied from "Copy fix prompt" on the CRACI job page, verbatim. */
  craciPrompt?: string | null;
}): string {
  const list = o.targets
    .map(
      (t) =>
        `- ${t.package} ${t.version} [${t.direct ? "direct" : "transitive"}] — ${t.id} (${t.severity}): ${t.title || "no title"} — ` +
        `${t.fixedIn ? `fixed in ${t.fixedIn} by the advisory record` : "the advisory record names no fixed version"} — ${t.url}`,
    )
    .join("\n");
  const rules = [
    "Change only package.json and package-lock.json. No source, test, build or workflow file.",
    'Change the lockfile with npm only: `npm update <pkg>`, `npm install <pkg>@<version>`, or an "overrides" entry in package.json followed by `npm install`. npm is set to write the lockfile only and to never run package scripts. Leave those settings alone.',
    "Use canonical sources, not memory: `npm view <pkg> versions --json`, `npm view <pkg> time --json`, `npm audit --json`, `npm explain <pkg>`.",
    `Never choose a version published less than ${o.minAgeHours} hours ago (read \`npm view <pkg> time --json\`). A release that young has not been looked at by anyone yet.`,
    "Prefer the lowest version that clears every advisory listed for a package. For a transitive package, move the direct dependency that pulls it in if one of its releases does that; use \"overrides\" only when none does.",
    "Add no new direct dependency and do not change where packages are downloaded from.",
    "If clearing an advisory needs a new major version of a direct dependency, take it only when the way this code base uses the package is not touched by that major's breaking changes. Read the code that uses it and say what you based that on. Otherwise leave it and say why.",
  ];
  const answer = [
    "One markdown table, one row per package:\n| Package | Installed | Now | Advisories | How | Reachable from this code | Risk |",
    '"Left alone:" every listed advisory you did not clear, with the reason.',
    '"Could not determine:" anything you could not establish from the sources.',
  ];
  const head = o.craciPrompt
    ? [
        "This is the fix prompt CRACI gives for this job (copied from the CRACI job page):",
        "",
        "<craci_fix_prompt>",
        o.craciPrompt.trim(),
        "</craci_fix_prompt>",
        "",
        "The user has read it and decided: do that audit, then apply it yourself in the repository in the current directory, under the rules below. Where the rules below differ from the prompt above, the rules below win.",
      ]
    : ["Fix known-vulnerable dependencies in the repository in the current directory (npm)."];
  return [
    ...head,
    "",
    `The list comes from the bill of materials CRACI recorded for the job "${o.job.jobName}" of ${o.repo} at commit ${o.job.commitSha.slice(0, 12)}, with the fixed version from each advisory's own record:`,
    "",
    list,
    "",
    "Make the smallest change that clears them.",
    "",
    "Rules:",
    ...rules.map((r, i) => `${i + 1}. ${r}`),
    "",
    "Your work will be built twice on CRACI runners and compared, and the bill of materials of that build decides which advisories are counted as cleared. Nothing you write in the answer is taken on trust.",
    "",
    "When you are done, answer with exactly this and nothing else:",
    ...answer.map((a, i) => `${i + 1}. ${a}`),
  ].join("\n");
}

// ---------- the gate ----------

/** Reasons a change may not be proposed (empty = it may), and things worth a line in the pull request. */
export function judgeChange(c: Change, minAgeHours: number): { refuse: string[]; notes: string[] } {
  const refuse: string[] = [];
  const notes: string[] = [];
  if (c.outside.length) refuse.push(`The agent changed files a dependency fix may not touch: ${c.outside.join(", ")}.`);
  if (c.newRegistries.length) refuse.push(`The lockfile would download packages from a host it did not use before: ${c.newRegistries.join(", ")}.`);
  const young = c.ages.filter((a) => a.ageHours !== null && a.ageHours < minAgeHours);
  if (young.length) {
    refuse.push(
      `${young.length === 1 ? "A version is" : "Versions are"} younger than ${minAgeHours} hours: ` +
        young.map((a) => `${a.name}@${a.version} (${a.ageHours} h)`).join(", ") +
        ".",
    );
  }
  const unknown = c.ages.filter((a) => a.ageHours === null);
  if (unknown.length) notes.push(`Publish time not found for ${unknown.map((a) => `${a.name}@${a.version}`).join(", ")}.`);
  if (c.installScripts.length) notes.push(`Runs a script at install: ${c.installScripts.join(", ")}.`);
  return { refuse, notes };
}

// ---------- texts ----------

const countsLine = (c: Record<Severity, number>) =>
  SEVERITIES.filter((s) => c[s] > 0)
    .map((s) => `${c[s]} ${s}`)
    .join(", ") || "none";

const cell = (s: string) => s.replaceAll("|", "\\|").replaceAll("\n", " ");

function ageText(h: number | null): string {
  if (h === null) return "";
  return h < 48 ? `${h} h` : `${Math.round(h / 24)} days`;
}

export function youngest(ages: Age[]): Age | null {
  const known = ages.filter((a) => a.ageHours !== null).sort((a, b) => a.ageHours! - b.ageHours!);
  return known[0] ?? null;
}

export function renderPrBody(r: FixRecord, notes: string[] = []): string {
  const lines: string[] = [];
  lines.push(
    `CRACI's bill of materials for [${r.base.jobName}](${r.base.jobUrl}) at \`${r.base.commitSha.slice(0, 7)}\` lists ${countsLine(r.before)} known advisories. ` +
      `This pull request goes after the ${r.targeted.length} ${r.scope === "high" ? "critical and high" : "listed"} ones.`,
    "",
    "| Package | Installed | Advisory | Severity | Fixed in (advisory record) |",
    "|---|---|---|---|---|",
    ...r.targeted.map(
      (t) => `| ${cell(t.package)} | ${t.version} | [${t.id}](${t.url}) ${cell(t.title)} | ${t.severity} | ${t.fixedIn ?? ""} |`,
    ),
    "",
  );
  if (r.change) {
    const d = r.change.diff;
    const y = youngest(r.change.ages);
    lines.push(
      "### What changed",
      "",
      `${d.changed.length} packages change version, ${d.added.length} are new, ${d.removed.length} go away. Only \`package.json\` and \`package-lock.json\` are touched, and every package still comes from the registries the lockfile used before.` +
        (y ? ` The youngest version brought in is ${y.name}@${y.version}, published ${ageText(y.ageHours)} ago.` : ""),
      "",
    );
    if (d.changed.length) {
      // The packages the advisories are about first; the long tail folded away.
      const named = new Set(r.targeted.map((t) => t.package));
      const row = (c: LockDiff["changed"][number]) => `| ${cell(c.name)} | ${c.from.join(", ")} | ${c.to.join(", ")} |`;
      const head = d.changed.filter((c) => named.has(c.name));
      const rest = d.changed.filter((c) => !named.has(c.name));
      if (head.length) lines.push("| Package | Before | After |", "|---|---|---|", ...head.map(row), "");
      if (rest.length) {
        lines.push(
          "<details>",
          `<summary>${head.length ? `${rest.length} more that moved with them` : `${rest.length} packages`}</summary>`,
          "",
          "| Package | Before | After |",
          "|---|---|---|",
          ...rest.map(row),
          "",
          "</details>",
          "",
        );
      }
    }
    if (d.added.length) lines.push(`New: ${d.added.map((a) => `${a.name}@${a.versions.join(", ")}`).join(", ")}`, "");
    if (d.removed.length) lines.push(`Gone: ${d.removed.map((a) => a.name).join(", ")}`, "");
    for (const n of notes) lines.push(n, "");
  }
  if (r.agent) {
    lines.push(
      "### The agent's own account",
      "",
      `Written by ${r.agent.model}${r.craciPrompt ? " from CRACI's fix prompt for this job" : ""} in ${r.agent.seconds} s. It could only edit \`package.json\` and run npm against the lockfile, with install scripts off.`,
      "",
      r.agent.report.trim(),
      "",
    );
  }
  lines.push(
    "### Not taken on trust",
    "",
    "A dependency change written by an agent is how a hijacked release gets installed fastest. So this one is built like any other change: twice on CRACI runners, one twin dressed as a release. Parallax then compares the bill of materials of that build with the one above and comments here with what is really cleared.",
    "",
    "🤖 Generated with [Claude Code](https://claude.com/claude-code)",
  );
  return lines.join("\n");
}

export function renderProof(r: FixRecord): string {
  const p = r.proof;
  if (!p) return "";
  const lines: string[] = [];
  const targeted = new Set(r.targeted.map((t) => `${t.id} ${t.package}`));
  const hit = p.cleared.filter((a) => targeted.has(`${a.id} ${a.package}`));
  const missed = p.remaining.filter((a) => targeted.has(`${a.id} ${a.package}`));
  const twinsLine = p.twins === "clean" ? " and the twins found nothing" : "";
  const headline =
    r.status === "proven"
      ? `**Proven.** ${hit.length} of ${r.targeted.length} targeted advisories are gone from the build${twinsLine}.`
      : r.status === "partly-proven"
        ? `**Proven for ${hit.length} of ${r.targeted.length}.** Those are gone from the build${twinsLine}. ${missed.length} ${missed.length === 1 ? "is" : "are"} still in it.`
        : `**Not proven.** ${hit.length} of ${r.targeted.length} targeted advisories are gone from the build.`;
  lines.push(
    headline,
    "",
    `Measured on [${p.job.jobName}](${p.job.jobUrl}) of [this run](${p.run.url}), against [${r.base.jobName}](${r.base.jobUrl}) on \`${r.base.branch}\`. Both lists are CRACI's bill of materials of the job, not the agent's claim.`,
    "",
    "| | Before | After |",
    "|---|---|---|",
    ...SEVERITIES.filter((s) => r.before[s] || p.after[s]).map((s) => `| ${s} | ${r.before[s]} | ${p.after[s]} |`),
    "",
    `- Twins: ${p.twins === "clean" ? "both builds made the same connections" : p.twins === "blocked" ? "the verdict blocked this build" : "no verdict for this run"}`,
    ...Object.entries(p.jobs).map(([name, c]) => `- ${name}: ${c ?? "not finished"}`),
  );
  if (r.status === "not-proven" && r.why.length) lines.push("", "Why not:", ...r.why.map((w) => `- ${w}`));
  if (missed.length) lines.push("", "Still in the build:", ...missed.map((a) => `- ${a.package} ${a.version}: [${a.id}](${a.url}) (${a.severity})`));
  if (p.introduced.length) lines.push("", "New with this change:", ...p.introduced.map((a) => `- ${a.package} ${a.version}: [${a.id}](${a.url}) (${a.severity})`));
  return lines.join("\n");
}

/**
 * proven = every targeted advisory is gone, nothing as bad came in, the build passed and the twins agree.
 * partly-proven = the same, but some targeted advisories are still in the build (and at least one is gone).
 */
export function judgeProof(r: FixRecord, p: Proof): { status: "proven" | "partly-proven" | "not-proven"; why: string[] } {
  const why: string[] = [];
  const targeted = new Set(r.targeted.map((t) => `${t.id} ${t.package}`));
  const missed = p.remaining.filter((a) => targeted.has(`${a.id} ${a.package}`));
  const bad = p.introduced.filter((a) => a.severity === "critical" || a.severity === "high");
  if (bad.length) why.push(`The change brings in ${bad.length} new critical or high ${bad.length === 1 ? "advisory" : "advisories"}.`);
  if (p.twins === "blocked") why.push("The twins did not agree.");
  if (p.twins === null) why.push("There is no twin verdict for this run.");
  const failed = Object.entries(p.jobs).filter(([, c]) => c !== "success" && c !== "skipped");
  if (failed.length) why.push(`Jobs that did not pass: ${failed.map(([n, c]) => `${n} (${c ?? "not finished"})`).join(", ")}.`);
  const sound = why.length === 0;
  if (missed.length) why.unshift(`${missed.length} targeted ${missed.length === 1 ? "advisory is" : "advisories are"} still in the build.`);
  if (sound && !missed.length) return { status: "proven", why };
  if (sound && missed.length < r.targeted.length) return { status: "partly-proven", why };
  return { status: "not-proven", why };
}

export { countBySeverity };
