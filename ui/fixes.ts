// The Fixes view of the console. Plain strings, same helpers as the rest of the UI.
import type { FixRow } from "../src/fix/view.ts";

type Helpers = { esc: (s: unknown) => string; ext: (url: string | null | undefined, label: string) => string; ago: (iso: string | null | undefined) => string };

const STATUS_WORDS: Record<FixRow["status"], string> = {
  "nothing-to-fix": "nothing to fix",
  "agent-failed": "agent failed",
  "no-change": "no change",
  refused: "refused",
  proposed: "waiting for its build",
  proven: "proven",
  "partly-proven": "proven in part",
  "not-proven": "not proven",
};
const OUTCOME_WORDS = { gone: "gone from the build", still_there: "still in the build", not_measured: "not measured yet" } as const;

function age(h: number): string {
  return h < 48 ? `${h} hours` : `${Math.round(h / 24)} days`;
}

function fixHtml(f: FixRow, { esc, ext, ago }: Helpers): string {
  const counts = f.counts.length
    ? `<table class="fix-counts"><thead><tr><th>Known advisories</th><th>Before</th><th>After</th></tr></thead><tbody>${f.counts
        .map((c) => `<tr><td>${esc(c.severity)}</td><td>${c.before}</td><td>${c.after === null ? "" : c.after}</td></tr>`)
        .join("")}</tbody></table>`
    : "";
  const advisories = f.advisories
    .map(
      (a) => `<li>
        <span class="chip fix-${a.outcome}">${OUTCOME_WORDS[a.outcome]}</span>
        <span class="what"><b class="mono">${esc(a.package)} ${esc(a.version)}</b> <span class="meta">${esc(a.severity)}${a.fixedIn ? ` · fixed in ${esc(a.fixedIn)} by the advisory record` : ""}</span>
        <span class="title">${esc(a.title)}</span>
        <span class="meta">${ext(a.url, a.id)}</span></span>
      </li>`,
    )
    .join("");
  const c = f.change;
  const change = c
    ? `<p class="fix-change">${c.moved.map((m) => `<span class="mono">${esc(m.name)} ${esc(m.from)} → ${m.to ? esc(m.to) : "removed"}</span>`).join(" ")}</p>
       <p class="meta">${c.changed} packages change version, ${c.added} new, ${c.removed} gone. Only the manifest and the lockfile were touched, no new download host.${
         c.youngest ? ` Youngest version brought in: ${esc(c.youngest.name)}@${esc(c.youngest.version)}, ${age(c.youngest.ageHours)} old.` : ""
       }</p>`
    : "";
  const twins = !f.proof ? "" : f.proof.twins === "clean" ? "The twins made the same connections." : f.proof.twins === "blocked" ? "The twins did not agree: blocked." : "No twin verdict for its build.";
  const links = [
    f.pr ? ext(f.pr.url, `PR #${f.pr.number}`) : "",
    ext(f.base.jobUrl, `before: ${f.base.jobName} @ ${f.base.commit.slice(0, 7)}`),
    f.proof ? ext(f.proof.jobUrl, "after: the fix's own build") : "",
  ]
    .filter(Boolean)
    .join("");
  const by = f.agent ? `Written by ${esc(f.agent.model)} in ${f.agent.seconds} s${f.craciPrompt ? ", from CRACI's fix prompt for the job" : ""}.` : "";
  return `<article class="fix">
    <header>
      <span class="chip fix-${esc(f.status)}">${STATUS_WORDS[f.status]}</span>
      <h2>${esc(f.headline)}</h2>
      <p class="meta">${esc(f.repo)} · ${esc(ago(f.createdAt))} · ${by} ${esc(twins)}</p>
    </header>
    <div class="fix-body">
      <div>${f.advisories.length ? `<ul class="rows fix-adv">${advisories}</ul>` : ""}${change}${f.why.length && f.status !== "partly-proven" ? `<ul class="fix-why">${f.why.map((w) => `<li>${esc(w)}</li>`).join("")}</ul>` : ""}</div>
      <div>${counts}<p class="links">${links}</p></div>
    </div>
  </article>`;
}

export function fixesHtml(rows: FixRow[], h: Helpers): string {
  return `<h1 class="plain">Fixes that have to prove themselves</h1>
    <p class="lead">CRACI lists the known advisories of every job and writes a fix prompt for them. Parallax hands that prompt to an agent, and then does not believe the agent: its change must pass a gate (only the manifest and lockfile, no new download host, no release younger than 72 hours), the twins build it like any other change, and the bill of materials of that build decides what is really gone.</p>
    ${rows.length ? rows.map((r) => fixHtml(r, h)).join("") : `<p class="empty">No fix has been proposed yet.</p>`}`;
}
