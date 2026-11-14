// Parallax console, browser side. Plain TypeScript, no framework. Everything shown comes from /api/*.
import type { FleetView, ReplayRow, RingsView, RunRow, RunView, Seed, TwinJob, TwinRow } from "../src/console/views.ts";
import type { FixRow } from "../src/fix/view.ts";
import { fixesHtml } from "./fixes.ts";

type State = {
  config: { mode: "box" | "public"; fixture: boolean; allowFence: boolean; liveLogs: boolean };
  lastContact: string | null;
  fleet: FleetView;
  replays: ReplayRow[];
  fixes?: FixRow[];
};
type RunPayload = RunView & { liveLogs: boolean };
type RingsPayload = (RingsView & { allowFence: boolean }) | { seed: ""; rings: null; suggestions: Seed[]; jobs: number; allowFence: boolean };

const main = document.getElementById("main")!;
const fresh = document.getElementById("fresh")!;

// ---------- small helpers ----------

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const short = (sha: string) => sha.slice(0, 7);

function ago(iso: string | null | undefined): string {
  if (!iso) return "";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (!Number.isFinite(s)) return "";
  if (s < 5) return "just now";
  if (s < 90) return `${s} s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short" });
}

function duration(sec: number | null): string {
  if (sec === null) return "";
  if (sec < 90) return `${sec} s`;
  return `${Math.floor(sec / 60)} min ${String(sec % 60).padStart(2, "0")} s`;
}

/** Only links to GitHub leave the page; anything else from the data is shown as text. */
const safeUrl = (u: string | null | undefined) => (u && /^https:\/\/github\.com\//.test(u) ? u : null);
const ext = (u: string | null | undefined, label: string) => {
  const s = safeUrl(u);
  return s ? `<a href="${esc(s)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>` : esc(label);
};
const runHref = (repo: string, runId: string) => `#/run/${repo}/${runId}`;
const ringsHref = (seed: string) => `#/rings?seed=${encodeURIComponent(seed)}`;

const VERDICT_WORDS: Record<string, string> = { clean: "clean", divergent: "divergent", inconclusive: "inconclusive" };

/** The twin verdict of a run, then one label per other detector that found something in it. */
function runChip(r: RunRow): string {
  const others = (r.caughtBy ?? []).filter((o) => o !== "twins").map((o) => `<span class="chip organ">${esc(o)}</span>`).join("");
  if (r.falseAlarm) return `<span class="chip inconclusive">false alarm</span>`;
  // "clean" beside a detector's name reads as a contradiction: the twins agreed, something else caught the run.
  if (r.verdict === "clean" && others) return `${others}<span class="chip none">twins agree</span>`;
  if (r.verdict) return `<span class="chip ${r.verdict}">${VERDICT_WORDS[r.verdict]}</span>${others}`;
  if (r.live || (r.status && r.status !== "completed")) return `<span class="chip running">running</span>${others}`;
  if (others) return others;
  return `<span class="chip none">${r.hasTwins ? "no verdict yet" : "no twins"}</span>`;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: { accept: "application/json" } });
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error(body?.error ?? `The server answered ${res.status}.`);
  return body as T;
}

// ---------- state polling ----------

let state: State | null = null;
let stateTag = "";
let stateError: string | null = null;
let lastOk = 0;

async function pollState(): Promise<boolean> {
  try {
    const res = await fetch("/api/state", { headers: stateTag ? { "if-none-match": stateTag } : {} });
    lastOk = Date.now();
    stateError = null;
    if (res.status === 304) return false;
    if (!res.ok) throw new Error(`The server answered ${res.status}.`);
    stateTag = res.headers.get("etag") ?? "";
    state = (await res.json()) as State;
    return true;
  } catch (e) {
    stateError = e instanceof Error ? e.message : String(e);
    return false;
  }
}

function paintFresh() {
  if (!state) {
    fresh.textContent = stateError ? "Cannot reach the console server." : "";
    fresh.className = `fresh${stateError ? " stale" : ""}`;
    return;
  }
  const down = stateError && Date.now() - lastOk > 15000;
  const pub = state.config.mode === "public";
  const at = pub ? state.lastContact : state.fleet.generatedAt;
  const age = at ? (Date.now() - Date.parse(at)) / 1000 : Infinity;
  let text: string;
  if (down) text = "Cannot reach the console server.";
  else if (!at) text = pub ? "Waiting for the first report from the build box." : "";
  else if (pub) text = `Build box reported ${ago(at)}`;
  else text = `Read ${ago(at)}`;
  fresh.textContent = text;
  fresh.className = `fresh${down || (pub && at && age > 120) ? " stale" : ""}`;
}

// ---------- fleet ----------

function runRow(r: RunRow, withRepo = false): string {
  const meta = [withRepo ? r.repo.split("/")[1] : "", r.branch, r.sha ? short(r.sha) : "", r.event.replace(/_/g, " "), r.pr ? `PR #${r.pr.number}` : "", r.gone ? "deleted on GitHub" : ""].filter(Boolean).join(" · ");
  const inner = `<span class="chips">${runChip(r)}</span>
    <span class="what"><span class="title">${esc(r.title || r.workflow || `Run ${r.runId}`)}</span><span class="meta">${esc(meta)}</span></span>
    <span class="when">${esc(ago(r.startedAt))}</span>`;
  return `<li><a class="run" href="${esc(runHref(r.repo, r.runId))}">${inner}</a></li>`;
}

function alertBlock(title: string, about: string, items: string[], traced: number): string {
  const n = items.length;
  const empty = traced === 0 ? "Nothing to check yet: no job of the fleet has a CRACI trace." : `None in ${plural(traced, "traced job")}.`;
  return `<div class="alert">
    <h3>${esc(title)} <span class="n${n ? " hot" : ""}">${n}</span></h3>
    <p class="about">${esc(about)}</p>
    ${n ? `<ul class="rows">${items.join("")}</ul>` : `<p class="empty">${esc(empty)}</p>`}
  </div>`;
}

function fleetHtml(s: State): string {
  const f = s.fleet;
  const a = f.alerts;
  const runLink = (repo: string, runId: string) => (runId ? `<a href="${esc(runHref(repo, runId))}">run ${esc(runId)}</a>` : "");
  const active = f.active.length
    ? `<ul class="rows">${f.active
        .map(
          (j) => `<li><a class="run" href="${esc(runHref(j.repo, j.runId))}">
            <span class="chips"><span class="chip running">${esc(j.status || "running")}</span></span>
            <span class="what"><span class="title">${esc(j.name)}</span><span class="meta">${esc([j.repo, j.branch, `run ${j.runId}`].filter(Boolean).join(" · "))}</span></span>
            <span class="when">${esc(ago(j.startedAt))}</span></a></li>`,
        )
        .join("")}</ul>`
    : `<p class="empty">${f.activeAt ? "No CRACI job of the fleet is running right now." : "Running jobs have not been read from CRACI yet."}</p>`;

  const repos = f.repos
    .map(
      (r) => `<div class="repo">
        <h3>${ext(r.url, r.repo)} <span class="n">${r.totalRuns ? plural(r.totalRuns, "run") : ""}</span></h3>
        ${r.error ? `<p class="hint err">GitHub could not be read for this repo: ${esc(r.error.slice(0, 160))}</p>` : ""}
        ${r.runs.length ? `<ul class="rows">${r.runs.map((x) => runRow(x)).join("")}</ul>` : `<p class="empty">No runs yet.</p>`}
      </div>`,
    )
    .join("");

  // The same host or cache in several jobs and runs is one line; the list is newest first, so the first one stands for the group.
  const group = <T,>(list: T[], key: (x: T) => string): T[][] => {
    const m = new Map<string, T[]>();
    for (const x of list) m.set(key(x), [...(m.get(key(x)) ?? []), x]);
    return [...m.values()];
  };
  const across = (g: Array<{ runId: string }>) => {
    const runs = new Set(g.map((x) => x.runId)).size;
    return g.length > 1 ? `${plural(g.length, "job")} in ${plural(runs, "run")}` : "";
  };
  const egress = group(a.egress, (e) => `${e.repo}\n${e.hosts.join()}`).map((g) => {
    const e = g[0]!;
    return `<li><span class="mono">${esc(e.hosts.join(", "))}</span><br><span class="meta">${[esc(e.repo), g.length > 1 ? across(g) : `job "${esc(e.name)}"`, runLink(e.repo, e.runId), `<a href="${esc(ringsHref(e.hosts[0]!))}">trace it</a>`].join(" · ")}</span></li>`;
  });
  const lineage = group(a.lineage, (e) => `${e.repo}\n${e.cacheKey}`).map((g) => {
    const e = g[0]!;
    return `<li>${esc(e.why)}<br><span class="meta">${[across(g), runLink(e.repo, e.runId), `<a href="${esc(ringsHref(e.seed))}">trace the cache</a>`].filter(Boolean).join(" · ")}</span></li>`;
  });
  const drift = a.drift.map((d) => {
    const last = d.versions[d.versions.length - 1]!;
    return `<li><span class="mono">${esc(d.url)}</span><br><span class="meta">${d.versions.length} different contents; the newest (${esc(last.sha256.slice(0, 12))}…) first seen in ${runLink(last.repo, last.runId)} · <a href="${esc(ringsHref(`sha256:${last.sha256}`))}">trace these bytes</a></span></li>`;
  });
  const images = a.images.map((e) => `<li>${esc(e.why)}<br><span class="meta">${esc(e.repo)} · ${runLink(e.repo, e.runId)}</span></li>`);
  const notFound = a.notFound.map((e) => `<li><span class="mono">${esc(e.registry)} ${esc(e.name)}</span><br><span class="meta">asked by ${plural(e.jobs, "job")} in ${esc(e.repos.join(", "))}${e.runs[0] ? ` · ${runLink(e.runs[0].repo, e.runs[0].runId)}` : ""}</span></li>`);

  return `
    <h1>Every build runs twice. A connection only one run makes stops the release.</h1>
    <p class="lead">One twin is bare. The other is dressed as a release and carries fake credentials. CRACI records every connection both make. Code that waits for a release shows itself in the decoy only.</p>
    <div class="how" aria-hidden="true">
      <div class="tw">
        <div class="node"><b>Bare twin</b><span>the plain build</span></div>
        <div class="node"><b>Decoy twin</b><span>looks like a release, fake tokens</span></div>
      </div>
      <div class="wire"></div>
      <div class="node"><b>CRACI trace</b><span>every connection of both</span></div>
      <div class="wire"></div>
      <div class="node gate"><b>Release job</b><span>starts only if the twins agree</span></div>
    </div>

    ${
      f.stopped?.length
        ? `<section aria-labelledby="h-stopped">
      <h2 id="h-stopped">Stopped <span class="n">${f.stopped.length}</span></h2>
      <p class="hint">Runs whose verdict job failed, so the release never started. The twins first. Open one to see what gave it away.${
        f.twins?.runs
          ? ` The twins have judged ${plural(f.twins.runs, "build")}: ${f.twins.clean} clean, ${f.twins.caught} caught${f.twins.inconclusive ? `, ${f.twins.inconclusive} inconclusive` : ""}${
              f.twins.falseAlarms.length ? `, ${f.twins.falseAlarms.map((x) => `<a href="${esc(runHref(x.repo, x.runId))}">${f.twins.falseAlarms.length} false alarm${f.twins.falseAlarms.length === 1 ? "" : "s"}</a>`)[0]}` : ""
            }.`
          : ""
      }</p>
      <ul class="rows">${f.stopped.map((r) => runRow(r, true)).join("")}</ul>
    </section>`
        : ""
    }

    <section aria-labelledby="h-now">
      <h2 id="h-now">Running on CRACI now <span class="n">${f.active.length || ""}</span></h2>
      ${active}
    </section>

    <section aria-labelledby="h-fleet">
      <h2 id="h-fleet">Fleet <span class="n">${plural(f.repos.length, "repo")}, ${plural(f.counts.traced, "traced job")}, ${plural(f.counts.verdicts, "verdict")}</span></h2>
      <ul class="legend" aria-label="What the labels mean">
        <li><span class="chip clean">clean</span> both twins made the same connections</li>
        <li><span class="chip divergent">divergent</span> one twin did something the other did not</li>
        <li><span class="chip inconclusive">inconclusive</span> the twins could not be compared</li>
        <li><span class="chip organ">new egress</span> another detector found something in the run (named on the label)</li>
        <li><span class="chip none">no verdict yet</span></li>
      </ul>
      <div class="repos">${repos || `<p class="empty">The fleet list is empty.</p>`}</div>
    </section>

    <section aria-labelledby="h-alerts">
      <h2 id="h-alerts">What the whole fleet shows</h2>
      <div class="alerts">
        ${alertBlock("New egress", "A job contacted a host that no earlier job of its repo had. Judged once a repo has three earlier runs. A new registry mirror shows up here just like an attacker's host: the list is for a person to read.", egress, a.jobs)}
        ${alertBlock("Cache lineage", "A trusted job restored a cache that a job anyone can trigger wrote.", lineage, a.jobs)}
        ${alertBlock("Same URL, new bytes", "A URL that should not change returned different content than before.", drift, a.jobs)}
        ${alertBlock("Image provenance", "A job pulled one of our own images and got bytes none of our jobs produced.", images, a.jobs)}
        ${alertBlock("Registry 404", "An install asked a registry for a package name that does not exist.", notFound, a.jobs)}
      </div>
    </section>`;
}

// ---------- run (twin view) ----------

const JOB_WORDS: Record<string, string> = {
  success: "passed", failure: "failed", skipped: "did not start", cancelled: "cancelled", in_progress: "running", queued: "queued", waiting: "waiting", completed: "finished", pending: "queued",
};

function pipeHtml(v: RunPayload): string {
  const state = (j: { status: string; conclusion: string | null }) => (j.status === "completed" ? (j.conclusion ?? "completed") : j.status);
  const box = (name: string, j: { status: string; conclusion: string | null; url: string } | null, offWords: string) => {
    if (!j) return `<div class="job off"><b>${esc(name)}</b><span>${esc(offWords)}</span></div>`;
    const st = state(j);
    const off = st === "skipped" || st === "cancelled";
    const url = safeUrl(j.url);
    const inner = `<b>${esc(name)}</b><span>${esc(JOB_WORDS[st] ?? st)}</span>`;
    return url ? `<a class="job ${esc(st)}${off ? " off" : ""}" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${inner}</a>` : `<div class="job ${esc(st)}${off ? " off" : ""}">${inner}</div>`;
  };
  const find = (re: RegExp) => v.jobs.find((j) => re.test(j.name)) ?? null;
  const bare = find(/\(bare\)\s*$/);
  const decoy = find(/\(decoy\)\s*$/);
  const verdict = find(/^verdict\b/i);
  return `<div class="pipe" aria-label="Jobs of this run, as GitHub reports them">
      ${box("build (bare)", bare, "not seen")}${box("build (decoy)", decoy, "not seen")}
      <span class="sep"></span>${box("verdict", verdict, "not started")}
      <span class="sep"></span>${box("release", v.gate.job, v.gate.state === "none" ? "not in this run" : v.gate.state === "unknown" ? "not read yet" : "not started")}
    </div>
    <p class="gate-line">${esc(v.gate.sentence)}</p>`;
}

function connRow(r: TwinRow): string {
  const cell = (c: TwinRow["bare"], side: string) =>
    c ? `<span class="cell has ${side}">${esc(r.key)}${c.count > 1 ? `<span class="x">×${c.count}</span>` : ""}${c.denied ? `<span class="x">blocked</span>` : ""}</span>` : `<span class="cell ${side}"></span>`;
  const why = r.state === "divergent" ? `<p class="why">${esc(r.why)}</p>` : r.state === "alone" && r.note ? `<p class="why">${esc(r.note)}</p>` : "";
  const tag = r.state === "divergent" && r.novel ? `<span class="tag">new in the fleet</span>` : "";
  return `<li class="conn ${r.state}">${cell(r.bare, "bare")}${cell(r.decoy, "decoy")}<span class="one">${esc(r.key)}${tag}</span>${why}</li>`;
}

function verdictHtml(v: RunPayload): string {
  const x = v.verdict;
  const running = !!(v.twins.bare?.running || v.twins.decoy?.running);
  if (!x) {
    const kept = (v.solo ?? []).reduce((n, j) => n + j.keys.length, 0);
    if (!running && !v.run.hasTwins && kept) {
      const text = v.run.gone
        ? `GitHub no longer has this run. CRACI still holds the ${plural(kept, "connection")} it made.`
        : `This run has no twin jobs, so there is no verdict. CRACI recorded the ${plural(kept, "connection")} it made.`;
      return `<div class="verdict"><span class="chip ${v.run.gone ? "caught" : "none"}">${v.run.gone ? "kept by CRACI" : "no twins"}</span><div><p>${esc(text)}</p><p class="sub">They are listed below.</p></div></div>`;
    }
    const text = running ? "The twins are running. The verdict comes when both have finished." : v.run.hasTwins ? "No verdict yet for this run." : "This run has no twin jobs, so there is no verdict.";
    return `<div class="verdict"><span class="chip ${running ? "running" : "none"}">${running ? "running" : v.run.hasTwins ? "no verdict yet" : "no twins"}</span><div><p>${esc(text)}</p></div></div>`;
  }
  const n = x.divergences.length;
  const head =
    x.status === "divergent"
      ? `The twins diverged: ${plural(n, "thing")} only one of them did.`
      : x.status === "clean"
        ? "Both twins made the same connections."
        : "Parallax could not compare the twins.";
  const other = [...new Set(v.findings.filter((f) => f.fails).map((f) => f.organ))];
  const stop = other.length ? `<p class="stop">${x.status === "divergent" ? "Also caught by" : "Caught by"}: ${esc(other.join(", "))}. See below.</p>` : "";
  const alarm = v.run.falseAlarm ? `<p class="stop">${esc(v.run.falseAlarm)}</p>` : "";
  // The twins agreeing is not the whole verdict when another detector caught the run.
  const chip = v.run.falseAlarm
    ? `<span class="chip inconclusive">false alarm</span>`
    : x.status === "clean" && other.length
      ? `<span class="chip organ">caught</span>`
      : `<span class="chip ${x.status}">${VERDICT_WORDS[x.status]}</span>`;
  // The request itself belongs in the banner: in the table below it can sit a hundred lines down.
  const lone = v.rows.filter((r) => r.state === "divergent");
  const only =
    lone
      .slice(0, 4)
      .map((r) => `<p class="only">${r.decoy && !r.bare ? "Only the decoy twin: " : r.bare && !r.decoy ? "Only the bare twin: " : ""}<span class="mono">${esc(r.key)}</span></p>`)
      .join("") + (lone.length > 4 ? `<p class="only">and ${lone.length - 4} more, in red below.</p>` : "");
  const sub = `${x.stats.shared} seen in both, bare ${x.stats.bare}, decoy ${x.stats.decoy}. ${x.ignored.count} ignored as noise${x.ignored.rules.length ? ` (${x.ignored.rules.join(", ")})` : ""}. Judged ${ago(x.createdAt)}.`;
  return `<div class="verdict ${v.run.falseAlarm ? "" : x.status}">${chip}<div><p>${esc(head)}</p>${only}${alarm}${stop}<p class="sub">${esc(sub)}</p></div></div>`;
}

const CHECK_WORDS: Record<string, string> = { checked: "checked", too_little_history: "not judged", nothing_to_check: "nothing to check" };

/** What the detectors other than the twin diff found for any job of this run, and what each of them looked at. */
function findingsHtml(v: RunPayload): string {
  if (!v.findings.length && !v.checks.length) return "";
  const jobUrl = (id: string) => safeUrl(v.jobs.find((j) => j.id === id)?.url);
  const judged = v.jobs.some((j) => /^verdict\b/i.test(j.name));
  // The same finding in both twins (or in several jobs) is one entry that lists the jobs.
  const groups = new Map<string, typeof v.findings>();
  for (const f of v.findings) {
    const k = `${f.organ}\n${f.key}`;
    groups.set(k, [...(groups.get(k) ?? []), f]);
  }
  const items = [...groups.values()]
    .map((g) => {
      const f = g[0]!;
      const fails = g.some((x) => x.fails);
      const jobs = g.map((x) => { const url = jobUrl(x.jobId); return url ? ext(url, `job "${x.jobName}"`) : `job "${esc(x.jobName)}"`; }).join(", ");
      const seed = f.organ === "new egress" || f.organ === "registry 404" || f.organ === "same URL, new bytes" ? f.host : "";
      const more = g.length > 1 ? ` The same holds for ${g.length - 1} more job${g.length === 2 ? "" : "s"} of this run.` : "";
      return `<li class="finding${fails ? " fails" : ""}">
        <span class="chip organ">${esc(f.organ)}</span> <span class="mono">${esc(f.key)}</span>
        <p>${esc(f.why)}${more}</p>
        <p class="meta">${jobs} · ${fails ? (judged ? "stops the run" : "stops a run that has a verdict job; this one has none") : "reported only, does not stop the run"}${seed ? ` · <a href="${esc(ringsHref(seed))}">trace it</a>` : ""}</p>
        <p class="meta">Evidence: ${esc(f.evidence)}.</p>
        <p class="meta">Would a CRACI network policy have blocked it? ${esc((f.policy ?? "No. No network rule tells this apart from normal traffic.").replace(/`/g, ""))}</p>
      </li>`;
    })
    .join("");
  const checks = v.checks.map((c) => `<li><b>${esc(c.organ)}</b> <span class="state ${esc(c.state)}">${esc(CHECK_WORDS[c.state] ?? c.state)}</span> <span>${esc(c.note)}</span></li>`).join("");
  return `<section aria-labelledby="h-find"><h2 id="h-find">What the other detectors found <span class="n">${groups.size || ""}</span></h2>
    ${v.findings.length ? `<ul class="rows findings">${items}</ul>` : `<p class="empty">Nothing. Every job of this run was looked at, the release job too.</p>`}
    ${checks ? `<ul class="checks" aria-label="What each detector looked at">${checks}</ul>` : ""}
  </section>`;
}

function runHtml(v: RunPayload): string {
  const r = v.run;
  const meta = [
    esc(r.repo), esc(r.branch), r.sha ? `<span class="mono">${esc(short(r.sha))}</span>` : "", esc(r.event.replace(/_/g, " ")),
    r.pr ? ext(r.pr.url, `PR #${r.pr.number}`) : "", r.gone ? "deleted on GitHub" : ext(r.url, `run ${r.runId} on GitHub`),
  ].filter(Boolean).join(" · ");

  const div = v.rows.filter((x) => x.state === "divergent").length;
  let table: string;
  if (v.rows.length) {
    const lone = v.rows.filter((x) => x.state !== "shared");
    const fold = v.rows.length > 30;
    const first = fold && lone.length ? `<ol class="lone">${lone.map(connRow).join("")}</ol>` : "";
    const all = `<ol>${v.rows.map(connRow).join("")}</ol>`;
    table = `<div class="twins">
        <div class="head"><div><span class="full">Bare twin</span><span class="abbr">bare</span><span class="n">${v.sides.bare ? plural(v.sides.bare.observations, "observation") : ""}</span></div><div><span class="full">Decoy twin</span><span class="abbr">decoy</span><span class="n">${v.sides.decoy ? plural(v.sides.decoy.observations, "observation") : ""}</span></div><div class="one"></div></div>
        ${fold ? `${first}<details class="allconn"><summary>All ${plural(v.rows.length, "connection")}, in the order CRACI recorded them</summary>${all}</details>` : all}
      </div>
      <p class="after">${fold && lone.length ? "What only one twin did comes first. " : ""}Repeats are folded into one line. ${div ? "Red lines are what only one twin did." : ""}</p>`;
  } else if (v.solo?.length) {
    table = v.solo
      .map((j) => `<h3 class="solo">Job "${esc(j.name)}" <span class="n">${plural(j.keys.length, "connection")}</span></h3><ol class="solo">${j.keys.map((k) => `<li class="mono">${esc(k)}</li>`).join("")}</ol>`)
      .join("") + `<p class="after">From CRACI's network trace of the job${v.run.gone ? ", which outlives the run on GitHub" : ""}.</p>`;
  } else if (v.verdict) {
    const miss = [!v.sides.bare?.hasTrace ? "bare" : "", !v.sides.decoy?.hasTrace ? "decoy" : ""].filter(Boolean);
    table = `<p class="empty">${miss.length ? `CRACI has no network trace for the ${miss.join(" and ")} twin.` : "The traces hold no connections."}</p>`;
  } else {
    table = `<p class="empty">CRACI hands out a job's network trace when the job has finished. Nothing to compare yet.</p>`;
  }

  const pkgs = v.packages.length
    ? `<section><h2>Packages only one twin pulled in <span class="n">${v.packages.length}</span></h2><ul class="rows alert">${v.packages
        .map((d) => `<li><span class="mono">${esc(d.key)}</span><br>${esc(d.why)} <a href="${esc(ringsHref(d.key))}">trace it</a></li>`)
        .join("")}</ul></section>`
    : "";
  const seeds = v.seeds.length
    ? `<section><h2>Where did it spread?</h2><p class="hint">Start contact tracing from what this run did alone.</p><p class="sugg">${v.seeds.map((s) => `<a href="${esc(ringsHref(s.seed))}">${esc(s.label)}</a>`).join("")}</p></section>`
    : "";

  return `<a class="back" href="#/">Fleet</a>
    <h1 class="plain">${esc(r.title || `Run ${r.runId}`)}</h1>
    <p class="lead meta">${meta}</p>
    <div id="run-verdict">${verdictHtml(v)}</div>
    <div id="run-pipe">${v.solo?.length ? "" : pipeHtml(v)}</div>
    <div id="run-find">${findingsHtml(v)}</div>
    <section aria-labelledby="h-conn"><h2 id="h-conn">${v.solo?.length ? "Connections CRACI recorded" : "Connections of the two twins"} ${div ? `<span class="n">${plural(div, "divergent line")}</span>` : ""}</h2><div id="run-conn">${table}</div></section>
    <div id="run-pkgs">${pkgs}</div>
    <section aria-labelledby="h-logs"><h2 id="h-logs">Job logs</h2><div class="logs" id="run-logs"></div></section>
    <div id="run-seeds">${seeds}</div>`;
}

// ---------- log panes ----------

class LogPane {
  el: HTMLElement;
  pre: HTMLElement;
  st: HTMLElement;
  mode: "idle" | "live" | "done" | "wait" = "idle";
  abort: AbortController | null = null;
  lines = 0;
  tries = 0;
  hits: string[] = [];

  constructor(readonly repo: string, readonly which: string, public job: TwinJob) {
    this.el = document.createElement("div");
    this.el.className = "term";
    this.el.innerHTML = `<header><span>${esc(job.name)}</span><span class="st"></span></header><pre tabindex="0" aria-label="${esc(`Log of ${job.name}`)}"></pre>`;
    this.pre = this.el.querySelector("pre")!;
    this.st = this.el.querySelector(".st")!;
  }

  status(text: string, live = false) {
    this.st.textContent = text;
    this.st.className = `st${live ? " live" : ""}`;
  }
  note(text: string) {
    this.pre.innerHTML = `<span class="note">${esc(text)}</span>`;
    this.lines = 0;
  }

  append(raw: string) {
    if (!raw || raw === ":") return;
    const tab = raw.indexOf("\t");
    const ts = tab > 0 ? raw.slice(0, tab) : "";
    const text = (tab >= 0 ? raw.slice(tab + 1) : raw).replace(/\x1b\[[0-9;]*m/g, "");
    if (this.lines === 0) this.pre.textContent = "";
    const stick = this.pre.scrollTop + this.pre.clientHeight >= this.pre.scrollHeight - 30;
    const line = document.createElement("span");
    if (this.hits.some((h) => text.includes(h))) line.className = "hit";
    const t = /T(\d\d:\d\d:\d\d)/.exec(ts)?.[1];
    if (t) {
      const time = document.createElement("time");
      time.textContent = t;
      line.append(time);
    }
    line.append(text + "\n");
    this.pre.append(line);
    if (++this.lines > 4000) this.pre.firstChild?.remove();
    if (stick) this.pre.scrollTop = this.pre.scrollHeight;
  }

  /** Called on every poll with what the server now says about the job. */
  update(job: TwinJob, liveLogs: boolean, hits: string[]) {
    this.job = job;
    this.hits = hits;
    if (this.mode === "live" || this.mode === "done") return;
    if (job.running) {
      if (liveLogs) void this.follow();
      else {
        this.status("running");
        if (this.lines === 0) this.note("This console has no CRACI token, so it cannot show the log while the job runs.");
      }
      return;
    }
    void this.finished();
  }

  async follow() {
    this.mode = "live";
    this.status("live", true);
    this.abort = new AbortController();
    try {
      const res = await fetch(`/api/logs?repo=${encodeURIComponent(this.repo)}&job=${this.job.jobId}&follow=1`, { signal: this.abort.signal });
      if (!res.ok || !res.body) throw new Error(String(res.status));
      if (this.lines === 0) this.note("Waiting for the first line.");
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let nl: number;
        while ((nl = buf.indexOf("\n")) >= 0) {
          this.append(buf.slice(0, nl));
          buf = buf.slice(nl + 1);
        }
      }
      if (buf) this.append(buf);
    } catch {
      /* the stream ended or could not start: the next poll decides what to do */
    }
    this.abort = null;
    this.mode = "idle";
    this.status(this.lines ? "stream ended" : "");
  }

  async finished() {
    this.mode = "wait";
    try {
      const res = await fetch(`/api/logs?repo=${encodeURIComponent(this.repo)}&job=${this.job.jobId}`);
      if (res.ok) {
        const text = await res.text();
        this.pre.textContent = "";
        this.lines = 0;
        for (const l of text.split("\n")) this.append(l);
        this.pre.scrollTop = this.pre.scrollHeight;
        this.status(plural(this.lines, "line"));
        this.mode = "done";
        return;
      }
    } catch {
      /* try again on a later poll */
    }
    this.tries++;
    if (this.lines === 0) this.note(this.tries > 3 ? "CRACI has no log for this job." : "The log has not arrived yet.");
    this.status("");
    this.mode = "idle";
  }

  stop() {
    this.abort?.abort();
  }
}

let panes = new Map<string, LogPane>();
function stopPanes() {
  for (const p of panes.values()) p.stop();
  panes = new Map();
}

function syncPanes(v: RunPayload) {
  const host = document.getElementById("run-logs");
  if (!host) return;
  const hits = [...new Set(v.rows.filter((r) => r.state === "divergent" && r.host).map((r) => r.host))];
  let any = false;
  // A run without twins: the log CRACI keeps for each of its jobs.
  for (const j of v.twins.bare || v.twins.decoy ? [] : (v.solo ?? []).slice(0, 2)) {
    any = true;
    const key = `solo:${j.jobId}`;
    let pane = panes.get(key);
    if (!pane) {
      pane = new LogPane(v.run.repo, "solo", { jobId: j.jobId, name: j.name, status: "", url: "", running: false, hasLog: false });
      panes.set(key, pane);
      host.append(pane.el);
    }
    pane.update(pane.job, v.liveLogs, ["posted to"]);
  }
  for (const which of ["bare", "decoy"] as const) {
    const job = v.twins[which];
    if (!job) continue;
    any = true;
    const key = `${which}:${job.jobId}`;
    let pane = panes.get(key);
    if (!pane) {
      for (const [k, p] of panes)
        if (k.startsWith(`${which}:`)) {
          p.stop();
          p.el.remove();
          panes.delete(k);
        }
      pane = new LogPane(v.run.repo, which, job);
      panes.set(key, pane);
      if (which === "bare") host.prepend(pane.el);
      else host.append(pane.el);
    }
    pane.update(job, v.liveLogs, hits);
  }
  const empty = host.querySelector(".empty");
  if (!any && !empty) host.innerHTML = `<p class="empty">This run has no twin jobs.</p>`;
  else if (any && empty) empty.remove();
}

// ---------- rings ----------

const RING_TITLES = [
  ["Ring 0", "jobs that fetched it"],
  ["Ring 1", "caches and image layers they wrote"],
  ["Ring 2", "jobs that read those"],
  ["Ring 3", "what those jobs wrote"],
];

function actionWords(a: any): string {
  if (a.type === "delete_cache") return `Delete cache "${a.key}" in ${a.repo}`;
  if (a.type === "cancel_run") return `Cancel run ${a.runId} in ${a.repo}`;
  if (a.type === "rerun_run") return `Run ${a.runId} in ${a.repo} again`;
  return `Open a pull request in ${a.repo} with the network policy the clean build needs`;
}

function fenceHtml(p: RingsView & { allowFence: boolean }, applied: RingsView["fence"] | null, busy: boolean, error: string | null): string {
  const f = applied ?? p.fence;
  const rows = f.actions
    .map((a) => {
      const st = !a.executed ? `<span class="st">planned</span>` : a.ok ? `<span class="st ok">done</span>` : `<span class="st bad">failed</span>`;
      return `<li>${st}<div>${esc(actionWords(a))}<p>${esc(a.executed && a.detail ? a.detail : a.reason)}</p></div></li>`;
    })
    .join("");
  const manual = f.manual.map((m) => `<li><span class="st">by hand</span><div>${esc(m)}</div></li>`).join("");
  const apply =
    p.allowFence && f.actions.length && !applied
      ? `<div class="apply"><button class="btn danger" id="fence-apply"${busy ? " disabled" : ""}>${busy ? "Applying" : `Apply ${plural(f.actions.length, "action")}`}</button><span class="hint">This changes GitHub: caches are deleted, runs cancelled or started again.</span></div>`
      : "";
  return `<section aria-labelledby="h-fence">
      <h2 id="h-fence">Ring fence <span class="n">${applied ? "applied" : "dry run, nothing is changed"}</span></h2>
      ${rows || manual ? `<ul class="rows fence">${rows}${manual}</ul>` : `<p class="empty">Nothing to fence: no cache, image or run is affected.</p>`}
      ${error ? `<p class="hint err">${esc(error)}</p>` : ""}${apply}
    </section>`;
}

function ringsHtml(p: RingsPayload, seed: string, error: string | null, fenceState: { applied: any; busy: boolean; error: string | null }): string {
  const sugg = p.suggestions.length ? `<p class="sugg"><span class="hint">From the fleet:</span>${p.suggestions.map((s) => `<a href="${esc(ringsHref(s.seed))}">${esc(s.label)}</a>`).join("")}</p>` : "";
  let result = "";
  if (error) result = `<p class="empty err">${esc(error)}</p>`;
  else if (p.rings) {
    const total = p.rings.reduce((n, r) => n + r.length, 0);
    if (total === 0)
      result = `<p class="empty">${esc(p.note ?? `No job in the fleet index has this${p.jobs === 0 ? ". The index holds no jobs yet" : ` (${plural(p.jobs, "job")} checked)`}.`)}</p>`;
    else {
      const cols = p.rings
        .map((ring, i) => {
          const items = ring
            .map((m) => {
              const name = m.type === "job" && m.runId && m.repo ? `<a href="${esc(runHref(m.repo, m.runId))}">${esc(m.label)}</a>` : esc(m.label);
              return `<li><b>${name}</b><span class="kind">${esc(m.type)}${m.repo ? ` in ${esc(m.repo)}` : ""}</span><p>${esc(m.why)}</p></li>`;
            })
            .join("");
          return `<div class="ring"><h3>${RING_TITLES[i]![0]} <span class="n">${ring.length}</span><small>${RING_TITLES[i]![1]}</small></h3>${items ? `<ul>${items}</ul>` : `<p class="none">Nothing.</p>`}</div>`;
        })
        .join("");
      const zero = p.rings[0]!.filter((m) => m.type === "job").length;
      result = `${p.note ? `<p class="hint">${esc(p.note)}</p>` : ""}
        <div class="r0"><b>R0 ${p.r0.toFixed(2)}</b><span>${zero ? `${plural(zero, "job")} fetched it. On average each passed it on to ${p.r0.toFixed(2)} other jobs through caches and images.` : "No job fetched it directly."}</span></div>
        <div class="ringgrid">${cols}</div>
        ${fenceHtml(p, fenceState.applied, fenceState.busy, fenceState.error)}`;
    }
  } else if (!p.suggestions.length) {
    result = `<p class="empty">${p.jobs === 0 ? "The fleet index holds no jobs yet, so there is nothing to trace." : "No divergence or cache to start from yet. Type a host or a package above."}</p>`;
  }
  return `<h1 class="plain">Where did it spread?</h1>
    <p class="lead">Start from a package, a host, the exact bytes behind a URL, or a cache. CRACI's cache and image provenance show which jobs wrote what, and which jobs read it afterwards.</p>
    <form class="seed" id="seed-form"><input id="seed" name="seed" value="${esc(seed)}" placeholder="pkg:npm/name@1.2.3, a host, sha256:…, or cache:…" aria-label="What to trace" autocomplete="off" autocapitalize="off" spellcheck="false"><button class="btn" type="submit">Trace</button></form>
    ${sugg}
    <div id="rings-result">${result}</div>`;
}

// ---------- replays ----------

const REPLAY_WORDS: Record<string, string> = { caught: "caught", missed: "missed", running: "running", not_run: "not run", not_set_up: "not set up", no_verdict: "no verdict yet", not_seen: "not seen yet" };

function replaysHtml(s: State): string {
  const rows = s.replays
    .map((r) => {
      const saw = r.saw.length ? `<ul>${r.saw.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : "";
      const jobUrl = safeUrl(r.job?.url);
      const links = r.run
        ? `<a href="${esc(runHref(r.run.repo, r.run.runId))}">run ${esc(r.run.runId)}</a>${r.run.gone ? "<span>deleted on GitHub</span>" : ext(r.run.url, "on GitHub")}${r.run.pr ? ext(r.run.pr.url, `PR #${r.run.pr.number}`) : ""}${jobUrl && !r.run.gone ? ext(jobUrl, `CRACI job: ${r.job!.name}`) : ""}`
        : "";
      const organs = r.organs.length ? esc(r.organs.join(", ")) : r.state === "missed" ? "nothing" : "";
      const place = [r.fullRepo ?? "", r.branch ?? "", r.workflow ? `workflow ${r.workflow}` : "", !r.branch && r.runId ? `run ${r.runId}` : ""].filter(Boolean).join(" · ");
      const where = r.state === "not_set_up" ? "" : `<span>${esc(place)}</span>`;
      const stopped =
        r.state !== "caught" || r.stopped === null
          ? ""
          : r.stopped
            ? `<span class="note">The run's verdict job failed. The release job did not start.</span>`
            : `<span class="note">Seen after the run. Its own verdict job had passed.</span>`;
      const unseen = r.state === "not_seen" ? `<span class="note">No run in this repo shows it yet.</span>` : "";
      return `<tr>
        <td class="inc"><b>${esc(r.incident)}</b><span>${esc(r.how)}</span>${where}</td>
        <td class="res"><span class="chip ${r.state}">${REPLAY_WORDS[r.state]}</span>${stopped}${unseen}</td>
        <td class="organ${r.organs.length ? "" : " dim"}" data-l="Caught by">${organs}<span class="note">expected: ${esc(r.expected)}</span></td>
        <td class="saw${saw ? "" : " dim"}" data-l="What Parallax saw">${saw}</td>
        <td class="dim" data-l="Push to verdict">${esc(duration(r.seconds))}</td>
        <td class="links">${links}</td>
      </tr>`;
    })
    .join("");
  const ran = s.replays.filter((r) => r.run).length;
  const caught = s.replays.filter((r) => r.state === "caught").length;
  const missed = s.replays.filter((r) => r.state === "missed").length;
  const rest = s.replays.length - ran;
  const inTime = s.replays.filter((r) => r.state === "caught" && r.stopped).length;
  const sum = ran
    ? `${caught} caught, ${missed} missed${rest ? `, ${rest} not run or not seen yet` : ""}.${inTime && inTime < caught ? ` ${inTime} of the ${caught} were stopped in their own run, before the release job.` : ""}`
    : "None has run yet.";
  return `<h1 class="plain">Real attacks, replayed on the fleet</h1>
    <p class="lead">Each replay is a harmless simulation of one real attack, run in a fleet repo. The row fills in from the real run: what Parallax saw, which detector caught it, how long it took from the push. A miss is shown as a miss. ${esc(sum)}</p>
    ${s.replays.length ? `<table class="board"><thead><tr><th>Attack and simulation</th><th>Result</th><th>Caught by</th><th>What Parallax saw</th><th>Push to verdict</th><th>Run and CRACI job</th></tr></thead><tbody>${rows}</tbody></table>` : `<p class="empty">No replays are defined.</p>`}`;
}

// ---------- router ----------

type Route = { view: "fleet" } | { view: "replays" } | { view: "fixes" } | { view: "rings"; seed: string } | { view: "run"; repo: string; runId: string } | { view: "lost" };

function parseRoute(): Route {
  const h = location.hash.replace(/^#/, "") || "/";
  const [path, query = ""] = h.split("?");
  if (path === "/" || path === "") return { view: "fleet" };
  if (path === "/replays") return { view: "replays" };
  if (path === "/fixes") return { view: "fixes" };
  if (path === "/rings") return { view: "rings", seed: new URLSearchParams(query).get("seed") ?? "" };
  const m = /^\/run\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)\/(\d+)$/.exec(path!);
  if (m) return { view: "run", repo: m[1]!, runId: m[2]! };
  return { view: "lost" };
}

let route: Route = parseRoute();
let runData: RunPayload | null = null;
let runError: string | null = null;
let runSig = "";
let ringsData: RingsPayload | null = null;
let ringsError: string | null = null;
const fence = { applied: null as any, busy: false, error: null as string | null };
let gen = 0;

function setNav() {
  const cur = route.view === "run" ? "fleet" : route.view;
  for (const a of document.querySelectorAll<HTMLAnchorElement>("[data-nav]")) {
    if (a.dataset.nav === cur) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  document.title = { fleet: "Parallax", replays: "Replays · Parallax", fixes: "Fixes · Parallax", rings: "Rings · Parallax", run: "Twins · Parallax", lost: "Parallax" }[route.view];
}

let painted = "";
function paint(html: string) {
  if (painted === html) return;
  const y = window.scrollY;
  painted = html;
  main.innerHTML = html;
  window.scrollTo(0, y);
}

function render() {
  if (!state) {
    paint(stateError ? `<p class="empty err">Cannot reach the console server. ${esc(stateError)}</p>` : `<p class="loading">Loading</p>`);
    return;
  }
  if (route.view === "fleet") paint(fleetHtml(state));
  else if (route.view === "replays") paint(replaysHtml(state));
  else if (route.view === "fixes") paint(fixesHtml(state.fixes ?? [], { esc, ext, ago }));
  else if (route.view === "lost") paint(`<h1 class="plain">There is no such page.</h1><p class="lead"><a href="#/">Back to the fleet</a></p>`);
  else if (route.view === "rings") {
    if (!ringsData && !ringsError) paint(`<p class="loading">Loading</p>`);
    else paint(ringsHtml(ringsData ?? { seed: "", rings: null, suggestions: [], jobs: 0, allowFence: false }, route.seed, ringsError, fence));
  } else renderRun();
}

function renderRun() {
  if (route.view !== "run") return;
  if (!runData) {
    stopPanes();
    paint(
      runError
        ? `<a class="back" href="#/">Fleet</a><h1 class="plain">Run ${esc(route.runId)}</h1><p class="empty">${esc(runError)}</p>`
        : `<p class="loading">Loading</p>`,
    );
    return;
  }
  // The log panes must survive a repaint, so only the parts that changed are replaced.
  if (!document.getElementById("run-logs")) {
    painted = "";
    main.innerHTML = runHtml(runData);
  } else {
    const tmp = document.createElement("div");
    tmp.innerHTML = runHtml(runData);
    for (const id of ["run-verdict", "run-pipe", "run-find", "run-conn", "run-pkgs", "run-seeds"]) {
      const a = document.getElementById(id);
      const b = tmp.querySelector(`#${id}`);
      if (a && b && a.innerHTML !== b.innerHTML) a.innerHTML = b.innerHTML;
    }
    const h = tmp.querySelector("#h-conn");
    const cur = document.getElementById("h-conn");
    if (h && cur && cur.innerHTML !== h.innerHTML) cur.innerHTML = h.innerHTML;
  }
  syncPanes(runData);
}

async function loadRun() {
  if (route.view !== "run") return;
  const g = gen;
  try {
    const d = await getJson<RunPayload>(`/api/run?repo=${encodeURIComponent(route.repo)}&run=${route.runId}`);
    if (g !== gen) return;
    const sig = JSON.stringify(d);
    runError = null;
    if (sig === runSig && runData) return;
    runSig = sig;
    runData = d;
  } catch (e) {
    if (g !== gen) return;
    if (runData) return; // keep what is on screen through a blip
    runError = e instanceof Error ? e.message : String(e);
  }
  renderRun();
}

async function loadRings() {
  if (route.view !== "rings") return;
  const g = gen;
  try {
    const d = await getJson<RingsPayload>(`/api/rings?seed=${encodeURIComponent(route.seed)}`);
    if (g !== gen) return;
    ringsData = d;
    ringsError = null;
  } catch (e) {
    if (g !== gen) return;
    ringsError = e instanceof Error ? e.message : String(e);
  }
  render();
}

async function applyFence() {
  if (route.view !== "rings" || fence.busy) return;
  if (!window.confirm("Apply the ring fence on GitHub now? Caches are deleted and runs are cancelled or started again.")) return;
  fence.busy = true;
  fence.error = null;
  render();
  try {
    const res = await fetch("/api/fence", { method: "POST", headers: { "content-type": "application/json", "x-plx-confirm": "apply" }, body: JSON.stringify({ seed: route.seed }) });
    const body = await res.json().catch(() => null);
    if (!res.ok) throw new Error(body?.error ?? `The server answered ${res.status}.`);
    fence.applied = body;
  } catch (e) {
    fence.error = e instanceof Error ? e.message : String(e);
  }
  fence.busy = false;
  render();
}

function onRoute() {
  gen++;
  route = parseRoute();
  stopPanes();
  runData = null;
  runError = null;
  runSig = "";
  ringsData = null;
  ringsError = null;
  fence.applied = null;
  fence.busy = false;
  fence.error = null;
  painted = "";
  setNav();
  render();
  window.scrollTo(0, 0);
  if (route.view === "run") void loadRun();
  if (route.view === "rings") void loadRings();
}

main.addEventListener("submit", (e) => {
  const form = e.target as HTMLFormElement;
  if (form.id !== "seed-form") return;
  e.preventDefault();
  const seed = (form.elements.namedItem("seed") as HTMLInputElement).value.trim();
  const next = seed ? ringsHref(seed) : "#/rings";
  if (location.hash === next) void loadRings();
  else location.hash = next;
});
main.addEventListener("click", (e) => {
  if ((e.target as HTMLElement).id === "fence-apply") void applyFence();
});
window.addEventListener("hashchange", onRoute);

async function tick() {
  const changed = await pollState();
  paintFresh();
  if (document.hidden) return;
  if (route.view === "run") void loadRun();
  else if (route.view === "rings") {
    if (changed && !fence.applied && !fence.busy && document.activeElement?.id !== "seed") void loadRings();
  } else if (changed || !state) render();
}

setNav();
void tick().then(() => {
  render();
  if (route.view === "run") void loadRun();
  if (route.view === "rings") void loadRings();
});
setInterval(tick, 3000);
setInterval(paintFresh, 1000);
