// Synthetic data only. Nothing here is a real job, advisory or package release.
import { describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { advisoriesOf, compareAdvisories, countBySeverity, inScope, parsePurl } from "../../src/fix/advisories.ts";
import type { Agent } from "../../src/fix/agent.ts";
import { lockDiff, lockPackages, newRegistries, outsideTheFix, porcelainPaths } from "../../src/fix/lockfile.ts";
import { buildBrief, judgeChange, renderPrBody, renderProof } from "../../src/fix/report.ts";
import type { FixDeps, Workspace } from "../../src/fix/run.ts";
import { proposeFix, publishFix, readFixes, verifyFix } from "../../src/fix/run.ts";
import { agesOf, fixedVersion } from "../../src/fix/sources.ts";
import { fixRows } from "../../src/fix/view.ts";
import { fixesHtml } from "../../ui/fixes.ts";
import type { CycloneDxBom } from "../../src/types.ts";

const NOW = Date.parse("2026-11-14T18:00:00Z");

const bom = (vulns: Array<[id: string, severity: string, purl: string, title?: string]>): CycloneDxBom => ({
  bomFormat: "CycloneDX",
  components: [],
  vulnerabilities: vulns.map(([id, severity, purl, title]) => ({
    id,
    source: { name: "osv" },
    ratings: [{ severity }],
    description: title ?? `about ${id}`,
    affects: [{ ref: purl }],
  })),
});

const BEFORE = bom([
  ["GHSA-aaaa-aaaa-aaaa", "critical", "pkg:npm/poolio@1.1.1", "Poolio: options reach the worker"],
  ["GHSA-bbbb-bbbb-bbbb", "high", "pkg:npm/%40scope/runner@2.1.9"],
  ["GHSA-cccc-cccc-cccc", "medium", "pkg:npm/tiny@0.5.2"],
  ["CLSA-2026-1", "unknown", "pkg:npm/tiny@0.5.2"],
]);

const lock = (pkgs: Record<string, { version: string; resolved?: string; hasInstallScript?: boolean }>) =>
  JSON.stringify({
    name: "demo",
    lockfileVersion: 3,
    packages: {
      "": { name: "demo", version: "1.0.0" },
      ...Object.fromEntries(
        Object.entries(pkgs).map(([name, p]) => [
          `node_modules/${name}`,
          { resolved: `https://registry.npmjs.org/${name}/-/${name.split("/").pop()}-${p.version}.tgz`, ...p },
        ]),
      ),
    },
  });

const LOCK_BEFORE = lock({ poolio: { version: "1.1.1" }, "@scope/runner": { version: "2.1.9" }, tiny: { version: "0.5.2" } });
const LOCK_AFTER = lock({ poolio: { version: "2.1.1" }, "@scope/runner": { version: "2.1.12" }, tiny: { version: "0.5.2" }, helper: { version: "1.0.0" } });

describe("advisories from a CRACI bill of materials", () => {
  test("a purl with a scope is read as the registry spells it", () => {
    expect(parsePurl("pkg:npm/%40scope/runner@2.1.9")).toEqual({ type: "npm", name: "@scope/runner", version: "2.1.9" });
    expect(parsePurl("pkg:ghacache/x?entry_id=1")).toBeNull();
  });

  test("most severe first, and the scope keeps only critical and high", () => {
    const all = advisoriesOf(BEFORE);
    expect(all.map((a) => a.severity)).toEqual(["critical", "high", "medium", "unknown"]);
    expect(all[0]).toMatchObject({ id: "GHSA-aaaa-aaaa-aaaa", package: "poolio", version: "1.1.1", url: "https://github.com/advisories/GHSA-aaaa-aaaa-aaaa" });
    expect(inScope(all, "high").map((a) => a.package)).toEqual(["poolio", "@scope/runner"]);
    expect(countBySeverity(all)).toEqual({ critical: 1, high: 1, medium: 1, low: 0, unknown: 1 });
    expect(advisoriesOf(null)).toEqual([]);
  });

  test("an advisory that follows the package to its new version is remaining, not cleared", () => {
    const after = bom([
      ["GHSA-bbbb-bbbb-bbbb", "high", "pkg:npm/%40scope/runner@2.1.12"],
      ["GHSA-dddd-dddd-dddd", "low", "pkg:npm/helper@1.0.0"],
    ]);
    const c = compareAdvisories(advisoriesOf(BEFORE), advisoriesOf(after));
    expect(c.cleared.map((a) => a.id)).toEqual(["GHSA-aaaa-aaaa-aaaa", "GHSA-cccc-cccc-cccc", "CLSA-2026-1"]);
    expect(c.remaining.map((a) => `${a.id} ${a.version}`)).toEqual(["GHSA-bbbb-bbbb-bbbb 2.1.12"]);
    expect(c.introduced.map((a) => a.id)).toEqual(["GHSA-dddd-dddd-dddd"]);
  });
});

describe("what a fix changed", () => {
  test("lockfile diff by package name", () => {
    const d = lockDiff(lockPackages(LOCK_BEFORE), lockPackages(LOCK_AFTER));
    expect(d.changed).toEqual([
      { name: "@scope/runner", from: ["2.1.9"], to: ["2.1.12"] },
      { name: "poolio", from: ["1.1.1"], to: ["2.1.1"] },
    ]);
    expect(d.added).toEqual([{ name: "helper", versions: ["1.0.0"] }]);
    expect(d.removed).toEqual([]);
  });

  test("a registry the lockfile did not use before is named", () => {
    const after = lock({ poolio: { version: "2.1.1", resolved: "https://packages.example.net/poolio-2.1.1.tgz" } });
    expect(newRegistries(lockPackages(LOCK_BEFORE), lockPackages(after))).toEqual(["packages.example.net"]);
    expect(newRegistries(lockPackages(LOCK_BEFORE), lockPackages(LOCK_AFTER))).toEqual([]);
  });

  test("only the manifest and the lockfile are inside the fix", () => {
    const paths = porcelainPaths(" M package.json\n M package-lock.json\n?? .github/workflows/extra.yml\n M src/index.ts\n");
    expect(paths).toEqual(["package.json", "package-lock.json", ".github/workflows/extra.yml", "src/index.ts"]);
    expect(outsideTheFix(paths)).toEqual([".github/workflows/extra.yml", "src/index.ts"]);
  });
});

describe("outside sources", () => {
  const osv = {
    id: "GHSA-aaaa-aaaa-aaaa",
    affected: [
      { package: { ecosystem: "npm", name: "poolio" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.1.4" }, { introduced: "2.0.0" }, { fixed: "2.1.1" }] }] },
      { package: { ecosystem: "PyPI", name: "poolio" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "9.9.9" }] }] },
    ],
  };

  test("the fixed version is the one for the line the installed version is on", () => {
    expect(fixedVersion(osv, "poolio", "1.1.1")).toBe("1.1.4");
    expect(fixedVersion(osv, "poolio", "2.0.3")).toBe("2.1.1");
    expect(fixedVersion(osv, "poolio", "1.5.0")).toBeNull();
    expect(fixedVersion(osv, "other", "1.0.0")).toBeNull();
    expect(fixedVersion(null, "poolio", "1.1.1")).toBeNull();
  });

  test("ages come from the registry's publish times, unknown stays unknown", async () => {
    const fetchImpl = async (url: string) =>
      url.endsWith("/poolio")
        ? Response.json({ time: { "2.1.1": "2026-11-14T06:00:00Z" } })
        : url.endsWith("/@scope%2Frunner")
          ? Response.json({ time: { "2.1.12": "2026-10-15T18:00:00Z" } })
          : new Response("no", { status: 404 });
    const ages = await agesOf(
      [
        { name: "poolio", version: "2.1.1" },
        { name: "@scope/runner", version: "2.1.12" },
        { name: "helper", version: "1.0.0" },
      ],
      NOW,
      fetchImpl,
    );
    expect(ages.map((a) => a.ageHours)).toEqual([12, 720, null]);
  });

  test("a version younger than the limit refuses the change, a missing time is only a note", () => {
    const base = { diff: { changed: [], added: [], removed: [] }, outside: [], newRegistries: [], installScripts: [] };
    const j = judgeChange(
      {
        ...base,
        ages: [
          { name: "poolio", version: "2.1.1", publishedAt: "2026-11-14T06:00:00Z", ageHours: 12 },
          { name: "helper", version: "1.0.0", publishedAt: null, ageHours: null },
        ],
      },
      72,
    );
    expect(j.refuse).toEqual(["A version is younger than 72 hours: poolio@2.1.1 (12 h)."]);
    expect(j.notes).toEqual(["Publish time not found for helper@1.0.0."]);
    expect(judgeChange({ ...base, ages: [] }, 72)).toEqual({ refuse: [], notes: [] });
  });
});

// ---------- the whole loop, with every outside party faked ----------

type Fake = { deps: FixDeps; dir: string; pushed: Array<{ branch: string; paths: string[] }>; posts: Array<{ url: string; body: any }>; briefs: string[] };

async function fake(o: { agentWrites: (dir: string) => Promise<void>; after?: CycloneDxBom; verdict?: string; times?: Record<string, Record<string, string>> }): Promise<Fake> {
  const dir = await mkdtemp(join(tmpdir(), "plx-fix-"));
  const pushed: Fake["pushed"] = [];
  const posts: Fake["posts"] = [];
  const briefs: string[] = [];
  const touched = new Set<string>();
  const workspace: Workspace = {
    async checkout(_repo, _branch, d) {
      await mkdir(d, { recursive: true });
      await writeFile(join(d, "package.json"), JSON.stringify({ name: "demo", dependencies: { "@scope/runner": "^2.1.8" } }));
      await writeFile(join(d, "package-lock.json"), LOCK_BEFORE);
    },
    async changedPaths() {
      return [...touched];
    },
    async push(_d, branch, paths) {
      pushed.push({ branch, paths });
    },
  };
  const agent: Agent = async ({ cwd, prompt }) => {
    briefs.push(prompt);
    const before = new Map<string, string>();
    for (const f of ["package.json", "package-lock.json"]) before.set(f, await readFile(join(cwd, f), "utf8"));
    await o.agentWrites(cwd);
    for (const f of ["package.json", "package-lock.json"]) if ((await readFile(join(cwd, f), "utf8")) !== before.get(f)) touched.add(f);
    for (const f of [".github/workflows/ci.yml"]) if (await Bun.file(join(cwd, f)).exists()) touched.add(f);
    return { ok: true, report: "| Package | Installed | Now |\n|---|---|---|\n| poolio | 1.1.1 | 2.1.1 |", model: "test-model", turns: 3, seconds: 7, error: null };
  };
  const run = (id: number, branch: string, event: string) => ({
    id,
    head_branch: branch,
    head_sha: `${id}`.repeat(8),
    event,
    status: "completed",
    conclusion: "success",
    created_at: "2026-11-14T17:00:00Z",
    updated_at: "2026-11-14T17:02:00Z",
    html_url: `https://github.example/runs/${id}`,
  });
  const job = (id: number, runId: number, name: string, conclusion = "success") => ({
    id,
    run_id: runId,
    name,
    status: "completed",
    conclusion,
    started_at: null,
    completed_at: null,
    html_url: `https://github.example/jobs/${id}`,
    head_sha: "",
  });
  const fetchImpl = async (url: string, init?: RequestInit) => {
    if (init?.method === "POST") {
      posts.push({ url, body: JSON.parse(String(init.body)) });
      return Response.json({ number: 7, html_url: "https://github.example/pull/7" });
    }
    if (url.includes("api.osv.dev")) {
      const id = url.split("/").pop()!;
      return Response.json({ id, affected: [{ package: { ecosystem: "npm", name: id.includes("aaaa") ? "poolio" : "@scope/runner" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: id.includes("aaaa") ? "2.1.1" : "2.1.12" }] }] }] });
    }
    const name = decodeURIComponent(url.split("registry.npmjs.org/")[1] ?? "");
    const time = (o.times ?? { poolio: { "2.1.1": "2026-10-01T00:00:00Z" }, "@scope/runner": { "2.1.12": "2026-10-20T00:00:00Z" }, helper: { "1.0.0": "2025-01-01T00:00:00Z" } })[name];
    return time ? Response.json({ time }) : new Response("no", { status: 404 });
  };
  const deps: FixDeps = {
    gh: {
      defaultBranch: async () => "main",
      listRuns: async (_r: string, q: { branch?: string } = {}) => (q.branch === "main" ? [run(1, "main", "push")] : [run(2, q.branch ?? "", "pull_request")]),
      listJobs: async (_r: string, runId: string | number) =>
        Number(runId) === 1
          ? [job(11, 1, "build (bare)"), job(12, 1, "build (decoy)")]
          : [job(21, 2, "build (bare)"), job(22, 2, "build (decoy)"), job(23, 2, "verdict", o.verdict ?? "success")],
      getRun: async () => run(1, "main", "push"),
    } as unknown as FixDeps["gh"],
    craci: { getSbom: async (_r: string, jobId: string) => (jobId === "11" ? BEFORE : (o.after ?? bom([["GHSA-cccc-cccc-cccc", "medium", "pkg:npm/tiny@0.5.2"]]))) } as FixDeps["craci"],
    agent,
    workspace,
    fetch: fetchImpl as FixDeps["fetch"],
    now: () => NOW,
    recordFile: join(dir, "fixes.jsonl"),
    workDir: join(dir, "work"),
  };
  process.env.GITHUB_TOKEN ||= "test-token";
  return { deps, dir, pushed, posts, briefs };
}

const goodFix = async (dir: string) => {
  await writeFile(join(dir, "package-lock.json"), LOCK_AFTER);
};

describe("a fix that has to prove itself", () => {
  test("propose: the brief names what CRACI saw, the change passes the gate, a pull request is opened", async () => {
    const f = await fake({ agentWrites: goodFix });
    const r = await proposeFix({ repo: "acme/web", craciPrompt: "Audit the known-vulnerable dependencies. Do not modify any files." }, f.deps);
    expect(r.status).toBe("proposed");
    expect(r.targeted.map((t) => [t.package, t.fixedIn, t.direct])).toEqual([
      ["poolio", "2.1.1", false],
      ["@scope/runner", "2.1.12", true],
    ]);
    expect(f.briefs[0]).toContain("<craci_fix_prompt>");
    expect(f.briefs[0]).toContain("- poolio 1.1.1 [transitive] — GHSA-aaaa-aaaa-aaaa (critical): Poolio: options reach the worker — fixed in 2.1.1 by the advisory record");
    expect(f.briefs[0]).toContain("Never choose a version published less than 72 hours ago");
    expect(f.pushed).toEqual([{ branch: "parallax/fix-20261114t1800", paths: ["package-lock.json"] }]);
    const pr = f.posts[0]!;
    expect(pr.url).toEndWith("/repos/acme/web/pulls");
    expect(pr.body.title).toBe("deps: clear known advisories in poolio, @scope/runner");
    expect(pr.body.body).toContain("| poolio | 1.1.1 | 2.1.1 |");
    expect(pr.body.body).toContain("New: helper@1.0.0");
    expect(r.pr).toEqual({ number: 7, url: "https://github.example/pull/7", branch: "parallax/fix-20261114t1800" });
    expect((await readFixes(f.deps.recordFile!)).map((x) => x.status)).toEqual(["proposed"]);
  });

  test("a dry run stops before the push, publish takes it from there", async () => {
    const f = await fake({ agentWrites: goodFix });
    const dry = await proposeFix({ repo: "acme/web", dryRun: true }, f.deps);
    expect(dry.status).toBe("proposed");
    expect(dry.pr).toBeNull();
    expect(f.pushed).toEqual([]);
    const done = await publishFix({ id: dry.id }, f.deps);
    expect(done.pr?.number).toBe(7);
    expect(f.pushed).toEqual([{ branch: "parallax/fix-20261114t1800", paths: ["package-lock.json"] }]);
    await expect(publishFix({ id: dry.id }, f.deps)).rejects.toThrow("No proposed fix without a pull request matches");
  });

  test("propose: an agent that also edits the workflow is refused and nothing is pushed", async () => {
    const f = await fake({
      agentWrites: async (dir) => {
        await goodFix(dir);
        await mkdir(join(dir, ".github/workflows"), { recursive: true });
        await writeFile(join(dir, ".github/workflows/ci.yml"), "on: push\n");
      },
    });
    const r = await proposeFix({ repo: "acme/web" }, f.deps);
    expect(r.status).toBe("refused");
    expect(r.why).toEqual(["The agent changed files a dependency fix may not touch: .github/workflows/ci.yml."]);
    expect(f.pushed).toEqual([]);
    expect(f.posts).toEqual([]);
  });

  test("propose: a release from this morning is refused however well it fixes the advisory", async () => {
    const f = await fake({ agentWrites: goodFix, times: { poolio: { "2.1.1": "2026-11-14T09:00:00Z" } } });
    const r = await proposeFix({ repo: "acme/web" }, f.deps);
    expect(r.status).toBe("refused");
    expect(r.why[0]).toBe("A version is younger than 72 hours: poolio@2.1.1 (9 h).");
    expect(f.pushed).toEqual([]);
  });

  test("propose: nothing in scope means no agent and no pull request", async () => {
    const f = await fake({ agentWrites: goodFix });
    f.deps.craci = { getSbom: async () => bom([["GHSA-cccc-cccc-cccc", "medium", "pkg:npm/tiny@0.5.2"]]) } as FixDeps["craci"];
    const r = await proposeFix({ repo: "acme/web" }, f.deps);
    expect(r.status).toBe("nothing-to-fix");
    expect(f.briefs).toEqual([]);
  });

  test("verify: proven when the build's own bill of materials no longer lists them and the twins agree", async () => {
    const f = await fake({ agentWrites: goodFix });
    await proposeFix({ repo: "acme/web" }, f.deps);
    const r = await verifyFix({ repo: "acme/web", pr: 7 }, f.deps);
    expect(r.status).toBe("proven");
    expect(r.proof!.cleared.map((a) => a.id)).toEqual(["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb", "CLSA-2026-1"]);
    expect(r.proof!.twins).toBe("clean");
    const comment = f.posts.at(-1)!;
    expect(comment.url).toEndWith("/repos/acme/web/issues/7/comments");
    expect(comment.body.body).toStartWith("**Proven.** 2 of 2 targeted advisories are gone from the build");
    expect(comment.body.body).toContain("| critical | 1 | 0 |");
    expect((await readFixes(f.deps.recordFile!)).map((x) => x.status)).toEqual(["proven"]);
  });

  test("verify: not proven when one advisory followed the package, or when the twins disagree", async () => {
    const f = await fake({ agentWrites: goodFix, after: bom([["GHSA-bbbb-bbbb-bbbb", "high", "pkg:npm/%40scope/runner@2.1.12"]]), verdict: "failure" });
    await proposeFix({ repo: "acme/web" }, f.deps);
    const r = await verifyFix({ repo: "acme/web", pr: 7 }, f.deps);
    expect(r.status).toBe("not-proven");
    expect(r.why).toEqual(["1 targeted advisory is still in the build.", "The twins did not agree.", "Jobs that did not pass: verdict (failure)."]);
    expect(renderProof(r)).toContain("- @scope/runner 2.1.12: [GHSA-bbbb-bbbb-bbbb]");
  });

  test("verify: proven for some when the rest is still there and nothing else is wrong", async () => {
    const f = await fake({ agentWrites: goodFix, after: bom([["GHSA-bbbb-bbbb-bbbb", "high", "pkg:npm/%40scope/runner@2.1.12"]]) });
    await proposeFix({ repo: "acme/web" }, f.deps);
    const r = await verifyFix({ repo: "acme/web", pr: 7 }, f.deps);
    expect(r.status).toBe("partly-proven");
    expect(renderProof(r)).toStartWith("**Proven for 1 of 2.** Those are gone from the build and the twins found nothing. 1 is still in it.");
    expect(renderProof(r)).not.toContain("Why not:");
  });

  test("the console row is built from the records: outcome per advisory, counts before and after", async () => {
    const f = await fake({ agentWrites: goodFix, after: bom([["GHSA-bbbb-bbbb-bbbb", "high", "pkg:npm/%40scope/runner@2.1.12"]]) });
    const dry = await proposeFix({ repo: "acme/web", dryRun: true }, f.deps);
    expect(fixRows([dry])[0]).toMatchObject({ status: "proposed", headline: "Passed the gate. Not pushed yet.", proof: null });
    expect(fixRows([dry])[0]!.advisories.map((a) => a.outcome)).toEqual(["not_measured", "not_measured"]);
    await publishFix({ id: dry.id }, f.deps);
    const done = await verifyFix({ repo: "acme/web", pr: 7 }, f.deps);
    const rows = fixRows([done]);
    expect(rows[0]).toMatchObject({ status: "partly-proven", headline: "Proven for 1 of 2. 1 still in the build.", pr: { number: 7 } });
    expect(rows[0]!.advisories.map((a) => [a.package, a.outcome])).toEqual([
      ["poolio", "gone"],
      ["@scope/runner", "still_there"],
    ]);
    expect(rows[0]!.counts).toEqual([
      { severity: "critical", before: 1, after: 0 },
      { severity: "high", before: 1, after: 1 },
      { severity: "medium", before: 1, after: 0 },
      { severity: "unknown", before: 1, after: 0 },
    ]);
    expect(rows[0]!.change).toMatchObject({ changed: 2, added: 1, removed: 0, moved: [{ name: "poolio", from: "1.1.1", to: "2.1.1" }, { name: "@scope/runner", from: "2.1.9", to: "2.1.12" }] });
    const html = fixesHtml(rows, { esc: (x) => String(x ?? "").replace(/</g, "&lt;"), ext: (_u, l) => l, ago: () => "now" });
    expect(html).toContain("Proven for 1 of 2. 1 still in the build.");
    expect(html).toContain("still in the build</span>");
    // A dry run that was never pushed drops out once the repo has a pushed fix.
    expect(fixRows([dry, done]).map((r) => r.status)).toEqual(["partly-proven"]);
  });

  test("the texts say where the numbers come from", () => {
    const brief = buildBrief({
      repo: "acme/web",
      job: { branch: "main", commitSha: "abcdef0123456789", runId: "1", jobId: "11", jobName: "build (bare)", jobUrl: "u" },
      targets: [],
      minAgeHours: 24,
    });
    expect(brief).toContain('recorded for the job "build (bare)" of acme/web at commit abcdef012345');
    expect(brief).not.toContain("craci_fix_prompt");
    expect(renderPrBody({ id: "x", repo: "acme/web", createdAt: "", scope: "high", minAgeHours: 72, base: { branch: "main", commitSha: "abcdef0", runId: "1", jobId: "11", jobName: "build (bare)", jobUrl: "u" }, before: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 }, targeted: [], craciPrompt: false, agent: null, change: null, status: "proposed", why: [], pr: null, proof: null })).toEndWith(
      "🤖 Generated with [Claude Code](https://claude.com/claude-code)",
    );
  });
});
