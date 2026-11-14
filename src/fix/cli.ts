#!/usr/bin/env bun
// bun src/fix/cli.ts propose --repo O/R [--scope high|all] [--min-age-hours 72] [--craci-prompt FILE] [--dry-run]
// bun src/fix/cli.ts publish --id ID            (push a change that --dry-run left proposed)
// bun src/fix/cli.ts verify  --repo O/R --pr N [--no-comment]
// bun src/fix/cli.ts list
import { readFile } from "node:fs/promises";
import { parseArgs } from "../cli.ts";
import { CraciClient } from "../craci.ts";
import { GithubClient } from "../github.ts";
import { claudeAgent } from "./agent.ts";
import type { FixRecord } from "./report.ts";
import { proposeFix, publishFix, readFixes, verifyFix } from "./run.ts";

const line = (r: FixRecord) =>
  [
    r.status.padEnd(14),
    r.repo,
    r.pr ? `#${r.pr.number}` : "",
    `${r.targeted.length} targeted`,
    r.proof ? `${r.proof.cleared.length} cleared, ${r.proof.remaining.length} remaining, twins ${r.proof.twins ?? "unknown"}` : "",
    r.why.join(" "),
  ]
    .filter(Boolean)
    .join("  ");

async function main(argv: string[]): Promise<number> {
  const a = parseArgs(argv);
  const cmd = a._[0];
  const log = (l: string) => console.error(l);
  const deps = { gh: new GithubClient(), craci: new CraciClient(), agent: claudeAgent, log };
  const repo = typeof a.repo === "string" ? a.repo : "";
  if (cmd === "list") {
    for (const r of await readFixes()) console.log(`${r.id}  ${line(r)}`);
    return 0;
  }
  if (cmd === "propose" && repo) {
    const r = await proposeFix(
      {
        repo,
        scope: a.scope === "all" ? "all" : "high",
        minAgeHours: typeof a["min-age-hours"] === "string" ? Number(a["min-age-hours"]) : undefined,
        craciPrompt: typeof a["craci-prompt"] === "string" ? await readFile(a["craci-prompt"], "utf8") : null,
        dryRun: a["dry-run"] === true,
      },
      deps,
    );
    console.log(line(r));
    if (r.pr) console.log(r.pr.url);
    return r.status === "proposed" || r.status === "nothing-to-fix" ? 0 : 1;
  }
  if (cmd === "publish" && typeof a.id === "string") {
    const r = await publishFix({ id: a.id }, deps);
    console.log(line(r));
    if (r.pr) console.log(r.pr.url);
    return 0;
  }
  if (cmd === "verify" && repo && typeof a.pr === "string") {
    const r = await verifyFix({ repo, pr: Number(a.pr), comment: a["no-comment"] !== true }, deps);
    console.log(line(r));
    return r.status === "proven" || r.status === "partly-proven" ? 0 : 1;
  }
  console.error("usage: fix propose --repo O/R [--scope high|all] [--craci-prompt FILE] [--dry-run] | fix publish --id ID | fix verify --repo O/R --pr N | fix list");
  return 2;
}

if (import.meta.main) process.exit(await main(process.argv.slice(2)));
