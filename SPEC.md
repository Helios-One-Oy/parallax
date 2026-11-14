# Parallax: a build immune system on CRACI

Junction 2026, challenge "Best use of CRACI" ("Make every build your first line of defence"). Judging: 50% technical depth, 50% creative use of CRACI's features (SBOMs, provenance, network traces, API, AI fixes). Research and prior art: `../RESEARCH.md`. CRACI docs and OpenAPI spec: `../research/dl/` (read `openapi.json`, `guides_setup-action-network.md`, `guides_cache-sbom-completeness.md`).

## The idea in three sentences

Malware in a dependency behaves differently when it smells a release (publish tokens, a tag ref, a later date). So before the real release job ever sees a secret, every build runs twice on CRACI runners: a **bare** twin and a **decoy** twin dressed as a release with fake credentials. CRACI records every connection both make; any connection only one twin makes is the alarm, and the real release job never starts.

When something is caught, CRACI's cache and image provenance tell us where it already spread (**contact tracing**), and Parallax ring-fences it. A **replay range** runs harmless simulations of the real attacks of 2025 and 2026 against the fleet and scores which ones are stopped.

## Parts

| Part | Where | What |
|---|---|---|
| Dress action | `dress/` | Composite GitHub Action. Input `twin: bare|decoy`. Decoy: writes fake credential files, exports fake credential env vars, puts `plx-run` on PATH. Bare: only puts a passthrough `plx-run` on PATH. |
| `plx-run` | `dress/plx-run` | Wrapper for build commands: `plx-run npm ci`. Decoy twin: runs the command with release-looking `GITHUB_*` values (tag ref, `release` event). Bare: `exec "$@"`. |
| Verdict | `src/`, `verdict/` action | After both twins finish: fetch both jobs' network traces and SBOMs from the CRACI API, normalise, diff, write the job summary, fail on divergence. |
| Contact tracing | `src/graph.ts` | Graph of jobs, packages, fetched URL+hash, caches, image layers; rings from a seed; ring-fence actions through the GitHub API. |
| Console | `src/server.ts`, `ui/` | Live fleet view, twin view, rings, replay scoreboard. |
| Specimens | `specimens/` | Harmless simulated malicious packages (see safety rules). |
| Sink | `sink/` | Our own endpoint the specimens call, plus a static registry that serves the specimen tarballs. Deployed on Fly as `parallax-sink`. |
| Fleet | `../fleet/web`, `../fleet/api`, `../fleet/base` | Demo repos (`Helios-One-Oy/parallax-demo-web|api|base`) whose CI runs on `runs-on: craci`. Attack replays are pull requests in them. |

## Safety rules for specimens (not negotiable)

- A specimen never reads, prints, stores or sends a real secret or any file content. It only checks *whether* a trigger condition holds (an env var name exists, a file exists, the ref looks like a tag, the date is past X).
- When triggered it does exactly this: one GET for a "second stage" (a small text file) and one POST with the constant JSON `{"specimen": "<id>", "run": "<GITHUB_RUN_ID or 'local'>"}`, both to our own sink. Nothing else: no other hosts, no cloud metadata addresses, no file writes outside the temp dir, no process spawning beyond what is needed for the two requests.
- Specimens are never published to npm, PyPI, Docker Hub or any public registry. They are served only from our own sink under clearly fake names, and every specimen's README and package description says "Parallax specimen: harmless simulation of <incident>".
- Decoy credentials are random strings with the right prefix and length, generated at run time, never committed. They must not make honest tools fail or behave differently (for example never put a fake token for `registry.npmjs.org` in `.npmrc`: npm would send it and get 401).
- The sink base URL comes from one place (`PLX_SINK_URL`, default `https://parallax-sink.fly.dev`) so tests can point at localhost.

## Contracts

CRACI API (`https://api.craci.com`, `Authorization: Bearer $CRACI_API_TOKEN`; token file `~/.config/crashtest/craci.token`, never print it):
- `GET /v1preview1/jobs?status=active`, `GET /v1preview1/job-logs?provider=github&repo=O/R&job_id=N[&follow=true]`
- `GET /v1preview1/network-trace?provider=github&repo=O/R&job_id=N` → `NetworkTrace` (`observations[]`, each `protocol: http|dns|tcp|ssh_git`)
- `GET /v1preview1/sbom?provider=github&repo=O/R&job_id=N` → CycloneDX
- `GET /v1preview1/artifact-provenance/gha_cache|oci_blob|oci_manifest`, `GET /v1experimental1/sbom/oci_manifest`
- The API answers 403 "Access denied" to calls made from inside a CRACI runner (every network mode, tested 14 Nov). The verdict job therefore runs on `ubuntu-latest`; only it.
- The token is per CRACI organization: ours is "Helios One" (GitHub org `Helios-One-Oy`). `~/.config/crashtest/craci.token` is that token.
- Finished jobs are not listed by CRACI: enumerate runs and jobs through the GitHub API (`gh api repos/O/R/actions/runs`, `.../runs/ID/jobs`).

Twin job names: `build (bare)` and `build (decoy)` (a matrix `twin: [bare, decoy]` on one job id `build`).

`Verdict` (written to `/bulk3/runs/craci/verdicts/<repo>/<runId>.json` and shown in the console):
```ts
type Verdict = {
  repo: string; runId: string; commitSha: string; branch: string;
  twins: { bare: JobRef; decoy: JobRef };          // JobRef = { jobId, name, status, url }
  status: "clean" | "divergent" | "inconclusive";  // inconclusive = a trace missing or a twin failed for another reason
  divergences: Divergence[];
  ignored: { count: number; rules: string[] };     // noise that was filtered and why
  stats: { bare: number; decoy: number; shared: number };  // normalised observation counts
  createdAt: string;
};
type Divergence = {
  side: "decoy-only" | "bare-only";
  kind: "http" | "dns" | "tcp" | "ssh_git" | "package";
  key: string;            // normalised identity, e.g. "http GET parallax-sink.fly.dev/stage2/*"
  host: string;
  sample: unknown;        // the raw CRACI observation or SBOM component
  novelInFleet: boolean;  // host or package never seen in any earlier job of the fleet
  why: string;            // one plain sentence
};
```

## Replay range (attack simulations)

Each replay is a pull request in a fleet repo. Scoreboard columns: incident, how it got in, what Parallax saw, which organ caught it (twins / new egress / cache lineage / URL-hash drift / image provenance), time to verdict, and honestly "missed" where it was missed.

| id | Real incident | Simulation | Expected catch |
|---|---|---|---|
| `shai-hulud` | Shai-Hulud npm worm, Sep and Nov 2025 | dependency update whose code fires only if an npm token is present (env or `.npmrc`) | twins (decoy-only connections) |
| `release-gate` | Nx s1ngularity, Aug 2025 (CI-aware payload) | fires only when the ref is a tag and the event is `release` | twins |
| `fresh-host` | axios, 31 Mar 2026 | new dependency that calls a never-seen host on every build | new egress (both twins do it, so twins alone miss it) |
| `pth` | LiteLLM, 24 Mar 2026 | Python package with a `.pth` file that fires at interpreter start if cloud keys are present | twins |
| `cache-poison` | TanStack, 11 May 2026; Ultralytics, Dec 2024 | a pull-request job saves a cache under the key the release job restores | cache lineage (CRACI cache provenance) |
| `tag-repoint` | tj-actions, Mar 2025; Trivy action, Mar 2026 | a script fetched by a mutable URL returns new bytes | URL-hash drift (CRACI body hashes) |
| `image-repoint` | KICS image, 22 Apr 2026 | base image tag moves to a digest no job of ours produced | image provenance |
| `time-bomb` | dormant payloads (XZ-style patience) | fires only after a date | future-clock twin (stretch) |
| `log-wipe` | wfx-loot, 10–12 Nov 2026 | workflow posts to a raw IP then the run is deleted | CRACI trace survives off GitHub |
| `slopsquat` | hallucinated package names, 2026 | install asks the registry for a name that does not exist | registry 404s pooled across the fleet |

## What the first real runs taught us (14 Nov, evening)

State: `Helios-One-Oy/parallax-demo-web` runs twins, verdict and release on every push and pull request; the console is live at https://parallax-console.fly.dev (the box pushes to it). Replays `shai-hulud` and `release-gate` are caught by the twins. `fresh-host` and `time-bomb` are not caught yet.

- The CRACI API is closed to CRACI runners, so the verdict job is `runs-on: ubuntu-latest`. Everything else stays `runs-on: craci`.
- Fleet workflows use the actions as `Helios-One-Oy/parallax/dress@v0` and `.../verdict@v0`. `main` moves all the time; a push that lands between the two twins makes them fetch different action code and the verdict (correctly) calls that divergent. After changing `dress/`, `verdict/` or `src/`: push `main`, then move the tag (`git tag -f v0 && git push -f origin v0`) only while no fleet run is queued or running.
- CRACI runners set `LOG_LEVEL` themselves. Docker Hub answers 429 to CRACI's shared addresses; `public.ecr.aws` and `ghcr.io` refused anonymous pull tokens inside `docker build`; `mirror.gcr.io/library/*`, `quay.io` and `cgr.dev` work. `RUN npm ci` inside `docker build` got no usable network, so images copy what the runner built. Pushing to `ghcr.io/helios-one-oy/*` with `github.token` and `packages: write` works.
- One twin's runner sometimes calls GitHub's `/_dns` endpoints at job start. The diff ignores what a twin did before its dress step started (`before-the-twins-differed`).
- CRACI bills Helios One by the minute. Runner size "2" or smaller, no retry loops, cancel runs you do not need.

## Rules for everyone working here

- No invented data: every number and row on screen comes from a real CRACI job or a real GitHub object. Unknown stays empty.
- Secrets never printed or written into files. `hsec exec --only NAME -- cmd` for vault values.
- `rm` only literal paths. Run output (traces, SBOMs, logs) goes to `/bulk3/runs/craci/`, not into the repos.
- The box must stay light: no heavy local builds, no new Docker images (use plain local processes for tests).
- Git: commit only the paths you own with `git add <paths>` (several agents share this checkout; retry if `index.lock` is busy). Push your own commits (`git pull --rebase` first; never force-push `main`). Commit author as configured; end commit messages with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.
- Stack: Bun 1.4 + TypeScript, no framework unless needed. Plain words in all UI and docs text.
