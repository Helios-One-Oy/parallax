# Parallax

Every build runs twice. One twin carries fake release keys. If the two don't do the same thing, the release stops.

Built at Junction 2026 for the "Best use of CRACI" challenge. Live console, no login: https://parallax-console.fly.dev (open Replays first).

## The idea

Some malicious packages only act where there is something to steal. They look for a publish token or a release tag first, and in a plain test build they do nothing, so a scan of that build sees nothing.

Parallax runs every build twice on CRACI, side by side. One twin is plain. The other is dressed as a release: a step puts a release tag in its environment and writes npm and AWS keys where malware looks for them. The keys are random but built like real ones, down to the checksum inside an npm token. Honest code does nearly the same thing in both twins. Code that looks for keys does not.

CRACI records every connection and every package of both. Parallax compares the two traces and the two SBOMs. If the dressed twin did something the plain one did not, the verdict job fails and shows the exact request, and the release job, which needs the verdict, never starts.

Most attacks don't bother to hide. For those Parallax uses what else CRACI knows about a build: hosts no earlier run called, caches written by a pull request job, a URL that answers with new content, an image no job of ours built, a package name the registry does not know, and the trace of a run that was deleted on GitHub.

## What it caught

Harmless copies of real attacks, run in our demo repos. Every row on the Replays page links to the real run.

| Attack | Result | Caught by | Push to verdict |
| --- | --- | --- | --- |
| Shai-Hulud npm worm (fires only with an npm token) | caught | twins | 53 s |
| Nx s1ngularity (fires only on a release tag) | caught | twins | 51 s |
| axios (calls a host no earlier run called) | caught | new egress | 55 s |
| TanStack (the build on main restores a cache a pull request job wrote) | caught | cache provenance | 52 s |
| tj-actions (same URL, new content) | caught, after the run | response hash in the trace | 40 s |
| KICS (base image tag moved) | caught | image provenance | 21 s |
| Hallucinated package name | caught | registry 404 in the trace | 97 s |
| Workflow deleted from GitHub after it ran | caught | CRACI still holds its 14 connections and its log | |
| Dormant payload (waits for a date) | missed | | |

Five of the eight were stopped in their own run, before the release job. Of the first 55 twin builds 50 came out clean, 4 were the two hiding packages (each pushed twice) and 1 was a false alarm, which is now a rule: what a twin does before it is dressed is ignored.

## Add it to a repo

About 20 lines of workflow. The build job becomes a matrix of two twins on CRACI, and one small job compares them.

```yaml
jobs:
  build:
    name: build (${{ matrix.twin }})
    runs-on: craci
    strategy:
      fail-fast: false
      matrix:
        twin: [bare, decoy]
    steps:
      - uses: cracicorp/setup@v1
      - uses: actions/checkout@v4
      - uses: Helios-One-Oy/parallax/dress@v0
        with:
          twin: ${{ matrix.twin }}
      - run: plx-run npm ci
      - run: plx-run npm test

  verdict:
    needs: build
    if: always()
    runs-on: ubuntu-latest   # CRACI's API does not answer from inside a CRACI runner
    steps:
      - uses: Helios-One-Oy/parallax/verdict@v0
        with:
          craci-token: ${{ secrets.CRACI_API_TOKEN }}
          github-token: ${{ github.token }}

  release:
    needs: verdict           # never starts if the twins disagree
    runs-on: craci
```

The twins only restore caches and never save them, so a twin cannot poison what the release job trusts.

## What is here

- `dress/`: the action that dresses a twin. It makes no network requests and reads no real secret.
- `verdict/`: the action that reads both traces and SBOMs from CRACI and compares them.
- `src/`, `ui/`: the detectors and the console (Fleet, Rings, Replays, Fixes). Bun and TypeScript.
- `src/fix/`: takes CRACI's fix prompt, lets an agent write the change, checks it at a gate, and reads the SBOM of the pull request's own build to see what is really fixed.
- `specimens/`, `sink/`: the harmless copies of the attacks and the one host they talk to.
- `replays.json`: which run proves which row of the scoreboard.
- `SPEC.md`: the design, and the safety rules for the specimens.

## How it uses CRACI

Every build job here and in the demo repos runs on `runs-on: craci`. Parallax reads `/network-trace`, `/sbom`, `/artifact-provenance` and `/job-logs`, and the fix agent starts from CRACI's AI fix prompt.

## Safety

The specimens are simulations. They never read or send a real secret, never publish anywhere, and only talk to our own host. The fake keys are made at run time and are never committed.

```
bun install
bun test
```
