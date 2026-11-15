# Parallax

**Punchline:** Every build runs twice. One twin carries fake release keys. If the two don't do the same thing, the release stops.

**Challenge:** Best use of CRACI (tech challenge)

**Demo:** https://parallax-console.fly.dev

**Source:** https://github.com/Helios-One-Oy/parallax

**Film:** https://youtu.be/T3MuWHmWIh0

## Description

The demo needs no login. Start on Replays, every row links to the real run.

Some malware only acts when there is something to steal. It looks for an npm token or a release tag first. A test build has neither, so it does nothing and a scan comes back clean.

Parallax runs every build twice on CRACI. The decoy twin looks like a release and carries fake npm and AWS keys. The bare twin is the plain build. CRACI records every connection and package of both, and if one twin does something the other doesn't, the release never starts.

We replayed nine attacks as harmless copies. Five were stopped before the release job started. Two of those wait for a token or a tag, and were stopped 53 and 51 seconds after the push. Two were seen but not stopped. In one the run was deleted from GitHub afterwards, and CRACI still had it. A time bomb got past us.

## How we used CRACI

- `/network-trace` is what we diff between the twins. It also showed a host that 11 earlier runs never called, and a URL that started serving new content.
- `/artifact-provenance` showed that the cache the main branch restored was written by a pull request job. 16 jobs had restored it.
- `/sbom` listed 5 critical and high vulnerabilities. An agent wrote a fix from CRACI's AI fix prompt, its pull request went through the twins too, and the next SBOM had 1 left.
- `/job-logs` still had the log of the deleted run.

One false alarm in the first 59 twin builds. Adding Parallax to a repo takes two GitHub Actions and a prefix on the build commands.

## Technologies

CRACI runners and API, GitHub Actions, Bun, TypeScript, Fly.io, Claude Fable 5.2 for the fix agent.
