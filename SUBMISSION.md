# Parallax

**Punchline:** Every build runs twice. One twin carries fake release keys. If the two don't do the same thing, the release stops.

**Challenge:** Best use of CRACI (tech challenge)

**Demo:** https://parallax-console.fly.dev

**Source:** https://github.com/Helios-One-Oy/parallax

**Film:** https://youtu.be/T3MuWHmWIh0

## Description

The demo needs no login. Start on Replays, every row links to the real run.

Some malware only acts when there is something to steal. It looks for an npm token or a release tag first. A test build has neither, so it does nothing there and a scan comes back clean.

Parallax runs every build twice on CRACI. The bare twin is the plain build. The decoy twin looks like a release and carries a fake npm token and fake AWS keys. CRACI records every connection and every package of both. If one twin does something the other doesn't, the release never starts.

We made two harmless packages that hide like this. One waits for an npm token, which is what the Shai-Hulud worm needed to spread. The other waits for a release tag. Both were stopped, 53 and 51 seconds after the push.

Most attacks don't hide, so we replayed seven more as harmless copies. Five of the nine were stopped before the release job started and two were seen but not stopped. In one, the run is deleted from GitHub afterwards to hide it, and CRACI still had its 14 connections and the log. A time bomb that waits for a date got past us.

## How we used CRACI

- We diff the `/network-trace` of the two twins. Compared with earlier runs it also caught a new dependency calling a host that 11 runs had never called.
- The trace keeps a hash of every response, so we saw one URL start serving new content.
- `/artifact-provenance` names the job that wrote a cache or an image. A pull request job had written the cache that main restored, and 16 jobs had restored it.
- `/sbom` listed 5 critical and high vulnerabilities in our demo repo. An agent wrote the fix from CRACI's AI fix prompt, its pull request went through the twins too, and the next SBOM had 1 left.
- `/job-logs` is where the deleted run's log came from.

Every build job in our 4 repos runs on CRACI, 160 traced so far. The first 59 twin builds gave one false alarm. The runner looked up GitHub in one twin before the build began, and we now ignore anything before the twins are set up.

Adding it to a repo is two actions and a prefix on the build commands. One action sets up the twins and one compares them. The twins run side by side and the verdict takes about 30 seconds.

## Technologies

CRACI runners and API, GitHub Actions, Bun, TypeScript, Fly.io, Claude Fable 5.2 for the fix agent.
