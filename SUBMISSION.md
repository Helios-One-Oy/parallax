# Parallax

**Punchline:** Every build runs twice. One twin carries fake release keys. If the two don't do the same thing, the release stops.

**Challenge:** Best use of CRACI (tech challenge)

**Demo:** https://parallax-console.fly.dev

**Source:** https://github.com/Helios-One-Oy/parallax

## Description

Some malicious packages only act where there is something to steal. They look for a publish token or a release tag first, and in a plain test build they do nothing, so a scan of that build sees nothing.

Parallax runs every build twice on CRACI, side by side. One twin is plain. The other is dressed as a release: a step puts a release tag in its environment and writes npm and AWS keys where malware looks for them (the environment and two key files, .npmrc and ~/.aws). The keys are random but built like real ones, down to the checksum inside an npm token. Honest code does nearly the same thing in both twins. Code that looks for keys does not.

CRACI records every connection and every package of both. We compare the two traces and the two SBOMs, and if the dressed twin did something the plain one did not, the verdict job fails and shows the exact request. The release job needs the verdict, so it never starts. The real release keys never enter either twin. A payload that goes online to test the key gives itself away with that one call.

We tried it on two harmless packages of our own that hide this way. One fires only when it finds an npm token, which is what the Shai-Hulud worm needed to spread. The other fires only on a release tag. Both were stopped, 53 and 51 seconds after the push.

Honest builds differ a little too. So we ignore any URL that clean builds call only now and then. Of the first 55 twin builds 50 came out clean and 4 were the two hiding packages, each pushed twice. One was a false alarm: the runner itself called GitHub in only one twin before the build began. Since then we ignore everything before the dress step. The second twin doubles the build. In our demo repos that is 13 to 36 seconds of runner time per push.

Most attacks don't bother to hide, and for those we use what else CRACI knows about a build. We replayed seven as harmless copies in our demo repos. Five were caught, three of them in time to stop their own release. A sixth got through, but after it deleted its own run CRACI still had the record. The seventh got past us: a time bomb, a package that does nothing until a set date.

- axios: both twins called a host that none of the repo's 11 earlier runs had called.
- TanStack: the build on main restored a cache that a pull request job had written. CRACI's cache provenance names the writer.
- tj-actions: the same URL answered with different content than last time. CRACI's trace carries a hash of the response.
- KICS: the tag of our own base image moved to a digest that none of our jobs built. CRACI's image provenance has no record of it.
- A package name that does not exist, the kind coding assistants invent: the install asked the registry for it. Whoever registers it next decides what that build installs.
- A workflow that posts to a hard-coded IP address and is then deleted from GitHub: CRACI still holds its 14 connections and its log, with the address in it.

For each catch you can ask where else it went: every other job that used the same package, host, cache or content.

The same distrust goes for fixes. CRACI's AI fix prompt asks for an audit and leaves the change to you. We copy it from the job page and hand it to an agent that does both. We don't trust the agent either: a bot that bumps dependencies is a fast way to install a hijacked release. Its pull request goes through the twins like any other, and the SBOM of that build decides what is really fixed. On the first real run 4 of the 5 critical and high vulnerabilities were gone, and the total went from 32 to 12.

The demo needs no login. Open the Replays page first: every row links to the real run.

## How we used CRACI

Every build job in the demo repos and in Parallax itself runs on `runs-on: craci`. We read `/network-trace`, `/sbom`, `/artifact-provenance` and `/job-logs`, and the fix agent starts from CRACI's AI fix prompt. Adding Parallax to a repo is about 20 lines of workflow: the dress step in the build job, and the verdict job after it. The API does not answer calls from inside a CRACI runner, so that one small verdict job runs on a GitHub runner.

## Technologies

CRACI runners and API, GitHub Actions, Bun, TypeScript, Python, Fly.io, Claude Fable 5.2 for the fix agent.
