import { describe, expect, test } from "bun:test";
import { BEFORE_DRESS_RULE, CACHE_RULE, diffTwins, diffTwinsDetailed, FLAP_RULE, policySuggestion, type TwinInput } from "../src/diff.ts";
import { normalizeTrace } from "../src/normalize.ts";
import { dressedAt, reachedBuild, renderMarkdown } from "../src/cli.ts";
import { dnsObs, httpObs, jobRef, npmBuild, sbom, tcpObs, trace } from "./factories.ts";

const PURLS = ["pkg:npm/left-pad@1.3.0", "pkg:npm/%40types/node@22.9.0"];
const bareTwin = (obs = npmBuild(), purls = PURLS): TwinInput => ({
  job: jobRef("70001", "build (bare)"),
  trace: trace(obs, { jobId: "70001", jobName: "build (bare)" }),
  sbom: sbom(purls),
  conclusion: "success",
});
const decoyTwin = (obs = npmBuild(), purls = PURLS): TwinInput => ({
  job: jobRef("70002", "build (decoy)"),
  trace: trace(obs, { jobId: "70002", jobName: "build (decoy)" }),
  sbom: sbom(purls),
  conclusion: "success",
});

describe("diffTwins", () => {
  test("a cache only one twin restored is not a twin divergence (real run 43622842616)", () => {
    // The twins race for the cache: the bare twin got a hit, the decoy a miss. CRACI's SBOM then names the
    // cache entry and the commit of the job that wrote it in one twin only.
    const cache = ["pkg:ghacache/7493989779944505418/7493989779944505563@c242501c?entry_id=6629298651489501765&key=npm-a41f", "pkg:github/Test-Org/test-web@1eb75e65f3ed"];
    const d = diffTwinsDetailed(bareTwin(npmBuild(), [...PURLS, ...cache]), decoyTwin());
    expect(d.verdict.status).toBe("clean");
    expect(d.verdict.ignored.rules).toContain(CACHE_RULE);
    // a package of another repository in one twin only still counts
    expect(diffTwins(bareTwin(), decoyTwin(npmBuild(), [...PURLS, "pkg:github/evil-org/tool@abc"])).status).toBe("divergent");
  });

  test("what one twin did before it was dressed is not counted, what it did after is", () => {
    // Seen in the first real fleet run: the runner checked GitHub's /_dns endpoints in one twin only, at job start.
    // The factory stamps observation i at 10:00:00 + i * 250 ms; the dress step started one second in.
    const dressed = "2026-11-14T10:00:01Z";
    const base = npmBuild();
    const check = httpObs("https://api.github.com/_dns");
    const later = httpObs("https://plx-sink.test/collect", { method: "POST" });
    const earlyObs = [check, ...base]; // the check is observation 0, before the dress step
    const early = diffTwinsDetailed({ ...bareTwin(), dressedAt: dressed }, { ...decoyTwin(earlyObs), dressedAt: dressed });
    expect(early.verdict.status).toBe("clean");
    expect(early.verdict.ignored.rules).toContain(BEFORE_DRESS_RULE);
    const both = diffTwins({ ...bareTwin(), dressedAt: dressed }, { ...decoyTwin([...earlyObs, later]), dressedAt: dressed });
    expect(both.status).toBe("divergent");
    expect(both.divergences.map((d) => d.key)).toEqual(["http POST plx-sink.test/collect"]);
    // No dress step known: nothing is excused.
    expect(diffTwins(bareTwin(), decoyTwin(earlyObs)).status).toBe("divergent");
    const step = (name: string, started_at: string) => ({ name, status: "completed", conclusion: "success", number: 1, started_at });
    expect(dressedAt({ steps: [step("Set up job", "2026-11-14T16:59:13Z"), step("Dress this twin", dressed)] })).toBe(dressed);
    expect(dressedAt({ steps: [step("Run Helios-One-Oy/parallax/dress@main", dressed)] })).toBe(dressed);
    expect(dressedAt({ steps: [step("Run actions/checkout@v4", dressed)] })).toBeNull();
  });

  test("identical twins are clean", () => {
    const v = diffTwins(bareTwin(), decoyTwin());
    expect(v.status).toBe("clean");
    expect(v.divergences).toEqual([]);
    expect(v.stats.bare).toBe(v.stats.decoy);
    expect(v.stats.shared).toBe(v.stats.bare);
    expect(v.repo).toBe("test-org/test-web");
    expect(v.runId).toBe("9001");
    expect(v.twins.decoy.jobId).toBe("70002");
  });

  test("decoy with an extra GET and POST to a new host is divergent with two divergences", () => {
    const extra = [
      httpObs("https://plx-sink.test/stage2/shai-hulud.txt", { ipAddress: "203.0.113.9" }),
      httpObs("https://plx-sink.test/collect", { method: "POST", ipAddress: "203.0.113.9" }),
    ];
    const v = diffTwins(bareTwin(), decoyTwin([...npmBuild(), ...extra]));
    expect(v.status).toBe("divergent");
    expect(v.divergences).toHaveLength(2);
    expect(v.divergences.map((d) => d.key).sort()).toEqual([
      "http GET plx-sink.test/stage2/shai-hulud.txt",
      "http POST plx-sink.test/collect",
    ]);
    for (const d of v.divergences) {
      expect(d.side).toBe("decoy-only");
      expect(d.kind).toBe("http");
      expect(d.host).toBe("plx-sink.test");
      expect(d.why).toContain("Only the decoy twin, which carries fake publish tokens,");
      expect(d.why).toContain("The bare twin never did.");
      expect((d.sample as any).http.originUrl).toContain("plx-sink.test");
    }
    expect(v.stats.decoy).toBe(v.stats.bare + 2);
  });

  test("CDN IP rotation, new signed-URL tokens and reordered observations are clean", () => {
    const decoyObs = npmBuild({ ip: "151.101.2.137", token: "sig-zzzz", guid: "99999999-8888-7777-6666-555555555555" }).reverse();
    // the same host answered from another storage shard
    const moved = decoyObs.map((o) =>
      o.protocol === "http" ? { ...o, http: { ...o.http, originUrl: o.http.originUrl.replace("productionresultssa7", "productionresultssa13") } } : o,
    );
    const v = diffTwins(bareTwin(), decoyTwin(moved));
    expect(v.divergences).toEqual([]);
    expect(v.status).toBe("clean");
  });

  test("a raw IP connection is never hidden behind a name", () => {
    const v = diffTwins(bareTwin(), decoyTwin([...npmBuild(), tcpObs(null, 8443, { remoteIp: "198.51.100.77" })]));
    expect(v.status).toBe("divergent");
    expect(v.divergences[0]!.key).toBe("tcp 198.51.100.77:8443");
    expect(v.divergences[0]!.why).toContain("raw IP address");
  });

  test("a key that flaps in the bare history is ignored, not reported", () => {
    const flappy = [dnsObs("ocsp.flappy.test"), httpObs("http://ocsp.flappy.test/check", { method: "POST" })];
    const base = [...normalizeTrace(trace(npmBuild())).keys.keys()];
    const withFlap = [...normalizeTrace(trace([...npmBuild(), ...flappy])).keys.keys()];
    const history = { bareRuns: [base, withFlap, base, withFlap] };

    const decoySide = diffTwinsDetailed(bareTwin(), decoyTwin([...npmBuild(), ...flappy]), history);
    expect(decoySide.verdict.status).toBe("clean");
    expect(decoySide.verdict.ignored.rules).toContain(FLAP_RULE);
    expect(decoySide.verdict.ignored.count).toBe(2);
    expect(decoySide.ignored.map((i) => i.key)).toContain("dns A ocsp.flappy.test");

    const bareSide = diffTwins(bareTwin([...npmBuild(), ...flappy]), decoyTwin(), history);
    expect(bareSide.status).toBe("clean");
    expect(bareSide.ignored.rules).toEqual([FLAP_RULE]);

    // without history the same difference is reported
    expect(diffTwins(bareTwin(), decoyTwin([...npmBuild(), ...flappy])).status).toBe("divergent");
    // a key never seen in any bare run is still reported, history or not
    const fresh = diffTwins(bareTwin(), decoyTwin([...npmBuild(), httpObs("https://plx-sink.test/collect", { method: "POST" })]), history);
    expect(fresh.status).toBe("divergent");
  });

  test("noise rules are counted as ignored with their rule name", () => {
    const v = diffTwins(bareTwin(), decoyTwin([...npmBuild(), httpObs("https://dc.services.visualstudio.com/v2/track", { method: "POST" })]));
    expect(v.status).toBe("clean");
    expect(v.ignored).toEqual({ count: 1, rules: ["runner-telemetry"] });
  });

  test("missing or empty trace, or a twin that died before the build, is inconclusive", () => {
    const missing = diffTwinsDetailed(bareTwin(), { job: jobRef("70002", "build (decoy)"), trace: null, sbom: null, meta: { repo: "test-org/test-web", runId: "9001" } });
    expect(missing.verdict.status).toBe("inconclusive");
    expect(missing.verdict.divergences).toEqual([]);
    expect(missing.notes.join(" ")).toContain("decoy twin has no network trace");

    const empty = diffTwins(bareTwin([]), decoyTwin());
    expect(empty.status).toBe("inconclusive");

    const early = diffTwins(bareTwin(), { ...decoyTwin(npmBuild().slice(0, 4)), conclusion: "failure", reachedBuild: false });
    expect(early.status).toBe("inconclusive");
    expect(early.divergences).toEqual([]);

    const noBare = diffTwins({ job: jobRef("", "build (bare)", "missing"), trace: null, meta: { repo: "test-org/test-web", runId: "9001" } }, decoyTwin());
    expect(noBare.status).toBe("inconclusive");
  });

  test("an SBOM-only difference becomes a package divergence", () => {
    const v = diffTwins(bareTwin(), decoyTwin(npmBuild(), [...PURLS, "pkg:npm/plx-specimen@9.9.9?checksum=sha1:abc"]));
    expect(v.status).toBe("divergent");
    expect(v.divergences).toHaveLength(1);
    const d = v.divergences[0]!;
    expect(d.kind).toBe("package");
    expect(d.side).toBe("decoy-only");
    expect(d.key).toBe("pkg:npm/plx-specimen@9.9.9");
    expect((d.sample as any).purl).toContain("plx-specimen");
    expect(d.why).toContain("SBOM");
  });

  test("novelInFleet comes from the fleet lookup and only then", () => {
    const extra = [httpObs("https://plx-sink.test/collect", { method: "POST" }), httpObs("https://old-friend.test/ping", { method: "POST" })];
    const fleet = { seenBefore: (_k: "host" | "purl", value: string) => value === "old-friend.test" };
    const v = diffTwins(bareTwin(), decoyTwin([...npmBuild(), ...extra]), { fleet });
    const by = Object.fromEntries(v.divergences.map((d) => [d.host, d]));
    expect(by["plx-sink.test"]!.novelInFleet).toBe(true);
    expect(by["plx-sink.test"]!.why).toContain("No earlier job in the fleet has contacted plx-sink.test.");
    expect(by["old-friend.test"]!.novelInFleet).toBe(false);
    const noFleet = diffTwins(bareTwin(), decoyTwin([...npmBuild(), ...extra]));
    expect(noFleet.divergences.every((d) => d.novelInFleet === false)).toBe(true);
  });

  test("a blocked request says so in plain words", () => {
    const v = diffTwins(bareTwin(), decoyTwin([...npmBuild(), httpObs("https://plx-sink.test/collect", { method: "POST", statusCode: 403, policyDenied: true, denyReason: "no_match" })]));
    expect(v.divergences[0]!.why).toContain("CRACI's network policy blocked it (no_match).");
  });
});

describe("policySuggestion", () => {
  test("renders valid YAML that allows the bare twin's needs and nothing from the decoy", () => {
    const extra = [httpObs("https://plx-sink.test/collect", { method: "POST" })];
    const bareObs = [...npmBuild(), tcpObs("db.internal.test", 5432, { tlsServerName: null, tlsAlpn: [], resolvedHosts: ["db.internal.test"] })];
    const v = diffTwins(bareTwin(bareObs), decoyTwin([...bareObs, ...extra]));
    const p = policySuggestion(v);
    const doc = Bun.YAML.parse(p.yaml) as any;
    expect(doc.default).toBe("deny");
    expect(doc.presets).toEqual(["github", "npm"]);
    expect(doc.connections).toEqual([
      { tls: { serverNamePatterns: ["example-docs.test"], ports: [443] } },
      { tcp: { hostPatterns: ["db.internal.test"], ports: [5432] } },
    ]);
    expect(p.yaml).not.toContain("plx-sink.test/");
    expect(JSON.stringify(doc)).not.toContain("plx-sink.test");
    expect(p.blocked).toEqual(["plx-sink.test"]);
    // only fields the CRACI schema knows
    expect(Object.keys(doc).sort()).toEqual(["connections", "default", "presets"]);

    const step = Bun.YAML.parse(p.step) as any;
    expect(step[0].uses).toBe("cracicorp/setup@v1");
    expect((Bun.YAML.parse(step[0].with.network) as any).default).toBe("deny");

    // a verdict loaded from disk needs the trace passed in
    const loaded = JSON.parse(JSON.stringify(v));
    expect(() => policySuggestion(loaded)).toThrow();
    expect(policySuggestion(loaded, trace(bareObs)).yaml).toBe(p.yaml);
  });
});

describe("report helpers", () => {
  test("markdown summary has the status line, the table and the counts", () => {
    const d = diffTwinsDetailed(bareTwin(), decoyTwin([...npmBuild(), httpObs("https://plx-sink.test/a|b", { method: "POST" })]));
    const md = renderMarkdown(d);
    expect(md).toContain("Divergent");
    expect(md).toContain("| Side | What | Why |");
    expect(md).toContain("| decoy only | `http POST plx-sink.test/a\\|b` |");
    expect(md).toContain(`Seen in both twins: ${d.verdict.stats.shared}`);
    expect(md).toContain("Ignored as noise: 0");
  });

  test("reachedBuild reads the GitHub steps", () => {
    const step = (name: string, conclusion: string | null) => ({ name, status: "completed", conclusion, number: 1 });
    expect(reachedBuild({ conclusion: "success", steps: [] })).toBe(true);
    expect(reachedBuild({ conclusion: "failure", steps: [step("Set up job", "success"), step("Run actions/checkout@v4", "failure"), step("Run plx-run npm ci", "skipped")] })).toBe(false);
    expect(reachedBuild({ conclusion: "failure", steps: [step("Set up job", "success"), step("Run oven-sh/setup-bun@v2", "success"), step("Run plx-run npm ci", "failure")] })).toBe(true);
    expect(reachedBuild({ conclusion: "failure" })).toBeUndefined();
  });
});

describe("a twin that failed part way", () => {
  const half = npmBuild().slice(0, 8);
  test("bare failed, decoy did not: inconclusive, never a false alarm", () => {
    const v = diffTwins({ ...bareTwin(half), conclusion: "failure", reachedBuild: true }, decoyTwin());
    expect(v.status).toBe("inconclusive");
    expect(v.divergences).toEqual([]);
  });
  test("decoy failed: what only the bare twin did is ignored, what only the decoy did still counts", () => {
    const quiet = diffTwins(bareTwin(), { ...decoyTwin(half), conclusion: "failure", reachedBuild: true });
    expect(quiet.status).toBe("clean");
    expect(quiet.ignored.rules).toEqual(["decoy-stopped-early"]);
    const loud = diffTwins(bareTwin(), { ...decoyTwin([...half, httpObs("https://plx-sink.test/collect", { method: "POST", statusCode: 403, policyDenied: true, denyReason: "no_match" })]), conclusion: "failure", reachedBuild: true });
    expect(loud.status).toBe("divergent");
    expect(loud.divergences.map((d) => d.key)).toEqual(["http POST plx-sink.test/collect"]);
  });
});

describe("policySuggestion with our own sink registry", () => {
  test("the registry part of the sink is a package source; its /collect stays blocked", async () => {
    const { SINK_HOST, SINK_URL } = await import("../src/rules.ts");
    const registry = [
      dnsObs(SINK_HOST),
      tcpObs(SINK_HOST, 443),
      httpObs(`${SINK_URL}/registry/@nbd%2ftelemetry-utils`),
      httpObs(`${SINK_URL}/registry/tarballs/telemetry-utils-2.1.1.tgz`),
    ];
    const attack = [httpObs(`${SINK_URL}/stage2/shai-hulud`), httpObs(`${SINK_URL}/collect`, { method: "POST" })];
    const v = diffTwins(bareTwin([...npmBuild(), ...registry]), decoyTwin([...npmBuild(), ...registry, ...attack]));
    expect(v.divergences.map((d) => d.key)).toEqual([`http GET ${SINK_HOST}/stage2/shai-hulud`, `http POST ${SINK_HOST}/collect`]);
    const p = policySuggestion(v);
    const doc = Bun.YAML.parse(p.yaml) as any;
    expect(doc.sources).toEqual([{ npm: { urls: [`${SINK_URL}/registry`] } }]);
    expect(JSON.stringify(doc.connections)).not.toContain(SINK_HOST);
    expect(p.blocked).toEqual([SINK_HOST]);
  });
});
