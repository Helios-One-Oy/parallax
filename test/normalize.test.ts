import { describe, expect, test } from "bun:test";
import { DEFAULT_RULES, normalizeObservation, normalizeTrace, parseDnsRecord } from "../src/normalize.ts";
import { dnsObs, httpObs, sshGitObs, tcpObs, trace } from "./factories.ts";

const key = (o: Parameters<typeof normalizeObservation>[0]) => normalizeObservation(o)!.key;

describe("normalize", () => {
  test("npm tarball keeps its path, loses the query", () => {
    expect(key(httpObs("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz?cache=1"))).toBe(
      "http GET registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
    );
    expect(key(httpObs("https://registry.npmjs.org/@types%2fnode"))).toBe("http GET registry.npmjs.org/@types/node");
  });

  test("volatile path parts are replaced", () => {
    expect(key(httpObs("https://productionresultssa3.blob.core.windows.net/actions-cache/aaaa-bbbb/c.tzst?sig=1"))).toBe(
      "http GET productionresultssa*.blob.core.windows.net/actions-cache/*",
    );
    expect(key(httpObs("https://files.pythonhosted.org/packages/ab/cd/0123456789abcdef/requests-2.32.3-py3-none-any.whl"))).toBe(
      "http GET files.pythonhosted.org/packages/*/requests-2.32.3-py3-none-any.whl",
    );
    expect(key(httpObs("https://cdn.thing.test/dl/11111111-2222-3333-4444-555555555555/1731578400/tool.tar.gz"))).toBe(
      "http GET cdn.thing.test/dl/{guid}/{time}/tool.tar.gz",
    );
    expect(key(httpObs("https://ghcr.io/v2/test-org/base/blobs/uploads/9f8e7d6c-1111-2222-3333-444444444444?_state=x", { method: "PATCH" }))).toBe(
      "http PATCH ghcr.io/v2/test-org/base/blobs/uploads/*",
    );
    const digest = "sha256:" + "ab".repeat(32);
    expect(key(httpObs(`https://ghcr.io/v2/test-org/base/blobs/${digest}`))).toBe(`http GET ghcr.io/v2/test-org/base/blobs/${digest}`);
  });

  test("an unknown storage account is not folded into GitHub's", () => {
    expect(key(httpObs("https://attackerstore.blob.core.windows.net/loot/x", { method: "PUT" }))).toBe(
      "http PUT attackerstore.blob.core.windows.net/loot/x",
    );
  });

  test("a URL recorded without a scheme still gets its host", () => {
    expect(key(httpObs("plx-sink.test:443", { method: "CONNECT" }))).toBe("http CONNECT plx-sink.test/");
    expect(normalizeObservation(httpObs("plx-sink.test/collect", { method: "POST" }))!.host).toBe("plx-sink.test");
  });

  test("non-default ports stay in the key", () => {
    expect(key(httpObs("http://plx-sink.test:8080/collect", { method: "POST" }))).toBe("http POST plx-sink.test:8080/collect");
  });

  test("DNS by record name and type, whatever the order", () => {
    expect(parseDnsRecord("registry.npmjs.org A")).toEqual({ name: "registry.npmjs.org", type: "A" });
    expect(parseDnsRecord("AAAA Registry.NPMJS.org.")).toEqual({ name: "Registry.NPMJS.org.", type: "AAAA" });
    expect(parseDnsRecord("example.test/TXT")).toEqual({ name: "example.test", type: "TXT" });
    expect(parseDnsRecord("example.test. IN A")).toEqual({ name: "example.test.", type: "A" });
    expect(key(dnsObs("Registry.NPMJS.org.", "AAAA"))).toBe("dns AAAA registry.npmjs.org");
    expect(key({ ...dnsObs("x"), dns: { nameserverIp: "10.0.0.2", record: "weird.test", response: "" } })).toBe("dns weird.test");
  });

  test("TCP by SNI, then resolved host, raw IP only when nothing else", () => {
    expect(key(tcpObs("registry.npmjs.org", 443, { remoteIp: "1.1.1.1" }))).toBe("tcp registry.npmjs.org:443");
    expect(key(tcpObs(null, 5432, { resolvedHosts: ["db.internal.test"], remoteIp: "10.1.2.3" }))).toBe("tcp db.internal.test:5432");
    expect(key(tcpObs(null, 443, { remoteIp: "169.254.169.254" }))).toBe("tcp 169.254.169.254:443");
    // several names on one IP: the one the job itself asked for wins
    const t = trace([dnsObs("b.shared-cdn.test"), tcpObs(null, 443, { resolvedHosts: ["a.shared-cdn.test", "b.shared-cdn.test"] })]);
    expect([...normalizeTrace(t).keys.keys()]).toContain("tcp b.shared-cdn.test:443");
  });

  test("ssh_git by host, repo path and service", () => {
    expect(key(sshGitObs("github.com", "/test-org/private-lib.git"))).toBe("ssh_git github.com/test-org/private-lib git-upload-pack");
    expect(key(sshGitObs("git.internal.test", "team/repo", { port: 2222, service: "git-receive-pack" }))).toBe(
      "ssh_git git.internal.test:2222/team/repo git-receive-pack",
    );
  });

  test("noise is kept apart with its rule and the raw observation stays attached", () => {
    const raw = httpObs("https://dc.services.visualstudio.com/v2/track", { method: "POST" });
    const nt = normalizeTrace(trace([raw, httpObs("https://registry.npmjs.org/left-pad")]));
    expect(nt.keys.size).toBe(1);
    expect(nt.noise.size).toBe(1);
    const n = [...nt.noise.values()][0]![0]!;
    expect(n.rule).toBe("runner-telemetry");
    expect(n.noise).toContain("telemetry");
    expect((n.raw as any).http.originUrl).toBe(raw.http.originUrl);
  });

  test("tolerant: unknown protocols and extra fields do not break anything", () => {
    const odd = { sequence: 0, observedAt: "2026-11-14T10:00:00Z", protocol: "quic", quic: { host: "x" } } as any;
    const extra = { ...httpObs("https://registry.npmjs.org/left-pad"), futureField: { a: 1 } } as any;
    const nt = normalizeTrace({ observations: [odd, extra, null as any] });
    expect(nt.unknown).toHaveLength(2);
    expect(nt.keys.size).toBe(1);
    expect(normalizeTrace(null).keys.size).toBe(0);
  });

  test("a new rule is one line", () => {
    const rs = { ...DEFAULT_RULES, rules: [{ name: "sink-stage2", proto: ["http" as const], host: /^plx-sink\.test$/, path: /^\/stage2\/.*$/, to: "/stage2/*" }, ...DEFAULT_RULES.rules] };
    expect(normalizeObservation(httpObs("https://plx-sink.test/stage2/abc.txt"), rs)!.key).toBe("http GET plx-sink.test/stage2/*");
  });
});
