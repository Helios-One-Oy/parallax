// Turn a CRACI NetworkTrace into normalised observation keys that are the same for two runs of the
// same build. All patterns live in rules.ts; this file only applies them.
import {
  HOST_RULES,
  RULES,
  SEGMENT_RULES,
  type HostRule,
  type Kind,
  type Rule,
  type SegmentRule,
} from "./rules.ts";
import type { NetworkObservation, NetworkTrace } from "./types.ts";

export type RuleSet = { hostRules: HostRule[]; rules: Rule[]; segmentRules: SegmentRule[] };
export const DEFAULT_RULES: RuleSet = { hostRules: HOST_RULES, rules: RULES, segmentRules: SEGMENT_RULES };

export type NormObs = {
  key: string;
  kind: Kind;
  host: string;
  /** Name of the rule that shaped the key or dropped it; null = generic handling. */
  rule: string | null;
  /** Reason when the observation is noise. */
  noise: string | null;
  raw: NetworkObservation;
};

export type NormTrace = {
  /** Non-noise observations by key. */
  keys: Map<string, NormObs[]>;
  /** Noise observations by key. */
  noise: Map<string, NormObs[]>;
  /** Observations whose protocol this code does not know (kept, never diffed). */
  unknown: unknown[];
  total: number;
};

const RR_TYPES = new Set([
  "A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "PTR", "SOA", "HTTPS", "SVCB", "CAA", "NAPTR", "DS", "DNSKEY", "ANY",
]);

export function isIp(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || (host.includes(":") && /^[0-9a-f:.]+$/i.test(host));
}

export function canonHost(host: string, rs: RuleSet = DEFAULT_RULES): string {
  let h = String(host ?? "").trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  for (const r of rs.hostRules) {
    if (r.match.test(h)) {
      h = h.replace(r.match, r.to);
      break;
    }
  }
  return h;
}

function cleanPath(pathname: string): string {
  let p = pathname.replace(/%2f/gi, "/").replace(/\/{2,}/g, "/");
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p || "/";
}

function scrubPath(path: string, rs: RuleSet): string {
  return path
    .split("/")
    .map((seg) => {
      for (const r of rs.segmentRules) if (r.match.test(seg)) return r.to;
      return seg;
    })
    .join("/");
}

function findRule(kind: Kind, host: string, path: string | null, rs: RuleSet): Rule | null {
  for (const r of rs.rules) {
    if (r.proto && !r.proto.includes(kind)) continue;
    if (!r.host.test(host)) continue;
    if (kind === "http") {
      if (r.path && !r.path.test(path ?? "")) continue;
    } else if (!r.noise) {
      continue; // path rules mean nothing outside HTTP
    }
    return r;
  }
  return null;
}

export function parseDnsRecord(record: string): { name: string; type: string } {
  let name = "";
  let type = "";
  for (const tok of String(record ?? "").trim().split(/[\s/,;|]+/).filter(Boolean)) {
    const up = tok.toUpperCase();
    if (!type && RR_TYPES.has(up) && (name || !tok.includes("."))) type = up;
    else if (up === "IN") continue;
    else if (!name) name = tok;
  }
  return { name: name || String(record ?? "").trim(), type };
}

/** Split an HTTP origin URL into canonical host (with a non-default port) and cleaned path. */
export function splitUrl(originUrl: string, rs: RuleSet = DEFAULT_RULES): { host: string; hostPort: string; path: string } | null {
  try {
    // Tolerate a URL recorded without a scheme ("host:443", "host/path").
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(originUrl) ? originUrl : `https://${originUrl}`);
    if (!u.hostname) return null;
    const host = canonHost(u.hostname, rs);
    return { host, hostPort: u.port ? `${host}:${u.port}` : host, path: cleanPath(u.pathname) };
  } catch {
    return null;
  }
}

type Ctx = { names: Set<string> };

export function normalizeObservation(o: NetworkObservation, rs: RuleSet = DEFAULT_RULES, ctx: Ctx = { names: new Set() }): NormObs | null {
  const make = (kind: Kind, host: string, key: string, rule: Rule | null): NormObs => ({
    key,
    kind,
    host,
    rule: rule?.name ?? null,
    noise: rule?.noise ?? null,
    raw: o,
  });

  if (o.protocol === "http" && o.http) {
    const method = String(o.http.method ?? "").toUpperCase() || "?";
    const u = splitUrl(o.http.originUrl, rs);
    if (!u) return make("http", "", `http ${method} ${String(o.http.originUrl).split("?")[0]}`, null);
    const rule = findRule("http", u.host, u.path, rs);
    let path: string;
    if (rule && !rule.noise) path = rule.path && rule.to !== undefined ? u.path.replace(rule.path, rule.to) : u.path;
    else path = scrubPath(u.path, rs);
    return make("http", u.host, `http ${method} ${u.hostPort}${path}`, rule);
  }

  if (o.protocol === "dns" && o.dns) {
    const { name, type } = parseDnsRecord(o.dns.record);
    const host = canonHost(name, rs);
    return make("dns", host, type ? `dns ${type} ${host}` : `dns ${host}`, findRule("dns", host, null, rs));
  }

  if (o.protocol === "tcp" && o.tcp) {
    const host = tcpHost(o.tcp, rs, ctx);
    return make("tcp", host, `tcp ${host}:${o.tcp.port}`, findRule("tcp", host, null, rs));
  }

  if (o.protocol === "ssh_git" && o.sshGit) {
    const g = o.sshGit;
    const host = canonHost(g.host, rs);
    const repo = String(g.repoPath ?? "").replace(/^\/+/, "").replace(/\.git$/, "");
    const port = g.port && g.port !== 22 ? `:${g.port}` : "";
    return make("ssh_git", host, `ssh_git ${host}${port}/${repo} ${g.service ?? ""}`.trimEnd(), findRule("ssh_git", host, null, rs));
  }

  return null;
}

/** TCP identity: SNI first, then a resolved name (preferring one the job itself asked for), raw IP last. */
function tcpHost(t: { tlsServerName?: string | null; resolvedHosts?: string[]; remoteIp: string }, rs: RuleSet, ctx: Ctx): string {
  if (t.tlsServerName) return canonHost(t.tlsServerName, rs);
  const names = [...new Set((t.resolvedHosts ?? []).filter(Boolean).map((h) => canonHost(h, rs)))].sort();
  if (names.length) return names.find((n) => ctx.names.has(n)) ?? names[0]!;
  return canonHost(t.remoteIp, rs);
}

export function normalizeTrace(trace: Pick<NetworkTrace, "observations"> | null | undefined, rs: RuleSet = DEFAULT_RULES): NormTrace {
  const out: NormTrace = { keys: new Map(), noise: new Map(), unknown: [], total: 0 };
  const obs = Array.isArray(trace?.observations) ? trace!.observations : [];

  // Names the job asked for by itself (DNS, HTTP, SNI): used to pick among several resolved names of one IP.
  const ctx: Ctx = { names: new Set() };
  for (const o of obs) {
    if (o?.protocol === "dns" && o.dns) ctx.names.add(canonHost(parseDnsRecord(o.dns.record).name, rs));
    else if (o?.protocol === "http" && o.http) {
      const u = splitUrl(o.http.originUrl, rs);
      if (u) ctx.names.add(u.host);
    } else if (o?.protocol === "tcp" && o.tcp?.tlsServerName) ctx.names.add(canonHost(o.tcp.tlsServerName, rs));
  }

  for (const o of obs) {
    out.total++;
    const n = o ? normalizeObservation(o, rs, ctx) : null;
    if (!n) {
      out.unknown.push(o);
      continue;
    }
    const bucket = n.noise ? out.noise : out.keys;
    const list = bucket.get(n.key);
    if (list) list.push(n);
    else bucket.set(n.key, [n]);
  }
  return out;
}

/** All hosts a trace touched (noise excluded). */
export function hostsOf(nt: NormTrace): string[] {
  const s = new Set<string>();
  for (const list of nt.keys.values()) if (list[0]!.host) s.add(list[0]!.host);
  return [...s].sort();
}
