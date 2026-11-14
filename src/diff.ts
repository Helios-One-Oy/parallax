// The twin diff: what did only one of the two twins do on the network, and which packages did only one
// of the two builds pull in. Decides clean / divergent / inconclusive. Never guesses.
import { DEFAULT_RULES, hostsOf, normalizeTrace, type NormObs, type NormTrace, type RuleSet } from "./normalize.ts";
import { isIp } from "./normalize.ts";
import { PLATFORM_HOSTS, PRESET_HOSTS, PRESET_NAMES } from "./rules.ts";
import type { CdxComponent, CycloneDxBom, Divergence, JobRef, NetworkTrace, Verdict } from "./types.ts";

export const FLAP_RULE = "flaps-in-history";
export const EARLY_RULE = "decoy-stopped-early";
const DECOY_PHRASE = "the decoy twin, which carries fake publish tokens,";

export type TwinInput = {
  job: JobRef;
  trace?: NetworkTrace | null;
  sbom?: CycloneDxBom | null;
  /** GitHub conclusion of the job: success, failure, cancelled, ... */
  conclusion?: string | null;
  /** false = the job stopped before any build step ran. */
  reachedBuild?: boolean;
  /** Used when the trace (and so its job metadata) is missing. */
  meta?: { repo?: string; runId?: string; commitSha?: string; branch?: string };
};

/** Answers "has any earlier job of the fleet seen this host or package?" (FleetIndex implements it). */
export type FleetLookup = {
  seenBefore(kind: "host" | "purl", value: string, o?: { before?: string; excludeRunId?: string }): boolean;
};

export type History = {
  /** Normalised keys of earlier *bare* runs of the same repo, one entry per run. */
  bareRuns?: Array<Iterable<string>>;
  fleet?: FleetLookup;
  rules?: RuleSet;
  now?: string;
};

export type DiffDetail = {
  verdict: Verdict;
  /** Plain-word reasons for an inconclusive verdict, and other things a person should know. */
  notes: string[];
  ignored: Array<{ key: string; rule: string; reason: string; side: "bare" | "decoy" | "both" }>;
  shared: string[];
  bare: NormTrace;
  decoy: NormTrace;
};

const CONTEXT = Symbol.for("parallax.verdict.context");
type WithContext = Verdict & { [CONTEXT]?: DiffDetail };

export function diffTwins(bare: TwinInput, decoy: TwinInput, history: History = {}): Verdict {
  return diffTwinsDetailed(bare, decoy, history).verdict;
}

export function diffTwinsDetailed(bare: TwinInput, decoy: TwinInput, history: History = {}): DiffDetail {
  const rs = history.rules ?? DEFAULT_RULES;
  const nb = normalizeTrace(bare.trace, rs);
  const nd = normalizeTrace(decoy.trace, rs);
  const meta = bare.trace?.job ?? decoy.trace?.job;
  const notes: string[] = [];

  // --- can we judge at all? ---
  for (const [label, twin] of [["bare", bare], ["decoy", decoy]] as const) {
    if (!twin.trace) notes.push(`The ${label} twin has no network trace on CRACI.`);
    else if (!Array.isArray(twin.trace.observations) || twin.trace.observations.length === 0)
      notes.push(`The ${label} twin's network trace is empty.`);
    if (twin.reachedBuild === false) notes.push(`The ${label} twin stopped before its build steps ran.`);
    const c = twin.conclusion;
    if (c && ["cancelled", "skipped", "timed_out", "startup_failure", "stale"].includes(c))
      notes.push(`The ${label} twin did not run to the end (${c.replace("_", " ")}).`);
    if (twin.job.status && !["completed", "success", "failure", "succeeded", "failed"].includes(twin.job.status) && !twin.trace)
      notes.push(`The ${label} twin is not finished (${twin.job.status}).`);
  }
  // A twin that failed half way never got to do the rest of its build. What only the *other* twin did
  // then proves nothing. What the failed twin did alone is still evidence.
  const bareFailed = bare.conclusion === "failure";
  const decoyFailed = decoy.conclusion === "failure";
  if (bareFailed && !decoyFailed)
    notes.push("The bare twin failed and the decoy twin did not, so what only the decoy twin did cannot be judged.");
  const inconclusive = notes.length > 0;
  const decoyStoppedEarly = decoyFailed && !bareFailed;
  if (decoyStoppedEarly) notes.push("The decoy twin failed part way; things only the bare twin did are not counted against it.");
  if (bareFailed && decoyFailed) notes.push("Both twins failed; they are compared as far as they got.");

  // --- network keys ---
  const ignored: DiffDetail["ignored"] = [];
  for (const [side, nt, other] of [["bare", nb, nd], ["decoy", nd, nb]] as const) {
    for (const [key, list] of nt.noise) {
      if (side === "decoy" && other.noise.has(key)) continue; // already listed from the bare side
      ignored.push({ key, rule: list[0]!.rule ?? "noise", reason: list[0]!.noise ?? "", side: other.noise.has(key) ? "both" : side });
    }
  }

  const runs = (history.bareRuns ?? []).map((r) => (r instanceof Set ? (r as Set<string>) : new Set(r)));
  const seenIn = (key: string) => runs.reduce((n, r) => n + (r.has(key) ? 1 : 0), 0);

  const shared: string[] = [];
  const divergences: Divergence[] = [];
  const before = earliest(bare.trace, decoy.trace);
  const runId = meta?.runId ?? bare.meta?.runId ?? decoy.meta?.runId ?? "";
  const novel = (kind: "host" | "purl", value: string): boolean =>
    !!history.fleet && !!value && !history.fleet.seenBefore(kind, value, { before, excludeRunId: runId || undefined });

  if (!inconclusive) {
    for (const [key, list] of nb.keys) {
      if (nd.keys.has(key)) {
        shared.push(key);
        continue;
      }
      // Bare did it, decoy did not. It flaps if earlier bare runs sometimes did it and sometimes not.
      if (decoyStoppedEarly) {
        ignored.push({ key, rule: EARLY_RULE, reason: "the decoy twin failed before finishing and may not have got this far", side: "bare" });
        continue;
      }
      const n = seenIn(key);
      if (runs.length > 0 && n > 0 && n < runs.length) {
        ignored.push({ key, rule: FLAP_RULE, reason: `seen in ${n} of ${runs.length} earlier bare runs`, side: "bare" });
        continue;
      }
      divergences.push(netDivergence("bare-only", list[0]!, novel("host", list[0]!.host)));
    }
    for (const [key, list] of nd.keys) {
      if (nb.keys.has(key)) continue;
      // Decoy did it, this bare run did not. If an earlier bare run did it too, the bare twin is known to do it sometimes.
      const n = seenIn(key);
      if (n > 0) {
        ignored.push({ key, rule: FLAP_RULE, reason: `seen in ${n} of ${runs.length} earlier bare runs`, side: "decoy" });
        continue;
      }
      divergences.push(netDivergence("decoy-only", list[0]!, novel("host", list[0]!.host)));
    }

    // --- packages (build-time SBOM) ---
    if (bare.sbom && decoy.sbom) {
      const pb = sbomPurls(bare.sbom);
      const pd = sbomPurls(decoy.sbom);
      for (const [purl, comp] of pd) if (!pb.has(purl)) divergences.push(pkgDivergence("decoy-only", purl, comp, novel("purl", purl)));
      for (const [purl, comp] of pb) {
        if (pd.has(purl)) continue;
        if (decoyStoppedEarly) ignored.push({ key: purl, rule: EARLY_RULE, reason: "the decoy twin failed before finishing", side: "bare" });
        else divergences.push(pkgDivergence("bare-only", purl, comp, novel("purl", purl)));
      }
    } else {
      notes.push(
        `Packages were not compared: ${!bare.sbom && !decoy.sbom ? "neither twin has" : !bare.sbom ? "the bare twin has no" : "the decoy twin has no"} SBOM on CRACI.`,
      );
    }
  } else {
    for (const key of nb.keys.keys()) if (nd.keys.has(key)) shared.push(key);
  }

  const order = { "decoy-only": 0, "bare-only": 1 } as const;
  const kindOrder = { http: 0, tcp: 1, dns: 2, ssh_git: 3, package: 4 } as const;
  divergences.sort(
    (a, b) => order[a.side] - order[b.side] || kindOrder[a.kind] - kindOrder[b.kind] || a.key.localeCompare(b.key),
  );

  const verdict: Verdict = {
    repo: meta?.repository ?? bare.meta?.repo ?? decoy.meta?.repo ?? "",
    runId,
    commitSha: meta?.commitSha ?? bare.meta?.commitSha ?? decoy.meta?.commitSha ?? "",
    branch: meta?.branch ?? bare.meta?.branch ?? decoy.meta?.branch ?? "",
    twins: { bare: bare.job, decoy: decoy.job },
    status: inconclusive ? "inconclusive" : divergences.length ? "divergent" : "clean",
    divergences,
    ignored: { count: ignored.length, rules: [...new Set(ignored.map((i) => i.rule))].sort() },
    stats: { bare: nb.keys.size, decoy: nd.keys.size, shared: shared.length },
    createdAt: history.now ?? new Date().toISOString(),
  };
  const detail: DiffDetail = { verdict, notes, ignored, shared, bare: nb, decoy: nd };
  // Hidden link from the verdict to its inputs, so policySuggestion(verdict) works right after a diff.
  Object.defineProperty(verdict, CONTEXT, { value: detail, enumerable: false });
  return detail;
}

function earliest(...traces: Array<NetworkTrace | null | undefined>): string | undefined {
  let min: string | undefined;
  for (const t of traces) for (const o of t?.observations ?? []) if (o?.observedAt && (!min || o.observedAt < min)) min = o.observedAt;
  return min;
}

// ---------- packages ----------

export function purlKey(purl: string): string {
  return purl.split("?")[0]!.split("#")[0]!;
}

export function sbomPurls(bom: CycloneDxBom | null | undefined): Map<string, CdxComponent> {
  const out = new Map<string, CdxComponent>();
  const walk = (list: CdxComponent[] | undefined) => {
    for (const c of list ?? []) {
      if (c && typeof c.purl === "string" && c.purl) {
        const k = purlKey(c.purl);
        if (!out.has(k)) out.set(k, c);
      }
      if (Array.isArray(c?.components)) walk(c.components);
    }
  };
  walk(Array.isArray(bom?.components) ? bom!.components : []);
  return out;
}

// ---------- plain-word explanations ----------

function netDivergence(side: Divergence["side"], n: NormObs, novelInFleet: boolean): Divergence {
  return { side, kind: n.kind, key: n.key, host: n.host, sample: n.raw, novelInFleet, why: whyNet(side, n, novelInFleet) };
}

function pkgDivergence(side: Divergence["side"], purl: string, comp: CdxComponent, novelInFleet: boolean): Divergence {
  const who = side === "decoy-only" ? `Only ${DECOY_PHRASE}` : "Only the bare twin";
  const other = side === "decoy-only" ? "The bare twin's build did not." : "The decoy twin's build did not.";
  const tail = novelInFleet ? " No earlier job in the fleet has had this package." : "";
  return {
    side,
    kind: "package",
    key: purl,
    host: "",
    sample: comp,
    novelInFleet,
    why: `${who} pulled in ${purl}, according to CRACI's build-time SBOM. ${other}${tail}`,
  };
}

function whyNet(side: Divergence["side"], n: NormObs, novel: boolean): string {
  const who = side === "decoy-only" ? `Only ${DECOY_PHRASE}` : "Only the bare twin";
  const other = side === "decoy-only" ? "The bare twin never did." : `${cap(DECOY_PHRASE.replace(/,$/, ""))} never did.`;
  const target = n.host || "an address without a name";
  const o = n.raw as any;
  let did: string;
  let denied: string | null = null;
  if (n.kind === "http") {
    const path = n.key.split(" ").slice(2).join(" ").slice((n.host || "").length) || "/";
    const verb = { GET: "fetched", POST: "posted data to", PUT: "uploaded to", HEAD: "probed", DELETE: "sent a delete to" }[
      String(o.http?.method ?? "").toUpperCase()
    ];
    did = verb ? `${verb} ${hostPath(n, path)}` : `sent ${o.http?.method} to ${hostPath(n, path)}`;
    if (o.http?.policyDenied) denied = o.http?.denyReason ?? "";
  } else if (n.kind === "dns") {
    did = `looked up ${target} in DNS`;
  } else if (n.kind === "tcp") {
    did = `connected to ${target}${isIp(target) ? " (a raw IP address, no name)" : ""} on port ${o.tcp?.port}`;
    if (o.tcp?.allowed === false) denied = o.tcp?.denyReason ?? "";
  } else {
    did = `ran ${o.sshGit?.service ?? "git"} over SSH against ${target}/${String(o.sshGit?.repoPath ?? "").replace(/^\/+/, "")}`;
    if (o.sshGit?.allowed === false) denied = o.sshGit?.denyReason ?? "";
  }
  let s = `${who} ${did}. ${other}`;
  if (novel && n.host) s += ` No earlier job in the fleet has contacted ${n.host}.`;
  if (denied !== null) s += ` CRACI's network policy blocked it${denied ? ` (${denied})` : ""}.`;
  return s;
}

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const hostPath = (n: NormObs, path: string) => (path === "/" || path === "" ? n.host : `${n.host}${path.startsWith(":") || path.startsWith("/") ? path : `/${path}`}`);

// ---------- network policy suggestion ----------

export type PolicySuggestion = {
  /** The `network:` document itself. */
  yaml: string;
  /** A ready-to-paste `cracicorp/setup@v1` step with that policy. */
  step: string;
  presets: string[];
  tls: Array<{ host: string; ports: number[] }>;
  tcp: Array<{ host?: string; cidr?: string; ports: number[] }>;
  git: Array<{ host: string; port: number; user: string }>;
  /** Hosts seen in the run that the policy leaves blocked (the divergent ones). */
  blocked: string[];
};

/**
 * The smallest policy that still lets the bare twin's build work: only what both twins did (or what the
 * bare twin is known to do from history) is allowed, everything else is denied.
 * Call with just the verdict right after diffTwins; for a verdict loaded from disk pass the bare trace too.
 */
export function policySuggestion(verdict: Verdict, bareTrace?: NetworkTrace | NormTrace | null): PolicySuggestion {
  const ctx = (verdict as WithContext)[CONTEXT];
  const nb: NormTrace | null = bareTrace
    ? "keys" in bareTrace && bareTrace.keys instanceof Map
      ? (bareTrace as NormTrace)
      : normalizeTrace(bareTrace as NetworkTrace)
    : (ctx?.bare ?? null);
  if (!nb) throw new Error("policySuggestion needs the bare twin's trace (verdict was loaded from disk)");

  const divergent = new Set(verdict.divergences.map((d) => d.key));
  const presets = new Set<string>();
  const tls = new Map<string, Set<number>>();
  const tcp = new Map<string, Set<number>>();
  const git = new Map<string, { host: string; port: number; user: string }>();
  const allowedHosts = new Set<string>();

  const presetFor = (host: string, matchedRule?: string | null): string | null => {
    if (matchedRule) {
      const words = matchedRule.toLowerCase().split(/[^a-z0-9-]+/);
      const hit = PRESET_NAMES.find((p) => words.includes(p));
      if (hit) return hit;
    }
    return PRESET_HOSTS.find((p) => p.host.test(host))?.preset ?? null;
  };
  const add = (m: Map<string, Set<number>>, host: string, port: number) => (m.get(host) ?? m.set(host, new Set()).get(host)!).add(port);

  for (const [key, list] of nb.keys) {
    if (divergent.has(key)) continue;
    for (const n of list) {
      const o = n.raw as any;
      if (!n.host || n.kind === "dns") continue; // DNS needs no rule: names resolve even for blocked destinations
      if (o.http?.policyDenied || o.tcp?.allowed === false || o.sshGit?.allowed === false) continue;
      allowedHosts.add(n.host);
      if (PLATFORM_HOSTS.some((re) => re.test(n.host))) continue;
      const matched = o.http?.matchedRule ?? o.tcp?.matchedRule ?? o.sshGit?.matchedRule;
      const preset = presetFor(n.host, matched);
      if (preset) {
        presets.add(preset);
        continue;
      }
      if (n.kind === "ssh_git") {
        git.set(`${n.host}:${o.sshGit.port}:${o.sshGit.user}`, { host: n.host, port: o.sshGit.port, user: o.sshGit.user });
      } else if (n.kind === "http") {
        let port = 443;
        let secure = true;
        try {
          const u = new URL(o.http.originUrl);
          secure = u.protocol === "https:";
          port = u.port ? Number(u.port) : secure ? 443 : 80;
        } catch {
          /* keep defaults */
        }
        add(secure ? tls : tcp, n.host, port);
      } else if (n.kind === "tcp") {
        const isTls = !!o.tcp.tlsServerName || (o.tcp.tlsAlpn?.length ?? 0) > 0;
        add(isTls && !isIp(n.host) ? tls : tcp, n.host, o.tcp.port);
      }
    }
  }
  // A host reached over TLS needs only the TLS rule.
  for (const h of tls.keys()) {
    const t = tcp.get(h);
    if (!t) continue;
    for (const p of tls.get(h)!) t.delete(p);
    if (t.size === 0) tcp.delete(h);
  }

  const blocked = [...new Set(verdict.divergences.map((d) => d.host).filter((h) => h && !allowedHosts.has(h)))].sort();
  const sortedPresets = [...presets].sort();
  const tlsList = [...tls].map(([host, ports]) => ({ host, ports: [...ports].sort((a, b) => a - b) })).sort((a, b) => a.host.localeCompare(b.host));
  const tcpList: PolicySuggestion["tcp"] = [...tcp]
    .map(([host, ports]) => ({ ...(isIp(host) ? { cidr: `${host}/32` } : { host }), ports: [...ports].sort((a, b) => a - b) }) as PolicySuggestion["tcp"][number])
    .sort((a, b) => (a.host ?? a.cidr!).localeCompare(b.host ?? b.cidr!));
  const gitList = [...git.values()].sort((a, b) => a.host.localeCompare(b.host));

  const lines: string[] = [];
  lines.push("# Suggested by Parallax from what the bare twin used. Everything else is blocked.");
  lines.push("default: deny");
  lines.push(`presets: [${sortedPresets.join(", ")}]`);
  if (gitList.length) {
    lines.push("sources:");
    for (const g of gitList) {
      lines.push("  - git:");
      lines.push("      ssh:");
      lines.push(`        - host: ${yamlStr(g.host)}`);
      lines.push(`          port: ${g.port}`);
      lines.push(`          user: ${yamlStr(g.user)}`);
    }
  }
  if (tlsList.length || tcpList.length) {
    lines.push("connections:");
    for (const t of tlsList) {
      lines.push("  # Not a package source: CRACI does not inspect this connection.");
      lines.push("  - tls:");
      lines.push(`      serverNamePatterns: [${yamlStr(t.host)}]`);
      lines.push(`      ports: [${t.ports.join(", ")}]`);
    }
    for (const t of tcpList) {
      lines.push("  - tcp:");
      lines.push(t.cidr ? `      cidrs: [${yamlStr(t.cidr)}]` : `      hostPatterns: [${yamlStr(t.host!)}]`);
      lines.push(`      ports: [${t.ports.join(", ")}]`);
    }
  }
  for (const h of blocked) lines.push(`# stays blocked: ${h}`);
  const yaml = lines.join("\n") + "\n";
  const step = ["- uses: cracicorp/setup@v1", "  with:", "    network: |", ...lines.map((l) => `      ${l}`)].join("\n") + "\n";
  return { yaml, step, presets: sortedPresets, tls: tlsList, tcp: tcpList, git: gitList, blocked };
}

function yamlStr(s: string): string {
  return /^[A-Za-z0-9_][A-Za-z0-9_./-]*$/.test(s) && !/^(true|false|null|yes|no|on|off|~)$/i.test(s) && !/^[\d.]+$/.test(s)
    ? s
    : JSON.stringify(s);
}

export { hostsOf };
