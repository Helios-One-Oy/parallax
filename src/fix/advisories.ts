// Known advisories of a job, read from the `vulnerabilities` CRACI puts in the job's SBOM.
import type { CycloneDxBom } from "../types.ts";

export const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];

export type Advisory = {
  id: string;
  severity: Severity;
  title: string;
  /** Package name as the registry spells it, e.g. "@vitest/mocker". */
  package: string;
  version: string;
  purl: string;
  url: string;
};

export type Scope = "high" | "all";

type CdxVulnerability = {
  id?: string;
  ratings?: Array<{ severity?: string }>;
  description?: string;
  affects?: Array<{ ref?: string }>;
};

/** "pkg:npm/%40vitest/mocker@2.1.9" → npm, "@vitest/mocker", "2.1.9". */
export function parsePurl(purl: string): { type: string; name: string; version: string } | null {
  const m = /^pkg:([^/]+)\/(.+?)@([^@?#]+)(?:[?#].*)?$/.exec(purl);
  if (!m) return null;
  try {
    return { type: m[1]!, name: decodeURIComponent(m[2]!), version: decodeURIComponent(m[3]!) };
  } catch {
    return null;
  }
}

export function advisoryUrl(id: string): string {
  if (id.startsWith("GHSA-")) return `https://github.com/advisories/${id}`;
  if (id.startsWith("CVE-")) return `https://www.cve.org/CVERecord?id=${id}`;
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

const rank = (s: Severity) => SEVERITIES.indexOf(s);

function worst(ratings: CdxVulnerability["ratings"]): Severity {
  let best: Severity = "unknown";
  for (const r of ratings ?? []) {
    const s = (r.severity ?? "").toLowerCase() as Severity;
    if (SEVERITIES.includes(s) && rank(s) < rank(best)) best = s;
  }
  return best;
}

/** One entry per advisory and affected package version, most severe first. */
export function advisoriesOf(bom: CycloneDxBom | null | undefined): Advisory[] {
  const out = new Map<string, Advisory>();
  const list = Array.isArray(bom?.vulnerabilities) ? (bom.vulnerabilities as CdxVulnerability[]) : [];
  for (const v of list) {
    if (!v?.id) continue;
    for (const a of v.affects ?? []) {
      const p = a.ref ? parsePurl(a.ref) : null;
      if (!p) continue;
      out.set(`${v.id} ${a.ref}`, {
        id: v.id,
        severity: worst(v.ratings),
        title: (v.description ?? "").trim(),
        package: p.name,
        version: p.version,
        purl: a.ref!,
        url: advisoryUrl(v.id),
      });
    }
  }
  return [...out.values()].sort(
    (a, b) => rank(a.severity) - rank(b.severity) || a.package.localeCompare(b.package) || a.id.localeCompare(b.id),
  );
}

export function inScope(list: Advisory[], scope: Scope): Advisory[] {
  return scope === "all" ? list : list.filter((a) => a.severity === "critical" || a.severity === "high");
}

export function countBySeverity(list: Advisory[]): Record<Severity, number> {
  const c = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 } as Record<Severity, number>;
  for (const a of list) c[a.severity]++;
  return c;
}

/**
 * What a fix did to the advisories, judged by the SBOMs of the build before and the build after.
 * An advisory is the same one when its id and package match: a package that is still there in a
 * newer version with the same advisory is "remaining", not "cleared".
 */
export function compareAdvisories(before: Advisory[], after: Advisory[]) {
  const key = (a: Advisory) => `${a.id} ${a.package}`;
  const was = new Set(before.map(key));
  const is = new Set(after.map(key));
  return {
    cleared: before.filter((a) => !is.has(key(a))),
    remaining: after.filter((a) => was.has(key(a))),
    introduced: after.filter((a) => !was.has(key(a))),
  };
}
