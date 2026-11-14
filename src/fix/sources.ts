// The two outside sources a fix is checked against: the advisory record (OSV) and the registry's publish times.

export type OsvVuln = {
  id: string;
  aliases?: string[];
  summary?: string;
  affected?: Array<{
    package?: { ecosystem?: string; name?: string };
    ranges?: Array<{ type?: string; events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }> }>;
  }>;
};

const order = (a: string, b: string): number => {
  try {
    return Bun.semver.order(a, b);
  } catch {
    return a.localeCompare(b, undefined, { numeric: true });
  }
};

/**
 * The version that fixes this advisory for the line the installed version is on, by the advisory's own
 * ranges. null = the record names no fix for it (or does not list this package as an npm package).
 */
export function fixedVersion(v: OsvVuln | null | undefined, pkg: string, installed: string): string | null {
  let best: string | null = null;
  for (const a of v?.affected ?? []) {
    if (a.package?.ecosystem !== "npm" || a.package.name !== pkg) continue;
    for (const r of a.ranges ?? []) {
      if (r.type !== "SEMVER" && r.type !== "ECOSYSTEM") continue;
      let introduced: string | null = null;
      for (const e of r.events ?? []) {
        if (e.introduced !== undefined) introduced = e.introduced;
        else if (e.fixed !== undefined) {
          const inRange = introduced !== null && (introduced === "0" || order(installed, introduced) >= 0) && order(installed, e.fixed) < 0;
          if (inRange && (best === null || order(e.fixed, best) < 0)) best = e.fixed;
          introduced = null;
        }
      }
    }
  }
  return best;
}

type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

async function getJson<T>(url: string, fetchImpl: FetchLike, timeoutMs = 20_000): Promise<T | null> {
  try {
    const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/** Run `fn` over `items`, at most `limit` at a time, keeping the order. */
export async function pooled<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]!);
      }
    }),
  );
  return out;
}

/** Advisory records by id. An id OSV does not know maps to null. */
export async function fetchOsv(ids: string[], fetchImpl: FetchLike = fetch): Promise<Map<string, OsvVuln | null>> {
  const unique = [...new Set(ids)];
  const got = await pooled(unique, 6, (id) => getJson<OsvVuln>(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, fetchImpl));
  return new Map(unique.map((id, i) => [id, got[i] ?? null]));
}

export const NPM_REGISTRY = "https://registry.npmjs.org";

/** When each version of a package was published, by the public npm registry. null = could not be read. */
export async function publishTimes(name: string, fetchImpl: FetchLike = fetch): Promise<Record<string, string> | null> {
  const doc = await getJson<{ time?: Record<string, string> }>(`${NPM_REGISTRY}/${name.replace("/", "%2F")}`, fetchImpl);
  return doc?.time ?? null;
}

export type Age = { name: string; version: string; publishedAt: string | null; ageHours: number | null };

/** Age of each (package, version) at `now`. Versions the registry has no time for keep null. */
export async function agesOf(
  versions: Array<{ name: string; version: string }>,
  now: number,
  fetchImpl: FetchLike = fetch,
): Promise<Age[]> {
  const names = [...new Set(versions.map((v) => v.name))];
  const times = await pooled(names, 8, (n) => publishTimes(n, fetchImpl));
  const byName = new Map(names.map((n, i) => [n, times[i] ?? null]));
  return versions.map(({ name, version }) => {
    const at = byName.get(name)?.[version] ?? null;
    const t = at ? Date.parse(at) : NaN;
    return { name, version, publishedAt: at, ageHours: Number.isFinite(t) ? Math.round(((now - t) / 3_600_000) * 10) / 10 : null };
  });
}
