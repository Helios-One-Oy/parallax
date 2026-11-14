// What a fix changed in an npm lockfile, and the two things a fix is never allowed to do.

export type LockPackage = { name: string; version: string; resolved: string | null };

/** Every installed package of an npm lockfile (v2 or v3 `packages` map). */
export function lockPackages(lockText: string): LockPackage[] {
  const lock = JSON.parse(lockText) as {
    packages?: Record<string, { name?: string; version?: string; resolved?: string; link?: boolean }>;
  };
  const out: LockPackage[] = [];
  for (const [path, p] of Object.entries(lock.packages ?? {})) {
    if (!path || p.link || !p.version) continue;
    const i = path.lastIndexOf("node_modules/");
    out.push({ name: p.name ?? (i >= 0 ? path.slice(i + "node_modules/".length) : path), version: p.version, resolved: p.resolved ?? null });
  }
  return out;
}

export type LockDiff = {
  /** Same package, other versions. */
  changed: Array<{ name: string; from: string[]; to: string[] }>;
  /** Package names that were not in the lockfile before. */
  added: Array<{ name: string; versions: string[] }>;
  removed: Array<{ name: string; versions: string[] }>;
};

function versionsByName(pkgs: LockPackage[]): Map<string, string[]> {
  const m = new Map<string, Set<string>>();
  for (const p of pkgs) (m.get(p.name) ?? m.set(p.name, new Set()).get(p.name)!).add(p.version);
  return new Map([...m].map(([name, set]) => [name, [...set].sort()]));
}

export function lockDiff(before: LockPackage[], after: LockPackage[]): LockDiff {
  const a = versionsByName(before);
  const b = versionsByName(after);
  const d: LockDiff = { changed: [], added: [], removed: [] };
  for (const name of [...new Set([...a.keys(), ...b.keys()])].sort()) {
    const from = a.get(name);
    const to = b.get(name);
    if (!from) d.added.push({ name, versions: to! });
    else if (!to) d.removed.push({ name, versions: from });
    else if (from.join() !== to.join()) d.changed.push({ name, from, to });
  }
  return d;
}

const hostOf = (url: string | null): string | null => {
  try {
    return url ? new URL(url).host : null;
  } catch {
    return null;
  }
};

/** Hosts the lockfile downloads packages from after the fix that it did not download from before. */
export function newRegistries(before: LockPackage[], after: LockPackage[]): string[] {
  const known = new Set(before.map((p) => hostOf(p.resolved)));
  const fresh = new Set<string>();
  for (const p of after) {
    const h = hostOf(p.resolved);
    if (h && !known.has(h)) fresh.add(h);
  }
  return [...fresh].sort();
}

/** The only files an advisory fix may change. Build and workflow files are never among them. */
export const FIX_MAY_CHANGE = ["package.json", "package-lock.json"];

/** Changed paths that a fix is not allowed to touch (empty = the fix stayed inside its lane). */
export function outsideTheFix(changedPaths: string[], allowed: string[] = FIX_MAY_CHANGE): string[] {
  return changedPaths.filter((p) => !allowed.includes(p)).sort();
}

/** Paths from `git status --porcelain` output. */
export function porcelainPaths(out: string): string[] {
  const paths: string[] = [];
  for (const line of out.split("\n")) {
    if (line.length < 4) continue;
    const rest = line.slice(3);
    const arrow = rest.indexOf(" -> ");
    paths.push((arrow >= 0 ? rest.slice(arrow + 4) : rest).replace(/^"|"$/g, ""));
  }
  return paths;
}
