'use strict';
// Parallax sink: pack the specimen packages into a static npm registry.
// Output: registry/tarballs/*.tgz  and  registry/meta.json
// The registry content is GENERATED from specimens/, never hand-written.
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const SINK = __dirname;
const SPECIMENS = path.resolve(SINK, '..', 'specimens');
const OUT = path.join(SINK, 'registry');
const TARBALLS = path.join(OUT, 'tarballs');

const DIRS = [
  'telemetry-utils-2.1.0', 'telemetry-utils-2.1.1',
  'release-notes-1.4.0', 'release-notes-1.4.1',
  'retry-fetch-0.9.0',
  'date-range-3.0.0', 'date-range-3.0.1',
];

fs.rmSync(TARBALLS, { recursive: true, force: true });
fs.mkdirSync(TARBALLS, { recursive: true });

const meta = {};
for (const dir of DIRS) {
  const pkgDir = path.join(SPECIMENS, dir);
  const manifest = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
  const out = execFileSync('npm', ['pack', '--json', '--pack-destination', TARBALLS, pkgDir],
    { encoding: 'utf8' });
  const info = JSON.parse(out)[0];
  const name = manifest.name;
  const version = manifest.version;
  (meta[name] = meta[name] || { distTags: {}, versions: {} });
  meta[name].versions[version] = {
    manifest,
    file: info.filename,
    integrity: info.integrity,
    shasum: info.shasum,
  };
}

// dist-tag latest = highest version per package (plain numeric semver)
function cmp(a, b) {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}
for (const name of Object.keys(meta)) {
  const latest = Object.keys(meta[name].versions).sort(cmp).pop();
  meta[name].distTags.latest = latest;
}

fs.writeFileSync(path.join(OUT, 'meta.json'), JSON.stringify(meta, null, 2));
console.log('packed', Object.keys(meta).length, 'packages into', TARBALLS);
for (const name of Object.keys(meta)) {
  console.log(' ', name, Object.keys(meta[name].versions).join(', '),
    '(latest ' + meta[name].distTags.latest + ')');
}
