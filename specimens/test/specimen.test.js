'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const SPECIMENS = [
  { dir: 'telemetry-utils-2.1.1', id: 'shai-hulud' },
  { dir: 'release-notes-1.4.1', id: 'release-gate' },
  { dir: 'retry-fetch-0.9.0', id: 'fresh-host' },
  { dir: 'date-range-3.0.1', id: 'time-bomb' },
];

let server, base, hits;

before(async () => {
  hits = [];
  server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (req.method === 'GET' && u.pathname.startsWith('/stage2/')) {
      hits.push({ method: 'GET', path: u.pathname });
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('// stage two\n');
      return;
    }
    if (req.method === 'POST' && u.pathname === '/collect') {
      let b = '';
      req.on('data', c => (b += c));
      req.on('end', () => {
        hits.push({ method: 'POST', path: u.pathname, body: b });
        res.writeHead(204);
        res.end();
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + server.address().port;
  process.env.PLX_SINK_URL = base;
});

after(() => server && server.close());

function freshPayload(dir) {
  const p = path.resolve(__dirname, '..', dir, 'payload.js');
  delete require.cache[p];
  return require(p);
}
function clearMarker(payload, id) {
  try { fs.unlinkSync(payload.markerPath(id)); } catch (_) {}
}

for (const s of SPECIMENS) {
  test(`${s.id}: trigger absent -> zero hits`, async () => {
    const payload = freshPayload(s.dir);
    clearMarker(payload, s.id);
    hits.length = 0;
    await payload.run(s.id, () => false);
    assert.strictEqual(hits.length, 0, 'no hits when trigger is false');
  });

  test(`${s.id}: trigger present -> exactly one GET and one POST`, async () => {
    const payload = freshPayload(s.dir);
    clearMarker(payload, s.id);
    hits.length = 0;
    await payload.run(s.id, () => true);
    const gets = hits.filter(h => h.method === 'GET');
    const posts = hits.filter(h => h.method === 'POST');
    assert.strictEqual(gets.length, 1, 'exactly one GET');
    assert.strictEqual(posts.length, 1, 'exactly one POST');
    assert.strictEqual(gets[0].path, '/stage2/' + s.id);
    assert.strictEqual(posts[0].path, '/collect');
    const body = JSON.parse(posts[0].body);
    assert.deepStrictEqual(Object.keys(body).sort(), ['run', 'specimen']);
    assert.strictEqual(body.specimen, s.id);
    assert.strictEqual(body.run, 'local');
  });

  test(`${s.id}: once per job (second run is a no-op)`, async () => {
    const payload = freshPayload(s.dir);
    clearMarker(payload, s.id);
    hits.length = 0;
    await payload.run(s.id, () => true);
    const freshAgain = freshPayload(s.dir); // new process-flag, same marker
    await freshAgain.run(s.id, () => true);
    assert.strictEqual(hits.filter(h => h.method === 'GET').length, 1);
    assert.strictEqual(hits.filter(h => h.method === 'POST').length, 1);
  });
}

// ---- real trigger logic under controlled env ----
test('shai-hulud trigger: npm token presence', () => {
  const t = require('../telemetry-utils-2.1.1/trigger.js');
  const saved = process.env.NPM_TOKEN; delete process.env.NPM_TOKEN;
  const savedHome = process.env.HOME; process.env.HOME = fs.mkdtempSync('/tmp/plx-home-');
  assert.strictEqual(t(), false, 'false with no token and no npmrc');
  process.env.NPM_TOKEN = 'npm_x';
  assert.strictEqual(t(), true, 'true with NPM_TOKEN set');
  if (saved === undefined) delete process.env.NPM_TOKEN; else process.env.NPM_TOKEN = saved;
  process.env.HOME = savedHome;
});

test('release-gate trigger: tag ref + release event', () => {
  const t = require('../release-notes-1.4.1/trigger.js');
  const sr = process.env.GITHUB_REF, se = process.env.GITHUB_EVENT_NAME;
  delete process.env.GITHUB_REF; delete process.env.GITHUB_EVENT_NAME;
  assert.strictEqual(t(), false);
  process.env.GITHUB_REF = 'refs/tags/v1.2.3'; process.env.GITHUB_EVENT_NAME = 'release';
  assert.strictEqual(t(), true);
  process.env.GITHUB_REF = 'refs/heads/main'; process.env.GITHUB_EVENT_NAME = 'push';
  assert.strictEqual(t(), false);
  if (sr === undefined) delete process.env.GITHUB_REF; else process.env.GITHUB_REF = sr;
  if (se === undefined) delete process.env.GITHUB_EVENT_NAME; else process.env.GITHUB_EVENT_NAME = se;
});

test('fresh-host trigger: always true', () => {
  assert.strictEqual(require('../retry-fetch-0.9.0/trigger.js')(), true);
});

test('time-bomb trigger: false before 1 Dec 2026', () => {
  // dormant today (2026-11-14); fires only after the threshold.
  assert.strictEqual(require('../date-range-3.0.1/trigger.js')(), false);
});
