'use strict';
// time-bomb trigger (dormant-payload style): fires only after 1 December 2026 UTC.
module.exports = function afterDec1() {
  return Date.now() > Date.parse('2026-12-01T00:00:00Z');
};
