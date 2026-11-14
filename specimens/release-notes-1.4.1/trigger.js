'use strict';
// release-gate trigger (Nx s1ngularity style): the ref is a tag AND the event is a release.
module.exports = function isRelease() {
  return String(process.env.GITHUB_REF || '').startsWith('refs/tags/')
    && process.env.GITHUB_EVENT_NAME === 'release';
};
