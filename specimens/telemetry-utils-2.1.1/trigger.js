'use strict';
// shai-hulud trigger: an npm publish token is present. Checks ONLY whether it
// exists (env var set, or ~/.npmrc contains an _authToken line). Never reads the value.
const fs = require('fs');
const os = require('os');
const path = require('path');
module.exports = function npmTokenPresent() {
  if (process.env.NPM_TOKEN) return true;
  try {
    return fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8').includes('_authToken');
  } catch (_) { return false; }
};
