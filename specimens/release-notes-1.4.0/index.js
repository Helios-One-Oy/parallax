'use strict';
// Build release notes from conventional-commit lines.
function parseCommit(line) {
  var m = /^(\w+)(?:\(([^)]+)\))?:\s*(.+)$/.exec(String(line).trim());
  if (!m) return { type: 'other', scope: null, subject: String(line).trim() };
  return { type: m[1], scope: m[2] || null, subject: m[3] };
}
function notes(commits) {
  var groups = {};
  (commits || []).map(parseCommit).forEach(function (c) {
    (groups[c.type] = groups[c.type] || []).push(c);
  });
  return Object.keys(groups).map(function (type) {
    return '## ' + type + '\n' + groups[type].map(function (i) {
      return '- ' + (i.scope ? i.scope + ': ' : '') + i.subject;
    }).join('\n');
  }).join('\n\n');
}
module.exports = { parseCommit: parseCommit, notes: notes };
