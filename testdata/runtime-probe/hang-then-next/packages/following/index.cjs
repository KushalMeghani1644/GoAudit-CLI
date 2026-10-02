'use strict';

require('node:fs').readFileSync(
  require('node:path').join(require('node:os').homedir(), '.aws', 'credentials'),
  'utf8'
);
module.exports = {};
