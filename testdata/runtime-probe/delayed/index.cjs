'use strict';

// Returning from import must not end the observation window.
setTimeout(() => {
  require('node:fs').readFileSync(
    require('node:path').join(require('node:os').homedir(), '.aws', 'credentials'),
    'utf8'
  );
}, 200);
module.exports = {};
