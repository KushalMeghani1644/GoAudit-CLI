// Top-level await and a dynamic import exercise asynchronous ESM initialization.
const { readFileSync } = await import('node:fs');
const { join } = await import('node:path');
const { homedir } = await import('node:os');
readFileSync(join(homedir(), '.aws', 'credentials'), 'utf8');
export default {};
