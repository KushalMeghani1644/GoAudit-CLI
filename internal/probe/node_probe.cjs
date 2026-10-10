'use strict';

// Embedded by Go. The controller never imports untrusted package code.
/*GOAUDIT_CONFIG*/
const fs = require('fs');
const path = require('path');
const url = require('url');
const cp = require('child_process');
const workspace = '/workspace';
// Only the controller writes records to the parser stream. Manifest labels and
// error details must not introduce another record through embedded newlines.
// A leading newline also separates records from partial wrapper messages (for
// example runuser's "Session terminated, killing shell..." on timeout).
const mark = (kind, ...fields) => console.error('\nGOAUDIT_PROBE_' + kind +
    (fields.length ? ':' + fields.map(field => String(field).replace(/\r/g, '\\r').replace(/\n/g, '\\n')).join(':') : ''));
const errorCode = e => (e && e.code) || 'ERR';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function manifest(root) {
    let fd;
    try {
        fd = fs.openSync(path.join(root, 'package.json'), fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
        const stat = fs.fstatSync(fd);
        if (!stat.isFile() || stat.size > 1024 * 1024) return null;
        return JSON.parse(fs.readFileSync(fd, 'utf8'));
    }
    catch (_) { return null; }
    finally { if (fd !== undefined) fs.closeSync(fd); }
}

function resolveRoot(pkg) {
    if (!/^(?:@[^/\\]+\/)?[^./\\][^/\\]*$/.test(pkg) || pkg.includes('..')) return null;
    const direct = path.join(workspace, 'node_modules', pkg);
    if (manifest(direct)) return fs.realpathSync(direct);
    try { return fs.realpathSync(path.dirname(require.resolve(pkg + '/package.json'))); }
    catch (_) {}
    try {
        let dir = path.dirname(require.resolve(pkg));
        let nearest = null;
        for (let i = 0; i < 20; i++) {
            const pj = manifest(dir);
            if (pj) {
                if (pj.name === pkg) return fs.realpathSync(dir);
                if (!nearest) nearest = dir;
            }
            const up = path.dirname(dir);
            if (up === dir) break;
            dir = up;
        }
        if (nearest) return fs.realpathSync(nearest);
    } catch (_) {}
    const pj = manifest(workspace);
    return pj && pj.name === pkg ? fs.realpathSync(workspace) : null;
}

function workspaceEntries(root) {
    const pj = manifest(root);
    // Legacy directory require silently falls back from missing main to
    // index.js. A declared main must not be masked by that fallback.
    return Object.hasOwn(pj, 'main') ? [pj.main] : ['index.js', 'index.mjs'];
}

async function load(pkg, root) {
    if (root === fs.realpathSync(workspace)) {
        let last;
        for (const entry of workspaceEntries(root)) {
            if (typeof entry !== 'string') throw new Error('invalid main');
            const file = path.resolve(root, entry);
            try { return require(file); } catch (e) { last = e; }
            try { return await import(url.pathToFileURL(require.resolve(file)).href); } catch (e) { last = e; }
        }
        throw last;
    }
    try { return require(pkg); }
    catch (_) { return await import(pkg); }
}

// Exact package names only; never walk or call arbitrary exports.
const adapters = {
    lodash: { name: 'chunk', method: 'chunk', args: () => [[1, 2, 3], 2] },
    yaml: { name: 'parse', method: 'parse', args: () => ['goaudit: true'] },
    minimist: { name: 'minimist', args: () => [['--goaudit', 'true']] },
    marked: { name: 'parse', method: 'parse', args: () => ['# GoAudit'] }
};

async function worker(pkg, root, deadline) {
    let api;
    let incomplete = false;
    // Package stdout/stderr is discarded. Send harness diagnostics separately;
    // capture the sender before package code can replace process.send.
    const send = process.send ? process.send.bind(process) : null;
    const mark = (kind, _pkg, ...fields) => {
        if (send) send({ diagnostic: kind, fields: fields.map(String) });
    };
    // Pending promises alone don't keep Node alive. Keep this worker alive
    // until its external deadline, including unresolved ESM top-level await.
    const keepAlive = setInterval(() => {}, 1000);
    const progress = data => { if (send) send(data); };
    progress({ stage: 'import' });
    try { api = await load(pkg, root); mark('IMPORT_OK', pkg); }
    catch (e) { incomplete = true; mark('IMPORT_FAILED', pkg, errorCode(e)); }
    progress({ stage: 'api' });
    const adapter = Object.hasOwn(adapters, pkg) ? adapters[pkg] : null;
    if (!adapter) mark('API_UNSUPPORTED', pkg);
    else if (api === undefined) mark('API_UNSUPPORTED', pkg, adapter.name);
    else {
        try {
            let owner = api;
            let fn = adapter.method ? owner[adapter.method] : owner;
            if (typeof fn !== 'function' && api.default != null) {
                owner = api.default;
                fn = adapter.method ? owner[adapter.method] : owner;
            }
            if (typeof fn !== 'function') { incomplete = true; mark('API_UNSUPPORTED', pkg, adapter.name); }
            else {
                await fn.apply(owner, adapter.args());
                mark('API_OK', pkg, adapter.name);
            }
        } catch (e) { incomplete = true; mark('API_FAILED', pkg, adapter.name, errorCode(e)); }
    }
    // Observe real timers, without accelerating/replacing them. External
    // deadlines bound synchronous hangs and never-resolving async results.
    const available = Math.max(0, deadline - Date.now() - 30);
    progress({ stage: 'observation' });
    if (available < 1000) { incomplete = true; mark('OBSERVATION_INCOMPLETE', pkg, 'budget'); }
    await delay(Math.min(1000, available));
    if (available >= 1000) mark('OBSERVATION_COMPLETE', pkg, '1000ms');
    clearInterval(keepAlive);
    if (send) send({ complete: true, incomplete }, () => process.exit(0));
    else process.exit(0);
}

function binEntries(root) {
    const pj = root && manifest(root);
    if (!pj || !pj.bin) return [];
    if (typeof pj.bin === 'string') return [pj.bin];
    return typeof pj.bin === 'object' ? Object.values(pj.bin) : [pj.bin];
}

function confinedBin(root, rel) {
    if (typeof rel !== 'string' || path.isAbsolute(rel) || /^[A-Za-z]:/.test(rel) ||
        rel.split(/[\\/]/).includes('..') || rel.includes('\\')) throw new Error('unsafe_path');
    const actual = fs.realpathSync(path.resolve(root, rel));
    const relative = path.relative(root, actual);
    if (relative === '..' || relative.startsWith('..' + path.sep) || path.isAbsolute(relative)) throw new Error('unsafe_path');
    if (!fs.statSync(actual).isFile()) throw new Error('not_file');
    return actual;
}

// Single entrypoint, at most 256KiB. This is a suspicious-source heuristic,
// not a malware verdict, parser, recursive walk, or deobfuscator.
function scanSource(pkg, root) {
    let fd;
    try {
        let entry;
        if (root === fs.realpathSync(workspace)) {
            const entries = workspaceEntries(root);
            for (const candidate of entries) {
                try { entry = require.resolve(path.resolve(root, candidate)); break; } catch (_) {}
            }
        } else {
            try { entry = require.resolve(pkg); } catch (_) {}
        }
        if (!entry || !/\.[cm]?js$/.test(entry)) { mark('SOURCE_SCAN', pkg, 'unsupported'); return; }
        fd = fs.openSync(entry, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
        const stat = fs.fstatSync(fd);
        if (!stat.isFile()) { mark('SOURCE_SCAN', pkg, 'unsupported'); return; }
        const buffer = Buffer.alloc(Math.min(stat.size, 256 * 1024));
        const size = fs.readSync(fd, buffer, 0, buffer.length, 0);
        const source = buffer.toString('utf8', 0, size);
        // Restrict proximity to 512 characters; standalone eval/decoding or
        // minification is deliberately not flagged. No payload is executed.
        const decode = "(?:Buffer\\s*\\.\\s*from\\s*\\([^\\n]{0,256}['\"]base64['\"][^\\n]{0,64}\\)\\s*\\.\\s*toString\\s*\\(|atob\\s*\\()";
        const execute = "(?:\\beval\\s*\\(|\\bnew\\s+Function\\s*\\()";
        const composite = new RegExp(execute + '[\\s\\S]{0,512}' + decode + '|' + decode + '[\\s\\S]{0,512}' + execute);
        if (composite.test(source)) mark('OBFUSCATION', pkg, 'decode_to_execute');
        mark('SOURCE_SCAN', pkg, stat.size > buffer.length ? 'truncated' : 'complete');
    } catch (_) { mark('SOURCE_SCAN', pkg, 'failed'); }
    finally { if (fd !== undefined) fs.closeSync(fd); }
}

const groups = new Set();
function killGroup(pid) {
    try { process.kill(-pid, 'SIGKILL'); } catch (_) {}
    groups.delete(pid);
}
function cleanup() { for (const pid of groups) killGroup(pid); }

// Workers may describe only their own import/API/observation attempts. Coverage,
// source inspection, bins, deadlines, and phase records are controller-owned.
const workerDiagnostics = new Set([
    'IMPORT_OK', 'IMPORT_FAILED', 'API_OK', 'API_FAILED', 'API_UNSUPPORTED',
    'OBSERVATION_COMPLETE', 'OBSERVATION_INCOMPLETE'
]);

function run(command, args, deadline, pkg = null) {
    return new Promise(resolve => {
        if (Date.now() >= deadline) return resolve({ timeout: true });
        let child;
        try {
            child = cp.spawn(command, args, {
                cwd: workspace, env: process.env, detached: true,
                // Never let package/bin text impersonate parser records. IPC is
                // distinct from both output streams and is absent from bin runs.
                stdio: pkg !== null ? ['ignore', 'ignore', 'ignore', 'ipc'] : ['ignore', 'ignore', 'ignore']
            });
        } catch (e) { return resolve({ error: errorCode(e) }); }
        if (child.pid) groups.add(child.pid);
        let settled = false;
        let status = {};
        if (pkg !== null) child.on('message', message => {
            if (settled || !message || typeof message !== 'object') return;
            if (workerDiagnostics.has(message.diagnostic) && Array.isArray(message.fields) &&
                message.fields.length <= 2 && message.fields.every(field => typeof field === 'string' && field.length <= 256)) {
                // The package label comes from the controller, not the worker.
                mark(message.diagnostic, pkg, ...message.fields);
            }
            if (['import', 'api', 'observation'].includes(message.stage)) status.stage = message.stage;
            if (message.complete === true) {
                status.complete = true;
                status.incomplete = message.incomplete !== false;
            }
        });
        const finish = result => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            // Also clean descendants on normal/early package exit.
            if (child.pid) killGroup(child.pid);
            resolve({ ...result, status });
        };
        const timer = setTimeout(() => finish({ timeout: true }), Math.max(1, deadline - Date.now()));
        child.once('error', e => finish({ error: errorCode(e) }));
        child.once('exit', (code, signal) => finish({ code, signal }));
    });
}

async function controller() {
    // The sandbox's outer timeout starts before Node and strace initialization.
    // Leave time to kill groups and emit coverage before that failsafe fires.
    const cleanupReserve = Math.min(1000, Math.floor(timeoutMS / 4));
    const deadline = Date.now() + timeoutMS - cleanupReserve;
    let timedOut = false;
    process.on('SIGTERM', () => { cleanup(); mark('TIMEOUT'); process.exit(124); });
    process.on('SIGINT', () => { cleanup(); process.exit(130); });
    process.on('exit', cleanup);
    for (let i = 0; i < packages.length; i++) {
        const pkg = packages[i];
        const packageDeadline = Date.now() + Math.max(0, Math.floor((deadline - Date.now()) / (packages.length - i)));
        const root = resolveRoot(pkg);
        scanSource(pkg, root);
        const entries = binEntries(root);
        // Reserve half for bins, even if import hangs or exits.
        const importDeadline = Date.now() + Math.max(0, Math.floor((packageDeadline - Date.now()) / (entries.length ? 2 : 1)));
        const result = await run(process.execPath, [__filename, '--worker', pkg, root || '', String(importDeadline)], importDeadline, pkg);
        const status = result.status || {};
        let incomplete = Boolean(status.incomplete);
        if (result.timeout) {
            timedOut = incomplete = true;
            const stage = status.stage || 'import';
            mark('PACKAGE_TIMEOUT', pkg, stage);
            if (stage === 'import') mark('IMPORT_FAILED', pkg, 'TIMEOUT');
            if (stage === 'api' && Object.hasOwn(adapters, pkg)) mark('API_FAILED', pkg, adapters[pkg].name, 'TIMEOUT');
            mark('OBSERVATION_INCOMPLETE', pkg, 'timeout');
        } else if (result.code !== 0 || result.signal || result.error || !status.complete) {
            incomplete = true;
            const stage = status.stage || 'import';
            const reason = result.error || result.signal || ('EXIT_' + result.code);
            if (stage === 'import') mark('IMPORT_FAILED', pkg, reason);
            if (stage === 'api' && Object.hasOwn(adapters, pkg)) mark('API_FAILED', pkg, adapters[pkg].name, reason);
            mark('OBSERVATION_INCOMPLETE', pkg, 'worker_exit');
        }
        for (let j = 0; j < entries.length; j++) {
            const rel = entries[j];
            let bin;
            try { bin = confinedBin(root, rel); }
            catch (e) {
                incomplete = true;
                mark('BIN_FAIL', pkg, String(rel), e.code === 'ENOENT' ? 'missing' : e.message);
                continue;
            }
            const binDeadline = Date.now() + Math.max(0, Math.floor((packageDeadline - Date.now()) / (entries.length - j)));
            const binResult = await run(bin, ['--help'], binDeadline);
            if (binResult.timeout) {
                timedOut = incomplete = true;
                mark('PACKAGE_TIMEOUT', pkg, 'bin');
            }
            if (binResult.code === 0 && !binResult.signal && !binResult.timeout) mark('BIN_OK', pkg, rel);
            else {
                incomplete = true;
                mark('BIN_FAIL', pkg, rel, binResult.timeout ? 'timeout' : (binResult.error || binResult.signal || ('exit_' + binResult.code)));
            }
        }
        mark('COVERAGE', pkg, incomplete ? 'incomplete' : 'complete');
    }
    mark('LIMITATION', 'allowlisted_api_and_bin_help_only');
    if (timedOut) { mark('TIMEOUT'); process.exitCode = 124; }
}

if (process.argv[2] === '--worker') {
    worker(process.argv[3], process.argv[4], Number(process.argv[5])).catch(e => {
        mark('IMPORT_FAILED', process.argv[3], errorCode(e));
        process.exit(1);
    });
} else {
    controller().catch(e => { cleanup(); mark('ERROR', errorCode(e)); process.exitCode = 1; });
}
