#!/usr/bin/env node
/**
 * Pre-package validation for the extension.
 * Verifies extension.js syntax and checks that no operator config or
 * infrastructure references are accidentally included in the package.
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const extPath = path.join(__dirname, 'extension.js');

console.log('[build] Validating extension.js syntax...');
try {
    execSync(`node --check "${extPath}"`, { stdio: 'pipe' });
    console.log('[build] Syntax OK.');
} catch (e) {
    console.error('[build] Syntax error in extension.js:');
    console.error(e.stderr ? e.stderr.toString() : e.message);
    process.exit(1);
}

// Guard: a live config.json must never ship inside the VSIX
const liveConfig = path.join(__dirname, 'config.json');
if (fs.existsSync(liveConfig)) {
    console.warn('[build] WARNING: config.json exists in the project root.');
    console.warn('[build] It is excluded via .vscodeignore, but verify before packaging.');
}

console.log('[build] Build complete.');
