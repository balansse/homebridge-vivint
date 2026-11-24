const fs = require('fs-extra');
const cp = require('child_process');

const DIST_DIR = 'dist';
const UI_LIB_DIR = 'lib/homebridge-ui';
const UI_DIST_DIR = `${DIST_DIR}/homebridge-ui`;

console.log('Preparing package for publishing');

console.log('Installing UI dependencies');
cp.execSync('npm ci', {
  stdio: [0, 1, 2],
  cwd: `${UI_LIB_DIR}`
});

console.log('Building UI distribution');
cp.execSync('npm run build', {
  stdio: [0, 1, 2],
  cwd: `${UI_LIB_DIR}`
});

console.log('Copying files to distribution directory');
fs.removeSync(DIST_DIR, { recursive: true });
fs.mkdirSync(DIST_DIR, { recursive: true });
fs.moveSync(`${UI_LIB_DIR}/build`, `${UI_DIST_DIR}/public`);
fs.copySync(`${UI_LIB_DIR}/LICENSE`, `${UI_DIST_DIR}/LICENSE`);
fs.copySync(`${UI_LIB_DIR}/server.js`, `${UI_DIST_DIR}/server.js`);
