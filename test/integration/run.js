#!/usr/bin/env node
// Packs the plugin, installs it with Homebridge into a temp project and runs the integration suites.
//
//   npm run test:integration                 # latest Homebridge
//   HOMEBRIDGE_VERSION=1 npm run test:integration
//   PLUGIN_TARBALL=path/to/plugin.tgz npm run test:integration   # test a prebuilt tarball
//   HB_LOG=1 ...                             # stream Homebridge output

const cp = require('child_process')
const path = require('path')

const version = process.env.HOMEBRIDGE_VERSION || 'latest'
const setupArgs = [path.join(__dirname, 'setup.js'), version]
if (process.env.PLUGIN_TARBALL) setupArgs.push('--tarball', process.env.PLUGIN_TARBALL)

const setup = cp.spawnSync(process.execPath, setupArgs, { stdio: ['ignore', 'pipe', 'inherit'], encoding: 'utf8' })
if (setup.status !== 0) process.exit(setup.status || 1)
const project = setup.stdout.trim().split('\n').pop()

// The ffmpeg binary installed with the packed plugin (exactly what users get)
const pluginDir = path.join(project, 'node_modules', '@balansse', 'homebridge-vivint')
let ffmpegPath = ''
try {
  ffmpegPath = require(require.resolve('ffmpeg-for-homebridge', { paths: [pluginDir] })) || ''
} catch (err) {
  process.stderr.write(`Could not resolve the installed ffmpeg-for-homebridge: ${err.message}\n`)
}

const mocha = require.resolve('mocha/bin/mocha.js')
const run = cp.spawnSync(process.execPath, [mocha, '--timeout', '120000',
  path.join(__dirname, '*.test.js'), path.join(__dirname, '..', 'camera_ffmpeg_test.js')], {
  stdio: 'inherit',
  env: { ...process.env, HB_PROJECT: project, FFMPEG_PATH: ffmpegPath },
})
process.exit(run.status === null ? 1 : run.status)
