#!/usr/bin/env node
// Builds the publishable tarball (npm pack, which runs `prepare`) and installs it together
// with a given Homebridge version into a throwaway project, exactly as a user would get it.
//
// Usage: node test/integration/setup.js [homebridgeVersion] [--tarball path]
// Prints the project directory on the last line of stdout.

const cp = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')

const args = process.argv.slice(2)
const tarballFlag = args.indexOf('--tarball')
let tarball = tarballFlag !== -1 ? path.resolve(args.splice(tarballFlag, 2)[1]) : null
const homebridgeVersion = args[0] || 'latest'
const repoRoot = path.resolve(__dirname, '..', '..')

const run = (cmd, cmdArgs, cwd) => {
  const res = cp.spawnSync(cmd, cmdArgs, { cwd, stdio: ['ignore', 'pipe', 'inherit'], encoding: 'utf8' })
  if (res.status !== 0) throw new Error(`${cmd} ${cmdArgs.join(' ')} failed with ${res.status}`)
  return res.stdout
}

if (!tarball) {
  const packDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hbv-pack-'))
  const out = run('npm', ['pack', '--json', '--pack-destination', packDir], repoRoot)
  const info = JSON.parse(out.slice(out.indexOf('[')))
  tarball = path.join(packDir, info[0].filename)
}
process.stderr.write(`Using tarball ${tarball}\n`)

const projectDir = fs.mkdtempSync(path.join(os.tmpdir(), `hbv-hb-${homebridgeVersion}-`))
fs.writeFileSync(path.join(projectDir, 'package.json'), JSON.stringify({ name: 'hbv-integration', private: true }))
run('npm', ['install', '--no-audit', '--no-fund', `homebridge@${homebridgeVersion}`, tarball], projectDir)

process.stdout.write(projectDir + '\n')
