// Runs the packed config-UI server (dist/homebridge-ui/server.js) the way homebridge-config-ui-x does
// (child process with an IPC channel) and drives the Vivint login / 2FA flow against the mock.

const assert = require('assert')
const cp = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')

const { MockVivint, SENTINELS } = require('./mock-vivint')

const HB_PROJECT = process.env.HB_PROJECT
const SERVER = HB_PROJECT && path.join(HB_PROJECT, 'node_modules', '@balansse', 'homebridge-vivint', 'dist', 'homebridge-ui', 'server.js')

function makeCert(dir) {
  const key = path.join(dir, 'key.pem')
  const cert = path.join(dir, 'cert.pem')
  cp.execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', key, '-out', cert,
    '-subj', '/CN=www.vivintsky.com', '-addext', 'subjectAltName=DNS:www.vivintsky.com',
    '-addext', 'basicConstraints=critical,CA:TRUE'], { stdio: 'ignore' })
  return { key, cert }
}

;(HB_PROJECT ? describe : describe.skip)('Config UI server (packed, mocked Vivint)', function () {
  this.timeout(30000)
  let tmp, mock, child, output = '', requestId = 0

  const call = (p, body) => new Promise((resolve, reject) => {
    const id = `req-${++requestId}`
    const onMessage = (msg) => {
      if (msg.action === 'response' && msg.payload.requestId === id) {
        child.off('message', onMessage)
        resolve(msg.payload)
      }
    }
    child.on('message', onMessage)
    child.send({ action: 'request', requestId: id, path: p, body })
    setTimeout(() => reject(new Error(`no response to ${p}`)), 15000)
  })

  before(async function () {
    assert.ok(fs.existsSync(SERVER), `missing ${SERVER}`)
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hbv-ui-'))
    const certs = makeCert(tmp)
    mock = new MockVivint({ cert: fs.readFileSync(certs.cert), key: fs.readFileSync(certs.key) })
    const port = await mock.start()
    child = cp.fork(SERVER, [], {
      cwd: tmp,
      silent: true,
      env: {
        ...process.env,
        NODE_OPTIONS: `--require ${path.join(__dirname, 'preload.js')}`,
        NODE_EXTRA_CA_CERTS: certs.cert,
        VIVINT_MOCK_PORT: String(port),
        HOMEBRIDGE_STORAGE_PATH: tmp,
      },
    })
    child.stdout.on('data', (d) => { output += d })
    child.stderr.on('data', (d) => { output += d })
    await new Promise((resolve, reject) => {
      child.on('message', (msg) => { if (msg.action === 'ready') resolve() })
      child.on('exit', (code) => reject(new Error(`UI server exited with ${code}\n${output}`)))
      setTimeout(() => reject(new Error(`UI server not ready\n${output}`)), 15000)
    })
  })

  after(async function () {
    if (child && child.exitCode === null) {
      child.disconnect()
      await new Promise((r) => child.once('exit', r))
    }
    if (mock) await mock.stop()
    if (tmp) fs.rmSync(tmp, { recursive: true, force: true })
  })

  it('rejects a wrong password with a readable message', async function () {
    const res = await call('/send-code', { email: 'user@example.com', password: 'wrong' })
    assert.strictEqual(res.success, false)
    assert.match(res.data.message, /Check your email and password/)
  })

  it('explains an HTTP 403 (Cloudflare block) instead of blaming the password (#107)', async function () {
    const blocked = /Vivint\/Cloudflare blocked this request \(HTTP 403\)\. Try again later or from another network\./
    mock.override((r) => r.method === 'POST' && r.path === '/api/login', { status: 403, body: 'error code: 1020' })
    const login = await call('/send-code', { email: 'user@example.com', password: SENTINELS.userPassword })
    assert.strictEqual(login.success, false)
    assert.match(login.data.message, blocked)
    assert.doesNotMatch(login.data.message, /password/)

    mock.override((r) => r.method === 'GET' && r.path === '/api/authuser', { status: 403, body: 'error code: 1020' })
    const authuser = await call('/send-code', { email: 'user@example.com', password: SENTINELS.userPassword })
    assert.strictEqual(authuser.success, false)
    assert.match(authuser.data.message, blocked)
    mock.clearOverrides()
  })

  it('returns the refresh token directly when 2FA is not enabled', async function () {
    mock.mfaRequired = false
    const res = await call('/send-code', { email: 'user@example.com', password: SENTINELS.userPassword })
    assert.strictEqual(res.success, true, JSON.stringify(res))
    // authuser succeeded and rotated the session cookie; the newest cookie is the one to keep
    assert.strictEqual(res.data.refreshToken, SENTINELS.rotatedToken)
  })

  it('asks for a 2FA code, rejects a wrong one and accepts the right one', async function () {
    mock.mfaRequired = true
    const first = await call('/send-code', { email: 'user@example.com', password: SENTINELS.userPassword })
    assert.strictEqual(first.success, true, JSON.stringify(first))
    assert.ok(first.data.codePrompt, 'prompts for a code')

    const wrong = await call('/token', { email: 'user@example.com', password: SENTINELS.userPassword, code: '000000' })
    assert.strictEqual(wrong.success, false)
    assert.match(wrong.data.message, /check the code/)

    const ok = await call('/token', { email: 'user@example.com', password: SENTINELS.userPassword, code: SENTINELS.mfaCode })
    assert.strictEqual(ok.success, true, JSON.stringify(ok))
    assert.strictEqual(ok.data.refreshToken, SENTINELS.loginCookie)
  })

  it('never logs the password, 2FA code or session cookie', function () {
    for (const secret of [SENTINELS.userPassword, SENTINELS.mfaCode, SENTINELS.loginCookie, 'SENTINEL_LOGIN_COOKIE', SENTINELS.rotatedToken]) {
      assert.ok(!output.includes(secret), `UI server output contains ${secret}:\n${output}`)
    }
  })
})
