const assert = require('assert')
const cp = require('child_process')
const fs = require('fs')
const https = require('https')
const os = require('os')
const path = require('path')

const { httpRequest, sessionCookie, describeError, VivintApiError } = require('../lib/http.js')

describe('http', function () {
  let server, port, agent, tmp, received
  let handler = (req, res) => res.end('ok')

  before(function (done) {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hbv-http-'))
    const key = path.join(tmp, 'key.pem')
    const cert = path.join(tmp, 'cert.pem')
    cp.execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', key, '-out', cert,
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' })
    agent = new https.Agent({ ca: fs.readFileSync(cert) })
    server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, async (req, res) => {
      const chunks = []
      for await (const c of req) chunks.push(c)
      received = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() }
      handler(req, res)
    })
    server.listen(0, '127.0.0.1', () => {
      port = server.address().port
      done()
    })
  })

  after(function (done) {
    agent.destroy()
    server.close(() => {
      fs.rmSync(tmp, { recursive: true, force: true })
      done()
    })
  })

  afterEach(() => { handler = (req, res) => res.end('ok') })

  const url = (p) => `https://localhost:${port}${p}`

  it('sends only the given headers (no User-Agent/Accept/Content-Type) for string bodies', async function () {
    await httpRequest({ method: 'PUT', url: url('/api/1/2/locks/3'), headers: { Cookie: 's=abc' }, body: '{"s":true}', agent })
    assert.strictEqual(received.method, 'PUT')
    assert.strictEqual(received.body, '{"s":true}')
    assert.deepStrictEqual(Object.keys(received.headers).sort(), ['connection', 'content-length', 'cookie', 'host'])
  })

  it('JSON-encodes object bodies with a JSON content type', async function () {
    await httpRequest({ method: 'POST', url: url('/login'), body: { a: 1 }, agent })
    assert.strictEqual(received.headers['content-type'], 'application/json')
    assert.deepStrictEqual(JSON.parse(received.body), { a: 1 })
  })

  it('rejects non-2xx with a VivintApiError that contains no secrets', async function () {
    handler = (req, res) => { res.statusCode = 500; res.end('{"msg":"boom"}') }
    await assert.rejects(
      httpRequest({ url: url('/api/systems/1'), headers: { Cookie: 's=SECRET' }, agent }),
      (err) => {
        assert.ok(err instanceof VivintApiError)
        assert.strictEqual(err.status, 500)
        assert.strictEqual(err.message, 'GET /api/systems/1 failed: HTTP 500')
        assert.ok(!JSON.stringify(err).includes('SECRET'))
        assert.ok(!describeError(err).includes('SECRET'))
        return true
      })
  })

  it('resolves non-2xx when throwOnError is false', async function () {
    handler = (req, res) => { res.statusCode = 401; res.end('') }
    const res = await httpRequest({ url: url('/authuser'), throwOnError: false, agent })
    assert.strictEqual(res.status, 401)
  })

  it('follows redirects for GET', async function () {
    handler = (req, res) => {
      if (req.url === '/old') { res.writeHead(302, { location: '/new' }); return res.end() }
      res.end('{"ok":true}')
    }
    const res = await httpRequest({ url: url('/old'), agent })
    assert.deepStrictEqual(res.json(), { ok: true })
  })

  it('times out', async function () {
    handler = () => {} // never respond
    await assert.rejects(httpRequest({ url: url('/slow'), timeoutMs: 200, agent }), /ETIMEDOUT/)
  })

  describe('network errors on a single line (#151, #173)', function () {
    it('describes a real connection failure to every address of a host', async function () {
      // localhost resolves to ::1 and 127.0.0.1; Node reports both failures as one AggregateError with an empty message
      await assert.rejects(httpRequest({ url: 'https://localhost:1/api/authuser', timeoutMs: 5000 }), (err) => {
        assert.ok(err instanceof VivintApiError)
        assert.match(describeError(err), /^GET \/api\/authuser failed: ECONNREFUSED$/)
        return true
      })
    })

    it('describes an AggregateError with an empty message', function () {
      const withCode = Object.assign(new AggregateError([
        Object.assign(new Error('connect ECONNREFUSED ::1:443'), { code: 'ECONNREFUSED' }),
        Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:443'), { code: 'ECONNREFUSED' }),
      ], ''), { code: 'ECONNREFUSED' })
      assert.strictEqual(describeError(withCode), 'ECONNREFUSED')

      const withoutCode = new AggregateError([
        Object.assign(new Error('connect ENETUNREACH ::1:443'), { code: 'ENETUNREACH' }),
        Object.assign(new Error('connect ETIMEDOUT 1.2.3.4:443'), { code: 'ETIMEDOUT' }),
        Object.assign(new Error('connect ETIMEDOUT 1.2.3.5:443'), { code: 'ETIMEDOUT' }),
      ], '')
      assert.strictEqual(describeError(withoutCode), 'ENETUNREACH, ETIMEDOUT')
      assert.strictEqual(describeError(new AggregateError([], '')), 'AggregateError')
    })

    it('keeps multi-line messages to their first line', function () {
      assert.strictEqual(describeError(new Error('first\nsecond')), 'first')
    })
  })

  it('extracts the session cookie from Set-Cookie', function () {
    assert.strictEqual(sessionCookie({ headers: { 'set-cookie': ['a=1; Path=/', 's=xyz; HttpOnly'] } }), 's=xyz')
    assert.strictEqual(sessionCookie({ headers: {} }), undefined)
  })
})
