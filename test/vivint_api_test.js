const assert = require('assert')
const http = require('../lib/http.js')

// Swap lib/http.js's httpRequest for a scripted fake before vivint_api.js captures it
const realHttpRequest = http.httpRequest
let script = []
let calls = []
http.httpRequest = async (opts) => {
  calls.push(opts)
  const next = script.shift()
  if (!next) throw new Error(`unexpected request ${opts.url}`)
  if (next instanceof Error) throw next
  return {
    status: next.status || 200,
    headers: next.headers || {},
    body: JSON.stringify(next.body || {}),
    json() { return next.body || {} },
  }
}
delete require.cache[require.resolve('../lib/vivint_api.js')]
const VivintApiModule = require('../lib/vivint_api.js')

const logs = []
const log = Object.assign((...a) => logs.push(['info', a.join(' ')]), {
  debug: (...a) => logs.push(['debug', a.join(' ')]),
  info: (...a) => logs.push(['info', a.join(' ')]),
  warn: (...a) => logs.push(['warn', a.join(' ')]),
  error: (...a) => logs.push(['error', a.join(' ')]),
})

const authOk = (cookie) => ({ body: { u: { mbc: 'chan', system: [{ panid: 13 }] } }, headers: cookie ? { 'set-cookie': [`${cookie}; Path=/`] } : {} })
const apiError = (status) => new http.VivintApiError(`GET /api/authuser failed: HTTP ${status}`, { status })

describe('VivintApi', function () {
  let VivintApi

  beforeEach(() => {
    script = []
    calls = []
    logs.length = 0
    VivintApi = VivintApiModule({}, log)
    VivintApi.retryDelayMs = 5
  })

  after(() => { http.httpRequest = realHttpRequest })

  describe('.doAuth', function () {
    it('uses the refresh token and adopts a rotated session cookie', async function () {
      script = [authOk('s=rotated')]
      const creds = { refreshToken: 's=original' }
      const result = await VivintApi.doAuth(creds)
      assert.strictEqual(calls[0].headers.Cookie, 's=original')
      assert.strictEqual(result.refreshToken, 's=rotated')
      assert.strictEqual(creds.refreshToken, 's=rotated')
      assert.strictEqual(result.sessionInfo.Users.MessageBroadcastChannel, 'chan')
    })

    it('fails fast with VivintAuthError on 401 (no retry loop)', async function () {
      script = [apiError(401)]
      await assert.rejects(VivintApi.doAuth({ refreshToken: 's=old' }), VivintApiModule.VivintAuthError)
      assert.strictEqual(calls.length, 1)
    })

    it('retries transient failures until it succeeds', async function () {
      script = [apiError(502), new http.VivintApiError('GET /api/authuser failed: ECONNRESET', { code: 'ECONNRESET' }), authOk()]
      const result = await VivintApi.doAuth({ refreshToken: 's=tok' })
      assert.strictEqual(calls.length, 3)
      assert.strictEqual(result.refreshToken, 's=tok')
      const errors = logs.filter(([l]) => l === 'error').map(([, m]) => m)
      assert.strictEqual(errors.length, 2)
      assert.ok(errors.every((m) => !m.includes('s=tok')), 'token never logged')
    })

    it('rethrows transient failures when retry is disabled', async function () {
      script = [apiError(500)]
      await assert.rejects(VivintApi.doAuth({ refreshToken: 's=tok' }, { retry: false }), /HTTP 500/)
    })
  })

  describe('.login and #renew', function () {
    const systemInfo = { body: { system: { panid: 13, pnlctx: { ts: 't' }, par: [{ parid: 1, d: [] }] } } }
    const panelLogin = { body: { n: 'u', pswd: 'p' } }

    it('logs in, then renews with a single in-flight request', async function () {
      script = [authOk('s=two'), systemInfo, panelLogin]
      const api = await VivintApi.login({ refreshToken: 's=one' })
      assert.strictEqual(api.panelId, 13)
      assert.strictEqual(api.parId, 1)
      assert.strictEqual(api.refreshToken, 's=two')
      assert.strictEqual(calls[1].headers.Cookie, 's=two')

      script = [authOk('s=three')]
      const [a, b] = await Promise.all([api.renew(), api.renew()])
      assert.strictEqual(a, api)
      assert.strictEqual(b, api)
      assert.strictEqual(calls.length, 4, 'one renewal request for two concurrent renew() calls')
      assert.strictEqual(api.refreshToken, 's=three')
    })

    it('renew() rejects instead of scheduling background retries', async function () {
      script = [authOk(), systemInfo, panelLogin]
      const api = await VivintApi.login({ refreshToken: 's=one' })
      script = [apiError(503)]
      await assert.rejects(api.renew(), /HTTP 503/)
      script = [authOk()]
      await api.renew()
      assert.strictEqual(calls.length, 5)
    })

    it('reports an account without systems clearly', async function () {
      script = [{ body: { u: { mbc: 'c', system: [] } } }]
      await assert.rejects(VivintApi.login({ refreshToken: 's=x' }), /No Vivint system found/)
    })

    describe('with several systems on the account (#133)', function () {
      const twoSystems = (cookie) => ({
        body: { u: { mbc: 'chan', system: [{ panid: 13, sn: 'Home' }, { panid: 14, sn: 'Cabin' }] } },
        headers: cookie ? { 'set-cookie': [`${cookie}; Path=/`] } : {},
      })
      const cabinInfo = { body: { system: { panid: 14, pnlctx: { ts: 't' }, par: [{ parid: 2, d: [] }] } } }

      it('logs every system and uses the first by default', async function () {
        script = [twoSystems(), systemInfo, panelLogin]
        const api = await VivintApi.login({ refreshToken: 's=one' })
        assert.strictEqual(api.panelId, 13)
        assert.strictEqual(api.defaultPanelId, 13)
        assert.strictEqual(calls[1].url, 'https://www.vivintsky.com/api/systems/13')
        const info = logs.filter(([l]) => l === 'info').map(([, m]) => m)
        assert.ok(info.includes('Found Vivint system [PanelId]:13 [Name]:Home'), info.join('\n'))
        assert.ok(info.includes('Found Vivint system [PanelId]:14 [Name]:Cabin'), info.join('\n'))
        assert.ok(info.some((m) => /Using the first Vivint system \[PanelId\]:13.*Set "panelId"/.test(m)), info.join('\n'))
      })

      for (const configured of [14, '14', ' 14 ']) {
        it(`uses the configured panelId (${JSON.stringify(configured)})`, async function () {
          VivintApi = VivintApiModule({ panelId: configured }, log)
          script = [twoSystems(), cabinInfo, panelLogin, { status: 200 }]
          const api = await VivintApi.login({ refreshToken: 's=one' })
          assert.strictEqual(api.panelId, 14)
          assert.strictEqual(api.parId, 2)
          assert.strictEqual(api.defaultPanelId, 13, 'legacy cached accessories still belong to the first system')
          assert.strictEqual(calls[1].url, 'https://www.vivintsky.com/api/systems/14')
          assert.strictEqual(calls[2].url, 'https://www.vivintsky.com/api/panel-login/14')
          await api.setLockState(24, true)
          assert.strictEqual(calls[3].url, 'https://www.vivintsky.com/api/14/2/locks/24')
        })
      }

      it('reports an unknown configured panelId with the available systems, without loading anything', async function () {
        VivintApi = VivintApiModule({ panelId: 99 }, log)
        script = [twoSystems()]
        await assert.rejects(VivintApi.login({ refreshToken: 's=one' }), (err) => {
          assert.ok(err instanceof VivintApiModule.VivintConfigError)
          assert.match(err.message, /panelId 99 was not found.*\[PanelId\]:13 \[Name\]:Home, \[PanelId\]:14 \[Name\]:Cabin/)
          return true
        })
        assert.strictEqual(calls.length, 1)
      })

      it('ignores an empty panelId', async function () {
        VivintApi = VivintApiModule({ panelId: '' }, log)
        script = [twoSystems(), systemInfo, panelLogin]
        assert.strictEqual((await VivintApi.login({ refreshToken: 's=one' })).panelId, 13)
      })

      it('does not suggest panelId for a single system', async function () {
        script = [authOk(), systemInfo, panelLogin]
        await VivintApi.login({ refreshToken: 's=one' })
        assert.ok(!logs.some(([, m]) => /Using the first/.test(m)))
        assert.ok(logs.some(([l, m]) => l === 'info' && m === 'Found Vivint system [PanelId]:13 [Name]:(unnamed)'))
      })
    })

    it('sends device commands as a raw JSON string with the session cookie', async function () {
      script = [authOk(), systemInfo, panelLogin, { status: 200 }]
      const api = await VivintApi.login({ refreshToken: 's=one' })
      await api.setLockState(24, true)
      const put = calls[3]
      assert.strictEqual(put.method, 'PUT')
      assert.strictEqual(put.url, 'https://www.vivintsky.com/api/13/1/locks/24')
      assert.strictEqual(typeof put.body, 'string')
      assert.deepStrictEqual(JSON.parse(put.body), { _id: 24, s: true })
      assert.strictEqual(put.headers.Cookie, 's=one')
    })
  })
})
