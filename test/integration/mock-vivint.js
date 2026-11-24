// Mock Vivint Sky API + PubNub subscribe endpoint served over HTTPS.
// The Homebridge child process is redirected here by preload.js (tls.connect patch),
// so the plugin's real HTTP / PubNub client code is exercised end-to-end.

const https = require('https')
const { URL } = require('url')

const SENTINELS = {
  refreshToken: 's=SENTINEL_REFRESH_TOKEN_9f3a',
  rotatedToken: 's=SENTINEL_ROTATED_TOKEN_77c1',
  panelUser: 'SENTINEL_PANEL_USER',
  panelPassword: 'SENTINEL_PANEL_PASSWORD_p@ss:w/rd',
  userPassword: 'SENTINEL_USER_PASSWORD',
  loginCookie: 's=SENTINEL_LOGIN_COOKIE_5d2e',
  mfaCode: '424242',
}

const PANEL_ID = 13
const PARTITION_ID = 1
const CHANNEL = 'SENTINEL_CHANNEL_abc'
const SNAPSHOT_TS = '2026-11-24T10:00:00.000000'

// Raw (abbreviated-key) Vivint device payloads
function devices() {
  return [
    { _id: 1, t: 'primary_touch_link_device', n: 'Panel' },
    { _id: 42, t: 'wireless_sensor', ec: 862, n: 'Basement Window', s: false, ser: 192977, ser32: 16970193, lb: false, ta: false },
    { _id: 45, t: 'wireless_sensor', ec: 869, n: 'Family Room Motion', s: false },
    { _id: 46, t: 'wireless_sensor', ec: 589, n: 'Hallway Smoke', s: false },
    { _id: 47, t: 'wireless_sensor', ec: 4040, n: 'Upstairs Combo Smoke', s: false },
    { _id: 48, t: 'wireless_sensor', ec: 4050, n: 'Upstairs Combo CO', s: false },
    { _id: 49, t: 'wireless_sensor', ec: 4020, n: 'Den PIR', s: false },
    { _id: 24, t: 'door_lock_device', n: 'Front Door', s: true, bl: 80 },
    { _id: 30, t: 'garage_door_device', n: 'Garage', s: 1 },
    { _id: 50, t: 'thermostat_device', n: 'Hall Thermostat', val: 21, om: 1, os: 0, hsp: 20, csp: 25, hmdt: 40, tc: false, fs: 0 },
    { _id: 51, t: 'thermostat_device', n: 'Euro Thermostat', val: 21.5, om: 2, os: 2, hsp: 19, csp: 24, hmdt: 45, tc: true, fs: 1 },
    { _id: 60, t: 'binary_switch_device', n: 'Porch Light', s: false },
    { _id: 61, t: 'multilevel_switch_device', n: 'Kitchen Light', s: false, val: 0 },
    {
      _id: 70, t: 'camera_device', n: 'Front Doorbell',
      ciu: ['rtsp://127.0.0.1:9/cam-hd'], cius: ['rtsp://127.0.0.1:9/cam-sd'],
      ceu: ['rtsp://127.0.0.1:9/ext-hd'], ceus: ['rtsp://127.0.0.1:9/ext-sd'],
    },
  ]
}

function systemInfo(securityStatus = 0, deviceOverrides = {}) {
  const d = devices().map((dev) => ({ ...dev, ...deviceOverrides[dev._id] }))
  return {
    system: {
      panid: PANEL_ID,
      pnlctx: { ts: SNAPSHOT_TS },
      par: [{ parid: PARTITION_ID, s: securityStatus, d }],
    },
  }
}

class MockVivint {
  constructor({ cert, key }) {
    this.requests = []
    this.overrides = [] // { match(req) -> bool, status, body, delayMs, times }
    this.pendingSubscribes = []
    this.pubnubQueue = []
    // Real PubNub timetokens are 10^-7 s since the epoch; pubnub >= 9 drops messages older than its subscription start
    this.timetoken = BigInt(Date.now()) * 10000n
    this.securityStatus = 0
    this.deviceOverrides = {} // { [deviceId]: partial raw device fields merged into the snapshot }
    this.mfaRequired = false
    this.mfaValidated = false
    this.server = https.createServer({ cert, key }, (req, res) => this._handle(req, res))
  }

  start() {
    return new Promise((resolve) => {
      this.server.listen(0, '127.0.0.1', () => resolve(this.server.address().port))
    })
  }

  stop() {
    for (const res of this.pendingSubscribes) {
      try { res.destroy() } catch (_) {}
    }
    this.pendingSubscribes = []
    if (this.server.closeAllConnections) this.server.closeAllConnections()
    return new Promise((resolve) => this.server.close(() => resolve()))
  }

  /** Make the next `times` requests matching `match` respond with the given status/body (optionally delayed). */
  override(match, { status = 200, body = '', delayMs = 0, times = 1 } = {}) {
    this.overrides.push({ match, status, body, delayMs, times })
  }

  clearOverrides() {
    this.overrides = []
  }

  vivintRequests(filter = () => true) {
    return this.requests.filter((r) => r.host.includes('vivintsky') && filter(r))
  }

  /** Deliver a raw Vivint PubNub message to every subscribed client. */
  pushPubNub(message) {
    this.pubnubQueue.push(message)
    this._flushSubscribes()
  }

  _flushSubscribes() {
    if (this.pubnubQueue.length === 0) return
    const messages = this.pubnubQueue.splice(0)
    const pending = this.pendingSubscribes.splice(0)
    if (pending.length === 0) {
      this.pubnubQueue.push(...messages)
      return
    }
    const now = BigInt(Date.now()) * 10000n
    this.timetoken = now > this.timetoken ? now : this.timetoken + 1n
    const tt = this.timetoken.toString()
    const payload = JSON.stringify({
      t: { t: tt, r: 1 },
      m: messages.map((d, i) => ({
        // Plain messages carry no `e` (event type) field on the wire
        a: '1', f: 0, i: 'vivint', p: { t: tt, r: 1 }, k: 'sub-key', c: `PlatformChannel#${CHANNEL}`, d,
      })),
    })
    for (const res of pending) {
      res.writeHead(200, { 'content-type': 'text/javascript; charset="UTF-8"' })
      res.end(payload)
    }
  }

  async _handle(req, res) {
    const chunks = []
    for await (const c of req) chunks.push(c)
    const body = Buffer.concat(chunks)
    const host = (req.headers.host || '').split(':')[0]
    const url = new URL(req.url, `https://${host}`)
    const record = { method: req.method, host, path: url.pathname, query: url.search, headers: req.headers, body: body.toString('utf8'), at: Date.now() }
    this.requests.push(record)

    if (/pndsn\.com$|pubnub\.com$/.test(host)) return this._handlePubNub(record, url, res)

    const override = this.overrides.find((o) => o.times > 0 && o.match(record))
    if (override) {
      override.times -= 1
      if (override.delayMs) await new Promise((r) => setTimeout(r, override.delayMs))
      res.writeHead(override.status, { 'content-type': 'application/json' })
      return res.end(typeof override.body === 'string' ? override.body : JSON.stringify(override.body))
    }

    const json = (status, obj, headers = {}) => {
      res.writeHead(status, { 'content-type': 'application/json', ...headers })
      res.end(obj === undefined ? '' : JSON.stringify(obj))
    }

    const p = url.pathname
    if (req.method === 'POST' && p === '/api/login') {
      let creds = {}
      try { creds = JSON.parse(body.toString()) } catch (_) {}
      if (creds.password !== SENTINELS.userPassword) return json(401, { msg: 'bad credentials' })
      this.mfaValidated = false
      return json(200, {}, { 'set-cookie': [`${SENTINELS.loginCookie}; Path=/; HttpOnly`] })
    }
    if (req.method === 'POST' && p === '/platform-user-api/v0/platformusers/2fa/validate') {
      let payload = {}
      try { payload = JSON.parse(body.toString()) } catch (_) {}
      if (req.headers.cookie !== SENTINELS.loginCookie || payload.code !== SENTINELS.mfaCode) return json(401, { msg: 'invalid code' })
      this.mfaValidated = true
      return json(200, {})
    }
    if (req.method === 'GET' && p === '/api/authuser') {
      const cookie = req.headers.cookie || ''
      if (cookie === SENTINELS.loginCookie && this.mfaRequired && !this.mfaValidated) return json(401, { msg: 'mfa required' })
      if (!cookie.includes('SENTINEL_')) return json(401, { msg: 'unauthorized' })
      return json(200, { u: { mbc: CHANNEL, system: [{ panid: PANEL_ID, n: 'Home' }] } }, {
        'set-cookie': [`${SENTINELS.rotatedToken}; Path=/; HttpOnly; Secure`, 'other=1; Path=/'],
      })
    }
    if (req.method === 'GET' && p === `/api/systems/${PANEL_ID}`) return json(200, systemInfo(this.securityStatus, this.deviceOverrides))
    if (req.method === 'GET' && p === `/api/panel-login/${PANEL_ID}`) return json(200, { n: SENTINELS.panelUser, pswd: SENTINELS.panelPassword })
    if (req.method === 'PUT' && p.startsWith(`/api/${PANEL_ID}/${PARTITION_ID}/`)) {
      if (p.endsWith('/armedstates')) {
        try { this.securityStatus = JSON.parse(body.toString()).armState } catch (_) {}
      }
      return json(200, undefined)
    }
    return json(404, { msg: 'not mocked' })
  }

  _handlePubNub(record, url, res) {
    const p = url.pathname
    if (p.startsWith('/time/')) {
      res.writeHead(200, { 'content-type': 'application/json' })
      return res.end(`[${this.timetoken}]`)
    }
    if (p.startsWith('/v2/subscribe/')) {
      const tt = url.searchParams.get('tt')
      if (!tt || tt === '0') {
        res.writeHead(200, { 'content-type': 'text/javascript; charset="UTF-8"' })
        return res.end(JSON.stringify({ t: { t: this.timetoken.toString(), r: 1 }, m: [] }))
      }
      this.pendingSubscribes.push(res)
      res.on('close', () => {
        this.pendingSubscribes = this.pendingSubscribes.filter((r) => r !== res)
      })
      return this._flushSubscribes()
    }
    // presence / leave / heartbeat etc.
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ status: 200, message: 'OK', service: 'Presence' }))
  }
}

module.exports = { MockVivint, SENTINELS, PANEL_ID, PARTITION_ID, CHANNEL, SNAPSHOT_TS }
