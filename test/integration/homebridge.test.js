// End-to-end test: runs a real Homebridge process with the packed plugin installed,
// Vivint + PubNub mocked over HTTPS, and drives accessories via the HAP HTTP API.
//
// Requires HB_PROJECT (output of test/integration/setup.js). Run with:
//   npm run test:integration

const assert = require('assert')
const cp = require('child_process')
const fs = require('fs')
const net = require('net')
const os = require('os')
const path = require('path')

const { MockVivint, SENTINELS, PANEL_ID, PARTITION_ID, SNAPSHOT_TS } = require('./mock-vivint')
const { HapClient, T } = require('./hap-client')

const HB_PROJECT = process.env.HB_PROJECT
const PIN = '031-45-154'
const PLUGIN_DIR = HB_PROJECT && path.join(HB_PROJECT, 'node_modules', '@balansse', 'homebridge-vivint')

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function waitFor(fn, { timeout = 20000, interval = 200, message = 'condition' } = {}) {
  const end = Date.now() + timeout
  let lastErr
  while (Date.now() < end) {
    try {
      const v = await fn()
      if (v) return v
    } catch (err) {
      lastErr = err
    }
    await sleep(interval)
  }
  throw new Error(`Timed out waiting for ${message}${lastErr ? `: ${lastErr.message}` : ''}`)
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
    srv.on('error', reject)
  })
}

function makeCert(dir) {
  const key = path.join(dir, 'key.pem')
  const cert = path.join(dir, 'cert.pem')
  cp.execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
    '-keyout', key, '-out', cert, '-subj', '/CN=www.vivintsky.com',
    '-addext', 'subjectAltName=DNS:www.vivintsky.com,DNS:ps.pndsn.com,DNS:*.pndsn.com,DNS:*.pubnub.com',
    '-addext', 'basicConstraints=critical,CA:TRUE',
  ], { stdio: 'ignore' })
  return { key, cert }
}

class HomebridgeProcess {
  constructor({ storage, hapPort, mockPort, certPath, platformConfig }) {
    this.storage = storage
    this.accessoriesSnapshot = null
    this.hapPort = hapPort
    this.log = ''
    this.exited = null
    fs.writeFileSync(path.join(storage, 'config.json'), JSON.stringify({
      bridge: { name: 'Vivint Test Bridge', username: 'CC:22:3D:E3:CE:31', port: hapPort, pin: PIN },
      platforms: [{ platform: 'Vivint', refreshToken: SENTINELS.refreshToken, ...platformConfig }],
    }, null, 2))
    this.env = {
      ...process.env,
      NODE_OPTIONS: `--require ${path.join(__dirname, 'preload.js')}`,
      NODE_EXTRA_CA_CERTS: certPath,
      VIVINT_MOCK_PORT: String(mockPort),
    }
  }

  start() {
    const bin = path.join(HB_PROJECT, 'node_modules', 'homebridge', 'bin', 'homebridge')
    this.child = cp.spawn(process.execPath, [bin, '-I', '-D', '-Q', '-T', '-U', this.storage, '-P', PLUGIN_DIR, '--strict-plugin-resolution'], {
      env: this.env, stdio: ['ignore', 'pipe', 'pipe'],
    })
    const append = (d) => {
      this.log += d.toString()
      if (process.env.HB_LOG) process.stderr.write(d)
    }
    this.child.stdout.on('data', append)
    this.child.stderr.on('data', append)
    this.child.on('exit', (code, signal) => { this.exited = { code, signal } })
  }

  async stop() {
    if (!this.child || this.exited) return this.exited
    this.child.kill('SIGTERM')
    const t0 = Date.now()
    while (!this.exited && Date.now() - t0 < 15000) await sleep(100)
    if (!this.exited) {
      this.child.kill('SIGKILL')
      throw new Error('Homebridge did not exit within 15s of SIGTERM')
    }
    return this.exited
  }

  assertAlive() {
    assert.strictEqual(this.exited, null, `Homebridge exited unexpectedly: ${JSON.stringify(this.exited)}\n${this.tail()}`)
  }

  tail(n = 60) {
    return this.log.split('\n').slice(-n).join('\n')
  }
}

const FATAL_PATTERNS = [/Unhandled( promise)? rejection/i, /uncaughtException/i, /Error while bootstrapping accessories/, /UnhandledPromiseRejection/]

;(HB_PROJECT ? describe : describe.skip)('Homebridge integration (packed plugin, mocked Vivint)', function () {
  this.timeout(120000)

  let tmp, certs, mock, mockPort, hb, hap

  before(async function () {
    assert.ok(fs.existsSync(PLUGIN_DIR), `plugin not installed in ${PLUGIN_DIR}`)
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hbv-it-'))
    certs = makeCert(tmp)
    mock = new MockVivint({ cert: fs.readFileSync(certs.cert), key: fs.readFileSync(certs.key) })
    mockPort = await mock.start()

    const storage = path.join(tmp, 'storage')
    fs.mkdirSync(storage)
    const hapPort = await freePort()
    hb = new HomebridgeProcess({
      storage, hapPort, mockPort, certPath: certs.cert,
      platformConfig: { motionDetectedOccupancySensorMins: 1, lowBatteryLevel: 15 },
    })
    hb.start()
    hap = new HapClient(hapPort, PIN)

    await waitFor(async () => {
      hb.assertAlive()
      const accs = await hap.accessories()
      return accs.some((a) => a.name === 'Front Door') && accs
    }, { timeout: 60000, message: 'accessories to be published' })
    // Wait for PubNub to subscribe (long-poll pending)
    await waitFor(() => mock.pendingSubscribes.length > 0, { timeout: 20000, message: 'PubNub subscribe' })
  })

  after(async function () {
    if (hb) {
      const exit = await hb.stop().catch((e) => e)
      if (process.env.HB_LOG_FILE) fs.writeFileSync(process.env.HB_LOG_FILE, hb.log)
      if (process.env.HB_LOG_ON_FAIL !== '0' && this.currentTest && this.currentTest.state === 'failed') {
        console.log(hb.tail(200))
      }
      void exit
    }
    if (mock && process.env.MOCK_DUMP) fs.writeFileSync(process.env.MOCK_DUMP, JSON.stringify(mock.requests, null, 2))
    if (mock) await mock.stop()
    if (tmp) fs.rmSync(tmp, { recursive: true, force: true })
  })

  afterEach(function () {
    mock.clearOverrides()
    if (this.currentTest.state === 'failed') console.log('---- Homebridge log tail ----\n' + hb.tail(80))
  })

  describe('bootstrap', function () {
    it('authenticates with the configured refresh token and loads the system', function () {
      const auth = mock.vivintRequests((r) => r.path === '/api/authuser')
      assert.ok(auth.length >= 1, 'authuser called')
      assert.strictEqual(auth[0].headers.cookie, SENTINELS.refreshToken)
      assert.ok(mock.vivintRequests((r) => r.path === `/api/systems/${PANEL_ID}`).length >= 1)
      assert.ok(mock.vivintRequests((r) => r.path === `/api/panel-login/${PANEL_ID}`).length >= 1)
    })

    it('uses the rotated refresh token from Set-Cookie for subsequent calls', function () {
      const sys = mock.vivintRequests((r) => r.path === `/api/systems/${PANEL_ID}`)
      assert.strictEqual(sys[sys.length - 1].headers.cookie, SENTINELS.rotatedToken)
    })

    it('publishes every supported device as a HomeKit accessory', async function () {
      hb.accessoriesSnapshot = await hap.accessories()
      const names = hb.accessoriesSnapshot.map((a) => a.name)
      for (const n of ['Vivint Test Bridge', 'Panel', 'Basement Window', 'Family Room Motion', 'Hallway Smoke', 'Front Door',
        'Upstairs Combo Smoke', 'Upstairs Combo CO', 'Den PIR', 'Garage', 'Hall Thermostat', 'Euro Thermostat', 'Porch Light', 'Kitchen Light', 'Front Doorbell']) {
        assert.ok(names.some((x) => x === n || x.startsWith(`${n} `)), `missing accessory ${n}; have ${names.join(', ')}`)
      }
    })

    it('exposes combo smoke/CO detectors and PIR3 motion with their own service types (#144, #172)', async function () {
      const accs = await hap.accessories()
      for (const [name, svc] of [['Upstairs Combo Smoke', T.SmokeSensor], ['Upstairs Combo CO', T.CarbonMonoxideSensor], ['Den PIR', T.MotionSensor]]) {
        const acc = accs.find((a) => a.name === name)
        const types = acc.services.map((s) => s.type)
        assert.ok(types.includes(svc), `${name} has service ${svc}; has ${types.join(',')}`)
        assert.ok(!types.includes(T.ContactSensor), `${name} must not be a contact sensor`)
      }
    })

    it('reflects the initial snapshot', async function () {
      const v = async (acc, svc, ch) => (await hap.get(await hap.find(acc, svc, ch))).value
      assert.strictEqual(await v('Basement Window', T.ContactSensor, T.ContactSensorState), 0)
      assert.strictEqual(await v('Front Door', T.LockMechanism, T.LockCurrentState), 1)
      assert.strictEqual(await v('Front Door', T.Battery, T.BatteryLevel), 80)
      assert.strictEqual(await v('Panel', T.SecuritySystem, T.SecuritySystemCurrentState), 3)
      assert.strictEqual(await v('Garage', T.GarageDoorOpener, T.CurrentDoorState), 1)
      assert.strictEqual(await v('Hall Thermostat', T.Thermostat, T.TargetHeatingCoolingState), 1)
      assert.strictEqual(await v('Hall Thermostat', T.Thermostat, T.TemperatureDisplayUnits), 1, 'Fahrenheit')
      assert.strictEqual(await v('Euro Thermostat', T.Thermostat, T.TemperatureDisplayUnits), 0, 'Celsius')
      assert.strictEqual(await v('Euro Thermostat', T.Thermostat, T.TargetTemperature), 24)
      assert.strictEqual(await v('Euro Thermostat', T.Thermostat, T.CurrentTemperature), 21.5)
      assert.strictEqual(Number(await v('Porch Light', T.Lightbulb, T.On)), 0)
    })
  })

  describe('commands', function () {
    const lastPut = (suffix) => {
      const puts = mock.vivintRequests((r) => r.method === 'PUT' && r.path.endsWith(suffix))
      return puts[puts.length - 1]
    }

    it('locks/unlocks a door', async function () {
      const ref = await hap.find('Front Door', T.LockMechanism, T.LockTargetState)
      const res = await hap.set(ref, 0)
      assert.strictEqual(res.status, 0)
      const put = await waitFor(() => lastPut('/locks/24'), { message: 'lock PUT' })
      assert.strictEqual(put.path, `/api/${PANEL_ID}/${PARTITION_ID}/locks/24`)
      assert.deepStrictEqual(JSON.parse(put.body), { _id: 24, s: false })
      assert.strictEqual(put.headers.cookie, SENTINELS.rotatedToken)
    })

    it('reports a failed lock command back to HomeKit', async function () {
      mock.override((r) => r.method === 'PUT' && r.path.endsWith('/locks/24'), { status: 500, body: { msg: 'boom' } })
      const ref = await hap.find('Front Door', T.LockMechanism, T.LockTargetState)
      const res = await hap.set(ref, 1)
      assert.notStrictEqual(res.status, 0, `expected HAP error status, got ${JSON.stringify(res)}`)
      hb.assertAlive()
    })

    it('reports an expired session (401) on a command back to HomeKit', async function () {
      mock.override((r) => r.method === 'PUT' && r.path.endsWith('/door/30'), { status: 401, body: { msg: 'unauthorized' } })
      const ref = await hap.find('Garage', T.GarageDoorOpener, T.TargetDoorState)
      const res = await hap.set(ref, 0)
      assert.notStrictEqual(res.status, 0)
      hb.assertAlive()
    })

    it('opens the garage door', async function () {
      const ref = await hap.find('Garage', T.GarageDoorOpener, T.TargetDoorState)
      const res = await hap.set(ref, 0)
      assert.strictEqual(res.status, 0)
      const put = await waitFor(() => lastPut('/door/30'), { message: 'garage PUT' })
      assert.deepStrictEqual(JSON.parse(put.body), { _id: 30, s: 4 })
    })

    it('arms the panel away', async function () {
      const ref = await hap.find('Panel', T.SecuritySystem, T.SecuritySystemTargetState)
      const res = await hap.set(ref, 1)
      assert.strictEqual(res.status, 0)
      const put = await waitFor(() => lastPut('/armedstates'), { message: 'arm PUT' })
      assert.deepStrictEqual(JSON.parse(put.body), { armState: 4, forceArm: false })
    })

    it('reports a failed arm command back to HomeKit', async function () {
      mock.override((r) => r.method === 'PUT' && r.path.endsWith('/armedstates'), { status: 500, body: {}, times: 5 })
      const ref = await hap.find('Panel', T.SecuritySystem, T.SecuritySystemTargetState)
      const res = await hap.set(ref, 0)
      assert.notStrictEqual(res.status, 0)
      hb.assertAlive()
    })

    it('sets the thermostat heat set point', async function () {
      const ref = await hap.find('Hall Thermostat', T.Thermostat, T.TargetTemperature)
      const res = await hap.set(ref, 22)
      assert.strictEqual(res.status, 0)
      const put = await waitFor(() => lastPut('/thermostats/50'), { message: 'thermostat PUT' })
      assert.deepStrictEqual(JSON.parse(put.body), { hsp: 22 })
    })

    it('reports a failed thermostat command without crashing Homebridge', async function () {
      await sleep(2500) // let any debounce window from the previous test close
      mock.override((r) => r.method === 'PUT' && r.path.endsWith('/thermostats/50'), { status: 500, body: {}, times: 5 })
      const ref = await hap.find('Hall Thermostat', T.Thermostat, T.TargetTemperature)
      const res = await hap.set(ref, 23)
      assert.notStrictEqual(res.status, 0, `expected HAP error status, got ${JSON.stringify(res)}`)
      await sleep(1000)
      hb.assertAlive()
    })

    it('coalesces rapid thermostat changes and applies the last value', async function () {
      await sleep(2500)
      const ref = await hap.find('Hall Thermostat', T.Thermostat, T.TargetTemperature)
      const before = mock.vivintRequests((r) => r.method === 'PUT' && r.path.endsWith('/thermostats/50')).length
      const results = await Promise.all([20.5, 21, 21.5, 24].map((v) => hap.set(ref, v)))
      results.forEach((r) => assert.strictEqual(r.status, 0))
      await sleep(3000)
      const puts = mock.vivintRequests((r) => r.method === 'PUT' && r.path.endsWith('/thermostats/50')).slice(before)
      assert.ok(puts.length >= 1 && puts.length <= 2, `expected 1-2 PUTs, got ${puts.length}`)
      assert.deepStrictEqual(JSON.parse(puts[puts.length - 1].body), { hsp: 24 })
    })

    it('turns a switch on', async function () {
      const ref = await hap.find('Porch Light', T.Lightbulb, T.On)
      const res = await hap.set(ref, true)
      assert.strictEqual(res.status, 0)
      const put = await waitFor(() => lastPut('/switches/60'), { message: 'switch PUT' })
      assert.deepStrictEqual(JSON.parse(put.body), { s: true, _id: 60 })
    })

    it('answers every rapid dimmer brightness change', async function () {
      const ref = await hap.find('Kitchen Light', T.Lightbulb, T.Brightness)
      const t0 = Date.now()
      const results = await Promise.all([10, 20, 30, 40, 50].map((v) => hap.set(ref, v)))
      results.forEach((r) => assert.strictEqual(r.status, 0, JSON.stringify(r)))
      assert.ok(Date.now() - t0 < 5000, `dimmer sets took ${Date.now() - t0}ms`)
      await sleep(1000)
      const puts = mock.vivintRequests((r) => r.method === 'PUT' && r.path.endsWith('/switches/61'))
      assert.deepStrictEqual(JSON.parse(puts[puts.length - 1].body), { val: 50, _id: 61 })
    })
  })

  describe('PubNub updates', function () {
    const push = (devices, extra = {}) => mock.pushPubNub({
      _id: `${PANEL_ID}|${PARTITION_ID}`, t: 'account_partition', panid: PANEL_ID, parid: PARTITION_ID, op: 'u',
      da: { plctx: { ts: '2026-11-24T11:00:00.000000' }, d: devices }, ...extra,
    })

    it('updates a contact sensor', async function () {
      const ref = await hap.find('Basement Window', T.ContactSensor, T.ContactSensorState)
      push([{ _id: 42, s: true }])
      await waitFor(async () => (await hap.get(ref)).value === 1, { message: 'contact open' })
      push([{ _id: 42, s: false }])
      await waitFor(async () => (await hap.get(ref)).value === 0, { message: 'contact closed' })
    })

    it('ignores stale updates older than the snapshot', async function () {
      const ref = await hap.find('Basement Window', T.ContactSensor, T.ContactSensorState)
      mock.pushPubNub({ _id: `${PANEL_ID}|${PARTITION_ID}`, t: 'account_partition', da: { plctx: { ts: '2020-01-01T00:00:00.000000' }, d: [{ _id: 42, s: true }] } })
      await sleep(1500)
      assert.strictEqual((await hap.get(ref)).value, 0)
      void SNAPSHOT_TS
    })

    it('updates the security system state', async function () {
      const ref = await hap.find('Panel', T.SecuritySystem, T.SecuritySystemCurrentState)
      mock.pushPubNub({ _id: PANEL_ID, t: 'account_system', panid: PANEL_ID, da: { plctx: { ts: '2026-11-24T11:00:01.000000' }, s: 3 } })
      await waitFor(async () => (await hap.get(ref)).value === 0, { message: 'panel STAY_ARM' })
    })

    it('marks motion and turns on the occupancy sensor', async function () {
      const motion = await hap.find('Family Room Motion', T.MotionSensor, T.MotionDetected)
      const occupancy = await hap.find('Family Room Motion', T.OccupancySensor, T.OccupancyDetected)
      push([{ _id: 45, s: true }])
      await waitFor(async () => Number((await hap.get(motion)).value) === 1, { message: 'motion detected' })
      await waitFor(async () => (await hap.get(occupancy)).value === 1, { message: 'occupancy detected' })
    })

    it('updates combo smoke/CO detectors and PIR3 motion', async function () {
      const smoke = await hap.find('Upstairs Combo Smoke', T.SmokeSensor, T.SmokeDetected)
      const co = await hap.find('Upstairs Combo CO', T.CarbonMonoxideSensor, T.CarbonMonoxideDetected)
      const pir = await hap.find('Den PIR', T.MotionSensor, T.MotionDetected)
      assert.strictEqual((await hap.get(smoke)).value, 0)
      assert.strictEqual((await hap.get(co)).value, 0)
      push([{ _id: 47, s: true }, { _id: 48, s: true }, { _id: 49, s: true }])
      await waitFor(async () => (await hap.get(smoke)).value === 1, { message: 'smoke detected' })
      await waitFor(async () => (await hap.get(co)).value === 1, { message: 'CO abnormal' })
      await waitFor(async () => Number((await hap.get(pir)).value) === 1, { message: 'PIR3 motion detected' })
      push([{ _id: 47, s: false }, { _id: 48, s: false }, { _id: 49, s: false }])
      await waitFor(async () => (await hap.get(smoke)).value === 0, { message: 'smoke cleared' })
    })

    it('marks a lock jammed from an inbox alert', async function () {
      const ref = await hap.find('Front Door', T.LockMechanism, T.LockCurrentState)
      mock.pushPubNub({ _id: 'msg1', t: 'inbox_message', da: { sub: 'Alert: Front Door failed to lock' } })
      await waitFor(async () => (await hap.get(ref)).value === 2, { message: 'lock jammed' })
    })

    it('recovers on its own from brief subscribe failures (PubNub retries)', async function () {
      const motion = await hap.find('Family Room Motion', T.MotionSensor, T.MotionDetected)
      push([{ _id: 45, s: false }])
      await waitFor(async () => Number((await hap.get(motion)).value) === 0, { message: 'motion cleared' })
      await waitFor(() => mock.pendingSubscribes.length > 0, { message: 'PubNub long-poll pending' })
      const before = mock.subscribeRequests().length
      mock.failSubscribes(2, 'drop')
      await waitFor(() => mock.subscribeFailures.remaining === 0 && mock.pendingSubscribes.length > 0,
        { timeout: 30000, message: 'PubNub resubscribed after dropped connections' })
      assert.ok(mock.subscribeRequests().length - before >= 2)
      push([{ _id: 45, s: true }])
      await waitFor(async () => Number((await hap.get(motion)).value) === 1, { message: 'motion after recovery' })
    })

    it('reconnects after PubNub gives up, and motion reaches HomeKit again (#172)', async function () {
      this.timeout(90000)
      const motion = await hap.find('Family Room Motion', T.MotionSensor, T.MotionDetected)
      push([{ _id: 45, s: false }])
      await waitFor(async () => Number((await hap.get(motion)).value) === 0, { message: 'motion cleared' })
      await waitFor(() => mock.pendingSubscribes.length > 0, { message: 'PubNub long-poll pending' })
      const logStart = hb.log.length
      // 403 is not retried by PubNub: the client gives up immediately, as it does after exhausting its retries.
      // The first failure kills the long-poll, the second the reconnect handshake (5s later); the reconnect 10s
      // after that succeeds.
      mock.failSubscribes(2, 403)
      await waitFor(() => /PubNub connection lost/.test(hb.log.slice(logStart)), { message: 'connection lost warning' })
      await waitFor(() => /PubNub connection restored/.test(hb.log.slice(logStart)),
        { timeout: 60000, message: 'connection restored after reconnect' })
      await waitFor(() => mock.pendingSubscribes.length > 0, { message: 'PubNub long-poll pending after reconnect' })
      push([{ _id: 45, s: true }])
      await waitFor(async () => Number((await hap.get(motion)).value) === 1, { message: 'motion after reconnect' })
      const lines = hb.log.slice(logStart).split('\n')
      assert.strictEqual(lines.filter((l) => /PubNub connection lost/.test(l)).length, 1, 'one warning per outage')
      assert.strictEqual(lines.filter((l) => /PubNub connection restored/.test(l)).length, 1, 'one recovery line')
      hb.assertAlive()
    })

    it('survives malformed messages', async function () {
      mock.pushPubNub({ _id: 'msg2', t: 'inbox_message', da: { sub: 'Something failed to lock' } })
      mock.pushPubNub({ _id: 'x', t: 'account_partition', da: { d: [{ _id: 42, s: [true] }] } })
      mock.pushPubNub({ garbage: true })
      await sleep(1500)
      hb.assertAlive()
      const ref = await hap.find('Basement Window', T.ContactSensor, T.ContactSensorState)
      push([{ _id: 42, s: true }])
      await waitFor(async () => (await hap.get(ref)).value === 1, { message: 'contact update after garbage' })
    })
  })

  describe('camera', function () {
    it('answers a snapshot request when the stream is unreachable, without crashing', async function () {
      const accs = await hap.accessories()
      const cam = accs.find((a) => a.name === 'Front Doorbell')
      const res = await hap.snapshot(cam.aid)
      assert.notStrictEqual(res.status, 200, 'no image expected from an unreachable stream')
      await sleep(500)
      hb.assertAlive()
    })
  })

  describe('hygiene', function () {
    it('never writes credentials or tokens to the log (debug mode)', function () {
      const leaked = Object.entries(SENTINELS)
        .filter(([, v]) => hb.log.includes(v) || hb.log.includes(v.replace(/^s=/, '')) || hb.log.includes(encodeURIComponent(v)))
        .map(([k]) => k)
      const lines = hb.log.split('\n').filter((l) => /SENTINEL_(REFRESH|ROTATED|PANEL_PASSWORD)/.test(l)).slice(0, 5)
      assert.deepStrictEqual(leaked.filter((k) => k !== 'panelUser'), [], `leaked: ${leaked.join(', ')}\n${lines.join('\n')}`)
    })

    it('logs no unhandled errors', function () {
      const hits = FATAL_PATTERNS.filter((p) => p.test(hb.log)).map(String)
      assert.deepStrictEqual(hits, [], hb.tail(80))
    })

    it('makes no unexpected outbound connections', function () {
      const lines = hb.log.split('\n').filter((l) => l.includes('[integration-preload] unexpected outbound'))
      assert.deepStrictEqual(lines, [])
    })

    it('shuts down cleanly on SIGTERM', async function () {
      const t0 = Date.now()
      const exit = await hb.stop()
      assert.ok(exit, 'exited')
      // Homebridge 2.x exits as soon as the event loop is empty, so a fast exit proves the plugin
      // leaves no timers/sockets behind. Homebridge 1.x always waits for a fixed 5s exit timer.
      const hbMajor = Number(require(path.join(HB_PROJECT, 'node_modules', 'homebridge', 'package.json')).version.split('.')[0])
      const limit = hbMajor >= 2 ? 3000 : 6500
      assert.ok(Date.now() - t0 < limit, `shutdown took ${Date.now() - t0}ms (limit ${limit}ms on Homebridge ${hbMajor}.x)`)
    })
  })

  describe('restart', function () {
    let hb2

    after(async function () {
      if (hb2) {
        await hb2.stop().catch(() => {})
        if (process.env.HB_LOG_FILE) fs.writeFileSync(process.env.HB_LOG_FILE + '.restart', hb2.log)
      }
    })

    it('reports a smarthomesystem-only account as not supported yet (#82)', async function () {
      mock.override((r) => r.path === '/api/authuser', {
        body: { u: { mbc: 'SENTINEL_CHANNEL_abc', system: [], smarthomesystem: [{ panid: 77 }] } },
      })
      hb2 = new HomebridgeProcess({ storage: hb.storage, hapPort: hb.hapPort, mockPort, certPath: certs.cert, platformConfig: {} })
      hb2.start()
      try {
        await waitFor(() => /This Vivint account type is not supported yet \(smarthomesystem\)/.test(hb2.log),
          { timeout: 60000, message: 'smarthomesystem message' })
        assert.doesNotMatch(hb2.log, /No Vivint system found/)
        await sleep(1000)
        hb2.assertAlive()
        // Logged as "Error while bootstrapping accessories: <message>", but nothing may crash
        assert.ok(![/Unhandled( promise)? rejection/i, /uncaughtException/i].some((p) => p.test(hb2.log)), hb2.tail(80))
      } finally {
        await hb2.stop() // don't leave it holding the HAP port for the next test
      }
    })

    it('restores cached accessories and keeps them working after a restart', async function () {
      const before = await (async () => hb.accessoriesSnapshot)()
      hb2 = new HomebridgeProcess({
        storage: hb.storage, hapPort: hb.hapPort, mockPort, certPath: certs.cert,
        platformConfig: { motionDetectedOccupancySensorMins: 1, lowBatteryLevel: 15 },
      })
      hb2.start()
      const accs = await waitFor(async () => {
        hb2.assertAlive()
        const a = await hap.accessories()
        return a.length === before.length && a
      }, { timeout: 60000, message: 'accessories after restart' })
      assert.deepStrictEqual(accs.map((a) => `${a.aid}:${a.name}`).sort(), before.map((a) => `${a.aid}:${a.name}`).sort(), 'same accessories and aids')
      await waitFor(() => /Adding 0 accessories/.test(hb2.log), { message: 'bootstrap after restart' })
      assert.match(hb2.log, /Removing 0 accessories/)

      const ref = await hap.find('Front Door', T.LockMechanism, T.LockTargetState)
      assert.strictEqual((await hap.set(ref, 1)).status, 0)
      await waitFor(() => mock.pendingSubscribes.length > 0, { message: 'PubNub subscribe after restart' })
      const contact = await hap.find('Basement Window', T.ContactSensor, T.ContactSensorState)
      mock.pushPubNub({ _id: `${PANEL_ID}|${PARTITION_ID}`, t: 'account_partition', da: { plctx: { ts: '2026-11-24T12:00:00.000000' }, d: [{ _id: 42, s: true }] } })
      await waitFor(async () => (await hap.get(contact)).value === 1, { message: 'contact update after restart' })
      assert.ok(!FATAL_PATTERNS.some((p) => p.test(hb2.log)), hb2.tail(80))
    })

    it('re-creates a cached accessory whose device class changed (e.g. contact sensor -> smoke sensor)', async function () {
      // Users upgrading with a 4040/4050/4020 device cached as a ContactSensor hit this path
      await hb2.stop()
      mock.deviceOverrides[42] = { ec: 4040 }
      try {
        hb2 = new HomebridgeProcess({
          storage: hb.storage, hapPort: hb.hapPort, mockPort, certPath: certs.cert,
          platformConfig: { motionDetectedOccupancySensorMins: 1, lowBatteryLevel: 15 },
        })
        hb2.start()
        await waitFor(() => /Adding \d+ accessories/.test(hb2.log), { timeout: 60000, message: 'bootstrap after class change' })
        assert.match(hb2.log, /Removing 1 accessories/)
        assert.match(hb2.log, /Adding 1 accessories/)
        const smoke = await waitFor(() => hap.find('Basement Window', T.SmokeSensor, T.SmokeDetected), { message: 'Basement Window as smoke sensor' })
        const accs = await hap.accessories()
        const matches = accs.filter((a) => a.name === 'Basement Window')
        assert.strictEqual(matches.length, 1, 'exactly one Basement Window accessory (no leftover duplicate)')
        assert.strictEqual(accs.length, hb.accessoriesSnapshot.length, 'accessory count unchanged')
        assert.ok(!matches[0].services.some((s) => s.type === T.ContactSensor), 'old ContactSensor service removed')
        assert.strictEqual((await hap.get(smoke)).value, 0)
        await waitFor(() => mock.pendingSubscribes.length > 0, { message: 'PubNub subscribe after class change' })
        mock.pushPubNub({ _id: `${PANEL_ID}|${PARTITION_ID}`, t: 'account_partition', da: { plctx: { ts: '2026-11-24T13:00:00.000000' }, d: [{ _id: 42, s: true }] } })
        await waitFor(async () => (await hap.get(smoke)).value === 1, { message: 'smoke update after class change' })
        hb2.assertAlive()
        assert.ok(!FATAL_PATTERNS.some((p) => p.test(hb2.log)), hb2.tail(80))
      } finally {
        delete mock.deviceOverrides[42]
      }
    })

    it('reports an expired refresh token clearly without retrying or crashing', async function () {
      await hb2.stop()
      const authBefore = mock.vivintRequests((r) => r.path === '/api/authuser').length
      hb2 = new HomebridgeProcess({
        storage: hb.storage, hapPort: hb.hapPort, mockPort, certPath: certs.cert,
        platformConfig: { refreshToken: 's=EXPIRED_TOKEN' },
      })
      hb2.start()
      await waitFor(() => /Vivint rejected the refresh token \(HTTP 401\)/.test(hb2.log), { timeout: 60000, message: 'auth error message' })
      // Cached accessories are still published but report errors instead of stale values
      const ref = await waitFor(() => hap.find('Front Door', T.LockMechanism, T.LockCurrentState), { message: 'cached lock' })
      const res = await hap.get(ref)
      assert.notStrictEqual(res.status, undefined, `expected an error status, got ${JSON.stringify(res)}`)
      await sleep(3000)
      hb2.assertAlive()
      assert.strictEqual(mock.vivintRequests((r) => r.path === '/api/authuser').length - authBefore, 1, 'no login retries on 401')
      assert.ok(!hb2.log.includes('EXPIRED_TOKEN'), 'token not logged')
    })
  })
})
