const assert = require('assert')
const fs = require('fs')
const os = require('os')
const path = require('path')
const Camera = require('../lib/accessories/camera.js')

const logLines = []
const log = Object.assign((...a) => logLines.push(a.join(' ')), {
  debug: (...a) => logLines.push(a.join(' ')),
  info: (...a) => logLines.push(a.join(' ')),
  warn: (...a) => logLines.push(a.join(' ')),
  error: (...a) => logLines.push(a.join(' ')),
})

// A Camera instance without the HAP controller setup, for exercising the snapshot/URL logic
function camera({ ffmpegPath, data, panelLogin } = {}) {
  const cam = Object.create(Camera.prototype)
  Object.assign(cam, {
    log,
    config: {},
    data: data || {
      Name: 'Front Doorbell',
      CameraInternalURL: ['rtsp://10.0.0.5:554/hd'], CameraInternalURLStandard: ['rtsp://10.0.0.5:554/sd'],
      CameraExternalURL: ['rtsp://example.com/ext'], CameraExternalURLStandard: ['rtsp://example.com/ext-sd'],
    },
    vivintApi: { panelLogin: panelLogin || { Name: 'panel', Password: 'p@ss:w/rd' } },
    ffmpegPath: ffmpegPath || 'ffmpeg',
  })
  return cam
}

const snapshot = (cam) => new Promise((resolve) => {
  let calls = 0
  cam.handleSnapshotRequest({ width: 640, height: 360 }, (err, image) => {
    calls++
    setTimeout(() => resolve({ err, image, calls }), 100) // catch double callbacks
  })
})

describe('Camera', function () {
  let tmp
  before(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hbv-cam-')) })
  after(() => fs.rmSync(tmp, { recursive: true, force: true }))
  beforeEach(() => { logLines.length = 0 })

  it('URL-encodes panel credentials into the RTSP URL', function () {
    const cam = camera()
    assert.strictEqual(cam.rtspUrl, 'rtsp://panel:p%40ss%3Aw%2Frd@10.0.0.5:554/hd')
    cam.config.useExternalVideoStreams = true
    assert.strictEqual(cam.rtspUrl, 'rtsp://panel:p%40ss%3Aw%2Frd@example.com/ext')
  })

  it('uses renewed panel credentials', function () {
    const cam = camera()
    cam.vivintApi.panelLogin = { Name: 'panel', Password: 'new' }
    assert.strictEqual(cam.rtspUrl, 'rtsp://panel:new@10.0.0.5:554/hd')
  })

  it('has no URL when the camera reports none', function () {
    assert.strictEqual(camera({ data: { Name: 'X' } }).rtspUrl, undefined)
  })

  it('redacts credentials and SRTP keys', function () {
    const text = Camera.redact("ffmpeg -i rtsp://panel:p%40ss@10.0.0.5/hd -srtp_out_params c2VjcmV0a2V5 'srtp://x' Error opening rtsp://u:pw@host/a")
    assert.ok(!/p%40ss|c2VjcmV0a2V5|u:pw/.test(text), text)
    assert.match(text, /rtsp:\/\/\*\*\*@10\.0\.0\.5\/hd/)
  })

  it('answers once with an error when ffmpeg is missing, without throwing', async function () {
    const res = await snapshot(camera({ ffmpegPath: path.join(tmp, 'does-not-exist') }))
    assert.ok(res.err instanceof Error)
    assert.strictEqual(res.calls, 1)
    assert.ok(logLines.every((l) => !l.includes('p@ss') && !l.includes('p%40ss')), logLines.join('\n'))
  })

  it('answers once with an error when ffmpeg fails', async function () {
    const fake = path.join(tmp, 'ffmpeg-fail.sh')
    fs.writeFileSync(fake, '#!/bin/sh\necho "Error opening input file $4" >&2\nexit 1\n', { mode: 0o755 })
    const res = await snapshot(camera({ ffmpegPath: fake }))
    assert.match(String(res.err), /exited with code 1/)
    assert.strictEqual(res.calls, 1)
    assert.ok(logLines.every((l) => !l.includes('p%40ss')), logLines.join('\n'))
  })

  it('returns the image from ffmpeg stdout', async function () {
    const fake = path.join(tmp, 'ffmpeg-ok.sh')
    fs.writeFileSync(fake, '#!/bin/sh\nprintf JPEGDATA\n', { mode: 0o755 })
    const res = await snapshot(camera({ ffmpegPath: fake }))
    assert.ifError(res.err)
    assert.strictEqual(res.image.toString(), 'JPEGDATA')
  })

  describe('snapshots (#205)', function () {
    const alive = (pid) => { try { process.kill(pid, 0); return true } catch (_) { return false } }
    const waitDead = async (pid) => { for (let i = 0; i < 100 && alive(pid); i++) await new Promise((r) => setTimeout(r, 20)); return !alive(pid) }
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
    // A fake ffmpeg that records its PID (and each run) before running `body`
    const fakeFfmpeg = (name, body) => {
      const file = path.join(tmp, name)
      fs.writeFileSync(file, `#!/bin/sh\necho $$ > "$0.pid"\necho run >> "$0.runs"\n${body}\n`, { mode: 0o755 })
      return { file, pid: () => Number(fs.readFileSync(`${file}.pid`, 'utf8')), runs: () => fs.readFileSync(`${file}.runs`, 'utf8').trim().split('\n').length }
    }

    it('waits 20 s by default, below the earliest point HAP-NodeJS gives up (22 s)', function () {
      assert.strictEqual(Camera.SNAPSHOT_TIMEOUT_MS, 20000)
      assert.strictEqual(camera().snapshotTimeoutMs, 20000)
      assert.ok(camera().snapshotTimeoutMs + camera().snapshotKillGraceMs <= 22000)
    })

    it('returns the image of a slow camera instead of stopping it early', async function () {
      const fake = fakeFfmpeg('ffmpeg-slow.sh', 'sleep 1\nprintf JPEGDATA')
      const cam = camera({ ffmpegPath: fake.file })
      cam.snapshotTimeoutMs = 3000
      const res = await snapshot(cam)
      assert.ifError(res.err)
      assert.strictEqual(res.image.toString(), 'JPEGDATA')
    })

    it('answers a hung snapshot with a timeout at the deadline, then stops ffmpeg with SIGTERM', async function () {
      const fake = fakeFfmpeg('ffmpeg-hang.sh', 'exec sleep 30')
      const cam = camera({ ffmpegPath: fake.file })
      cam.snapshotTimeoutMs = 400
      cam.snapshotKillGraceMs = 5000
      const t0 = Date.now()
      const res = await snapshot(cam)
      assert.match(String(res.err), /timed out/)
      assert.strictEqual(res.calls, 1)
      assert.ok(Date.now() - t0 < 1500, `answered after ${Date.now() - t0}ms`)
      // `sleep` exits on SIGTERM, long before the SIGKILL grace period ends
      assert.ok(await waitDead(fake.pid()), 'ffmpeg stopped by SIGTERM')
      assert.ok(logLines.some((l) => /Snapshot for 'Front Doorbell' timed out after 0.4 seconds/.test(l)), logLines.join('\n'))
      assert.ok(!logLines.some((l) => /killed with signal/.test(l)), 'our own stop is not reported as an error')
    })

    it('sends SIGKILL when ffmpeg ignores SIGTERM', async function () {
      const fake = fakeFfmpeg('ffmpeg-stubborn.sh', "trap '' TERM\nexec sleep 30")
      const cam = camera({ ffmpegPath: fake.file })
      cam.snapshotTimeoutMs = 300
      cam.snapshotKillGraceMs = 500
      const res = await snapshot(cam)
      assert.match(String(res.err), /timed out/)
      await sleep(150)
      assert.ok(alive(fake.pid()), 'still running during the grace period')
      assert.ok(await waitDead(fake.pid()), 'killed after the grace period')
      assert.strictEqual(cam.snapshotStoppers.size, 0)
    })

    it('runs one ffmpeg for requests that arrive while it runs, and a new one afterwards', async function () {
      const fake = fakeFfmpeg('ffmpeg-shared.sh', 'sleep 0.5\nprintf JPEGDATA')
      const cam = camera({ ffmpegPath: fake.file })
      const results = await Promise.all([snapshot(cam), snapshot(cam), snapshot(cam)])
      results.forEach((res) => {
        assert.ifError(res.err)
        assert.strictEqual(res.image.toString(), 'JPEGDATA')
        assert.strictEqual(res.calls, 1)
      })
      assert.strictEqual(fake.runs(), 1, 'one ffmpeg run for three requests')
      assert.ifError((await snapshot(cam)).err)
      assert.strictEqual(fake.runs(), 2, 'a later request runs ffmpeg again')
    })

    it('shares a failure between waiting requests too', async function () {
      const fake = fakeFfmpeg('ffmpeg-shared-fail.sh', 'sleep 0.3\nexit 1')
      const cam = camera({ ffmpegPath: fake.file })
      const results = await Promise.all([snapshot(cam), snapshot(cam)])
      results.forEach((res) => {
        assert.match(String(res.err), /exited with code 1/)
        assert.strictEqual(res.calls, 1)
      })
      assert.strictEqual(fake.runs(), 1)
    })

    it('reads the SD stream by default, and the HD stream when configured or when there is no SD stream', async function () {
      // Prints the input URL (4th argument) as the "image"
      const fake = fakeFfmpeg('ffmpeg-url.sh', 'printf "%s" "$4"')
      const url = async (cam) => (await snapshot(cam)).image.toString()
      const cam = camera({ ffmpegPath: fake.file })
      assert.strictEqual(await url(cam), 'rtsp://panel:p%40ss%3Aw%2Frd@10.0.0.5:554/sd')
      assert.ok(logLines.some((l) => /Snapshot for 'Front Doorbell' from the SD stream/.test(l)))
      cam.config = { snapshotStream: 'hd' }
      assert.strictEqual(await url(cam), 'rtsp://panel:p%40ss%3Aw%2Frd@10.0.0.5:554/hd')
      cam.config = { snapshotStream: 'bogus' }
      assert.strictEqual(await url(cam), 'rtsp://panel:p%40ss%3Aw%2Frd@10.0.0.5:554/sd', 'unknown value: default')
      cam.config = { useExternalVideoStreams: true }
      assert.strictEqual(await url(cam), 'rtsp://panel:p%40ss%3Aw%2Frd@example.com/ext-sd')
      cam.config = { useExternalVideoStreams: true, snapshotStream: 'hd' }
      assert.strictEqual(await url(cam), 'rtsp://panel:p%40ss%3Aw%2Frd@example.com/ext')

      const hdOnly = camera({ ffmpegPath: fake.file, data: { Name: 'Garage', CameraInternalURL: ['rtsp://10.0.0.6/hd'], CameraInternalURLStandard: [] } })
      assert.strictEqual(await url(hdOnly), 'rtsp://panel:p%40ss%3Aw%2Frd@10.0.0.6/hd')
      assert.ok(logLines.some((l) => /Snapshot for 'Garage' from the HD stream/.test(l)))
    })

    it('stops a running snapshot on destroy() (Homebridge shutdown)', async function () {
      const fake = fakeFfmpeg('ffmpeg-destroy.sh', "trap '' TERM\nexec sleep 30")
      const cam = camera({ ffmpegPath: fake.file })
      const pending = snapshot(cam)
      await sleep(200)
      const t0 = Date.now()
      cam.destroy()
      const res = await pending
      assert.match(String(res.err), /stopped/)
      assert.strictEqual(res.calls, 1)
      assert.ok(Date.now() - t0 < 500)
      assert.ok(await waitDead(fake.pid()), 'ffmpeg killed right away')
      assert.strictEqual(cam.snapshotStoppers.size, 0)
    })

    it('destroy() also stops an ffmpeg that is still exiting after its deadline', async function () {
      const fake = fakeFfmpeg('ffmpeg-destroy-grace.sh', "trap '' TERM\nexec sleep 30")
      const cam = camera({ ffmpegPath: fake.file })
      cam.snapshotTimeoutMs = 200
      cam.snapshotKillGraceMs = 10000
      assert.match(String((await snapshot(cam)).err), /timed out/)
      assert.ok(alive(fake.pid()), 'in the grace period')
      cam.destroy()
      assert.ok(await waitDead(fake.pid()), 'killed by destroy()')
    })
  })

  describe('camera motion messages (#206)', function () {
    const VivintApiModule = require('../lib/vivint_api.js')
    const VivintApi = VivintApiModule({}, log)
    // The real PubNub field mapping, as applied to every incoming message
    const parse = (raw) => VivintApi.prototype.parsePubNub.call(null, raw)

    // A camera with a stub motion service that records MotionDetected updates
    const motionCamera = (config = {}) => {
      const cam = camera()
      cam.config = config
      cam.id = 70
      cam.data = { Id: 70, Name: 'Front Doorbell', DeterOnDuty: false }
      cam.Characteristic = { MotionDetected: 'MotionDetected' }
      cam.motionUpdates = []
      cam.motionService = { updateCharacteristic: (c, v) => { if (c === 'MotionDetected') cam.motionUpdates.push(v) } }
      return cam
    }
    const DETER = { _id: 70, deter_on_duty: true, t: 'camera_device' }
    const STATUS = { _id: 70, act: 'camera_device', s: 1 }

    // Motion is reset after 5s; keep those timers from holding up the test run
    let realSetTimeout
    beforeEach(() => {
      realSetTimeout = global.setTimeout
      global.setTimeout = (fn, ms, ...args) => (ms === 5000 ? { unref() {} } : realSetTimeout(fn, ms, ...args))
    })
    afterEach(() => { global.setTimeout = realSetTimeout })

    it('recognises the deter and status messages by their exact fields, after the real PubNub mapping', function () {
      assert.deepStrictEqual(parse(DETER), { Id: 70, DeterOnDuty: true, Type: 'camera_device' })
      assert.deepStrictEqual(parse(STATUS), { Id: 70, ActualType: 'camera_device', Status: 1 })
      assert.strictEqual(Camera.motionMessageKind(parse(DETER)), 'deter')
      assert.strictEqual(Camera.motionMessageKind(parse(STATUS)), 'status')
      assert.strictEqual(Camera.motionMessageKind(parse({ ...STATUS, s: 0 })), 'status', 'any status value, as in vivintpy')
      assert.strictEqual(Camera.motionMessageKind(parse({ ...DETER, deter_on_duty: 1 })), 'deter', 'numeric values, like locks sending 0/1 (#121)')
      assert.strictEqual(Camera.motionMessageKind(parse({ ...DETER, deter_on_duty: false })), null, 'Smart Deter turning off')
      assert.strictEqual(Camera.motionMessageKind(parse({ ...DETER, deter_on_duty: 0 })), null)
      assert.strictEqual(Camera.motionMessageKind(parse({ ...DETER, piv: true })), null, 'extra fields')
      assert.strictEqual(Camera.motionMessageKind(parse({ _id: 70, deter_on_duty: true })), null, 'missing fields')
      assert.strictEqual(Camera.motionMessageKind(parse({ _id: 70, s: 1 })), null)
      assert.strictEqual(Camera.motionMessageKind(undefined), null)
    })

    it('ignores them by default, as before, and logs a hint once per kind', function () {
      const cam = motionCamera()
      cam.handlePatch(parse(DETER))
      cam.handlePatch(parse(DETER))
      cam.handlePatch(parse(STATUS))
      assert.deepStrictEqual(cam.motionUpdates, [])
      const hints = logLines.filter((l) => /Camera \[Front Doorbell\] sent a .* Some cameras report motion only this way/.test(l))
      assert.strictEqual(hints.length, 2, hints.join('\n'))
      assert.match(hints[0], /Smart Deter message \(deter_on_duty\).*"cameraMotionFromDeter"/)
      assert.match(hints[1], /camera status message \(act\/s\).*"cameraMotionFromStatus"/)
    })

    it('still reports PersonInView / VisitorDetected motion', function () {
      const cam = motionCamera()
      cam.handlePatch(parse({ _id: 70, piv: true }))
      cam.handlePatch(parse({ _id: 70, vdt: true }))
      assert.deepStrictEqual(cam.motionUpdates, [true, true])
    })

    it('counts deter messages as motion with cameraMotionFromDeter', function () {
      const cam = motionCamera({ cameraMotionFromDeter: true })
      cam.handlePatch(parse(DETER))
      assert.deepStrictEqual(cam.motionUpdates, [true])
      cam.handlePatch(parse(STATUS))
      assert.deepStrictEqual(cam.motionUpdates, [true], 'status messages need their own setting')
      assert.ok(logLines.some((l) => /\[Front Doorbell\] Motion from a Smart Deter message/.test(l)))
    })

    it('counts status messages as motion with cameraMotionFromStatus', function () {
      const cam = motionCamera({ cameraMotionFromStatus: true })
      cam.handlePatch(parse(STATUS))
      cam.handlePatch(parse(DETER))
      assert.deepStrictEqual(cam.motionUpdates, [true])
    })

    it('never counts fields kept from earlier messages or snapshots, or HomeKit reads', function () {
      const cam = motionCamera({ cameraMotionFromDeter: true, cameraMotionFromStatus: true })
      cam.handlePatch(parse(DETER))
      assert.deepStrictEqual(cam.motionUpdates, [true])
      assert.strictEqual(cam.data.DeterOnDuty, true, 'the field stays in the device data')
      // The minute-by-minute snapshot carries the same fields
      cam.handleSnapshot({ Id: 70, Name: 'Front Doorbell', DeterOnDuty: true, ActualType: 'camera_device', Status: 1 })
      // Another, unrelated patch
      cam.handlePatch(parse({ _id: 70, n: 'Front Doorbell' }))
      assert.deepStrictEqual(cam.motionUpdates, [true])
      // HomeKit reading MotionDetected
      assert.strictEqual(cam.getMotionDetectedState(), false)
      assert.strictEqual(cam.patchMotionKind, null)
    })
  })

  describe('.isDoorbell (#12, #32)', function () {
    const cam = (names, id = 70) => ({ id, names })
    it('detects doorbells by name, as before', function () {
      assert.strictEqual(Camera.isDoorbell(cam(['Front Doorbell'])), true)
      assert.strictEqual(Camera.isDoorbell(cam(['DOORBELL cam'])), true)
      assert.strictEqual(Camera.isDoorbell(cam(['Front Door'])), false)
      assert.strictEqual(Camera.isDoorbell(cam(['Front Door']), {}), false)
    })

    it('detects doorbells listed by ID or name in doorbellCameraIds', function () {
      const config = { doorbellCameraIds: ['71', ' front door ', '', null] }
      assert.strictEqual(Camera.isDoorbell(cam(['Front Door'], 99), config), true, 'by name, case/space-insensitive')
      assert.strictEqual(Camera.isDoorbell(cam(['Garage Camera'], 71), config), true, 'by id')
      assert.strictEqual(Camera.isDoorbell(cam(['Garage Camera'], 72), config), false)
      assert.strictEqual(Camera.isDoorbell(cam(['Garage Camera'], 71), { doorbellCameraIds: [71] }), true, 'numeric id')
      assert.strictEqual(Camera.isDoorbell(cam([undefined, 'Front Door'], 5), config), true, 'sanitized name variant')
      assert.strictEqual(Camera.isDoorbell(cam(['Patio'], 5), { doorbellCameraIds: 'Patio' }), false, 'ignores a non-list value')
    })
  })

  describe('live streaming (#171, #174, #134)', function () {
    const SRTP_KEY = Buffer.from('0123456789abcdef0123456789abcdef', 'hex')
    const session = () => ({
      address: '10.0.0.9', videoPort: 50000, returnVideoPort: 50002, videoSSRC: 111, videoSRTP: SRTP_KEY,
      audioPort: 50004, returnAudioPort: 50006, audioSSRC: 222, audioSRTP: SRTP_KEY,
    })
    const request = (audio = true) => ({
      sessionID: 'S1', type: 'start',
      video: { width: 1280, height: 720, fps: 30, pt: 99 },
      ...(audio ? { audio: { pt: 110 } } : {}),
    })
    const argAfter = (args, flag) => args[args.indexOf(flag) + 1]

    describe('buildStreamArgs', function () {
      const build = (opts) => Camera.buildStreamArgs({ rtspUrl: 'rtsp://u:p@10.0.0.5/hd', request: request(), session: session(), ...opts })

      it('copy mode passes the H.264 video through with the 1.10.1 low-latency flags and TCP transport', function () {
        const args = build({ mode: 'copy' })
        assert.strictEqual(argAfter(args, '-codec:v'), 'copy')
        assert.ok(!args.includes('libx264'))
        assert.ok(!args.some((a) => String(a).startsWith('scale=')))
        assert.strictEqual(argAfter(args, '-rtsp_transport'), 'tcp')
        for (const [flag, value] of [['-probesize', '10000'], ['-analyzeduration', '0'], ['-fflags', '+nobuffer'], ['-flags', '+low_delay']]) {
          assert.ok(args.indexOf(flag) < args.indexOf('-i'), `${flag} is an input option`)
          assert.strictEqual(argAfter(args, flag), value)
        }
        assert.strictEqual(argAfter(args, '-i'), 'rtsp://u:p@10.0.0.5/hd')
      })

      it('transcode mode re-encodes with libx264 at the negotiated size', function () {
        const args = build({ mode: 'transcode' })
        assert.strictEqual(argAfter(args, '-codec:v'), 'libx264')
        assert.strictEqual(argAfter(args, '-vf'), 'scale=1280:720')
        assert.strictEqual(argAfter(args, '-r'), 30)
        assert.strictEqual(argAfter(args, '-threads'), '1')
        assert.strictEqual(argAfter(args, '-rtsp_transport'), 'tcp')
        assert.ok(!args.includes('-probesize'))
      })

      it('defaults to copy mode and TCP', function () {
        assert.deepStrictEqual(Camera.buildStreamArgs({ rtspUrl: 'rtsp://x', request: request(), session: session() }), build({ mode: 'copy', rtspTransport: 'tcp', rtspUrl: 'rtsp://x' }))
      })

      it('honours UDP transport', function () {
        assert.strictEqual(argAfter(build({ rtspTransport: 'udp' }), '-rtsp_transport'), 'udp')
        assert.strictEqual(argAfter(build({ mode: 'transcode', rtspTransport: 'udp' }), '-rtsp_transport'), 'udp')
      })

      for (const mode of ['copy', 'transcode']) {
        it(`${mode} mode sends SRTP video and AAC-ELD audio to the negotiated ports`, function () {
          const args = build({ mode })
          assert.strictEqual(argAfter(args, '-progress'), 'pipe:1')
          assert.ok(args.includes('srtp://10.0.0.9:50000?rtcpport=50000&localrtcpport=50002&pkt_size=1316'))
          assert.ok(args.includes('srtp://10.0.0.9:50004?rtcpport=50004&localrtcpport=50006&pkt_size=188'))
          assert.strictEqual(argAfter(args, '-codec:a'), 'libfdk_aac')
          assert.strictEqual(argAfter(args, '-profile:a'), 'aac_eld')
          assert.deepStrictEqual(args.filter((a, i) => args[i - 1] === '-payload_type'), [99, 110])
          assert.deepStrictEqual(args.filter((a, i) => args[i - 1] === '-srtp_out_params'), [SRTP_KEY.toString('base64'), SRTP_KEY.toString('base64')])
          assert.ok(args.every((a) => typeof a === 'string' || typeof a === 'number'))
        })
      }

      it('omits audio when the camera has none or HomeKit did not request it', function () {
        // ffmpeg 8 refuses to start when an audio output is requested from a stream without audio
        for (const args of [
          Camera.buildStreamArgs({ rtspUrl: 'rtsp://x', request: request(), session: session(), withAudio: false }),
          Camera.buildStreamArgs({ rtspUrl: 'rtsp://x', request: request(false), session: session() }),
        ]) {
          assert.ok(!args.includes('libfdk_aac'))
          assert.ok(!args.some((a) => String(a).includes(':50004')))
        }
      })
    })

    describe('sessions with a fake ffmpeg', function () {
      let argsFile
      const fake = (name, body) => {
        const file = path.join(tmp, name)
        fs.writeFileSync(file, `#!/bin/sh\nprintf '%s\\n' "$@" > "$FAKE_FFMPEG_ARGS"\n${body}\n`, { mode: 0o755 })
        return file
      }
      // Prints progress like `ffmpeg -progress pipe:1`, then keeps "streaming"
      const STREAMS = 'printf "frame=0\\nprogress=continue\\n"; sleep 0.2; printf "frame=7\\nprogress=continue\\n"; exec sleep 30'
      const SILENT = 'printf "frame=0\\nprogress=continue\\n"; exec sleep 30'

      const streamingCamera = (ffmpegPath, config = {}) => {
        const cam = camera({ ffmpegPath })
        cam.config = config
        cam.hap = { StreamRequestTypes: { START: 'start', STOP: 'stop', RECONFIGURE: 'reconfigure' } }
        cam.forceStopped = []
        cam.controller = { forceStopStreamingSession: (id) => cam.forceStopped.push(id) }
        cam.pendingSessions = {}
        cam.ongoingSessions = {}
        cam.prepare = (id) => { cam.pendingSessions[id] = session() }
        return cam
      }
      const start = (cam, id = 'S1') => new Promise((resolve) => {
        cam.prepare(id)
        let calls = 0
        let first
        cam.handleStreamRequest({ ...request(), sessionID: id, type: 'start' }, (err) => {
          calls++
          if (calls === 1) first = err
          setTimeout(() => resolve({ err: first, calls: () => calls }), 50)
        })
      })
      const stop = (cam, id = 'S1') => new Promise((resolve) => cam.handleStreamRequest({ sessionID: id, type: 'stop' }, resolve))
      const alive = (pid) => { try { process.kill(pid, 0); return true } catch (_) { return false } }
      const waitDead = async (pid) => { for (let i = 0; i < 50 && alive(pid); i++) await new Promise((r) => setTimeout(r, 20)); return !alive(pid) }
      const readArgs = () => fs.readFileSync(argsFile, 'utf8').trim().split('\n')

      beforeEach(() => {
        argsFile = path.join(tmp, `args-${Date.now()}-${Math.random()}`)
        process.env.FAKE_FFMPEG_ARGS = argsFile
      })
      after(() => { delete process.env.FAKE_FFMPEG_ARGS })

      it('answers HomeKit once the first frame is sent, using copy mode by default, and stops on STOP', async function () {
        const cam = streamingCamera(fake('ffmpeg-stream.sh', STREAMS))
        const t0 = Date.now()
        const res = await start(cam)
        assert.ifError(res.err)
        assert.ok(Date.now() - t0 >= 150, 'not answered on ffmpeg start, only after a frame')
        const args = readArgs()
        assert.strictEqual(argAfter(args, '-codec:v'), 'copy')
        assert.strictEqual(argAfter(args, '-rtsp_transport'), 'tcp')
        const pid = cam.ongoingSessions.S1.process.pid
        assert.ok(alive(pid))
        assert.ok(logLines.some((l) => /Starting stream for session S1 \(video: copy, audio: no, RTSP over tcp\)/.test(l)), logLines.join('\n'))

        await stop(cam)
        assert.ok(await waitDead(pid), 'ffmpeg killed on STOP')
        assert.deepStrictEqual(cam.ongoingSessions, {})
        assert.strictEqual(res.calls(), 1)
        assert.deepStrictEqual(cam.forceStopped, [], 'an intentional stop is not reported as a failure')
      })

      it('uses transcode mode and UDP when configured', async function () {
        const cam = streamingCamera(fake('ffmpeg-stream2.sh', STREAMS), { videoProcessing: 'transcode', rtspTransport: 'udp' })
        assert.ifError((await start(cam)).err)
        const args = readArgs()
        assert.strictEqual(argAfter(args, '-codec:v'), 'libx264')
        assert.strictEqual(argAfter(args, '-rtsp_transport'), 'udp')
        await stop(cam)
      })

      it('adds audio only for cameras that report an audio stream', async function () {
        const cam = streamingCamera(fake('ffmpeg-stream-audio.sh', STREAMS))
        cam.data.CameraInternalAudioURL = ['rtsp://10.0.0.5:554/audio']
        assert.ifError((await start(cam)).err)
        assert.strictEqual(argAfter(readArgs(), '-codec:a'), 'libfdk_aac')
        assert.ok(logLines.some((l) => /\(video: copy, audio: yes, RTSP over tcp\)/.test(l)))
        await stop(cam)
      })

      it('answers HomeKit after the grace period when the camera is slow, then stops the stream if no video ever arrives', async function () {
        const cam = streamingCamera(fake('ffmpeg-slow.sh', SILENT))
        cam.startGraceMs = 200
        cam.firstFrameTimeoutMs = 700
        const t0 = Date.now()
        const res = await start(cam)
        assert.ifError(res.err)
        const answeredAfter = Date.now() - t0
        assert.ok(answeredAfter >= 200 && answeredAfter < 600, `answered after ${answeredAfter}ms`)
        const pid = cam.ongoingSessions.S1.process.pid
        for (let i = 0; i < 50 && cam.forceStopped.length === 0; i++) await new Promise((r) => setTimeout(r, 20))
        assert.deepStrictEqual(cam.forceStopped, ['S1'], 'HomeKit stream slot released')
        assert.ok(await waitDead(pid), 'ffmpeg killed')
        assert.deepStrictEqual(cam.ongoingSessions, {})
        assert.strictEqual(res.calls(), 1, 'START answered once')
      })

      it('answers a START still waiting for video when HomeKit stops the session', async function () {
        const cam = streamingCamera(fake('ffmpeg-slow2.sh', SILENT))
        const pending = start(cam)
        await new Promise((r) => setTimeout(r, 100))
        const pid = cam.ongoingSessions.S1.process.pid
        await stop(cam)
        const res = await pending
        assert.match(String(res.err), /Stream stopped/)
        assert.strictEqual(res.calls(), 1)
        assert.ok(await waitDead(pid))
      })

      it('falls back to copy/tcp for unknown config values', function () {
        const cam = streamingCamera('ffmpeg', { videoProcessing: 'bogus', rtspTransport: 'http' })
        assert.strictEqual(cam.videoProcessing, 'copy')
        assert.strictEqual(cam.rtspTransport, 'tcp')
      })

      it('kills ffmpeg and answers with an error when no frame arrives in time', async function () {
        const cam = streamingCamera(fake('ffmpeg-silent.sh', SILENT))
        cam.firstFrameTimeoutMs = 300
        const t0 = Date.now()
        let pid
        const pending = start(cam)
        await new Promise((r) => setTimeout(r, 100))
        pid = cam.ongoingSessions.S1.process.pid
        const res = await pending
        assert.match(String(res.err), /did not start in time/)
        assert.ok(Date.now() - t0 < 2000)
        assert.ok(await waitDead(pid), 'ffmpeg killed')
        assert.deepStrictEqual(cam.ongoingSessions, {})
        assert.strictEqual(res.calls(), 1)
        assert.ok(logLines.some((l) => /No video from the camera within \d+s; stopping stream for session S1/.test(l)), logLines.join('\n'))
      })

      it('answers once with an error when ffmpeg exits before sending video', async function () {
        const cam = streamingCamera(fake('ffmpeg-exit.sh', 'echo "Connection refused" >&2; exit 1'))
        const res = await start(cam)
        assert.match(String(res.err), /exited with 1/)
        await new Promise((r) => setTimeout(r, 100))
        assert.strictEqual(res.calls(), 1)
        assert.deepStrictEqual(cam.ongoingSessions, {})
      })

      it('releases the HomeKit stream slot when the stream dies after starting', async function () {
        const cam = streamingCamera(fake('ffmpeg-dies.sh', 'printf "frame=3\\nprogress=continue\\n"; sleep 0.2; exit 1'))
        assert.ifError((await start(cam)).err)
        for (let i = 0; i < 50 && cam.forceStopped.length === 0; i++) await new Promise((r) => setTimeout(r, 20))
        assert.deepStrictEqual(cam.forceStopped, ['S1'])
        assert.deepStrictEqual(cam.ongoingSessions, {})
      })

      it('refuses more than CAMERA_STREAM_COUNT concurrent streams, and accepts again after one stops', async function () {
        const cam = streamingCamera(fake('ffmpeg-stream3.sh', STREAMS))
        assert.strictEqual(Camera.CAMERA_STREAM_COUNT, 2)
        assert.ifError((await start(cam, 'A')).err)
        assert.ifError((await start(cam, 'B')).err)
        assert.match(String((await start(cam, 'C')).err), /Too many concurrent streams/)
        await stop(cam, 'A')
        assert.ifError((await start(cam, 'D')).err)
        assert.deepStrictEqual(Object.keys(cam.ongoingSessions).sort(), ['B', 'D'])
        cam.destroy()
      })

      it('answers a START for an unknown session instead of leaving HomeKit waiting', async function () {
        const cam = streamingCamera('ffmpeg')
        const err = await new Promise((resolve) => cam.handleStreamRequest({ ...request(), sessionID: 'nope', type: 'start' }, resolve))
        assert.match(String(err), /Unknown streaming session/)
      })

      it('kills every stream on destroy() (Homebridge shutdown)', async function () {
        const cam = streamingCamera(fake('ffmpeg-stream4.sh', STREAMS))
        await start(cam, 'A')
        await start(cam, 'B')
        const pids = Object.values(cam.ongoingSessions).map((s) => s.process.pid)
        assert.strictEqual(pids.length, 2)
        cam.prepare('pending')
        cam.destroy()
        for (const pid of pids) assert.ok(await waitDead(pid), `pid ${pid} killed`)
        assert.deepStrictEqual(cam.ongoingSessions, {})
        assert.deepStrictEqual(cam.pendingSessions, {})
      })

      it('never logs panel credentials or SRTP keys', async function () {
        const cam = streamingCamera(fake('ffmpeg-stream5.sh', STREAMS))
        await start(cam)
        await stop(cam)
        const args = readArgs()
        assert.ok(args.some((a) => a.includes('p%40ss')), 'credentials are passed to ffmpeg')
        assert.ok(args.includes(SRTP_KEY.toString('base64')), 'SRTP key is passed to ffmpeg')
        const joined = logLines.join('\n')
        assert.ok(!joined.includes('p%40ss') && !joined.includes('p@ss'), joined)
        assert.ok(!joined.includes(SRTP_KEY.toString('base64')), joined)
      })
    })
  })
})
