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
    data: data || { Name: 'Front Doorbell', CameraInternalURL: ['rtsp://10.0.0.5:554/hd'], CameraExternalURL: ['rtsp://example.com/ext'] },
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

  it('kills a hung ffmpeg and answers with a timeout', async function () {
    this.timeout(15000)
    const fake = path.join(tmp, 'ffmpeg-hang.sh')
    fs.writeFileSync(fake, '#!/bin/sh\nexec sleep 30\n', { mode: 0o755 })
    const t0 = Date.now()
    const res = await snapshot(camera({ ffmpegPath: fake }))
    assert.match(String(res.err), /timed out/)
    assert.strictEqual(res.calls, 1)
    assert.ok(Date.now() - t0 < 10000)
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

      it('omits audio when HomeKit did not request it', function () {
        const args = Camera.buildStreamArgs({ rtspUrl: 'rtsp://x', request: request(false), session: session() })
        assert.ok(!args.includes('libfdk_aac'))
        assert.ok(!args.some((a) => String(a).includes(':50004')))
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
        assert.ok(logLines.some((l) => /Starting stream for session S1 \(video: copy, RTSP over tcp\)/.test(l)), logLines.join('\n'))

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
