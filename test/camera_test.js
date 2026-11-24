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
})
