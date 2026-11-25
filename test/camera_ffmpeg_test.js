// Runs the live-stream arguments from buildStreamArgs() with the bundled ffmpeg (ffmpeg-for-homebridge)
// against a generated local file instead of the camera's RTSP stream, and checks that video frames are reported
// on stdout (-progress) and SRTP packets actually arrive. This proves the argument set is accepted by the ffmpeg
// version we ship; real Vivint RTSP streams still need tester confirmation.

const assert = require('assert')
const cp = require('child_process')
const dgram = require('dgram')
const fs = require('fs')
const os = require('os')
const path = require('path')
const Camera = require('../lib/accessories/camera.js')

let ffmpegPath
try {
  ffmpegPath = require('ffmpeg-for-homebridge')
} catch (_) {
  ffmpegPath = undefined
}

const available = ffmpegPath && fs.existsSync(ffmpegPath)

;(available ? describe : describe.skip)('Camera streaming with the bundled ffmpeg', function () {
  this.timeout(30000)
  let tmp, withAudioFile, videoOnlyFile

  const generate = (file, withAudio) => {
    const args = ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'lavfi', '-i', 'testsrc=size=640x360:rate=15']
    if (withAudio) args.push('-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=16000')
    args.push('-t', '5', '-c:v', 'libx264', '-profile:v', 'baseline', '-pix_fmt', 'yuv420p', '-g', '15')
    if (withAudio) args.push('-c:a', 'aac', '-shortest')
    args.push(file)
    cp.execFileSync(ffmpegPath, args, { stdio: 'ignore' })
  }

  before(function () {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hbv-ffmpeg-'))
    withAudioFile = path.join(tmp, 'av.mkv')
    videoOnlyFile = path.join(tmp, 'v.mkv')
    generate(withAudioFile, true)
    generate(videoOnlyFile, false)
  })
  after(() => fs.rmSync(tmp, { recursive: true, force: true }))

  const bind = () => new Promise((resolve) => {
    const socket = dgram.createSocket('udp4')
    socket.packets = 0
    socket.on('message', () => socket.packets++)
    socket.bind(0, '127.0.0.1', () => resolve(socket))
  })

  /** Streams `file` with the plugin's arguments until video packets arrive (or ffmpeg exits / 10s pass). */
  async function stream({ mode, file, withAudio }) {
    const video = await bind()
    const audio = await bind()
    const key = Buffer.alloc(30, 7)
    const args = Camera.buildStreamArgs({
      mode, rtspTransport: 'tcp', rtspUrl: 'RTSP_URL', withAudio,
      request: { video: { width: 640, height: 360, fps: 30, pt: 99 }, audio: { pt: 110 } },
      session: {
        address: '127.0.0.1', videoPort: video.address().port, returnVideoPort: video.address().port + 1, videoSSRC: 1, videoSRTP: key,
        audioPort: audio.address().port, returnAudioPort: audio.address().port + 1, audioSSRC: 2, audioSRTP: key,
      },
    })
    // A local file instead of RTSP: drop the RTSP transport option, read in real time like a camera
    args.splice(args.indexOf('-rtsp_transport'), 2, '-re')
    args[args.indexOf('RTSP_URL')] = file

    return new Promise((resolve) => {
      const proc = cp.spawn(ffmpegPath, args)
      let firstFrame = false
      let stderr = ''
      let done = false
      const finish = (exit) => {
        if (done) return
        done = true
        clearInterval(poll)
        clearTimeout(timer)
        proc.kill('SIGKILL')
        // let in-flight UDP packets arrive
        setTimeout(() => {
          video.close()
          audio.close()
          resolve({ firstFrame, videoPackets: video.packets, audioPackets: audio.packets, exit, stderr })
        }, 200)
      }
      proc.stdout.on('data', (d) => {
        const m = /frame=\s*(\d+)/.exec(String(d))
        if (m && Number(m[1]) > 0) firstFrame = true
      })
      proc.stderr.on('data', (d) => { stderr += d })
      // Copy mode uses wall-clock timestamps, so -re does not throttle a file: ffmpeg may finish (exit 0) quickly
      proc.on('close', (code) => finish(code))
      const poll = setInterval(() => {
        if (firstFrame && video.packets > 5 && (!withAudio || audio.packets > 5)) finish('streaming')
      }, 50)
      const timer = setTimeout(() => finish('timeout'), 10000)
    })
  }

  for (const mode of ['copy', 'transcode']) {
    it(`${mode} mode: reports video frames and sends SRTP video and audio`, async function () {
      const res = await stream({ mode, file: withAudioFile, withAudio: true })
      assert.ok(res.exit === 'streaming' || res.exit === 0, `ffmpeg exit ${res.exit}\n${res.stderr.slice(-1500)}`)
      assert.ok(res.firstFrame, 'frame=N>0 reported on stdout')
      assert.ok(res.videoPackets > 5 && res.audioPackets > 5, JSON.stringify({ ...res, stderr: undefined }))
    })
  }

  it('copy mode without audio streams video from a source that has no audio track', async function () {
    const res = await stream({ mode: 'copy', file: videoOnlyFile, withAudio: false })
    assert.ok(res.exit === 'streaming' || res.exit === 0, `ffmpeg exit ${res.exit}\n${res.stderr.slice(-1500)}`)
    assert.ok(res.firstFrame && res.videoPackets > 5, JSON.stringify({ ...res, stderr: undefined }))
    assert.strictEqual(res.audioPackets, 0)
  })

  it('requesting audio from a source without an audio track makes ffmpeg fail (why audio is gated)', async function () {
    const res = await stream({ mode: 'copy', file: videoOnlyFile, withAudio: true })
    assert.ok(res.exit !== 'streaming' && res.exit !== 0, `ffmpeg exit ${res.exit}`)
    assert.ok(!res.firstFrame)
    assert.strictEqual(res.videoPackets, 0)
  })
})
