const Device = require('../device.js')
const VivintDict = require('../vivint_dictionary.json')
const SanitizeName = require('../sanitize_name.js')

const getPort = require('get-port')
const ffmpegPath = require('ffmpeg-for-homebridge')
const { spawn } = require('child_process')

// Snapshot deadline. HAP-NodeJS only warns about a slow snapshot (after 5 or 8 s) and gives up after 22 s
// (HAP-NodeJS 0.11/0.12, Homebridge 1.x) or 25 s (0.13 and 2.x), so a slow camera gets until just before the
// earliest give-up. An 8 s limit failed cameras that need longer for their first frame (#205).
const SNAPSHOT_TIMEOUT_MS = 20000

// After the deadline ffmpeg gets SIGTERM, so it can close the RTSP session on the panel, and SIGKILL if it is
// still running this much later
const SNAPSHOT_KILL_GRACE_MS = 2000

// Stream used for snapshots: the standard-definition stream (as in 1.10) or the HD stream
const SNAPSHOT_STREAMS = ['sd', 'hd']

// Kill a live-stream ffmpeg process (and release the HomeKit stream) if no video frame has been sent by then
const FIRST_FRAME_TIMEOUT_MS = 15000

// HomeKit's START request is answered at the first video frame, or after this grace period if ffmpeg is still
// running. HAP-NodeJS reports handlers slower than 3s as "slow to respond" and times them out after 9s.
const START_GRACE_MS = 2500

// Concurrent live streams per camera (HomeKit stream management services). A doorbell ring can make
// several Apple devices request a stream at the same moment.
const CAMERA_STREAM_COUNT = 2

// Camera messages that count as motion when their setting is on (#206), see Camera.motionMessageKind
const MOTION_MESSAGE_KINDS = {
	deter: { setting: 'cameraMotionFromDeter', description: 'Smart Deter message (deter_on_duty)' },
	status: { setting: 'cameraMotionFromStatus', description: 'camera status message (act/s)' },
}

const VIDEO_PROCESSING_MODES = ['copy', 'transcode']
const RTSP_TRANSPORTS = ['tcp', 'udp']

function flattenArgs(args) {
	return [].concat(...args.map((arg) => arg.map((a) => (typeof a == 'string' ? a.trim() : a))))
}

/**
 * Builds the ffmpeg arguments for one live-stream session (pure; no I/O).
 *
 * - mode "copy" (default): passes the camera's H.264 video through unchanged, with low-latency input
 *   flags. This is the 1.10.1 pipeline that users confirmed working (#171, #174), plus an explicit
 *   RTSP transport.
 * - mode "transcode": re-encodes with libx264 at the resolution/fps HomeKit negotiated (1.11 - 1.12).
 *   CPU-heavy, but may be needed for remote/cellular viewing (#185).
 * Both modes send AAC-ELD audio (1.11) when the camera has audio. HomeKit always requests audio, but ffmpeg
 * cannot start at all if an audio output is requested from a stream without an audio track (checked with
 * ffmpeg 8), so audio is only added for cameras that report an audio stream (as in 1.10.1).
 *
 * @param {object} p
 * @param {'copy'|'transcode'} p.mode
 * @param {'tcp'|'udp'} p.rtspTransport
 * @param {string} p.rtspUrl
 * @param {object} p.request HomeKit START request (video: {width, height, fps, pt}, audio?: {pt})
 * @param {object} p.session prepared session (address, ports, SSRCs, SRTP keys)
 * @param {boolean} [p.withAudio=true] whether the camera stream has audio
 * @returns {string[]}
 */
function buildStreamArgs({ mode = 'copy', rtspTransport = 'tcp', rtspUrl, request, session, withAudio = true }) {
	// Reports "frame=N" progress on stdout so the plugin knows when video is actually flowing
	const globalArgs = [['-progress', 'pipe:1']]

	const sourceArgs = mode === 'transcode'
		? [
			['-rtsp_transport', rtspTransport],
			['-i', rtspUrl],
		]
		: [
			['-rtsp_transport', rtspTransport],
			['-probesize', '10000'],
			['-analyzeduration', '0'],
			['-fflags', '+nobuffer'],
			['-flags', '+low_delay'],
			['-use_wallclock_as_timestamps', '1'],
			['-guess_layout_max', '0'],
			['-i', rtspUrl],
		]

	const videoCodecArgs = mode === 'transcode'
		? [
			['-an'],
			['-sn'],
			['-dn'],
			// Match the dimensions negotiated by HomeKit for this session.
			['-vf', `scale=${request.video.width}:${request.video.height}`],
			// Single-threaded encoding avoids first-frame delay on direct WiFi streams.
			['-threads', '1'],
			['-codec:v', 'libx264'],
			['-pix_fmt', 'yuv420p'],
			['-preset', 'ultrafast'],
			['-tune', 'zerolatency'],
			['-r', request.video.fps],
			['-b:v', '1000k'],
			['-bufsize', '1000k'],
			['-maxrate', '1000k'],
		]
		: [
			// Exactly the 1.10.1 video arguments
			['-an'],
			['-sn'],
			['-dn'],
			['-codec:v', 'copy'],
			['-pix_fmt', 'yuvj420p'],
			['-color_range', 'mpeg'],
			['-f', 'rawvideo'],
			['-use_wallclock_as_timestamps', '1'],
			['-fflags', '+genpts'],
			['-r', '15'],
			['-bufsize', '300k'],
		]

	const videoOutputArgs = [
		['-payload_type', request.video.pt],
		['-ssrc', session.videoSSRC],
		['-f', 'rtp'],
		['-srtp_out_suite', 'AES_CM_128_HMAC_SHA1_80'],
		['-srtp_out_params', session.videoSRTP.toString('base64')],
		[`srtp://${session.address}:${session.videoPort}?rtcpport=${session.videoPort}&localrtcpport=${session.returnVideoPort}&pkt_size=1316`],
	]

	const audioArgs = withAudio && request.audio
		? [
			['-vn'],
			['-sn'],
			['-dn'],
			['-codec:a', 'libfdk_aac'],
			['-profile:a', 'aac_eld'],
			['-flags', '+global_header'],
			['-fflags', '+genpts'],
			['-ar', '16k'],
			['-b:a', '24k'],
			['-ac', '1'],
			['-use_wallclock_as_timestamps', '1'],
			['-bufsize', '24k'],

			['-payload_type', request.audio.pt],
			['-ssrc', session.audioSSRC],
			['-f', 'rtp'],
			['-srtp_out_suite', 'AES_CM_128_HMAC_SHA1_80'],
			['-srtp_out_params', session.audioSRTP.toString('base64')],
			[`srtp://${session.address}:${session.audioPort}?rtcpport=${session.audioPort}&localrtcpport=${session.returnAudioPort}&pkt_size=188`],
		]
		: []

	return flattenArgs([...globalArgs, ...sourceArgs, ...videoCodecArgs, ...videoOutputArgs, ...audioArgs])
}

/** Remove credentials and SRTP keys from strings before logging them. */
function redact(text) {
	return String(text)
		.replace(/(rtsps?:\/\/)[^@\s'"]*@/gi, '$1***@')
		.replace(/(srtp_(?:in|out)_params\s+)\S+/g, '$1***')
}

//To prevent double notifications we're ignoring doorbell button events for this amount of time
const DOORBELL_IGNORE_MILLISECONDS = 5000

// Need to reserve ports in sequence because ffmpeg uses the next port up by default.  If it's taken, ffmpeg will error
async function reservePorts(count) {
	const port = await getPort()
	const ports = [port]
	const tryAgain = () => {
		return reservePorts(count)
	}

	for (let i = 1; i < count; i++) {
		const targetConsecutivePort = port + i
		 
		const openPort = await getPort({ port: targetConsecutivePort })

		if (openPort !== targetConsecutivePort) {
			// can't reserve next port, bail and get another set
			return tryAgain()
		}

		ports.push(openPort)
	}

	return ports
}

class Camera extends Device {
	constructor(accessory, data, config, log, homebridge, vivintApi) {
		super(accessory, data, config, log, homebridge, vivintApi)

		this.UUIDGen = homebridge.hap.uuid

		this.lastPressedDoorbellButton = 0

		this.pendingSessions = {}
		this.ongoingSessions = {}

		this.ffmpegPath = ffmpegPath || 'ffmpeg'

		if (!this.rtspUrl) {
			log.warn(`Camera [${data.Name}] did not report a stream URL; streaming and snapshots will not work`)
		}

		let streamingOptions = {
			supportedCryptoSuites: [
				this.hap.SRTPCryptoSuites.AES_CM_128_HMAC_SHA1_80,
			],
			video: {
				resolutions: [
					[320, 180, 30],
					[320, 240, 15], // Apple Watch requires this configuration
					[320, 240, 30],
					[480, 270, 30],
					[480, 360, 30],
					[640, 360, 30],
					[640, 480, 30],
					[1280, 720, 30],
					[1280, 960, 30],
					[1920, 1080, 30],
					[1600, 1200, 30],
				],
				codec: {
					profiles: [
						this.hap.H264Profile.BASELINE,
						this.hap.H264Profile.MAIN,
						this.hap.H264Profile.HIGH,
					],
					levels: [
						this.hap.H264Level.LEVEL3_1,
						this.hap.H264Level.LEVEL3_2,
						this.hap.H264Level.LEVEL4_0,
					],
				},
			},
		}

		//Checking if Camera supports audio
		if (data.CameraInternalAudioURL) {
			streamingOptions.audio = {
				//twoWayAudio: this.camera.info.capabilities.includes('audio.microphone'),
				codecs: [
					{
						type: this.hap.AudioStreamingCodecType.AAC_ELD,
						samplerate: this.hap.AudioStreamingSamplerate.KHZ_16,
					},
				],
			}
		}

		this.isDoorbell = Camera.isDoorbell({ id: data.Id, names: [data.Name, accessory.context.name] }, config)
		if (this.isDoorbell) {
			log.info(`Camera [${accessory.context.name}] [ID]:${data.Id} is set up as a doorbell`)
		} else {
			log.info(`Camera [${accessory.context.name}] [ID]:${data.Id} is set up as a camera. If it is a doorbell, add its name or ID to "doorbellCameraIds".`)
		}

		//If "Show Camera Config" is enabled, show FFMPEG config for cameras in log
		let config_showCameraConfig = config.showCameraConfig || false
		if (config_showCameraConfig == true) {
			let informationService = accessory.getService(this.Service.AccessoryInformation)
			var cameraConfigObject = {
				name: data.Name,
				manufacturer: informationService.getCharacteristic(this.Characteristic.Manufacturer).value,
				model: informationService.getCharacteristic(this.Characteristic.Model).value,
				motion: true,
				motionTimeout: 1
			}

			if (this.isDoorbell) {
				cameraConfigObject.doorbell = true
			}

			cameraConfigObject.videoConfig = {
				source: `-rtsp_transport tcp -re -i ${this.rtspUrl}`,
				vcodec: 'copy',
				audio: true
			}

			log.info(`Camera [${data.Name}] configuration:`, JSON.stringify(cameraConfigObject, undefined, 4))
      	}

		let controllerOptions = {
			cameraStreamCount: CAMERA_STREAM_COUNT,
			delegate: this,
			streamingOptions: streamingOptions,
		}

		if (config.disableCameras != true) {
			// HAP-NodeJS migrates a cached accessory between the two (adds/removes the Doorbell service)
			if (this.isDoorbell) {
				this.controller = new this.hap.DoorbellController(controllerOptions)
			} else this.controller = new this.hap.CameraController(controllerOptions)

			accessory.configureController(this.controller)
		}

		this.motionService = accessory.getService(this.Service.MotionSensor)
		this.motionService
			.getCharacteristic(this.Characteristic.MotionDetected)
			.on('get', (callback) => callback(null, this.getMotionDetectedState()))

		//Add a Contact Sensor service for Doorbell button press
		if (this.isDoorbell) {
			//In case cached accessory does not have contact sensor service added (upgraded from previous versions,
			//or the camera was just added to doorbellCameraIds)
			if (accessory.getService(this.Service.ContactSensor) === undefined) {
				accessory.addService(new this.Service.ContactSensor(accessory.context.name + ' Button'))
			}

			this.buttonService = accessory.getService(this.Service.ContactSensor)
			this.buttonService
				.getCharacteristic(this.Characteristic.ContactSensorState)
				.on('get', (callback) => callback(null, this.getDoorbellButtonPress()))
		} else {
			//No longer a doorbell (e.g. removed from doorbellCameraIds): drop the cached button sensor
			const staleButton = accessory.getService(this.Service.ContactSensor)
			if (staleButton) accessory.removeService(staleButton)
		}
		
		this.notify()
	}

	getMotionDetectedState() {
		let motionDetected =
			Boolean(this.data.PersonInView) || Boolean(this.data.VisitorDetected)

		//Do not retain this data
		this.data.PersonInView = this.data.VisitorDetected = null

		return motionDetected
	}

	getDoorbellButtonPress() {
		let doorbellPuttonPressed = Boolean(this.data.DingDong)

		//Do not retain this data
		this.data.DingDong = null

		return doorbellPuttonPressed
	}

	/** RTSP URL with the current panel credentials (URL-encoded); rebuilt on every use so renewed panel logins apply. */
	get rtspUrl() {
		return this.buildRtspUrl(this.config.useExternalVideoStreams ? this.data.CameraExternalURL : this.data.CameraInternalURL)
	}

	get rtspUrl_SD() {
		return this.buildRtspUrl(this.config.useExternalVideoStreams ? this.data.CameraExternalURLStandard : this.data.CameraInternalURLStandard)
	}

	buildRtspUrl(urls) {
		const url = Array.isArray(urls) ? urls[0] : urls
		if (typeof url !== 'string' || !url.startsWith('rtsp://')) return undefined
		const login = (this.vivintApi && this.vivintApi.panelLogin) || {}
		const user = encodeURIComponent(login.Name || '')
		const password = encodeURIComponent(login.Password || '')
		return url.replace('rtsp://', `rtsp://${user}:${password}@`)
	}

	/** Live-stream video pipeline from config (`videoProcessing`), defaulting to "copy". */
	get videoProcessing() {
		const mode = this.config && this.config.videoProcessing
		return VIDEO_PROCESSING_MODES.includes(mode) ? mode : 'copy'
	}

	/** RTSP transport from config (`rtspTransport`), defaulting to "tcp". */
	get rtspTransport() {
		const transport = this.config && this.config.rtspTransport
		return RTSP_TRANSPORTS.includes(transport) ? transport : 'tcp'
	}

	/** Snapshot stream from config (`snapshotStream`), defaulting to "sd". */
	get snapshotStream() {
		const stream = this.config && this.config.snapshotStream
		return SNAPSHOT_STREAMS.includes(stream) ? stream : 'sd'
	}

	/**
	 * Where snapshots are read from: the SD stream, like 1.10 did, unless `snapshotStream` is "hd".
	 * Cameras without an SD stream use the HD stream.
	 *
	 * @returns {{ url: string|undefined, stream: 'sd'|'hd' }}
	 */
	get snapshotSource() {
		if (this.snapshotStream === 'sd') {
			const sd = this.rtspUrl_SD
			if (sd) return { url: sd, stream: 'sd' }
		}
		return { url: this.rtspUrl, stream: 'hd' }
	}

	get snapshotTimeoutMs() {
		return this._snapshotTimeoutMs || SNAPSHOT_TIMEOUT_MS
	}

	set snapshotTimeoutMs(ms) {
		this._snapshotTimeoutMs = ms
	}

	get snapshotKillGraceMs() {
		return this._snapshotKillGraceMs || SNAPSHOT_KILL_GRACE_MS
	}

	set snapshotKillGraceMs(ms) {
		this._snapshotKillGraceMs = ms
	}

	/** Stop functions of snapshot ffmpeg processes that are still running. */
	get snapshotStoppers() {
		if (!this._snapshotStoppers) this._snapshotStoppers = new Set()
		return this._snapshotStoppers
	}

	get firstFrameTimeoutMs() {
		return this._firstFrameTimeoutMs || FIRST_FRAME_TIMEOUT_MS
	}

	set firstFrameTimeoutMs(ms) {
		this._firstFrameTimeoutMs = ms
	}

	get startGraceMs() {
		return this._startGraceMs || START_GRACE_MS
	}

	set startGraceMs(ms) {
		this._startGraceMs = ms
	}

	/** Whether the camera reports an audio stream (it is carried in the same RTSP stream as the video). */
	get hasAudio() {
		return Boolean(this.data && this.data.CameraInternalAudioURL)
	}

	handleSnapshotRequest(request, callback) {
		this.log.debug(
			`Handling camera snapshot for '${this.data.Name}' at ${request.width}x${request.height}`
		)

		// Requests that arrive while ffmpeg is running (several Apple devices at once) share its image (#205)
		if (this.snapshotRun) {
			this.log.debug(`Snapshot for '${this.data.Name}' already running; sharing its image`)
		} else {
			this.snapshotRun = this.takeSnapshot().finally(() => { this.snapshotRun = null })
		}
		this.snapshotRun
			.then((image) => callback(undefined, image), (err) => callback(err))
			.catch((err) => this.log.error('Error answering a snapshot request:', redact(err && err.message)))
	}

	/** Runs ffmpeg once for a single JPEG frame. Rejects at the snapshot deadline, then stops ffmpeg. */
	takeSnapshot() {
		return new Promise((resolve, reject) => {
			const { url: rtspUrl, stream } = this.snapshotSource
			if (!rtspUrl) {
				return reject(new Error('No stream URL for this camera'))
			}
			this.log.debug(`Snapshot for '${this.data.Name}' from the ${stream.toUpperCase()} stream`)

			const snapshot = [
				'-rtsp_transport', this.rtspTransport,
				'-i', rtspUrl,
				'-frames:v', '1',
				'-vcodec', 'mjpeg',
				'-f', 'image2',
				'-',
			]

			let ffmpeg
			let done = false
			let deadline = null
			let killTimer = null
			const running = () => ffmpeg && ffmpeg.exitCode === null && ffmpeg.signalCode === null
			const finish = (err, image) => {
				if (done) return
				done = true
				clearTimeout(deadline)
				if (err) reject(err)
				else resolve(image)
			}
			const kill = (signal) => {
				if (!running()) return
				try {
					ffmpeg.kill(signal)
				} catch (err) {
					this.log.debug('Could not stop the snapshot ffmpeg:', redact(err.message))
				}
			}

			// Homebridge shutdown (destroy): answer HomeKit and stop ffmpeg right away. Kept until ffmpeg exits, which
			// can be after the deadline (SIGTERM grace period) when a newer snapshot is already running.
			const stop = () => {
				finish(new Error('Snapshot stopped'))
				clearTimeout(killTimer)
				kill('SIGKILL')
			}

			deadline = setTimeout(() => {
				this.log.warn(`Snapshot for '${this.data.Name}' timed out after ${this.snapshotTimeoutMs / 1000} seconds`)
				finish(new Error('Snapshot timed out'))
				kill('SIGTERM')
				killTimer = setTimeout(() => kill('SIGKILL'), this.snapshotKillGraceMs)
			}, this.snapshotTimeoutMs)

			try {
				ffmpeg = spawn(this.ffmpegPath, snapshot, {
					env: process.env,
				})
			} catch (err) {
				this.log.error('Could not start ffmpeg for snapshot:', redact(err.message))
				return finish(err)
			}
			this.snapshotStoppers.add(stop)
			const snapshotBuffers = []
			ffmpeg.stdout.on('data', (data) => snapshotBuffers.push(data))
			ffmpeg.stderr.on('data', (data) => {
				this.log.debug('SNAPSHOT: ' + redact(String(data)))
			})
			ffmpeg.on('error', (err) => {
				this.log.error(`Could not run ffmpeg (${this.ffmpegPath}) for snapshot:`, redact(err.message))
				this.snapshotStoppers.delete(stop)
				finish(new Error('ffmpeg failed to start'))
			})
			ffmpeg.on('close', (code, signal) => {
				clearTimeout(killTimer)
				this.snapshotStoppers.delete(stop)
				// Stopped by us after the deadline or at shutdown: HomeKit already has its answer
				if (done) return
				if (signal) {
					this.log.error('Snapshot process was killed with signal: ' + signal)
					finish(new Error('killed with signal ' + signal))
				} else if (code === 0 && snapshotBuffers.length > 0) {
					finish(undefined, Buffer.concat(snapshotBuffers))
				} else {
					this.log.error(`Snapshot for '${this.data.Name}' failed: ffmpeg exited with code ${code}`)
					finish(new Error('Snapshot process exited with code ' + code))
				}
			})
		})
	}

	async prepareStream(request, callback) {
		this.log.debug(`Prepare stream for session ${request.sessionID} to ${request.targetAddress}`)

		const sessionId = request.sessionID
		const targetAddress = request.targetAddress

		//video setup
		const video = request.video
		const videoPort = video.port
		const returnVideoPort = (await reservePorts())[0]
		const videoCryptoSuite = video.srtpCryptoSuite
		const videoSrtpKey = video.srtp_key
		const videoSrtpSalt = video.srtp_salt
		const videoSSRC = this.hap.CameraController.generateSynchronisationSource()

		//audio setup
		const audio = request.audio
		const audioPort = audio.port
		const returnAudioPort = (await reservePorts())[0]
		//const twoWayAudioPort = (await reservePorts(2))[0];
		const audioServerPort = (await reservePorts())[0]
		const audioCryptoSuite = video.srtpCryptoSuite
		const audioSrtpKey = audio.srtp_key
		const audioSrtpSalt = audio.srtp_salt
		const audioSSRC = this.hap.CameraController.generateSynchronisationSource()

		const sessionInfo = {
			address: targetAddress,

			videoPort: videoPort,
			returnVideoPort: returnVideoPort,
			videoCryptoSuite: videoCryptoSuite,
			videoSRTP: Buffer.concat([videoSrtpKey, videoSrtpSalt]),
			videoSSRC: videoSSRC,

			audioPort: audioPort,
			returnAudioPort: returnAudioPort,
			//twoWayAudioPort: twoWayAudioPort,
			//rtpSplitter: new RtpSplitter(audioServerPort, returnAudioPort, twoWayAudioPort),
			audioCryptoSuite: audioCryptoSuite,
			audioSRTP: Buffer.concat([audioSrtpKey, audioSrtpSalt]),
			audioSSRC: audioSSRC,
		}

		const response = {
			video: {
				port: returnVideoPort,
				ssrc: videoSSRC,
				srtp_key: videoSrtpKey,
				srtp_salt: videoSrtpSalt,
			},
			audio: {
				port: audioServerPort,
				ssrc: audioSSRC,
				srtp_key: audioSrtpKey,
				srtp_salt: audioSrtpSalt,
			},
		}
		this.pendingSessions[sessionId] = sessionInfo

		callback(undefined, response)
	}

	async handleStreamRequest(request, callback) {
		const sessionId = request.sessionID
		this.log.debug(`[${this.data.Name}] Handling stream request: ${request.type} for session ${sessionId}`)

		switch (request.type) {
			case this.hap.StreamRequestTypes.START:
				return this.startStream(sessionId, request, callback)
			case this.hap.StreamRequestTypes.STOP:
				this.stopStream(sessionId)
				return callback()
			case this.hap.StreamRequestTypes.RECONFIGURE:
				// not implemented
				this.log.debug('(Not implemented) Received request to reconfigure to: ' + JSON.stringify(request.video, undefined, 4))
				return callback()
			default:
				return callback()
		}
	}

	/** Live ffmpeg sessions of this camera, by HomeKit session id. */
	get sessions() {
		if (!this.ongoingSessions) this.ongoingSessions = {}
		return this.ongoingSessions
	}

	startStream(sessionId, request, callback) {
		const sessionInfo = this.pendingSessions && this.pendingSessions[sessionId]
		if (this.pendingSessions) delete this.pendingSessions[sessionId]

		// HomeKit's START callback may only be answered once, but ffmpeg can report several outcomes
		let answered = false
		const answer = (err) => {
			if (answered) return
			answered = true
			callback(err)
		}

		if (!sessionInfo) {
			this.log.warn(`[${this.data.Name}] Stream start for unknown session ${sessionId}`)
			return answer(new Error('Unknown streaming session'))
		}
		const rtspUrl = this.rtspUrl
		if (!rtspUrl) {
			return answer(new Error('No stream URL for this camera'))
		}
		const active = Object.keys(this.sessions).length
		if (active >= CAMERA_STREAM_COUNT) {
			this.log.warn(`[${this.data.Name}] Already streaming to ${active} devices; refusing another stream`)
			return answer(new Error('Too many concurrent streams'))
		}

		const mode = this.videoProcessing
		const withAudio = this.hasAudio
		const args = buildStreamArgs({ mode, rtspTransport: this.rtspTransport, rtspUrl, request, session: sessionInfo, withAudio })
		this.log.info(`[${this.data.Name}] Starting stream for session ${sessionId} (video: ${mode}, audio: ${withAudio ? 'yes' : 'no'}, RTSP over ${this.rtspTransport})`)
		this.log.debug(redact([this.ffmpegPath, ...args].join(' ')))

		let cmd
		try {
			cmd = spawn(this.ffmpegPath, args, { env: process.env })
		} catch (err) {
			this.log.error(`[${this.data.Name}] Could not start ffmpeg for streaming:`, redact(err.message))
			return answer(err)
		}

		const session = { process: cmd, started: false, stopping: false, timer: null, graceTimer: null, answer }
		this.sessions[sessionId] = session

		const cleanup = () => {
			clearTimeout(session.timer)
			clearTimeout(session.graceTimer)
			if (this.sessions[sessionId] === session) delete this.sessions[sessionId]
		}

		// Answer HomeKit in time even if the camera is slow to deliver the first frame
		session.graceTimer = setTimeout(() => {
			this.log.debug(`[${this.data.Name}] No video frame yet for session ${sessionId}; answering HomeKit and waiting for the camera`)
			answer()
		}, this.startGraceMs)

		session.timer = setTimeout(() => {
			if (session.started) return
			this.log.warn(`[${this.data.Name}] No video from the camera within ${Math.round(this.firstFrameTimeoutMs / 1000)}s; stopping stream for session ${sessionId}`)
			session.stopping = true
			cleanup()
			cmd.kill('SIGKILL')
			if (answered) this.releaseStream(sessionId)
			answer(new Error('Camera stream did not start in time'))
		}, this.firstFrameTimeoutMs)

		cmd.stdout.on('data', (data) => {
			if (session.started) return
			const frames = /frame=\s*(\d+)/.exec(String(data))
			if (frames && Number(frames[1]) > 0) {
				session.started = true
				clearTimeout(session.timer)
				clearTimeout(session.graceTimer)
				this.log.debug(`[${this.data.Name}] First video frame sent for session ${sessionId}`)
				answer()
			}
		})

		cmd.stderr.on('data', (data) => {
			this.log.debug(redact(data.toString()))
		})

		cmd.on('error', (err) => {
			this.log.error(`[${this.data.Name}] Could not run ffmpeg (${this.ffmpegPath}) for streaming:`, redact(err.message))
			cleanup()
			answer(err)
		})

		cmd.on('close', (code, signal) => {
			cleanup()
			if (session.stopping) {
				this.log.debug(`[${this.data.Name}] Stream for session ${sessionId} stopped`)
				return
			}
			const how = signal ? 'signal ' + signal : 'code ' + code
			if (!session.started) {
				this.log.error(`[${this.data.Name}] Stream for session ${sessionId} failed: ffmpeg exited with ${how} before sending video`)
			} else {
				this.log.warn(`[${this.data.Name}] Stream for session ${sessionId} ended unexpectedly (ffmpeg ${how})`)
			}
			if (!answered) return answer(new Error(`ffmpeg exited with ${signal || code}`))
			// HomeKit was already told the stream started: release its stream slot so new requests (e.g. the next ring) work
			this.releaseStream(sessionId)
		})
	}

	/** Tell HomeKit a stream it believes is running has ended, freeing the stream slot. */
	releaseStream(sessionId) {
		if (!this.controller) return
		try {
			this.controller.forceStopStreamingSession(sessionId)
		} catch (err) {
			this.log.debug('forceStopStreamingSession failed:', redact(err.message))
		}
	}

	stopStream(sessionId) {
		if (this.pendingSessions) delete this.pendingSessions[sessionId]
		const session = this.sessions[sessionId]
		if (!session) return
		session.stopping = true
		clearTimeout(session.timer)
		clearTimeout(session.graceTimer)
		delete this.sessions[sessionId]
		// A START still waiting for its first frame must be answered too
		session.answer(new Error('Stream stopped'))
		try {
			session.process.kill('SIGKILL')
		} catch (err) {
			this.log.error('Error occurred terminating the video process!')
			this.log.debug(redact(err.message))
		}
	}

	/** Stop every ffmpeg process of this camera (Homebridge shutdown). */
	destroy() {
		super.destroy()
		Object.keys(this.sessions).forEach((sessionId) => this.stopStream(sessionId))
		this.pendingSessions = {}
		this.snapshotStoppers.forEach((stop) => stop())
	}

	ringDoorbell() {
		this.log.info(`[${this.data.Name}] Doorbell rang`)

		this.controller.ringDoorbell()

		//Update "Doorbell button pressed" sensor
		this.buttonService.updateCharacteristic(
			this.Characteristic.ContactSensorState,
			this.Characteristic.ContactSensorState.CONTACT_NOT_DETECTED
		)
		setTimeout(() => {
			this.buttonService.updateCharacteristic(
				this.Characteristic.ContactSensorState,
				this.Characteristic.ContactSensorState.CONTACT_DETECTED
			)
		}, 500)
	}

	/**
	 * Handle a PubNub patch. Its field set is checked before it is merged into this.data: the fields of the
	 * motion messages (#206) are also regular camera fields that stay in the data and arrive in every snapshot.
	 */
	handlePatch(patch) {
		this.patchMotionKind = Camera.motionMessageKind(patch)
		try {
			super.handlePatch(patch)
		} finally {
			this.patchMotionKind = null
		}
	}

	/** Whether the patch being handled is a motion message of a kind enabled in the settings (#206). */
	motionFromMessage() {
		const kind = this.patchMotionKind
		if (!kind) return false
		const { setting, description } = MOTION_MESSAGE_KINDS[kind]
		if (this.config && this.config[setting] === true) {
			this.log.debug(`[${this.data.Name}] Motion from a ${description}`)
			return true
		}
		// Point testers at the setting once per camera and kind, without counting it as motion
		if (!this.motionHintsLogged) this.motionHintsLogged = new Set()
		if (!this.motionHintsLogged.has(kind)) {
			this.motionHintsLogged.add(kind)
			this.log.info(`Camera [${this.data.Name}] sent a ${description}. Some cameras report motion only this way; ` +
				`if this camera never shows motion in HomeKit, try turning on "${setting}".`)
		}
		return false
	}

	async notify() {
		if (this.motionService) {
			let motionDetected = this.getMotionDetectedState() || this.motionFromMessage()
			if (motionDetected) {
				this.motionService.updateCharacteristic(
					this.Characteristic.MotionDetected,
					true
				)
				setTimeout(() => {
					this.motionService.updateCharacteristic(
						this.Characteristic.MotionDetected,
						false
					)
				}, 5000)
			}
		}

		if (
			this.controller &&
			this.controller.doorbellService &&
			this.getDoorbellButtonPress() === true
		) {
			let delta = Date.now() - this.lastPressedDoorbellButton
			this.log.debug("Timediff from last notification: " + delta)
			if (Date.now() - this.lastPressedDoorbellButton >= DOORBELL_IGNORE_MILLISECONDS) {
				this.ringDoorbell()
				this.lastPressedDoorbellButton = Date.now()
			}
		}
	}

	static appliesTo(data) {
		return data.Type == VivintDict.PanelDeviceType.Camera
	}

	/**
	 * Kind of camera motion message, recognised by its exact field set as in vivintpy (Home Assistant), #206:
	 * - 'deter': { _id, deter_on_duty, t }. vivintpy ignores the value; this requires a truthy one (true, 1, ...),
	 *   so a message that turns Smart Deter off is not counted as motion.
	 * - 'status': { _id, act, s }, any value. It is also sent when a detection ends.
	 *
	 * @param {object} patch PubNub device patch with mapped field names
	 * @returns {'deter'|'status'|null}
	 */
	static motionMessageKind(patch) {
		if (!patch || typeof patch !== 'object') return null
		const fields = Object.keys(patch).sort().join(',')
		if (fields === 'DeterOnDuty,Id,Type' && patch.DeterOnDuty) return 'deter'
		if (fields === 'ActualType,Id,Status') return 'status'
		return null
	}

	/**
	 * A camera is a doorbell if its name contains "doorbell", or if its ID or name is listed in the
	 * `doorbellCameraIds` setting (#12, #32: doorbells named e.g. "Front Door" got no ring notifications).
	 *
	 * @param {object} camera
	 * @param {number|string} camera.id
	 * @param {string[]} camera.names raw and/or sanitized names
	 * @param {object} [config]
	 */
	static isDoorbell({ id, names = [] }, config = {}) {
		const lowerNames = names.filter((n) => typeof n === 'string').map((n) => n.trim().toLowerCase())
		if (lowerNames.some((n) => n.indexOf('doorbell') > -1)) return true
		const listed = Array.isArray(config.doorbellCameraIds) ? config.doorbellCameraIds : []
		return listed
			.filter((entry) => entry !== undefined && entry !== null && `${entry}`.trim() !== '')
			.map((entry) => `${entry}`.trim().toLowerCase())
			.some((entry) => entry === `${id}` || lowerNames.includes(entry))
	}

	static inferCategory(data, Categories, config) {
		if (Camera.isDoorbell({ id: data.Id, names: [data.Name] }, config))
			return Categories.VIDEO_DOORBELL
		else return Categories.IP_CAMERA
	}
	
	static addServices(accessory, Service, config) {
		// Sanitize the names before creating services
		const sanitizedName = SanitizeName.sanitizeDeviceName(accessory.context.name, accessory.context.id)
		const sanitizedMotionName = sanitizedName + ' PIV Detector'
		const sanitizedButtonName = sanitizedName + ' Button'
			
		accessory.addService(
			new Service.MotionSensor(sanitizedMotionName)
		)
		
		if (Camera.isDoorbell({ id: accessory.context.id, names: [accessory.context.name] }, config)) {
			accessory.addService(new Service.ContactSensor(sanitizedButtonName))
		}
	}
}

module.exports = Camera
module.exports.redact = redact
module.exports.buildStreamArgs = buildStreamArgs
module.exports.CAMERA_STREAM_COUNT = CAMERA_STREAM_COUNT
module.exports.SNAPSHOT_TIMEOUT_MS = SNAPSHOT_TIMEOUT_MS
