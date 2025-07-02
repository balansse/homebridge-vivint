const Device = require('../device.js')
const VivintDict = require('../vivint_dictionary.json')
const SanitizeName = require('../sanitize_name.js')

const getPort = require('get-port')
const ffmpegPath = require('ffmpeg-for-homebridge')
const { spawn } = require('child_process')

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
		// eslint-disable-next-line no-await-in-loop
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

		if (this.config.useExternalVideoStreams) {
			this.rtspUrl = data.CameraExternalURL[0].replace(
				'rtsp://',
				`rtsp://${vivintApi.panelLogin.Name}:${vivintApi.panelLogin.Password}@`
			)
			this.rtspUrl_SD = data.CameraExternalURLStandard[0].replace(
				'rtsp://',
				`rtsp://${vivintApi.panelLogin.Name}:${vivintApi.panelLogin.Password}@`
			)
		} else {
      		this.rtspUrl = data.CameraInternalURL[0].replace(
				'rtsp://',
				`rtsp://${vivintApi.panelLogin.Name}:${vivintApi.panelLogin.Password}@`
			)
			this.rtspUrl_SD = data.CameraInternalURLStandard[0].replace(
				'rtsp://',
				`rtsp://${vivintApi.panelLogin.Name}:${vivintApi.panelLogin.Password}@`
			)
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

			if (data.Name.toLowerCase().indexOf('doorbell') > -1) {
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
			cameraStreamCount: 2,
			delegate: this,
			streamingOptions: streamingOptions,
		}

		if (config.disableCameras != true) {
			if (data.Name.toLowerCase().indexOf('doorbell') > -1) {
				this.controller = new this.hap.DoorbellController(controllerOptions)
			} else this.controller = new this.hap.CameraController(controllerOptions)

			accessory.configureController(this.controller)
		}

		this.motionService = accessory.getService(this.Service.MotionSensor)
		this.motionService
			.getCharacteristic(this.Characteristic.MotionDetected)
			.on('get', (callback) => callback(null, this.getMotionDetectedState()))

		//Add a Contact Sensor service for Doorbell button press
		if (data.Name.toLowerCase().indexOf('doorbell') > -1) {
			//In case cached accessory does not have contact sensor service added (upgraded from previous versions)
			if (accessory.getService(this.Service.ContactSensor) === undefined) {
				accessory.addService(new this.Service.ContactSensor(accessory.context.name + ' Button'))
			}

			this.buttonService = accessory.getService(this.Service.ContactSensor)
			this.buttonService
				.getCharacteristic(this.Characteristic.ContactSensorState)
				.on('get', (callback) => callback(null, this.getDoorbellButtonPress()))
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

	async handleSnapshotRequest(request, callback) {
		this.log.debug(
			`Handling camera snapshot for '${this.data.Name}' at ${request.width}x${request.height}`
		)

		////Getting snapshot from Vivint API
		////
		// try {
		//   await this.vivintApi.refreshCameraThumbnail(this.id)
		//   let img = await this.vivintApi.getCameraThumbnail(this.id)
		//   this.log.debug(`Closed '${this.data.Name}' snapshot request with ${Math.round(img.length/1000)}kB image`)
		//   callback(undefined, img)
		// }
		// catch (err) {
		//   this.log.error('An error occurred while making snapshot request:', err.statusCode ? err.statusCode : '', err.statusMessage ? err.statusMessage : '')
		//   this.log.debug(err)
		//   callback(err)
		// }

		let snapshotArgs = [
			['-rtsp_transport', 'tcp'],
			['-i', `${this.rtspUrl}`],
			['-frames:v', '1'],
			['-vcodec', 'mjpeg'],
			['-f', 'image2'],
			['-'],
		]

		let snapshot = [].concat(
			...snapshotArgs.map((arg) =>
				arg.map((a) => (typeof a == 'string' ? a.trim() : a))
			)
		)

		try {
			let ffmpeg = spawn(this.ffmpegPath, [...snapshot], {
				env: process.env,
			})
			const snapshotBuffers = []
			ffmpeg.stdout.on('data', (data) => snapshotBuffers.push(data))
			ffmpeg.stderr.on('data', (data) => {
				this.log.debug('SNAPSHOT: ' + String(data))
			})
			ffmpeg.on('exit', (code, signal) => {
				if (signal) {
					this.log.error('Snapshot process was killed with signal: ' + signal)
					callback(new Error('killed with signal ' + signal))
				} else if (code === 0) {
					callback(undefined, Buffer.concat(snapshotBuffers))
				} else {
					this.log.error('Snapshot process exited with code ' + code)
					callback(new Error('Snapshot process exited with code ' + code))
				}
			})
		} catch (err) {
			this.log.error(err)
			callback(err)
		}
	}

	async prepareStream(request, callback) {
		this.log.debug('Prepare stream with request:', request)

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
		this.log.info(`[${this.data.Name}] Handling stream request: ${request.type} for session ${request.sessionID}`)
		this.log.debug('handleStreamRequest with request:', request)

		let sessionId = request.sessionID

		switch (request.type) {
			case this.hap.StreamRequestTypes.START:
				this.log.info(`[${this.data.Name}] Starting stream for session ${sessionId}`)
				let sessionInfo = this.pendingSessions[sessionId]
				if (sessionInfo) {
					let sourceArgs = [
						['-rtsp_transport', 'tcp'],
						['-i', this.rtspUrl],
					]

					let videoArgs = [
						['-an'],
						['-sn'],
						['-dn'],
						['-codec:v', 'libx264'],
						['-pix_fmt', 'yuv420p'],
						['-preset', 'ultrafast'],
						['-tune', 'zerolatency'],
						['-r', request.video.fps],
						['-b:v', '1000k'],
						['-bufsize', '1000k'],
						['-maxrate', '1000k'],

						['-payload_type', request.video.pt],
						['-ssrc', sessionInfo.videoSSRC],
						['-f', 'rtp'],
						['-srtp_out_suite', 'AES_CM_128_HMAC_SHA1_80'],
						['-srtp_out_params', sessionInfo.videoSRTP.toString('base64')],
						[
							`srtp://${sessionInfo.address}:${sessionInfo.videoPort}?rtcpport=${sessionInfo.videoPort}&localrtcpport=${sessionInfo.returnVideoPort}&pkt_size=1316`,
						],
					]

					let audioArgs = []
					if (request.audio) {
						audioArgs = [
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
							['-ssrc', sessionInfo.audioSSRC],
							['-f', 'rtp'],
							['-srtp_out_suite', 'AES_CM_128_HMAC_SHA1_80'],
							['-srtp_out_params', sessionInfo.audioSRTP.toString('base64')],
							[
								`srtp://${sessionInfo.address}:${sessionInfo.audioPort}?rtcpport=${sessionInfo.audioPort}&localrtcpport=${sessionInfo.returnAudioPort}&pkt_size=188`,
							],
						]
					}

					let source = [].concat(
						...sourceArgs.map((arg) =>
							arg.map((a) => (typeof a == 'string' ? a.trim() : a))
						)
					)
					let video = [].concat(
						...videoArgs.map((arg) =>
							arg.map((a) => (typeof a == 'string' ? a.trim() : a))
						)
					)
					let audio = [].concat(
						...audioArgs.map((arg) =>
							arg.map((a) => (typeof a == 'string' ? a.trim() : a))
						)
					)

					let cmd = spawn(this.ffmpegPath, [...source, ...video, ...audio], {
						env: process.env,
					})

					this.log.debug(`Start streaming video for camera '${this.data.Name}'`)
					this.log.debug(
						[
							this.ffmpegPath,
							source.join(' '),
							video.join(' '),
							audio.join(' '),
						].join(' ')
					)

					let started = false
					cmd.stderr.on('data', (data) => {
						if (!started) {
							started = true
							this.log.debug('FFMPEG received first frame')
							callback() // do not forget to execute callback once set up
						}

						this.log.debug(data.toString())
					})

					cmd.on('error', (err) => {
						this.log.error(
							'An error occurred while making stream request:',
							err
						)
						callback(err)
					})

					cmd.on('close', (code) => {
						switch (code) {
							case null:
							case 0:
							case 255:
								this.log.debug('Camera stopped streaming')
								break
							default:
								this.log.debug(`Error: FFmpeg exited with code ${code}`)
								if (!started) {
									callback(new Error(`Error: FFmpeg exited with code ${code}`))
								} else {
									this.controller.forceStopStreamingSession(sessionId)
								}
								break
						}
					})

					this.ongoingSessions[sessionId] = cmd
				}
				delete this.pendingSessions[sessionId]
				break

			case this.hap.StreamRequestTypes.STOP:
				let cmd = this.ongoingSessions[sessionId]
				try {
					if (cmd) {
						cmd.kill('SIGKILL')
					}
				} catch (e) {
					this.log.error('Error occurred terminating the video process!')
					this.log.debug(e)
				}

				delete this.ongoingSessions[sessionId]
				callback()
				break

			case this.hap.StreamRequestTypes.RECONFIGURE:
				// not implemented
				this.log.debug(
					'(Not implemented) Received request to reconfigure to: ' +
						JSON.stringify(request.video, undefined, 4)
				)
				callback()
				break
		}
	}

	ringDoorbell() {

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

	async notify() {
		if (this.motionService) {
			let motionDetected = this.getMotionDetectedState()
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

	static inferCategory(data, Categories) {
		let name = data.Name

		if (name.toLowerCase().indexOf('doorbell') > -1)
			return Categories.VIDEO_DOORBELL
		else return Categories.IP_CAMERA
	}
	
	static addServices(accessory, Service) {
		// Sanitize the names before creating services
		const sanitizedName = SanitizeName.sanitizeDeviceName(accessory.context.name, accessory.context.id)
		const sanitizedMotionName = sanitizedName + ' PIV Detector'
		const sanitizedButtonName = sanitizedName + ' Button'
			
		accessory.addService(
			new Service.MotionSensor(sanitizedMotionName)
		)
		
		if (accessory.context.name.toLowerCase().indexOf('doorbell') > -1) {
			accessory.addService(new Service.ContactSensor(sanitizedButtonName))
		}
	}
}

module.exports = Camera
