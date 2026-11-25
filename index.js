var Service;

const PluginName = "homebridge-vivint"
const PlatformName = "Vivint"
const VivintApiModule = require("./lib/vivint_api.js")
const DeviceSetModule = require("./lib/device_set.js")
const { describeError } = require("./lib/http.js")
const PubNubSupervisor = require("./lib/pubnub_supervisor.js")
const { startWithRetry, StartupCancelled } = require("./lib/startup_retry.js")

module.exports = function (homebridge) {
  Service = homebridge.hap.Service;

  // Answers HomeKit reads with an error, so HomeKit shows "No Response" instead of stale values
  // while the platform could not start. One shared handler, so it can be removed again.
  function failGet(next) {
    next(new Error("Platform failed to initialize"))
  }

  function forEachCharacteristic(accessories, fn) {
    accessories.forEach((accessory) => {
      accessory.services
      .filter((service) => service.UUID !== Service.AccessoryInformation.UUID)
      .forEach((service) => service.characteristics.forEach(fn))
    })
  }

  // Make every characteristic of the given accessories report an error. Safe to call repeatedly.
  function setCatastrophe(accessories) {
    forEachCharacteristic(accessories, (characteristic) => {
      characteristic.removeListener('get', failGet)
      characteristic.on('get', failGet)
    })
  }

  // Undo setCatastrophe once a later startup attempt succeeds. Must run before the devices bind their own
  // 'get' handlers: HAP answers with the first handler that calls back.
  function clearCatastrophe(accessories) {
    forEachCharacteristic(accessories, (characteristic) => characteristic.removeListener('get', failGet))
  }

  function formatDelay(ms) {
    const secs = Math.round(ms / 1000)
    return secs % 60 === 0 ? `${secs / 60} minute${secs === 60 ? '' : 's'}` : `${secs} seconds`
  }

  class VivintPlatform {
    constructor(log, config, api) {
      this.log = log
      this.config = config || {}
      this.api = api
      this.cachedAccessories = []
      this.timers = []
      this.pubNub = null
      this.pubNubSupervisor = null
      this.deviceSet = null
      this.startup = null
      this.stopped = false

      if (!config || !config.refreshToken) {
        log.error("No refresh token configured. Open the plugin settings to log in to Vivint and generate one.")
        return
      }

      let config_apiLoginRefreshSecs = config.apiLoginRefreshSecs || 1200 // once per 20 minutes default

      let VivintApi = VivintApiModule(config, log)
      // Shared by every attempt: a login stores the rotated refresh token here
      const creds = {refreshToken: config.refreshToken}
      // Start logging in right away; bootstrapping waits until cached accessories are restored.
      this.vivintApiPromise = VivintApi.login(creds)
      // Avoid an unhandled rejection before didFinishLaunching attaches its handlers
      this.vivintApiPromise.catch(() => {})

      const launched = new Promise((resolve) => api.on('didFinishLaunching', resolve))

      // Login and PubNub connect are retried with backoff after errors a later attempt can fix (#204).
      // An invalid refresh token or a configuration error is final.
      const connect = async (attempt) => {
        const vivintApi = await (attempt === 1 ? this.vivintApiPromise : VivintApi.login(creds))
        if (this.stopped) throw new StartupCancelled()
        const pubNub = await vivintApi.connectPubNub()
        if (this.stopped) {
          this.stopPubNub(pubNub)
          throw new StartupCancelled()
        }
        return { vivintApi, pubNub }
      }

      this.initialLoad = launched
        .then(() => {
          if (this.stopped) throw new StartupCancelled()
          this.startup = startWithRetry(connect, {
            shouldRetry: (error) => !(error instanceof VivintApiModule.VivintAuthError ||
              error instanceof VivintApiModule.VivintConfigError || error instanceof StartupCancelled),
            onRetry: (error, delayMs) => {
              log.error(`Could not connect to Vivint (${describeError(error)}). Retrying in ${formatDelay(delayMs)}.`)
              setCatastrophe(this.cachedAccessories)
            },
          })
          return this.startup.promise
        })
        .then(({ result: { vivintApi, pubNub }, attempts }) => {
          this.startup = null
          if (this.stopped) return this.stopPubNub(pubNub)
          if (attempts > 1) {
            log.info(`Connected to Vivint after ${attempts} attempts`)
            clearCatastrophe(this.cachedAccessories)
          }
          this.pubNub = pubNub
          // Runs once: it registers new accessories, so it is never retried
          this.bootstrap(vivintApi, pubNub, config_apiLoginRefreshSecs)
        })
        .catch((error) => {
          this.startup = null
          if (error instanceof StartupCancelled) return
          if (error instanceof VivintApiModule.VivintAuthError || error instanceof VivintApiModule.VivintConfigError) {
            log.error(error.message)
          } else {
            log.error("Error while bootstrapping accessories:", describeError(error))
          }
          setCatastrophe(this.cachedAccessories)
        })

      api.on('shutdown', () => this.shutdown())
    }

    bootstrap(vivintApi, pubNub, config_apiLoginRefreshSecs) {
      const log = this.log
      const config = this.config
      const api = this.api

      let DeviceSet = DeviceSetModule(config, log, homebridge, vivintApi)
      let deviceSet = new DeviceSet()
      this.deviceSet = deviceSet
      let cachedAccessories = this.cachedAccessories

      log.debug(JSON.stringify(vivintApi.deviceSnapshot(), undefined, 4))

      let snapshotDevices = vivintApi.deviceSnapshot().Devices || []
      let snapshotAccessories = snapshotDevices
          .filter((data) => data.Id)
          .map((deviceData) => {
            try {
              return DeviceSet.createDeviceAccessory(deviceData)
            } catch (err) {
              log.error(`Skipping device [ID]:${deviceData.Id} [Type]:${deviceData.Type} [Name]:${deviceData.Name} - could not create accessory:`, describeError(err))
              return null
            }
          })
          .filter((dvc) => dvc)

      //Device ids are only unique within a panel. Accessories cached before panelId was recorded
      //belong to the first system on the account, which is the one older versions always used.
      const panelOf = (acc) => acc.context.panelId !== undefined ? acc.context.panelId : vivintApi.defaultPanelId
      let currentPanelCached = cachedAccessories.filter((acc) => `${panelOf(acc)}` === `${vivintApi.panelId}`)

      //Remove stale/ignored accessories, and accessories of another panel
      let removedAccessories = cachedAccessories
          .filter((acc) => !currentPanelCached.includes(acc) || !snapshotAccessories.some((snap_acc) => snap_acc.context.id === acc.context.id))
      //Remove accessories that are handled differently (and previously enabled cameras if disabled now)
      let changedAccessories = currentPanelCached
          .filter((acc) => snapshotAccessories.some((snap_acc) => snap_acc.context.id === acc.context.id && snap_acc.context.deviceClassName !== acc.context.deviceClassName || config.disableCameras && acc.getService(Service.CameraRTPStreamManagement)))
      let removedAndChangedAccessories = removedAccessories.concat(changedAccessories)
      log.info(`Removing ${removedAndChangedAccessories.length} accessories`)
      api.unregisterPlatformAccessories(PluginName, PlatformName, removedAndChangedAccessories)

      //Adding new accessories
      let newAccessories = snapshotAccessories
          .filter((acc) => !currentPanelCached.some((cached_acc) => cached_acc.context.id === acc.context.id) || changedAccessories.some((changed_acc) => changed_acc.context.id === acc.context.id))
      log.info(`Adding ${newAccessories.length} accessories`)
      api.registerPlatformAccessories(PluginName, PlatformName, newAccessories)

      let keptAccessories = cachedAccessories.filter((el) => !removedAndChangedAccessories.includes(el))

      //Record the panel on accessories cached by older versions
      let legacyAccessories = keptAccessories.filter((acc) => acc.context.panelId === undefined)
      if (legacyAccessories.length > 0) {
        legacyAccessories.forEach((acc) => { acc.context.panelId = vivintApi.panelId })
        api.updatePlatformAccessories(legacyAccessories)
      }

      keptAccessories.concat(newAccessories).forEach((accessory) => {
        let data = snapshotDevices.find((snap_device) => snap_device.Id === accessory.context.id)
        try {
          deviceSet.bindAccessory(accessory, data)
        } catch (err) {
          log.error(`Could not set up accessory '${accessory.displayName}':`, describeError(err))
          setCatastrophe([accessory])
        }
      })

      // Reconnects PubNub after it gives up retrying, and resubscribes if the stream goes quiet for too long
      const supervisor = new PubNubSupervisor(pubNub, [vivintApi.pubNubChannel()], log)
      this.pubNubSupervisor = supervisor
      pubNub.addListener({
        status: (statusEvent) => supervisor.handleStatus(statusEvent),
        message: (msg) => {
          supervisor.noteActivity()
          // A single malformed message must never break the real-time update stream
          try {
            let parsed = vivintApi.parsePubNub(msg.message)
            log.debug("Parsed PubNub message:", JSON.stringify(parsed, undefined, 4))
            deviceSet.handleMessage(parsed)
          } catch (err) {
            log.warn("Ignoring PubNub message that could not be processed:", describeError(err))
          }
        }
      })
      deviceSet.handleSnapshot(vivintApi.deviceSnapshot(), vivintApi.deviceSnapshotTs())

      //Refreshing the token
      this.timers.push(setInterval(() => {
        supervisor.check()
        vivintApi.renew()
          .then((vivintApi) => vivintApi.renewPanelLogin())
          .catch((err) => log.error("Error refreshing login info:", describeError(err)))
      }, config_apiLoginRefreshSecs * 1000))

      //Setting up the system info refresh to keep the notification stream active
      this.timers.push(setInterval(() => {
          vivintApi.renewSystemInfo()
            .then((vivintApi) => deviceSet.handleSnapshot(vivintApi.deviceSnapshot(), vivintApi.deviceSnapshotTs()))
            .catch((err) => log.error("Error getting system info:", describeError(err)))
      }, (config_apiLoginRefreshSecs / 20) * 1000))
    }

    shutdown() {
      this.stopped = true
      if (this.startup) this.startup.cancel()
      this.timers.forEach((t) => clearInterval(t))
      this.timers = []
      if (this.deviceSet) this.deviceSet.destroy()
      if (this.pubNubSupervisor) this.pubNubSupervisor.destroy()
      if (this.pubNub) this.stopPubNub(this.pubNub)
    }

    stopPubNub(pubNub) {
      try {
        pubNub.unsubscribeAll()
        pubNub.stop()
      } catch (err) {
        this.log.debug("Error stopping PubNub:", describeError(err))
      }
    }

    configureAccessory(accessory) {
      this.cachedAccessories.push(accessory)
    }
  }

  homebridge.registerPlatform(PluginName, PlatformName, VivintPlatform)
};
