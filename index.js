var Service;

const PluginName = "homebridge-vivint"
const PlatformName = "Vivint"
const VivintApiModule = require("./lib/vivint_api.js")
const DeviceSetModule = require("./lib/device_set.js")
const { describeError } = require("./lib/http.js")
const PubNubSupervisor = require("./lib/pubnub_supervisor.js")

module.exports = function (homebridge) {
  Service = homebridge.hap.Service;

  // Make every characteristic of the given accessories report an error, so HomeKit shows
  // "No Response" instead of stale values when the platform could not start.
  function setCatastrophe(accessories) {
    accessories.forEach((accessory) => {
      accessory.services
      .filter((service) => service.UUID !== Service.AccessoryInformation.UUID)
      .forEach((service) => {
        service.characteristics.forEach((characteristic) => {
          characteristic.on('get', (next) => {
            next(new Error("Platform failed to initialize"))
          })
        })
      })
    })
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

      if (!config || !config.refreshToken) {
        log.error("No refresh token configured. Open the plugin settings to log in to Vivint and generate one.")
        return
      }

      let config_apiLoginRefreshSecs = config.apiLoginRefreshSecs || 1200 // once per 20 minutes default

      let VivintApi = VivintApiModule(config, log)
      // Start logging in right away; bootstrapping waits until cached accessories are restored.
      this.vivintApiPromise = VivintApi.login({refreshToken: config.refreshToken})
      // Avoid an unhandled rejection before didFinishLaunching attaches its handlers
      this.vivintApiPromise.catch(() => {})

      const launched = new Promise((resolve) => api.on('didFinishLaunching', resolve))

      this.initialLoad = launched
        .then(() => this.vivintApiPromise)
        .then(async (vivintApi) => {
          let pubNub = await vivintApi.connectPubNub()
          this.pubNub = pubNub
          this.bootstrap(vivintApi, pubNub, config_apiLoginRefreshSecs)
        })
        .catch((error) => {
          if (error instanceof VivintApiModule.VivintAuthError) {
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

      //Remove stale/ignored accessories
      let removedAccessories = cachedAccessories
          .filter((acc) => !snapshotAccessories.some((snap_acc) => snap_acc.context.id === acc.context.id))
      //Remove accessories that are handled differently (and previously enabled cameras if disabled now)
      let changedAccessories = cachedAccessories
          .filter((acc) => snapshotAccessories.some((snap_acc) => snap_acc.context.id === acc.context.id && snap_acc.context.deviceClassName !== acc.context.deviceClassName || config.disableCameras && acc.getService(Service.CameraRTPStreamManagement)))
      let removedAndChangedAccessories = removedAccessories.concat(changedAccessories)
      log.info(`Removing ${removedAndChangedAccessories.length} accessories`)
      api.unregisterPlatformAccessories(PluginName, PlatformName, removedAndChangedAccessories)

      //Adding new accessories
      let newAccessories = snapshotAccessories
          .filter((acc) => !cachedAccessories.some((cached_acc) => cached_acc.context.id === acc.context.id) || changedAccessories.some((changed_acc) => changed_acc.context.id === acc.context.id))
      log.info(`Adding ${newAccessories.length} accessories`)
      api.registerPlatformAccessories(PluginName, PlatformName, newAccessories)

      let keptAccessories = cachedAccessories.filter((el) => !removedAndChangedAccessories.includes(el))

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
      this.timers.forEach((t) => clearInterval(t))
      this.timers = []
      if (this.deviceSet) this.deviceSet.destroy()
      if (this.pubNubSupervisor) this.pubNubSupervisor.destroy()
      if (this.pubNub) {
        try {
          this.pubNub.unsubscribeAll()
          this.pubNub.stop()
        } catch (err) {
          this.log.debug("Error stopping PubNub:", describeError(err))
        }
      }
    }

    configureAccessory(accessory) {
      this.cachedAccessories.push(accessory)
    }
  }

  homebridge.registerPlatform(PluginName, PlatformName, VivintPlatform)
};
