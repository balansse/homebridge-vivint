const dataPatch = require("./datapatch.js")
const SanitizeName = require('./sanitize_name.js')

class Device {
    constructor(accessory, data, config, log, homebridge, vivintApi) {
        this.Service = homebridge.hap.Service
        this.Accessory = homebridge.hap.Accessory
        this.Characteristic = homebridge.hap.Characteristic
        this.hap = homebridge.hap

        this.config = config
        this.log = log
        this.vivintApi = vivintApi

        this.id = accessory.context.id
        this.name = accessory.context.name
        this.data = data || {}

        this.batteryService = accessory.getService(this.Service.Battery)

        if (this.batteryService) {
          this.batteryService
            .getCharacteristic(this.Characteristic.StatusLowBattery)
            .on('get', callback => callback(null, this.getLowBatteryState()))

          this.batteryService
            .getCharacteristic(this.Characteristic.BatteryLevel)
            .on('get', callback => callback(null, this.getBatteryLevelValue()))
        }
    }

    getBatteryLevelValue() {
      return (typeof this.data.BatteryLevel === 'number') ? this.data.BatteryLevel : 100
    }

    getLowBatteryState() {
      if (this.config.lowBatteryLevel && this.getBatteryLevelValue() <= this.config.lowBatteryLevel ||
          !this.config.lowBatteryLevel && Boolean(this.data.LowBattery)) {
        return this.Characteristic.StatusLowBattery.BATTERY_LEVEL_LOW
      }
      else {
        return this.Characteristic.StatusLowBattery.BATTERY_LEVEL_NORMAL
      }
    }

    getTamperedState() {
      if (this.data.Tamper) {
        return this.Characteristic.StatusTampered.TAMPERED
      }
      else {
        return this.Characteristic.StatusTampered.NOT_TAMPERED
      }
    }

    handleSnapshot(data) {
      if (data.Id != this.id)
        throw "This snapshot does not belong to this device"
      this.data = data
      this.notify()
    }

    /**
     * Handle a PubSub patch
     */
    handlePatch(patch) {
      if (patch.Id != this.id)
        throw "This patch does not belong to this device"

      this.log.debug("Patching data: ", this.data)
      this.log.debug("Applying patch: ", patch)

      if (!this.data) this.data = {}

      dataPatch(this.data, patch)

      this.log.debug("Patched data: ", this.data)

      this.notify()
    }

    notify() {
      if (this.batteryService) {
        this.batteryService.updateCharacteristic(this.Characteristic.StatusLowBattery, this.getLowBatteryState())
        this.batteryService.updateCharacteristic(this.Characteristic.BatteryLevel, this.getBatteryLevelValue())
      }
    }

    /** Release timers/resources. Subclasses that start timers must override and call super. */
    destroy() {}

    /** Set a characteristic on the battery service if this accessory has one. */
    updateBatteryCharacteristic(characteristic, value) {
      if (this.batteryService) this.batteryService.updateCharacteristic(characteristic, value)
    }

    static appliesTo(data) {
      throw "appliesTo is not implemented"
    }

    static inferCategory(data) {
      throw "inferCategory is not implemented"
    }

    static addServices(accessory, Service) {
        const sanitizedName = SanitizeName.sanitizeDeviceName(accessory.context.name, accessory.context.id)
        accessory.addService(new Service.Battery(sanitizedName))
    }
}

module.exports = Device
