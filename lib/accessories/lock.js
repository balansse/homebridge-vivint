const Device = require('../device.js')
const VivintDict = require("../vivint_dictionary.json")
const SanitizeName = require('../sanitize_name.js')
const { describeError } = require('../http.js')

class Lock extends Device {
    constructor(accessory, data, config, log, homebridge, vivintApi) {
        super(accessory, data, config, log, homebridge, vivintApi)
      
      this.service = accessory.getService(this.Service.LockMechanism)

      this.updateBatteryCharacteristic(this.Characteristic.ChargingState, this.Characteristic.ChargingState.NOT_CHARGEABLE)

      this.service
        .getCharacteristic(this.Characteristic.LockCurrentState)
        .on('get', async callback => this.getCurrentState(callback))

      this.service
        .getCharacteristic(this.Characteristic.LockTargetState)
        //.on('get', async callback => this.getTargetState(callback))
        .on('set', async (state, callback) => this.setTargetState(state, callback))

      this.notify()
    }

    async setTargetState(targetState, callback) {
      let locked = (targetState == this.Characteristic.LockTargetState.SECURED)
      try {
        await this.vivintApi.setLockState(this.id, locked)
        callback()
      }
      catch (err) {
        this.log.error("Failure setting lock state:", describeError(err))
        callback(new Error(`An error occurred while setting the door lock state: ${describeError(err)}`))
      }
    }

    // async getTargetState(callback) {
    //   let state = this.service.getCharacteristic(this.Characteristic.LockTargetState).value
    //   return callback(null, state)
    // }

    async getCurrentState(callback) {
      return callback(null, this.getLockState())
    }

    getLockState() {
      const status = this.data.Status
      switch (status){
        case false:
        case 0:
          return this.Characteristic.LockCurrentState.UNSECURED
        case true:
        case 1:
        case 255: // Z-Wave door lock mode 0xFF = secured
          return this.Characteristic.LockCurrentState.SECURED
        // Set by DeviceSet from a "failed to lock" inbox alert
        case this.Characteristic.LockCurrentState.JAMMED:
          return this.Characteristic.LockCurrentState.JAMMED
        default:
          // Other numbers are ambiguous: in Z-Wave, 0x01/0x10/0x20/... are *unsecured* variants and 0xFE is unknown.
          // Never guess "secured"; report the raw value once so it can be mapped (#121).
          this.reportUnrecognizedStatus(status)
          return this.Characteristic.LockCurrentState.UNKNOWN
      }
    }

    reportUnrecognizedStatus(status) {
      if (status === undefined || status === null) return
      if (!this.reportedStatuses) this.reportedStatuses = new Set()
      const key = JSON.stringify(status)
      if (this.reportedStatuses.has(key)) return
      this.reportedStatuses.add(key)
      this.log.info(`Lock '${this.name}' reported an unrecognized state ${key}; showing it as unknown. ` +
        'Please report this value on https://github.com/balansse/homebridge-vivint/issues/121')
    }

    notify() {
      super.notify()
      if (this.service) {
        let state = this.getLockState()
        this.service.updateCharacteristic(this.Characteristic.LockCurrentState, state)
        // Only move the target for definite states; JAMMED/UNKNOWN keep the last requested target
        if (state === this.Characteristic.LockCurrentState.SECURED) {
          this.service.updateCharacteristic(this.Characteristic.LockTargetState, this.Characteristic.LockTargetState.SECURED)
        } else if (state === this.Characteristic.LockCurrentState.UNSECURED) {
          this.service.updateCharacteristic(this.Characteristic.LockTargetState, this.Characteristic.LockTargetState.UNSECURED)
        }
      }
    }

    static appliesTo(data) {
      return data.Type == VivintDict.PanelDeviceType.DoorLock
    }

    static inferCategory(data, Categories) {
        return Categories.DOOR_LOCK
    }

    static addServices(accessory, Service) {
        super.addServices(accessory, Service)
        const sanitizedName = SanitizeName.sanitizeDeviceName(accessory.context.name, accessory.context.id)
        accessory.addService(new Service.LockMechanism(sanitizedName))
    }
  }

  module.exports = Lock
