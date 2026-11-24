const Device = require('../device.js')
const VivintDict = require("../vivint_dictionary.json")
const SanitizeName = require('../sanitize_name.js')
const { describeError } = require('../http.js')

class LightSwitch extends Device {
  constructor(accessory, data, config, log, homebridge, vivintApi) {
    super(accessory, data, config, log, homebridge, vivintApi)

      this.service = accessory.getService(this.Service.Lightbulb) || accessory.getService(this.Service.Fan) || accessory.getService(this.Service.Switch)

      this.service
        .getCharacteristic(this.Characteristic.On)
        .on('get', (next) => next(null, this.switchCurrentValue()))
        .on('set', this.setSwitchCurrentValue.bind(this))
    }

    switchCurrentValue() {
      return this.data.Status
    }

    setSwitchCurrentValue(targetState, next) {
      if (targetState) {
        // turn switch on
        this.vivintApi.putDevice('switches', this.id, {
            s: true,
            _id: this.id
          })
          .then(
            (success) => next(),
            (failure) => {
              this.log.error("Failure setting switch state:", describeError(failure))
              next(failure)
            })
      } else {
        // turn switch off
        this.vivintApi.putDevice('switches', this.id, {
            s: false,
            _id: this.id
          })
          .then(
            (success) => next(),
            (failure) => {
              this.log.error("Failure setting switch state:", describeError(failure))
              next(failure)
            })
      }
    }


    notify() {
      if (this.service) {
        if (this.data.Value == 0) {
          this.service
            .getCharacteristic(this.Characteristic.On)
            .updateValue(false)
        } else {
          this.service
            .getCharacteristic(this.Characteristic.On)
            .updateValue(true)
        }
      }
    }

    static appliesTo(data) {
      return data.Type == VivintDict.PanelDeviceType.BinarySwitch
    }

    static inferCategory(data, Categories) {
      return Categories.SWITCH
    }

    static addServices(accessory, Service) {
        const sanitizedName = SanitizeName.sanitizeDeviceName(accessory.context.name, accessory.context.id)
        if (accessory.context.name.match(/\blight\b/i)) {
            accessory.addService(new Service.Lightbulb(sanitizedName))
        } else if (accessory.context.name.match(/\bfan\b/i)) {
            accessory.addService(new Service.Fan(sanitizedName))
        } else {
            accessory.addService(new Service.Switch(sanitizedName))
        }
    }
  }

module.exports = LightSwitch
