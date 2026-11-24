const Device = require('../device.js')
const VivintDict = require("../vivint_dictionary.json")
const coalesce = require("../coalesce.js")
const { describeError } = require("../http.js")
const SanitizeName = require('../sanitize_name.js')

class LightGroup extends Device {
  constructor(accessory, data, config, log, homebridge, vivintApi) {
    super(accessory, data, config, log, homebridge, vivintApi)

      // Brightness/speed sliders fire many sets per second: send only the latest value,
      // and answer every HomeKit request once the write that covers it has completed.
      let writeBrightness = coalesce((value) => this.vivintApi.putDevice('switches', this.id, { val: value, _id: this.id }), 300)
      let promiseSetter = () => async (value, next) => {
        try {
          await writeBrightness(value)
          next()
        } catch (err) {
          this.log.error("Failure setting dimmer brightness state:", describeError(err))
          next(err)
        }
      }

      this.service = accessory.getService(this.Service.Lightbulb) || accessory.getService(this.Service.Fan)

      this.service
        .getCharacteristic(this.Characteristic.On)
        .on('get', (next) => next(null, this.switchCurrentValue()))
        .on('set', this.setSwitchCurrentValue.bind(this))

      if (accessory.context.name.match(/\bfan\b/i)) {
        this.is_fan = true
        this.service
            .getCharacteristic(this.Characteristic.RotationSpeed)
            .on('get', (next) => next(null, this.switchBrightnessValue()))
            .on('set', promiseSetter())
        } else {
        this.is_fan = false
        this.service
            .getCharacteristic(this.Characteristic.Brightness)
            .on('get', (next) => next(null, this.switchBrightnessValue()))
            .on('set', promiseSetter())
      }

      this.last_val_s = null
      this.last_val = null
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
              this.log.error("Failure setting lighting group state:", describeError(failure))
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
              this.log.error("Failure setting lighting group state:", describeError(failure))
              next(failure)
            })
      }
    }

    switchBrightnessValue() {
      return this.data.Value
    }

    notify() {
      // vivint will typically send two notifications

      if (this.service) {
        if (this.data.Value !== this.last_val) {
          // light group level has changed, update HomeKit
          this.last_val = this.data.Value
          if (this.is_fan) {
            this.service
              .getCharacteristic(this.Characteristic.RotationSpeed)
              .updateValue(this.data.Value)
          } else {
            this.service
              .getCharacteristic(this.Characteristic.Brightness)
              .updateValue(this.data.Value)
          }
        }

        if (this.data.Status !== this.last_val_s) {
          // on/off state has changed, update HomeKit
          this.last_val_s = this.data.Status
          this.service
            .getCharacteristic(this.Characteristic.On)
            .updateValue(this.switchCurrentValue())
        }
      }
    }

    static appliesTo(data) {
      return data.Type == VivintDict.PanelDeviceType.GroupDevices &&
        data.panel_capability_types &&
        data.panel_capability_types.includes(VivintDict.PanelCapabilityType.Dimmable) &&
        data.panel_capability_types.includes(VivintDict.PanelCapabilityType.GroupDevices)
    }

    static inferCategory(data, Categories) {
      return Categories.SWITCH
    }

    static addServices(accessory, Service) {
        const sanitizedName = SanitizeName.sanitizeDeviceName(accessory.context.name, accessory.context.id)
        if (accessory.context.name.match(/\bfan\b/i)) {
            accessory.addService(new Service.Fan(sanitizedName))
        } else {
            accessory.addService(new Service.Lightbulb(sanitizedName))
        }
    }
  }

module.exports = LightGroup
