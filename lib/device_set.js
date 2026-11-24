const VivintDict = require("./vivint_dictionary.json")
const SanitizeName = require('./sanitize_name.js')

const ContactSensor = require("./accessories/contact_sensor.js")
const SmokeSensor = require("./accessories/smoke_sensor.js")
const CarbonMonoxideSensor = require("./accessories/carbon_monoxide_sensor.js")
const MotionSensor = require("./accessories/motion_sensor.js")
const Lock = require("./accessories/lock.js")
const Thermostat = require("./accessories/thermostat.js")
const GarageDoor = require("./accessories/garage_door.js")
const Panel = require("./accessories/panel.js")
const Camera = require("./accessories/camera.js")
const LightSwitch = require("./accessories/light_switch.js")
const DimmerSwitch = require("./accessories/dimmer_switch.js")
const LightGroup = require("./accessories/light_group.js")

function DeviceSetModule(config, log, homebridge, vivintApi) {
  let PlatformAccessory = homebridge.platformAccessory
  let Service = homebridge.hap.Service
  let Characteristic = homebridge.hap.Characteristic
  let uuid = homebridge.hap.uuid
  let Categories = homebridge.hap.Categories

  let config_IgnoredDevices = config.ignoreDeviceTypes || []
  let config_LogDeviceList = config.logDeviceList || false

  class DeviceSet {
    constructor() {
      this.lastSnapshotTime = 0
      this.devices = []
      this.devicesById = {}
      this.panel_DeviceId = 0
    }

    bindAccessory(accessory, data) {

      let deviceClass = Devices.find((dc) => {
        return dc.name == accessory.context.deviceClassName
      })
      if (!deviceClass)
        throw "Unknown device class name " + accessory.context.deviceClassName

      let device = new deviceClass(accessory, data, config, log, homebridge, vivintApi)
      this.devices.push(device)
      this.devicesById[device.id] = device

      if (accessory.context.deviceClassName === "Panel") this.panel_DeviceId = device.id
    }

    handleSnapshot(deviceData, timestamp) {
      this.lastSnapshotTime = timestamp
      log.debug(`Handling incoming device snapshot for timestamp ${timestamp}`)

      //Move Security Status value to the Panel device
      let panelData = deviceData.Devices.find((dvc) => dvc.Id == this.panel_DeviceId)
      if (panelData) {
        panelData.Status = deviceData.Status
      }

      for (let _deviceId in this.devicesById) {
        let deviceId = parseInt(_deviceId)
        let data = deviceData.Devices.find((dvc) => dvc.Id == deviceId)

        if (data) this.devicesById[_deviceId].handleSnapshot(data)
      }
    }

    handleMessage(message) {
      if (message.Data) {

        //Messages from Nest and MyQ devices does not have PlatformContext info
        if (message.Data.PlatformContext && message.Data.PlatformContext.Timestamp < this.lastSnapshotTime) {
          log.warn("Ignoring stale update", message.Data.PlatformContext.Timestamp, "<", this.lastSnapshotTime)
          return;
        }

        //Panel
        if (message.Id === vivintApi.panelId && message.Data.Status != undefined) {
          //Move Security Status value to the Panel device
          message.Data.Devices = [{
            Id: this.panel_DeviceId,
            Status: message.Data.Status
          }]
        }
        //Jammed lock notification
        else if (message.Type === VivintDict.ObjectType.InboxMessage && typeof message.Data.Subject === 'string' && message.Data.Subject.indexOf('failed to lock') !== -1){
          const match = /^Alert:\s*(.+?) failed to lock/.exec(message.Data.Subject)
          const lockName = match && SanitizeName.sanitizeDeviceName(match[1], '')
          var lockDevice = lockName && this.devices.find(device => {
            return device.data.Type === VivintDict.PanelDeviceType.DoorLock && device.name === lockName
          })
          if (lockDevice) {
            message.Data.Devices = [{
              Id: lockDevice.data.Id,
              Status: Characteristic.LockCurrentState.JAMMED
            }]
          }
        }

        if (message.Data.Devices) {
          message.Data.Devices.forEach((patch) => {
            if (this.devicesById[patch.Id]) {
              this.devicesById[patch.Id].handlePatch(patch)
            }
          })
        }
      }
    }

    /** Stop timers and release resources held by devices (called on Homebridge shutdown). */
    destroy() {
      this.devices.forEach((device) => device.destroy())
    }

    static createDeviceAccessory(data) {
      let deviceClass = Devices.find((dc) => {
        return dc.appliesTo(data)
      })

      //These device types are not useable for HomeKit purposes
      const irrelevantDeviceTypes = ['sensor_group','network_hosts_service','panel_diagnostics_service','iot_service','scheduler_service','yofi_device','keyfob_device','control4_device','lgit_poe_wifi_bridge_device','mqtt_audio_sync_service','holiday_theme_service']
      if (irrelevantDeviceTypes.indexOf(data.Type) != -1) {
        log.debug(`Ignored unuseable device [Type]:${data.Type} [Data]:`, JSON.stringify(data, undefined, 4))
        return null
      }

      if (!deviceClass) {
        log.info(`Device not (yet) supported [ID]:${data.Id} [Type]:${data.Type} [EquipmentCode]:${data.EquipmentCode} [Name]:${data.Name}`)
        log.debug('Unsupported device found! [Data]:', JSON.stringify(data, undefined, 4))
        return null
      }

      if ((config_IgnoredDevices.indexOf(data.Type) != -1) ||
          (config_IgnoredDevices.indexOf(`${data.EquipmentCode}`) != -1) ||
          (config_IgnoredDevices.indexOf(`${data.Id}`) != -1)) {
        log.info(`Ignored device [ID]:${data.Id} [Type]:${data.Type} [EquipmentCode]:${data.EquipmentCode} [Name]:${data.Name}`)
        return null
      }

      let serial = (data.SerialNumber32Bit || 0).toString(16).padStart(8, '0') + ':' + (data.SerialNumber || 0).toString(16).padStart(8, '0') + ':' + data.Id

      let category = deviceClass.inferCategory && deviceClass.inferCategory(data, Categories) || Categories.OTHER

      var manufacturer = "Vivint"
      var model = data.EquipmentCode !== undefined ? vivintApi.getDictionaryKeyByValue(VivintDict.EquipmentCode, data.EquipmentCode) : deviceClass.name

      //For non-Vivint devices override values
      if (data.ActualType) {
        let splittedName = data.ActualType.split('_')
        if (splittedName.length > 0) {
          manufacturer = splittedName[0].toUpperCase()
        }
        if (splittedName.length > 1) {
          model = splittedName[1].toUpperCase()
        }
      }

      //Rename device if no name is received from Vivint
      let deviceName = data.Name;
      if (!deviceName || deviceName.length === 0) {
        deviceName = 'Unnamed device ID' + data.Id;
      }

      // Sanitize the device name of unsupported characters
      deviceName = SanitizeName.sanitizeDeviceName(deviceName, data.Id);

      let accessory = new PlatformAccessory(
        deviceName,
        uuid.generate("Vivint:" + data.Id + ":" + serial),
        category)

      accessory.context.name = deviceName
      accessory.context.id = data.Id
      accessory.context.deviceClassName = deviceClass.name

      let informationService = accessory.getService(Service.AccessoryInformation)
      informationService
        .setCharacteristic(Characteristic.Manufacturer, manufacturer)
        .setCharacteristic(Characteristic.Model, model)
        .setCharacteristic(Characteristic.SerialNumber, serial)

      if (data.CurrentSoftwareVersion || data.SoftwareVersion){
        informationService
          .setCharacteristic(Characteristic.FirmwareRevision, data.CurrentSoftwareVersion || data.SoftwareVersion)
      }

      deviceClass.addServices(accessory, Service, config)

      //Print device info to log for config purposes
      if (config_LogDeviceList === true) {
        log.info(`Managing device [ID]:${data.Id} [Type]:${data.Type} [EquipmentCode]:${data.EquipmentCode} [Name]:${data.Name}`)
      }

      return accessory
    }
  }

  let Devices = [ContactSensor, SmokeSensor, CarbonMonoxideSensor, MotionSensor, Lock, Thermostat, GarageDoor, Panel, Camera, LightSwitch, DimmerSwitch, LightGroup]
  return DeviceSet
}

module.exports = DeviceSetModule
