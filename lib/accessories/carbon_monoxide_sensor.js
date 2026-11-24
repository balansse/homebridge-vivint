const Device = require('../device.js')
const VivintDict = require("../vivint_dictionary.json")
const SanitizeName = require('../sanitize_name.js')

class CarbonMonoxideSensor extends Device {
    constructor(accessory, data, config, log, homebridge, vivintApi) {
        super(accessory, data, config, log, homebridge, vivintApi)
      this.service = accessory.getService(this.Service.CarbonMonoxideSensor)

      this.updateBatteryCharacteristic(this.Characteristic.ChargingState, this.Characteristic.ChargingState.NOT_CHARGEABLE)
      
      this.service
        .getCharacteristic(this.Characteristic.CarbonMonoxideDetected)
        .on('get', callback => callback(null, this.getSensorState()))
      
      this.service
        .getCharacteristic(this.Characteristic.StatusTampered)
        .on('get', callback => callback(null, this.getTamperedState()))

      this.notify()
    }

    getSensorState() {
      if (this.data.Status)
        return this.Characteristic.CarbonMonoxideDetected.CO_LEVELS_ABNORMAL
      else
        return this.Characteristic.CarbonMonoxideDetected.CO_LEVELS_NORMAL
    }

    notify() {
      super.notify()
      if (this.service) {
        this.service.updateCharacteristic(this.Characteristic.CarbonMonoxideDetected, this.getSensorState())
        this.service.updateCharacteristic(this.Characteristic.StatusTampered, this.getTamperedState())
      }
    }

    static appliesTo(data) {
      return (
        (data.Type == VivintDict.PanelDeviceType.WirelessSensor) && 
        (
          (data.EquipmentCode == VivintDict.EquipmentCode.VS_CO3_DETECTOR) || 
          (data.EquipmentCode == VivintDict.EquipmentCode.EXISTING_CO) || 
          (data.EquipmentCode == VivintDict.EquipmentCode.CO1_CO_CANADA) || 
          (data.EquipmentCode == VivintDict.EquipmentCode.CO1_CO) || 
          (data.EquipmentCode == VivintDict.EquipmentCode.CO3_2GIG_CO) || 
          (data.EquipmentCode == VivintDict.EquipmentCode.CARBON_MONOXIDE_DETECTOR_345_MHZ) || 
          (data.EquipmentCode == VivintDict.EquipmentCode.VS_CO3_DETECTOR)
        ) 
      )
    }

    static inferCategory(data, Categories) {
        return Categories.SENSOR
    }
    
    static addServices(accessory, Service) {
        super.addServices(accessory, Service)
        
        // Sanitize the name before creating the service
        const sanitizedName = SanitizeName.sanitizeDeviceName(accessory.context.name, accessory.context.id)
            accessory.addService(new Service.CarbonMonoxideSensor(sanitizedName))
    }
}

  module.exports = CarbonMonoxideSensor
