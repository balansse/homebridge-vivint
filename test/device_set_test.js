const assert = require('assert')
const DeviceSetModule = require('../lib/device_set.js')
const VivintDict = require('../lib/vivint_dictionary.json')

// ---------------------------------------------------------------------------
// Minimal Homebridge / HAP mocks
// ---------------------------------------------------------------------------

class MockCharacteristic {
  constructor(type) {
    this.type = type
    this.value = undefined
    this.props = {}
    this.handlers = {}
  }
  on(event, fn) {
    this.handlers[event] = fn
    return this
  }
  setProps(props) {
    Object.assign(this.props, props)
    return this
  }
  // Invoke the registered legacy 'get' handler and resolve with its value
  triggerGet() {
    return new Promise((resolve, reject) => {
      this.handlers.get((err, value) => (err ? reject(err) : resolve(value)))
    })
  }
}

class MockService {
  constructor(displayName) {
    this.displayName = displayName
    this.characteristics = new Map()
  }
  getCharacteristic(type) {
    if (!this.characteristics.has(type)) this.characteristics.set(type, new MockCharacteristic(type))
    return this.characteristics.get(type)
  }
  setCharacteristic(type, value) {
    this.getCharacteristic(type).value = value
    return this
  }
  updateCharacteristic(type, value) {
    this.getCharacteristic(type).value = value
    return this
  }
  valueOf(type) {
    return this.getCharacteristic(type).value
  }
}

const Service = {}
for (const name of ['AccessoryInformation', 'Battery', 'ContactSensor', 'MotionSensor',
  'OccupancySensor', 'SmokeSensor', 'CarbonMonoxideSensor', 'LockMechanism', 'SecuritySystem']) {
  Service[name] = class extends MockService {}
  Object.defineProperty(Service[name], 'name', { value: name })
}

class MockPlatformAccessory {
  constructor(displayName, uuid, category) {
    this.displayName = displayName
    this.UUID = uuid
    this.category = category
    this.context = {}
    this.services = [new Service.AccessoryInformation(displayName)]
  }
  addService(service) {
    this.services.push(service)
    return service
  }
  getService(ServiceClass) {
    return this.services.find((s) => s instanceof ServiceClass)
  }
}

// Values mirror HAP-NodeJS constants
const Characteristic = {
  Manufacturer: { name: 'Manufacturer' },
  Model: { name: 'Model' },
  SerialNumber: { name: 'SerialNumber' },
  FirmwareRevision: { name: 'FirmwareRevision' },
  BatteryLevel: { name: 'BatteryLevel' },
  ChargingState: { name: 'ChargingState', NOT_CHARGING: 0, CHARGING: 1, NOT_CHARGEABLE: 2 },
  StatusLowBattery: { name: 'StatusLowBattery', BATTERY_LEVEL_NORMAL: 0, BATTERY_LEVEL_LOW: 1 },
  StatusTampered: { name: 'StatusTampered', NOT_TAMPERED: 0, TAMPERED: 1 },
  ContactSensorState: { name: 'ContactSensorState', CONTACT_DETECTED: 0, CONTACT_NOT_DETECTED: 1 },
  MotionDetected: { name: 'MotionDetected' },
  SmokeDetected: { name: 'SmokeDetected', SMOKE_NOT_DETECTED: 0, SMOKE_DETECTED: 1 },
  CarbonMonoxideDetected: { name: 'CarbonMonoxideDetected', CO_LEVELS_NORMAL: 0, CO_LEVELS_ABNORMAL: 1 },
  OccupancyDetected: { name: 'OccupancyDetected', OCCUPANCY_NOT_DETECTED: 0, OCCUPANCY_DETECTED: 1 },
  LockCurrentState: { name: 'LockCurrentState', UNSECURED: 0, SECURED: 1, JAMMED: 2, UNKNOWN: 3 },
  LockTargetState: { name: 'LockTargetState', UNSECURED: 0, SECURED: 1 },
  SecuritySystemCurrentState: { name: 'SecuritySystemCurrentState', STAY_ARM: 0, AWAY_ARM: 1, NIGHT_ARM: 2, DISARMED: 3, ALARM_TRIGGERED: 4 },
  SecuritySystemTargetState: { name: 'SecuritySystemTargetState', STAY_ARM: 0, AWAY_ARM: 1, NIGHT_ARM: 2, DISARM: 3 },
}

const Categories = { OTHER: 1, SECURITY_SYSTEM: 11, DOOR_LOCK: 6, DOOR: 12, WINDOW: 13, SENSOR: 10 }

const MockHomebridge = {
  platformAccessory: MockPlatformAccessory,
  hap: {
    uuid: { generate: (input) => `uuid:${input}` },
    Service,
    Characteristic,
    Categories,
    Accessory: { Categories },
  },
}

const silentLog = Object.assign(() => {}, { debug() {}, info() {}, warn() {}, error() {} })

const PANEL_ID = 1
const mockVivintApi = {
  panelId: 99,
  getDictionaryKeyByValue: (dict, value) => Object.keys(dict).find((k) => dict[k] === value),
}

// ---------------------------------------------------------------------------
// Fixtures (current Vivint API format, after parsePubNub/mapObject)
// ---------------------------------------------------------------------------

const panelData = () => ({ Id: PANEL_ID, Type: VivintDict.PanelDeviceType.Panel, Name: 'Panel' })

const windowSensorData = () => ({
  Id: 42,
  Type: VivintDict.PanelDeviceType.WirelessSensor,
  EquipmentCode: VivintDict.EquipmentCode.DW10_THIN_DOOR_WINDOW,
  Name: 'Basement Shop Window',
  SerialNumber: 192977,
  SerialNumber32Bit: 16970193,
  Status: false,
  LowBattery: false,
  Tamper: false,
})

const doorSensorData = () => ({
  Id: 28,
  Type: VivintDict.PanelDeviceType.WirelessSensor,
  EquipmentCode: VivintDict.EquipmentCode.DW10_THIN_DOOR_WINDOW,
  Name: 'Back Door',
  Status: false,
})

const motionSensorData = () => ({
  Id: 45,
  Type: VivintDict.PanelDeviceType.WirelessSensor,
  EquipmentCode: VivintDict.EquipmentCode.PIR1_MOTION,
  Name: 'Family Room Motion Sensor',
  Status: false,
})

const doorLockData = () => ({
  Id: 24,
  Type: VivintDict.PanelDeviceType.DoorLock,
  Name: 'Front Door',
  Status: true,
  BatteryLevel: 50,
})

const snapshotTs = '2018-06-16T06:59:00.000000'
const earlierTs = '2018-06-16T06:58:00.999999'
const laterTs = '2018-06-16T06:59:09.198000'

// ---------------------------------------------------------------------------

describe('DeviceSet', function () {
  let DeviceSet

  const build = (devices, { config = {}, securityStatus = VivintDict.SecurityState.DISARMED } = {}) => {
    DeviceSet = DeviceSetModule(config, silentLog, MockHomebridge, mockVivintApi)
    const deviceSet = new DeviceSet()
    devices.forEach((data) => {
      const accessory = DeviceSet.createDeviceAccessory(data)
      if (accessory) deviceSet.bindAccessory(accessory, data)
    })
    deviceSet.handleSnapshot({ Status: securityStatus, Devices: devices }, snapshotTs)
    return deviceSet
  }

  const contactState = (device) => device.service.valueOf(Characteristic.ContactSensorState)

  describe('.createDeviceAccessory', function () {
    beforeEach(() => {
      DeviceSet = DeviceSetModule({}, silentLog, MockHomebridge, mockVivintApi)
    })

    it('creates a contact sensor accessory with category inferred from its name', function () {
      const accessory = DeviceSet.createDeviceAccessory(windowSensorData())
      assert.strictEqual(accessory.context.deviceClassName, 'ContactSensor')
      assert.strictEqual(accessory.context.id, 42)
      assert.strictEqual(accessory.category, Categories.WINDOW)
      assert.ok(accessory.getService(Service.ContactSensor))
      assert.ok(accessory.getService(Service.Battery))

      const info = accessory.getService(Service.AccessoryInformation)
      assert.strictEqual(info.valueOf(Characteristic.Manufacturer), 'Vivint')
      assert.strictEqual(info.valueOf(Characteristic.Model), 'DW10_THIN_DOOR_WINDOW')
      assert.strictEqual(info.valueOf(Characteristic.SerialNumber), '0102f1d1:0002f1d1:42')
    })

    it('categorizes doors and locks', function () {
      assert.strictEqual(DeviceSet.createDeviceAccessory(doorSensorData()).category, Categories.DOOR)
      assert.strictEqual(DeviceSet.createDeviceAccessory(doorLockData()).category, Categories.DOOR_LOCK)
    })

    it('sanitizes device names and names unnamed devices', function () {
      const named = DeviceSet.createDeviceAccessory({ ...doorSensorData(), Name: ' Back Door! (Main) ' })
      assert.strictEqual(named.context.name, 'Back Door Main')

      const unnamed = DeviceSet.createDeviceAccessory({ ...doorSensorData(), Name: '' })
      assert.strictEqual(unnamed.context.name, 'Unnamed device ID28')
    })

    it('returns null for unsupported and irrelevant device types', function () {
      assert.strictEqual(DeviceSet.createDeviceAccessory({ Id: 7, Type: 'some_future_device', Name: 'X' }), null)
      assert.strictEqual(DeviceSet.createDeviceAccessory({ Id: 8, Type: 'keyfob_device', Name: 'Fob' }), null)
    })

    it('honours ignoreDeviceTypes by type, equipment code and id', function () {
      for (const ignored of [VivintDict.PanelDeviceType.WirelessSensor, `${VivintDict.EquipmentCode.DW10_THIN_DOOR_WINDOW}`, '42']) {
        DeviceSet = DeviceSetModule({ ignoreDeviceTypes: [ignored] }, silentLog, MockHomebridge, mockVivintApi)
        assert.strictEqual(DeviceSet.createDeviceAccessory(windowSensorData()), null, `ignore ${ignored}`)
      }
    })

    describe('wireless sensor classification by equipment code', function () {
      const sensor = (code, Id = 80) => ({
        Id, Type: VivintDict.PanelDeviceType.WirelessSensor, EquipmentCode: code, Name: `Sensor ${code}`, Status: false,
      })
      const EC = VivintDict.EquipmentCode

      // #144 / #172: these were claimed by ContactSensor, which is checked first
      for (const [code, className, ServiceClass] of [
        [EC.APOLLO_COMBO_SMOKE, 'SmokeSensor', 'SmokeSensor'],
        [EC.APOLLO_COMBO_CO, 'CarbonMonoxideSensor', 'CarbonMonoxideSensor'],
        [EC.PIR3_MOTION, 'MotionSensor', 'MotionSensor'],
      ]) {
        it(`maps equipment code ${code} to ${className}`, function () {
          const accessory = DeviceSet.createDeviceAccessory(sensor(code))
          assert.strictEqual(accessory.context.deviceClassName, className)
          assert.ok(accessory.getService(Service[ServiceClass]), `has ${ServiceClass} service`)
          assert.ok(!accessory.getService(Service.ContactSensor), 'no ContactSensor service')
        })
      }

      for (const code of [EC.EXISTING_HEAT, EC.EXISTING_FLOOD_TEMP, EC.GB3_GLASS_BREAK, EC.DW10_THIN_DOOR_WINDOW]) {
        it(`keeps equipment code ${code} as a contact sensor`, function () {
          assert.strictEqual(DeviceSet.createDeviceAccessory(sensor(code)).context.deviceClassName, 'ContactSensor')
        })
      }

      it('reports combo smoke/CO and PIR3 motion state from snapshots and patches', function () {
        const deviceSet = build([panelData(), sensor(EC.APOLLO_COMBO_SMOKE, 81), sensor(EC.APOLLO_COMBO_CO, 82), sensor(EC.PIR3_MOTION, 83)])
        const smoke = deviceSet.devicesById[81].service
        const co = deviceSet.devicesById[82].service
        const motion = deviceSet.devicesById[83].service
        assert.strictEqual(smoke.valueOf(Characteristic.SmokeDetected), Characteristic.SmokeDetected.SMOKE_NOT_DETECTED)
        assert.strictEqual(co.valueOf(Characteristic.CarbonMonoxideDetected), Characteristic.CarbonMonoxideDetected.CO_LEVELS_NORMAL)
        assert.strictEqual(motion.valueOf(Characteristic.MotionDetected), false)

        deviceSet.handleMessage({ Id: 13, Data: { PlatformContext: { Timestamp: laterTs },
          Devices: [{ Id: 81, Status: true }, { Id: 82, Status: true }, { Id: 83, Status: true }] } })
        assert.strictEqual(smoke.valueOf(Characteristic.SmokeDetected), Characteristic.SmokeDetected.SMOKE_DETECTED)
        assert.strictEqual(co.valueOf(Characteristic.CarbonMonoxideDetected), Characteristic.CarbonMonoxideDetected.CO_LEVELS_ABNORMAL)
        assert.strictEqual(motion.valueOf(Characteristic.MotionDetected), true)
      })
    })

    it('only adds an occupancy service when motionDetectedOccupancySensorMins is set', function () {
      assert.ok(!DeviceSet.createDeviceAccessory(motionSensorData()).getService(Service.OccupancySensor))

      DeviceSet = DeviceSetModule({ motionDetectedOccupancySensorMins: 5 }, silentLog, MockHomebridge, mockVivintApi)
      assert.ok(DeviceSet.createDeviceAccessory(motionSensorData()).getService(Service.OccupancySensor))
    })
  })

  describe('#bindAccessory', function () {
    it('binds devices by id using the matching accessory class', function () {
      const deviceSet = build([panelData(), windowSensorData(), doorSensorData(), doorLockData()])
      assert.strictEqual(deviceSet.devices.length, 4)
      assert.strictEqual(deviceSet.devicesById[1].constructor.name, 'Panel')
      assert.strictEqual(deviceSet.devicesById[42].constructor.name, 'ContactSensor')
      assert.strictEqual(deviceSet.devicesById[28].constructor.name, 'ContactSensor')
      assert.strictEqual(deviceSet.devicesById[24].constructor.name, 'Lock')
      assert.strictEqual(deviceSet.panel_DeviceId, PANEL_ID)
    })

    it('throws for an unknown cached device class', function () {
      DeviceSet = DeviceSetModule({}, silentLog, MockHomebridge, mockVivintApi)
      const accessory = new MockPlatformAccessory('Old', 'uuid', Categories.OTHER)
      accessory.context = { id: 5, name: 'Old', deviceClassName: 'NoSuchDevice' }
      assert.throws(() => new DeviceSet().bindAccessory(accessory, {}), /Unknown device class name/)
    })
  })

  describe('#handleSnapshot', function () {
    it('publishes sensor state from the snapshot', async function () {
      const deviceSet = build([panelData(), windowSensorData()])
      const window = deviceSet.devicesById[42]
      assert.strictEqual(contactState(window), Characteristic.ContactSensorState.CONTACT_DETECTED)
      assert.strictEqual(
        await window.service.getCharacteristic(Characteristic.ContactSensorState).triggerGet(),
        Characteristic.ContactSensorState.CONTACT_DETECTED)

      deviceSet.handleSnapshot({
        Status: VivintDict.SecurityState.DISARMED,
        Devices: [panelData(), { ...windowSensorData(), Status: true }],
      }, laterTs)

      assert.strictEqual(contactState(window), Characteristic.ContactSensorState.CONTACT_NOT_DETECTED)
      assert.strictEqual(deviceSet.lastSnapshotTime, laterTs)
    })

    it('moves the partition security status onto the panel device', function () {
      const deviceSet = build([panelData()], { securityStatus: VivintDict.SecurityState.ARMED_AWAY })
      const panel = deviceSet.devicesById[PANEL_ID]
      assert.strictEqual(panel.service.valueOf(Characteristic.SecuritySystemCurrentState),
        Characteristic.SecuritySystemCurrentState.AWAY_ARM)
    })

    it('handles a snapshot when the panel is not managed (e.g. ignored)', function () {
      const deviceSet = build([windowSensorData()])
      assert.strictEqual(contactState(deviceSet.devicesById[42]), Characteristic.ContactSensorState.CONTACT_DETECTED)
    })

    it('reports lock and battery state', function () {
      const deviceSet = build([panelData(), doorLockData()], { config: { lowBatteryLevel: 50 } })
      const lock = deviceSet.devicesById[24]
      assert.strictEqual(lock.service.valueOf(Characteristic.LockCurrentState), Characteristic.LockCurrentState.SECURED)
      assert.strictEqual(lock.batteryService.valueOf(Characteristic.BatteryLevel), 50)
      assert.strictEqual(lock.batteryService.valueOf(Characteristic.StatusLowBattery),
        Characteristic.StatusLowBattery.BATTERY_LEVEL_LOW)
    })
  })

  describe('#handleMessage', function () {
    const deviceUpdate = (devices, ts) => ({
      Id: 13,
      Type: 'account_partition',
      Data: { PlatformContext: { Timestamp: ts }, Devices: devices },
    })

    it('applies device patches', function () {
      const deviceSet = build([panelData(), windowSensorData(), doorSensorData()])
      deviceSet.handleMessage(deviceUpdate([{ Id: 42, Status: true }], laterTs))
      assert.strictEqual(contactState(deviceSet.devicesById[42]), Characteristic.ContactSensorState.CONTACT_NOT_DETECTED)
      assert.strictEqual(contactState(deviceSet.devicesById[28]), Characteristic.ContactSensorState.CONTACT_DETECTED)
    })

    it('ignores messages originating before the current snapshot', function () {
      const deviceSet = build([panelData(), windowSensorData()])
      deviceSet.handleMessage(deviceUpdate([{ Id: 42, Status: true }], earlierTs))
      assert.strictEqual(contactState(deviceSet.devicesById[42]), Characteristic.ContactSensorState.CONTACT_DETECTED)
    })

    it('applies messages without a platform context (Nest/MyQ)', function () {
      const deviceSet = build([panelData(), windowSensorData()])
      deviceSet.handleMessage({ Id: 13, Data: { Devices: [{ Id: 42, Status: true }] } })
      assert.strictEqual(contactState(deviceSet.devicesById[42]), Characteristic.ContactSensorState.CONTACT_NOT_DETECTED)
    })

    it('ignores patches for unknown devices', function () {
      const deviceSet = build([panelData(), windowSensorData()])
      assert.doesNotThrow(() => deviceSet.handleMessage(deviceUpdate([{ Id: 12345, Status: true }], laterTs)))
    })

    it('routes panel security status updates to the panel device', function () {
      const deviceSet = build([panelData()])
      deviceSet.handleMessage({
        Id: mockVivintApi.panelId,
        Data: { PlatformContext: { Timestamp: laterTs }, Status: VivintDict.SecurityState.ARMED_STAY },
      })
      assert.strictEqual(deviceSet.devicesById[PANEL_ID].service.valueOf(Characteristic.SecuritySystemCurrentState),
        Characteristic.SecuritySystemCurrentState.STAY_ARM)
    })

    it('marks a lock as jammed from a "failed to lock" inbox message', function () {
      const deviceSet = build([panelData(), doorLockData()])
      deviceSet.handleMessage({
        Id: 13,
        Type: VivintDict.ObjectType.InboxMessage,
        Data: { Subject: 'Alert: Front Door failed to lock' },
      })
      assert.strictEqual(deviceSet.devicesById[24].service.valueOf(Characteristic.LockCurrentState),
        Characteristic.LockCurrentState.JAMMED)
    })
  })
})
