// Tiny HAP client for a Homebridge bridge running in insecure mode (-I).
const http = require('http')

// Short-form HAP type UUIDs
const T = {
  AccessoryInformation: '3E', Name: '23',
  ContactSensor: '80', ContactSensorState: '6A',
  MotionSensor: '85', MotionDetected: '22',
  OccupancySensor: '86', OccupancyDetected: '71',
  SmokeSensor: '87', SmokeDetected: '76',
  LockMechanism: '45', LockCurrentState: '1D', LockTargetState: '1E',
  SecuritySystem: '7E', SecuritySystemCurrentState: '66', SecuritySystemTargetState: '67',
  GarageDoorOpener: '41', CurrentDoorState: 'E', TargetDoorState: '32',
  Thermostat: '4A', TargetTemperature: '35', CurrentTemperature: '11', TargetHeatingCoolingState: '33',
  HeatingThresholdTemperature: '12', CoolingThresholdTemperature: '0D', TemperatureDisplayUnits: '36',
  Fan: '40', Lightbulb: '43', Switch: '49', On: '25', Brightness: '8',
  Battery: '96', BatteryLevel: '68', StatusLowBattery: '79',
  CameraRTPStreamManagement: '110',
}

const shortType = (type) => {
  const m = /^0*([0-9A-F]+)-0000-1000-8000-0026BB765291$/i.exec(type)
  return (m ? m[1] : type.replace(/^0+/, '')).toUpperCase()
}

class HapClient {
  constructor(port, pin) {
    this.port = port
    this.pin = pin
  }

  request(method, path, body) {
    return new Promise((resolve, reject) => {
      const data = body ? Buffer.from(JSON.stringify(body)) : undefined
      const req = http.request({
        host: '127.0.0.1', port: this.port, method, path,
        headers: {
          authorization: this.pin,
          ...(data ? { 'content-type': 'application/hap+json', 'content-length': data.length } : {}),
        },
      }, (res) => {
        const chunks = []
        res.on('data', (c) => chunks.push(c))
        res.on('end', () => {
          const text = Buffer.concat(chunks)
          let json
          try { json = text.length ? JSON.parse(text.toString()) : undefined } catch (_) { json = undefined }
          resolve({ status: res.statusCode, json, raw: text, headers: res.headers })
        })
      })
      req.setTimeout(30000, () => req.destroy(new Error(`HAP ${method} ${path} timed out`)))
      req.on('error', reject)
      if (data) req.write(data)
      req.end()
    })
  }

  async accessories() {
    const res = await this.request('GET', '/accessories')
    if (res.status !== 200) throw new Error(`GET /accessories -> ${res.status}`)
    return res.json.accessories.map((acc) => {
      const services = acc.services.map((s) => ({
        iid: s.iid,
        type: shortType(s.type),
        characteristics: s.characteristics.map((c) => ({ ...c, type: shortType(c.type) })),
      }))
      const info = services.find((s) => s.type === T.AccessoryInformation)
      const nameChar = info && info.characteristics.find((c) => c.type === T.Name)
      return { aid: acc.aid, name: nameChar && nameChar.value, services }
    })
  }

  /** Resolve {aid, iid} for a characteristic on the named accessory. */
  async find(accessoryName, serviceType, charType) {
    const accs = await this.accessories()
    const acc = accs.find((a) => a.name === accessoryName)
    if (!acc) throw new Error(`accessory "${accessoryName}" not found; have: ${accs.map((a) => a.name).join(', ')}`)
    const svc = acc.services.find((s) => s.type === serviceType)
    if (!svc) throw new Error(`service ${serviceType} not on "${accessoryName}"`)
    const ch = svc.characteristics.find((c) => c.type === charType)
    if (!ch) throw new Error(`characteristic ${charType} not on ${serviceType} of "${accessoryName}"`)
    return { aid: acc.aid, iid: ch.iid }
  }

  async get(ref) {
    const res = await this.request('GET', `/characteristics?id=${ref.aid}.${ref.iid}`)
    const c = res.json && res.json.characteristics && res.json.characteristics[0]
    return { httpStatus: res.status, value: c && c.value, status: c && c.status }
  }

  /** Returns { httpStatus, status } where status is the HAP status code (0 = success). */
  async set(ref, value) {
    const res = await this.request('PUT', '/characteristics', { characteristics: [{ aid: ref.aid, iid: ref.iid, value }] })
    if (res.status === 204) return { httpStatus: 204, status: 0 }
    const c = res.json && res.json.characteristics && res.json.characteristics[0]
    return { httpStatus: res.status, status: c ? c.status : undefined, body: res.json }
  }

  async snapshot(aid, width = 640, height = 360) {
    return this.request('POST', '/resource', { aid, 'resource-type': 'image', 'image-width': width, 'image-height': height })
  }
}

module.exports = { HapClient, T }
