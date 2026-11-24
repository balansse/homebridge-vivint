const isObject = require("isobject")
const PubNub = require('pubnub')
const { httpRequest, sessionCookie, describeError, VivintApiError } = require('./http.js')

const VivintDict = require("./vivint_dictionary.json")

const PUBNUB_KEY = 'sub-c-6fb03d68-6a78-11e2-ae8f-12313f022c90'
const VIVINT_URL = 'https://www.vivintsky.com/api'

function VivintApiModule(config, log) { 
  class VivintApi {
    constructor(creds, panelId, refreshToken, sessionInfo, systemInfo, panelLogin) {
      this.creds = creds
      this.panelId = panelId
      this.parId = systemInfo.System.Partitions[0].PartitionId
      this.refreshToken = refreshToken
      this.sessionInfo = sessionInfo
      this.systemInfo = systemInfo
      this.panelLogin = panelLogin
    }

    deviceSnapshot() {
      return this.systemInfo.System.Partitions[0]
    }

    deviceSnapshotTs() {
      return this.systemInfo.System.PanelContext.Timestamp
    }

    /**
     * Re-authenticates with the current refresh token. Concurrent callers share a single
     * in-flight attempt so periodic timers can never stack up parallel login loops.
     */
    renew() {
      if (!this._renewing) {
        this._renewing = VivintApi.doAuth(this.creds, { retry: false })
          .then((result) => {
            this.refreshToken = result.refreshToken
            this.sessionInfo = result.sessionInfo
            log.debug("Renewed Vivint API session")
            return this
          })
          .finally(() => { this._renewing = null })
      }
      return this._renewing
    }

    async renewSystemInfo() {
      let sysInfo = await VivintApi.getSystemInfo(this.refreshToken, this.panelId)
      this.systemInfo = sysInfo
      return this
    }

    async renewPanelLogin() {
      let panelLogin = await VivintApi.getPanelLogin(this.refreshToken, this.panelId)
      this.panelLogin = panelLogin
      return this
    }

    pubNubChannel() {
      return "PlatformChannel#" + this.sessionInfo.Users.MessageBroadcastChannel
    }

    async connectPubNub() {
      let channel = this.pubNubChannel()
      let pubnub = new PubNub({
        subscribeKey : PUBNUB_KEY,
        userId: this.sessionInfo.Users.MessageBroadcastChannel
      })

      pubnub.subscribe({
        channels: [channel]
      })

      return pubnub
    }

    parsePubNub(message) {
      return mapObject(message, VivintDict)
    }

    async setGarageDoorState(garageDoorId, newState) {
      return await this.putDevice('door', garageDoorId, { [VivintDict.Fields.Id]: garageDoorId, [VivintDict.Fields.Status]: newState } )
    }

    async setLockState(lockId, newState) {
      return await this.putDevice('locks', lockId, { [VivintDict.Fields.Id]: lockId, [VivintDict.Fields.Status]: newState } )
    }

    async setPanelState(newState) {
      return await this.putDevice('armedstates', null, { armState: newState, forceArm: false } )
    }

    async setThermostatFanState(thermostatId, newState) {
      return await this.putDevice('thermostats', thermostatId, { [VivintDict.Fields.FanMode]: newState } )
    }

    async setThermostatState(thermostatId, newState) {
      return await this.putDevice('thermostats', thermostatId, { [VivintDict.Fields.OperatingMode]: newState } )
    }

    async setThermostatHeatSetPoint(thermostatId, newTemperature) {
      return await this.putDevice('thermostats', thermostatId, { [VivintDict.Fields.HeatSetPoint]: newTemperature } )
    }

    async setThermostatCoolSetPoint(thermostatId, newTemperature) {
      return await this.putDevice('thermostats', thermostatId, { [VivintDict.Fields.CoolSetPoint]: newTemperature } )
    }

    async setSensorBypass(id, bypassState) {
      return await this.putDevice('sensors', id, { [VivintDict.Fields.Bypassed]: bypassState } )
    }

    async putDevice(category, id, data) {
      //In case of Alarm panel there is no id because it is treated on the Panel level
      let uriString = id != null ?
        `${category}/${id}` :
        category

      // Sent as a raw string without Content-Type, exactly like the previous request-based client
      await httpRequest({
        method: "PUT",
        url: `${VIVINT_URL}/${this.panelId}/${this.parId}/${uriString}`,
        body: JSON.stringify(data),
        headers: { Cookie: this.refreshToken },
        // Below HAP's 9s write timeout so failures reach HomeKit as errors, not "No Response"
        timeoutMs: 7000
      })
    }

    getDictionaryKeyByValue(dictionary, value) {
      return getKeyByValueDeep(dictionary, value)
    }
  }

  // Delay between login attempts while Vivint is unreachable. Kept long on purpose:
  // hammering the endpoint gets the account blocked by Cloudflare for 24h.
  VivintApi.retryDelayMs = 60 * 1000

  /**
   * Authenticates with the refresh token (session cookie).
   * - 401: the token is invalid/expired -> throws VivintAuthError (retrying cannot help).
   * - Other failures (network, 5xx, Cloudflare 403/429): retried every `retryDelayMs`
   *   when `retry` is true, otherwise rethrown.
   */
  VivintApi.doAuth = async (creds, { retry = true } = {}) => {
    for (;;) {
      try {
        let response = await httpRequest({
          url: `${VIVINT_URL}/authuser`,  //changed to authuser for MFA
          headers: { "Cookie": creds.refreshToken }
        })

        let sessionInfo = mapObject(response.json(), VivintDict)
        let refreshToken = sessionCookie(response)
        if (refreshToken) {
          creds.refreshToken = refreshToken //update creds.refreshToken if vivint sends a new one
        }
        return {sessionInfo: sessionInfo, refreshToken: creds.refreshToken}
      }
      catch (err) {
        if (err instanceof VivintApiError && err.status === 401) {
          throw new VivintAuthError('Vivint rejected the refresh token (HTTP 401). It has expired or was revoked - ' +
            'generate a new one in the plugin settings (or with `npm run mfa`) and restart Homebridge.')
        }
        if (!retry) throw err
        log.error(`Error occurred during login (${describeError(err)}), retrying in ${Math.round(VivintApi.retryDelayMs / 1000)} seconds...`)
        await new Promise(r => setTimeout(r, VivintApi.retryDelayMs))
      }
    }
  }

  VivintApi.getSystemInfo = async (refreshToken, panelId) => {
    let response = await httpRequest({
      "url": `${VIVINT_URL}/systems/${panelId}`,
      "headers": {
        "Cookie": refreshToken,
        "Cache-Control": "no-store"
      }
    })

    return mapObject(response.json(), VivintDict)
  }

  VivintApi.getPanelLogin = async (refreshToken, panelId) => {
    let response = await httpRequest({
      "url": `${VIVINT_URL}/panel-login/${panelId}`,
      "headers": {
        "Cookie": refreshToken,
        "Cache-Control": "no-store"
      }
    })

    return mapObject(response.json(), VivintDict)
  }

  VivintApi.login = async (creds) => {
    let authResult = await VivintApi.doAuth(creds)

    let sessionInfo = authResult.sessionInfo
    let refreshToken = authResult.refreshToken
    // System may appear under System (primary/active accounts) or RestrictedSystem (lapsed/secondary accounts)
    let systemList = (sessionInfo.Users.System && sessionInfo.Users.System.length > 0)
      ? sessionInfo.Users.System
      : sessionInfo.Users.RestrictedSystem
    if (!systemList || systemList.length === 0) {
      throw new Error('No Vivint system found for this account')
    }
    let panelId = systemList[0].PanelId

    const [sysInfo, panelLogin] = await Promise.all([VivintApi.getSystemInfo(refreshToken, panelId), VivintApi.getPanelLogin(refreshToken, panelId)])

    return new VivintApi(creds, panelId, refreshToken, sessionInfo, sysInfo, panelLogin)
  }

  function getKeyByValueDeep(object, value){
    var key = Object.keys(object).find(key => object[key] === value)
  
    if (key === undefined){
      for (const property in object) {
        if (Object.prototype.hasOwnProperty.call(object, property) && isObject(object[property])) {
            const propertyValue = object[property]
            var result = getKeyByValueDeep(propertyValue, value)
            if (result !== undefined) return (property !== "Fields" ? property + "_" : "" ) + result
        }
      }
    }
    else return key;
  }
  
  function mapObject(object, dict){
    var mappedObject = {}
    for (const property in object) {
        if (Object.prototype.hasOwnProperty.call(object, property)) {
            const value = object[property]
            var mappedProperty = getKeyByValueDeep(dict.Fields, property) || getKeyByValueDeep(dict, property) || property
  
            if (!isObject(value) && !Array.isArray(value)){
              mappedObject[mappedProperty] = value
            }
            else if (Array.isArray(value)){
              mappedObject[mappedProperty] = value.map((item) => { return isObject(item) || Array.isArray(item) ? mapObject(item, dict) : item })
            }
            else {
              mappedObject[mappedProperty] = mapObject(value, dict)
            }
        }
    }
  
    return mappedObject;
  }

  return VivintApi;
}

class VivintAuthError extends Error {
  constructor(message) {
    super(message)
    this.name = 'VivintAuthError'
  }
}

VivintApiModule.VivintAuthError = VivintAuthError

module.exports = VivintApiModule
