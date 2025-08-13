const request = require("request-promise-native")
const isObject = require("isobject")
const PubNub = require('pubnub')
const jpegExtract = require('jpeg-extract')

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

    renew() {
      let self = this
      return VivintApi.doAuth(this.creds)
      .then((result) => {
          log.debug("Renewed Vivint API session. ", self.refreshToken, result.refreshToken)

          self.refreshToken = result.refreshToken
          self.sessionInfo = result.sessionInfo
          return this
        },
        (error) => {
          log.error("Error renewing login", error)
          setTimeout(() => { this.renew() }, 30000)//changed from 5 seconds to 30 seconds
        }
      )
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

    async connectPubNub() {
      let channel = "PlatformChannel#" + this.sessionInfo.Users.MessageBroadcastChannel
      let pubnub = new PubNub({
        subscribeKey : PUBNUB_KEY,
        uuid: this.sessionInfo.Users.MessageBroadcastChannel
      })

      pubnub.subscribe({
        channels: [channel]
      })

      log.debug(pubnub)

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

      // data.systemId = this.panelId
      // data.partitionId = this.parId
      
      return request({
        method: "PUT",
        url: `${VIVINT_URL}/${this.panelId}/${this.parId}/${uriString}`,
        body: JSON.stringify(data),
        headers: { Cookie: this.refreshToken }
      })
    }

    async refreshCameraThumbnail(id) {
      
      return request({
        method: "GET",
        url: `${VIVINT_URL}/${this.panelId}/${this.parId}/${id}/request-camera-thumbnail`,
        headers: { Cookie: this.refreshToken }
      })
      
    }

    async getCameraThumbnail(id) {

      const url = {
          url: `${VIVINT_URL}/${this.panelId}/${this.parId}/${id}/camera-thumbnail`,
          headers: { Cookie: this.refreshToken }
      };

      return jpegExtract(url)
    }

    getDictionaryKeyByValue(dictionary, value) {
      return getKeyByValueDeep(dictionary, value)
    }
  }

  VivintApi.doAuth = async (creds) => {
    try {
      let requestResult = await request({
        url: `${VIVINT_URL}/authuser`,  //changed to authuser for MFA
        "headers": {
        "Cookie": creds.refreshToken
      },
        resolveWithFullResponse: true
      })

      let sessionInfo = mapObject(JSON.parse(requestResult.body), VivintDict)
      // Safely handle absence of set-cookie header
      const setCookies = requestResult.headers["set-cookie"]
      let refreshToken
      if (Array.isArray(setCookies)) {
        refreshToken = setCookies.find(cookie => cookie.startsWith("s="))
      }
      if (refreshToken) {
        //log.info("doAuth old refreshToken = " + creds.refreshToken)
        //log.info("doAuth new refreshToken = " + refreshToken)
        creds.refreshToken = refreshToken.split(";")[0]; //added to update creds.refreshToken if vivint sends a new one
      }
      return {sessionInfo: sessionInfo, refreshToken: creds.refreshToken} // 10/20/2023 changed to return creds.refreshToken instead of refreshToken
    }
    catch (err) {
      log.error('Error occurred during login, retrying in 60 seconds...', err)
      await new Promise(r => setTimeout(r, 60*1000));  //added sleep timer to prevent being blocked for 24hrs by Cloudflare
      return VivintApi.doAuth(creds)
    }
  }
  

  VivintApi.getSystemInfo = async (refreshToken, panelId) => {
    let sysInfo = await request({
      "url": `${VIVINT_URL}/systems/${panelId}`,
      "headers": {
        "Cookie": refreshToken,
        "Cache-Control": "no-store"
      }
    })

    return mapObject(JSON.parse(sysInfo), VivintDict) 
  }

  VivintApi.getPanelLogin = async (refreshToken, panelId) => {
    let panelLogin = await request({
      "url": `${VIVINT_URL}/panel-login/${panelId}`,
      "headers": {
        "Cookie": refreshToken,
        "Cache-Control": "no-store"
      }
    })

    return mapObject(JSON.parse(panelLogin), VivintDict) 
  }

  VivintApi.login = async (creds, persistent = 0) => {
    let authResult = await VivintApi.doAuth(creds, persistent)

    let sessionInfo = authResult.sessionInfo
    let refreshToken = authResult.refreshToken
    let panelId = sessionInfo.Users.System[0].PanelId

    const [sysInfo, panelLogin] = await Promise.all([VivintApi.getSystemInfo(refreshToken, panelId), VivintApi.getPanelLogin(refreshToken, panelId)])

    return new VivintApi(creds, panelId, refreshToken, sessionInfo, sysInfo, panelLogin)
  }

  function getKeyByValueDeep(object, value){
    var key = Object.keys(object).find(key => object[key] === value)
  
    if (key === undefined){
      for (const property in object) {
        if (object.hasOwnProperty(property) && isObject(object[property])) {
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
        if (object.hasOwnProperty(property)) {
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

module.exports = VivintApiModule
