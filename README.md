<SPAN ALIGN="CENTER">

[![homebridge-vivint: Native HomeKit support for Vivint](https://raw.githubusercontent.com/balansse/homebridge-vivint/master/homebridge-vivint.svg)](https://github.com/balansse/homebridge-vivint)

# Homebridge Vivint

[![verified-by-homebridge](https://badgen.net/badge/homebridge/verified/purple)](https://github.com/homebridge/homebridge/wiki/Verified-Plugins) [![npm](https://badgen.net/npm/v/@balansse/homebridge-vivint) ![npm](https://badgen.net/npm/dt/@balansse/homebridge-vivint)](https://www.npmjs.com/package/@balansse/homebridge-vivint) [![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=6NDY338ETGK4Q&currency_code=USD&source=url)

## HomeKit support for Vivint system using [Homebridge](https://homebridge.io).
</SPAN>

## Overview

This is a fork of [homebridge-vivint](https://github.com/timcharper/homebridge-vivint) plugin for [homebridge](https://github.com/nfarina/homebridge).
It allows to use your Vivint SmartHome products in Apple Homekit. The main changes in this fork include:
  * Support to Multi Factor Authentication
  * More devices are supported
  * Increased stability of notifications
  * Support for camera streaming
  * Ignore list for specific device types (useful in case of external integrations like Nest or MyQ that may be managed directly by another plugin) 
  * Dynamic accessory cache management - any accessories that are no longer managed by the plugin or are disconnected from Vivint system would be removed from the cache automatically
  * Homebridge Config UI X Web UI settings support

Homebridge-Vivint was initially written by a former Vivint employee, Tim Harper. This project is not officially endorsed, sponsored, or affiliated with Vivint SmartHome in any way.

## Usage

This plugin supports installation and changing settings (for `config.js`) via the popular [Config UI X plugin](https://github.com/oznu/homebridge-config-ui-x) (recommended for easiest usage).

After entering your name and password (and possibly a MFA code) in the Plugin Settings a Vivint Refresh Token will be automatically poplulated.  Depending on your Vivint user settings, your MFA code may come from your authenticator app or it will be sent to you via SMS or email.  When done, click Save then Restart Homebridge to connect.

Ensure you are running Node v10.17.0 or higher (this version is required by Homebridge v1.0.0). You can check by using `node -v`.

Either install and configure using Config UI X or you can manually install the plugin by running:

```
npm install -g @balansse/homebridge-vivint
```

Then, add the following configuration to the `platforms` array in your Homebridge `config.json`.

If needed, you can manually generate a refresh token by running `npm run mfa` in the command line.

```
{
    {
      "platform": "Vivint",
      "refreshToken": "your-vivint-refresh-token"
    }
}
```

That's it! The plugin will automatically load all supported Vivint devices into Homebridge.

### HOOBS Users:

Unfortunately HOOBS doesn't support the Custom UI components created for Homebridge.

As a workaround, you can open a terminal in HOOBS and run the following commands, where "vivintbridge" is the name of the bridge but all lowercase and with no spaces:

```
cd /var/lib/hoobs/vivintbridge/node_modules/@balansse/homebridge-vivint
npm run mfa
```

## Supported Items

Currently, the following items are supported:

* Locks
* Contact sensors
* Thermostat
* Motion sensors
* Garage Door Opener
* Alarm Panel (arm home/away, disarm)
* Cameras & Doorbells
* Tilt sensors
* Fire alert sensors
* Glass break sensors
* Smoke detectors
* Carbon monoxide sensors
* Heat / Freeze sensors
* Z-Wave switches (binary and dimmer) that are paired with the Vivint panel. Be sure they are labeled "light" or "fan" if they control those respective devices.

As I do not have access to all varieties of hardware that is supported by Vivint, some incompatibilities might happen. If you notice any weird behavior or your Vivint device is not supported, please submit an issue with your homebridge.log file attached.

## Configuration

Configuration of the plugin is simple. The Vivint plugin is a dynamic platform which caches the accessories registered.

Configuration sample:

    {
      "platform": "Vivint",
      "refreshToken": "your-vivint-refresh-token",
      "ignoreDeviceTypes": ["thermostat_device", "garage_door_device"]
    }

A general recommendation: consider creating and using a new Vivint account named "Apple Home". This way, your Vivint logs will show "the front door was unlocked by Apple Home", etc.

Configuration options overview:

* **refreshToken** - Your Vivint refresh token.  This will be generated after entering your Vivint user name and password in the Config UI X plugin.
* **apiLoginRefreshSecs** - How often should Vivint Homebridge renew the session token? The token that Vivint provides when authenticating will expire. Also, when this renewal occurs, the plugin requests another snapshot. The event stream can sometimes fail to report device state appropriately and events can come out of order with the snapshot, or updates can be missed entirely. The occasional snapshot retrieval will auto-correct any such errors. Avoid setting this any more frequent that 10 minutes.
* **motionDetectedOccupancySensorMins** - Homebridge-Vivint will create occupancy sensors for motion sensors that will stay active for X minutes after a motion event is detected. This value configures for how long that occupancy sensor will stay active if no further motion events are detected. Note: Vivint's reporting of motion events over the event stream can be a little inconsistent, at times. As a recommendation, don't plan on creating Homekit automations that respond to Vivint motion events.
* **ignoreDeviceTypes** - The array containing the device types that should be ignored. Allowed types: "thermostat_device", "door_lock_device", "garage_door_device", "camera_device", "wireless_sensor". "phillips_hue_bridge_device", "multilevel_switch_device". Could also be used to ignore individual devices by ID or Equipment Code.
* **logDeviceList** - If checked, shows data for all configured Vivint devices in the log.
* **disableCameras** - If checked, camera video feeds would not appear in Homebridge.
* **useExternalVideoStreams** - Stream camera feeds from Vivint servers instead of streaming directly from the Panel.
* **showCameraConfig** - Log [homebridge-camera-ffmpeg](https://github.com/Sunoo/homebridge-camera-ffmpeg) configuration for all detected cameras.

## Credits

 * @timcharper - https://github.com/timcharper/homebridge-vivint - The original creator of the homebridge-vivint plugin
 * @dgreif - https://github.com/dgreif/ring - The base for vivint-homebridge custom UI for entering login and MFA codes.
