## 1.10.1 (2025-03-03)
### Changes
- Add additional types to irrelevantDeviceTypes. by @meek2100 in #167
- Sanative Device Names to prevent incompatibility or HomeKit errors. by @meek2100 in #169

## 1.10.0 (2025-02-28)
### Changes
- Added garage tilt sensor; fixes #125 by @mbentley in #165
- Homebridge 2.0 support by @jgrimard in #164

## 1.9.0 (2024-06-27)
### Changes
- Add Lighting Groups to Accessories by @erceth in #146

## 1.8.1 (2023-05-18)
### Changes
- Add hue bridge & multi level switch devices to the ignore device type list (@LuisRodriguezLD)
- Add capability to manually enter device type / equipment code / ID to the ignore list using Settings UI.

## 1.8.0 (2023-05-17)
### Changes
- Added support for new wireless sensor devices (#83) (#96).
- Doorbells now create a linked "contact sensor" accessory to indicate the doorbell button press (#78).
    - The contact sensor briefly becomes "open" on the button press event.
- Added the ability to ignore individual devices based on their ID or equipment code (#110).
    - To use this feature, add the [] key to the config to show all configured Vivint device data in the log. Then, add the IDs or Equipment Codes of devices to hide to the ignore list.
- Added back the ability to generate ffmpeg configs for all cameras in the log using the showCameraConfig flag (#77)
### Bug fixes
- Fixed double notification from doorbell button press

## 1.7.0 (2022-06-29)
### Changes
- Add support for fan rotation speed (thanks to @mikedecaro)
- Add support for water sensor (#67)
- Add lowBatteryLevel override to config (#52)
    - Use lowBatteryLevel key in config to configure, if not defined plugin will use default Vivint flag
    
### Bug fixes
- Fixed empty name preventing devices from being added (#41) (#65)
- Fixed Garage Door handling (#35) (#30)
- Fixed for handling missing device info (#25) (#56) (#62)

## 1.6.1 (2022-05-03)
### Bug fixes
- Fixed handling Dimmer switches (thanks to @mikedecaro)
- Fixed event subscription

## 1.6.0 (2021-09-19)
### Changes
- Added support for Multi Factor Authentication (thanks to @jgrimard and @arjunmehta)
    - If upgrading from previous versions, please go to the settings page of the plugin to reconfigure the authentication.

## 1.5.4 (2021-03-21)
### Bug Fixes
- Fix for the camera snapshot / streaming issue

## 1.5.3 (2021-03-11)
### Changes
- Added the option to switch video feeds to stream from Vivint servers

## 1.5.1 (2021-03-10)
### Bug Fixes
- Fixed handling cameras with no audio feed
- Improved video loading speed
- Switched to the direct snapshot retrieval
- Remove cameras from the system completely after disableCameras flag was enabled

## 1.5.0 (2021-02-23)
### Changes
- Added native support for cameras and doorbells, no external plugin required

## 1.4.3 (2021-02-21)
### Bug Fixes
- Fixed bug with locks when updated to Homebridge 1.3.0

## 1.4.2 (2021-02-07)
### Bug Fixes
- Fixed bug with too many doorbell notifications
- Fixed bug with panel when updated to Homebridge 1.3.0

## 1.4.1 (2021-01-26)
### Bug Fixes
- Fixed error on old NodeJS versions

## 1.4.0 (2021-01-14)
### Bug Fixes
- Fixed Thermostat handling

## 1.3.0 (2020-10-14)
### Changes
- Added support for new contact and glass break sensors
#### Other Changes
- More accurate Serial number assignment (important for Home Assistant integrations)

## 1.2.2 (2020-10-13)
### Bug Fixes
- Fixed thermostat handling

## 1.2.1 (2020-10-13)
### Bug Fixes
- Fixed startup issues

## 1.2.0 (2020-10-12)
### Changes
- Added Doorbell button press detection 
- Added "Motion detected" event handlihg for cameras
    - Requires [homebridge-camera-ffmpeg](https://github.com/Sunoo/homebridge-camera-ffmpeg) HTTP automation set up. Make sure to specify HTTP port configured on [homebridge-camera-ffmpeg](https://github.com/Sunoo/homebridge-camera-ffmpeg) side in **cameraAutomationHttpPort** config parameter

## 1.1.0 (2020-10-09)
### Changes
- Added support for new sensors
- Added Smoke Sensor and Carbon Monoxide device handling
- Added Tamper monitoring for sensors
### Bug Fixes
- Fixed error handling
- Fixed error if panel device is ignored

## 1.0.1 (2020-09-10)
### Bug Fixes
- Fixed thermostat handling

## 1.0.0 (2020-09-10)
### Changes
- Added support for new devices:
    - CO detector
    - Smoke detector
    - Heat / Freeze sensors
- "Jammed" state support for locks
- Ability to change panel states between Stay and Away while armed

## 0.0.13 (2020-08-11)
### Bug Fixes
- Fixed Panel arm/disarm notification lag

## 0.0.11 (2020-08-02)
### Bug Fixes
- Fixed thermostat handling
### Other Changes
- More accurate security panel status mapping

## 0.0.10 (2020-07-31)
### Changes
- Use Vivint battery management for Low Battery states
- Added an option to display camera config in the log file to be used with [homebridge-camera-ffmpeg](https://github.com/Sunoo/homebridge-camera-ffmpeg) plugin

## 0.0.9 (2020-07-14)
### Changes
- Added support for new devices:
    - Glass Break
    - Fire Alert
    - Tilt sensor
    - Third party motion detectors
    - Third party contact sensors

### Bug Fixes
- Report battery level as 100 in case it is not reported

## 0.0.8 (2020-07-09)
### Bug Fixes
- Default contact sensor battery value to 100% when unknown

## 0.0.7 (2020-06-26)
### Changes
- Increase stability of event stream;
- Dynamically add and remove accessories;
- Remove excessive logging;
- Add object mapping using dictionary;
