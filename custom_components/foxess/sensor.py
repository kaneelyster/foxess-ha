from __future__ import annotations

from collections import namedtuple
from datetime import timedelta
from datetime import datetime
import logging
import json
import hashlib

import voluptuous as vol

from homeassistant.components.rest.data import RestData
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorStateClass,
    PLATFORM_SCHEMA,
    SensorEntity,
)


from homeassistant.const import (
    ATTR_DATE,
    ATTR_TEMPERATURE,
    ATTR_TIME,
    ATTR_VOLTAGE,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_NAME,
    UnitOfEnergy,
    POWER_KILO_WATT,
    ENERGY_KILO_WATT_HOUR,
    TEMP_CELSIUS,
    UnitOfEnergy,
    ELECTRIC_POTENTIAL_VOLT,
    ELECTRIC_CURRENT_AMPERE,
    FREQUENCY_HERTZ,
    POWER_VOLT_AMPERE_REACTIVE,
)
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)


from homeassistant.helpers.icon import icon_for_battery_level
from homeassistant.core import callback
import homeassistant.helpers.config_validation as cv

from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem

software_names = [SoftwareName.CHROME.value]
operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value]
user_agent_rotator = UserAgent(software_names=software_names, operating_systems=operating_systems, limit=100)

_LOGGER = logging.getLogger(__name__)
_ENDPOINT_AUTH = "https://www.foxesscloud.com/c/v0/user/login"
_ENDPOINT_RAW = "https://www.foxesscloud.com/c/v0/device/history/raw"
_ENDPOINT_REPORT = "https://www.foxesscloud.com/c/v0/device/history/report"
_ENDPOINT_ADDRESSBOOK = "https://www.foxesscloud.com/c/v0/device/addressbook?deviceID="

METHOD_POST = "POST"
METHOD_GET = "GET"
DEFAULT_ENCODING = "UTF-8"


ATTR_DEVICE_SN = "deviceSN"
ATTR_PLANTNAME = "plantName"
ATTR_MODULESN = "moduleSN"
ATTR_DEVICE_TYPE = "deviceType"
ATTR_STATUS = "status"
ATTR_COUNTRY = "country"
ATTR_COUNTRYCODE = "countryCode"
ATTR_CITY = "city"
ATTR_ADDRESS = "address"
ATTR_FEEDINDATE = "feedinDate"
ATTR_LASTCLOUDSYNC = "lastCloudSync"

BATTERY_LEVELS = {"High": 80, "Medium": 50, "Low": 25, "Empty": 10}

CONF_DEVICEID = "deviceID"

CONF_SYSTEM_ID = "system_id"

DEFAULT_NAME = "FoxESS"
DEFAULT_VERIFY_SSL = True

SCAN_INTERVAL = timedelta(minutes=5)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Required(CONF_DEVICEID): cv.string,
        vol.Optional(CONF_NAME, default=DEFAULT_NAME): cv.string,
    }
)

token = None

async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    """Set up the FoxESS sensor."""
    name = config.get(CONF_NAME)
    username = config.get(CONF_USERNAME)
    password = config.get(CONF_PASSWORD)
    deviceID = config.get(CONF_DEVICEID)

    hashedPassword = hashlib.md5(password.encode()).hexdigest()

    async def async_update_data():
        _LOGGER.debug("Updating data from https://www.foxesscloud.com/")

        allData = {
            "report":{},
            "reportDailyGeneration": {},
            "raw":{},
            "online":False
        }

        global token
        if token is None:
            _LOGGER.debug("Token is empty, authenticating for the firts time")
            token = await authAndgetToken(hass, username, hashedPassword)

        user_agent = user_agent_rotator.get_random_user_agent()
        headersData = {"token": token,
                       "User-Agent": user_agent,
                       "Accept": "application/json, text/plain, */*",
                       "lang": "en",
                       "sec-ch-ua-platform": "macOS",
                       "Sec-Fetch-Site": "same-origin",
                       "Sec-Fetch-Mode": "cors",
                       "Sec-Fetch-Dest": "empty",
                       "Referer": "https://www.foxesscloud.com/bus/device/inverterDetail?id=xyz&flowType=1&status=1&hasPV=true&hasBattery=false",
                       "Accept-Language":"en-US;q=0.9,en;q=0.8,de;q=0.7,nl;q=0.6",
                       "Connection": "keep-alive",
                       "X-Requested-With": "XMLHttpRequest"}

        await getAddresbook(hass, headersData, allData, deviceID, username, hashedPassword,0)


        if int(allData["addressbook"]["result"]["status"]) == 1 or int(allData["addressbook"]["result"]["status"]) == 2 or int(allData["addressbook"]["result"]["status"]) == 3:
            allData["online"] = True
            await getRaw(hass, headersData, allData, deviceID)
            await getReport(hass, headersData, allData, deviceID)
            await getReportDailyGeneration(hass, headersData, allData, deviceID)
        else:
            _LOGGER.debug("Inverter is off-line, not fetching addictional data")

        _LOGGER.debug(allData)

        return allData

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        # Name of the data. For logging purposes.
        name=DEFAULT_NAME,
        update_method=async_update_data,
        # Polling interval. Will only be polled if there are subscribers.
        update_interval=SCAN_INTERVAL,
    )

    await coordinator.async_refresh()

    if not coordinator.last_update_success:
        _LOGGER.error(
            "FoxESS Cloud initializaction failed, fix error and restar ha")
        return False

    async_add_entities([
        FoxESSPVPower(coordinator, name, deviceID),
        FoxESSBatSoC(coordinator, name, deviceID),
        FoxESSGridConsumptionPower(coordinator, name, deviceID),
        FoxESSBatDischargePower(coordinator, name, deviceID),
        FoxESSBatChargePower(coordinator, name, deviceID),
    ])


async def authAndgetToken(hass, username, hashedPassword):

    #https://github.com/macxq/foxess-ha/issues/93#issuecomment-1319326849
#    payloadAuth = {"user": username, "password": hashedPassword}
    payloadAuth = f'user={username}&password={hashedPassword}'
    user_agent = user_agent_rotator.get_random_user_agent()
    headersAuth = {"User-Agent": user_agent,
                   "Accept": "application/json, text/plain, */*",
                   "lang": "en",
                   "sec-ch-ua-platform": "macOS",
                   "Sec-Fetch-Site": "same-origin",
                   "Sec-Fetch-Mode": "cors",
                   "Sec-Fetch-Dest": "empty",
                   "Referer": "https://www.foxesscloud.com/bus/device/inverterDetail?id=xyz&flowType=1&status=1&hasPV=true&hasBattery=false",
                   "Accept-Language":"en-US;q=0.9,en;q=0.8,de;q=0.7,nl;q=0.6",
                   "Connection": "keep-alive",
                    "X-Requested-With": "XMLHttpRequest"}

    restAuth = RestData(hass, METHOD_POST, _ENDPOINT_AUTH, DEFAULT_ENCODING,  None,
                        headersAuth, None, payloadAuth, DEFAULT_VERIFY_SSL)

    await restAuth.async_update()

    if restAuth.data is None:
        _LOGGER.error("Unable to login to FoxESS Cloud - No data recived")
        return False

    response = json.loads(restAuth.data)

    if response["result"] is None:
        if response["errno"] is not None and response["errno"] == 41807:
            raise UpdateFailed(
                f"Unable to login to FoxESS Cloud - bad username or password! {restAuth.data}")
        else:
            raise UpdateFailed(
                f"Error communicating with API: {restAuth.data}")
    else:
        _LOGGER.debug("Login succesfull" + restAuth.data)

    token = response["result"]["token"]
    return token


async def getAddresbook(hass, headersData, allData, deviceID,username, hashedPassword,tokenRefreshRetrys):
    restAddressBook = RestData(hass, METHOD_GET, _ENDPOINT_ADDRESSBOOK +
                               deviceID, DEFAULT_ENCODING,  None, headersData, None, None, DEFAULT_VERIFY_SSL)
    await restAddressBook.async_update()

    if restAddressBook.data is None:
        _LOGGER.error("Unable to get Addressbook data from FoxESS Cloud")
        return False
    else:
        response = json.loads(restAddressBook.data)
        if response["errno"] is not None and (response["errno"] == 41809 or response["errno"] == 41808):
                global token
                _LOGGER.debug(f"Token has expired, re-authenticating {tokenRefreshRetrys}")
                token = None
        else:
            _LOGGER.debug(
                "FoxESS Addressbook data fetched correcly "+restAddressBook.data)
            allData['addressbook'] = response

async def getReport(hass, headersData, allData, deviceID):
    now = datetime.now()


    reportData = '{"deviceID":"'+deviceID+'","reportType":"day","variables":["feedin","generation","gridConsumption","chargeEnergyToTal","dischargeEnergyToTal","loads"],"queryDate":{"year":'+now.strftime(
        "%Y")+',"month":'+now.strftime("%_m")+',"day":'+now.strftime("%_d")+'}}'

    restReport = RestData(hass, METHOD_POST, _ENDPOINT_REPORT,DEFAULT_ENCODING,
                          None, headersData, None, reportData, DEFAULT_VERIFY_SSL)

    await restReport.async_update()

    if restReport.data is None:
        _LOGGER.error("Unable to get Report data from FoxESS Cloud")
        return False
    else:
        _LOGGER.debug("FoxESS Report data fetched correctly " +
                      restReport.data[:150] + " ... ")

        for item in json.loads(restReport.data)['result']:
            variableName = item['variable']
            allData['report'][variableName] = None
            # Daily reports break down the data hour by hour for the whole day
            # even if we're only partially through, so sum the values together
            # to get our daily total so far...
            cumulative_total = 0
            for dataItem in item['data']:
                cumulative_total += dataItem['value']
            allData['report'][variableName] = cumulative_total


async def getReportDailyGeneration(hass, headersData, allData, deviceID):
    now = datetime.now()

    generationData = ('{"deviceID":"' + deviceID + '","reportType": "month",' + '"variables": ["generation"],' + '"queryDate": {' + '"year":' + now.strftime(
        "%Y") + ',"month":' + now.strftime("%_m") + ',"day":' + now.strftime("%_d") + ',"hour":' + now.strftime("%_H") + "}}")

    restGeneration = RestData(
        hass,
        METHOD_POST,
        _ENDPOINT_REPORT,
        DEFAULT_ENCODING,
        None,
        headersData,
        None,
        generationData,
        DEFAULT_VERIFY_SSL,
    )

    await restGeneration.async_update()

    if restGeneration.data is None:
        _LOGGER.error("Unable to get daily generation from FoxESS Cloud")
        return False
    else:
        _LOGGER.debug("FoxESS daily generation data fetched correctly " +
                      restGeneration.data)

        parsed = json.loads(restGeneration.data)["result"]
        allData["reportDailyGeneration"] = parsed[0]["data"][int(
            now.strftime("%d")) - 1]


async def getRaw(hass, headersData, allData, deviceID):
    now = datetime.now()

    rawData = '{"deviceID":"'+deviceID+'","variables":["ambientTemperation","batChargePower","batCurrent","batDischargePower","batTemperature","batVolt","boostTemperation","chargeEnergyToTal","chargeTemperature","dischargeEnergyToTal","dspTemperature","epsCurrentR","epsCurrentS","epsCurrentT","epsPower","epsPowerR","epsPowerS","epsPowerT","epsVoltR","epsVoltS","epsVoltT","feedin","feedin2","feedinPower","generation","generationPower","gridConsumption","gridConsumption2","gridConsumptionPower","input","invBatCurrent","invBatPower","invBatVolt","invTemperation","loads","loadsPower","loadsPowerR","loadsPowerS","loadsPowerT","meterPower","meterPower2","meterPowerR","meterPowerS","meterPowerT","PowerFactor","pv1Current","pv1Power","pv1Volt","pv2Current","pv2Power","pv2Volt","pv3Current","pv3Power","pv3Volt","pv4Current","pv4Power","pv4Volt","pvPower","RCurrent","ReactivePower","RFreq","RPower","RVolt","SCurrent","SFreq","SoC","SPower","SVolt","TCurrent","TFreq","TPower","TVolt"],"timespan":"hour","beginDate":{"year":'+now.strftime(
        "%Y")+',"month":'+now.strftime("%_m")+',"day":'+now.strftime("%_d")+',"hour":'+now.strftime("%_H")+'}}'

    restRaw = RestData(hass, METHOD_POST, _ENDPOINT_RAW,DEFAULT_ENCODING,
                       None, headersData, None, rawData, DEFAULT_VERIFY_SSL)
    await restRaw.async_update()

    if restRaw.data is None:
        _LOGGER.error("Unable to get Raw data from FoxESS Cloud")
        return False
    else:
        _LOGGER.debug("FoxESS Raw data fetched correcly " +
                      restRaw.data[:150] + " ... ")
        allData['raw'] = {}
        for item in json.loads(restRaw.data)['result']:
            variableName = item['variable']
            # If data is a non-empty list, pop the last value off the list, otherwise return the previously found value
            if item["data"]:
                allData['raw'][variableName] = item["data"].pop().get("value",None)


class FoxESSPVPower(CoordinatorEntity, SensorEntity):

    _attr_state_class: SensorStateClass = SensorStateClass.MEASUREMENT
    _attr_device_class = SensorDeviceClass.POWER
    _attr_native_unit_of_measurement = POWER_KILO_WATT

    def __init__(self, coordinator, name, deviceID):
        super().__init__(coordinator=coordinator)
        _LOGGER.debug("Initiating Entity - PV Power")
        self._attr_name = name+" - PV Power"
        self._attr_unique_id = deviceID+"pv-power"
        self.status = namedtuple(
            "status",
            [
                ATTR_DATE,
                ATTR_TIME,
            ],
        )

    @property
    def native_value(self) -> float | None:
        if self.coordinator.data["online"]:
            return self.coordinator.data["raw"]["pvPower"]
        return None


class FoxESSBatSoC(CoordinatorEntity, SensorEntity):

    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = "%"

    def __init__(self, coordinator, name, deviceID):
        super().__init__(coordinator=coordinator)
        _LOGGER.debug("Initiating Entity - Bat SoC")
        self._attr_name = name+" - Bat SoC"
        self._attr_unique_id = deviceID+"bat-soc"
        self.status = namedtuple(
            "status",
            [
                ATTR_DATE,
                ATTR_TIME,
            ],
        )

    @property
    def native_value(self) -> float | None:
        if self.coordinator.data["online"]:
            return self.coordinator.data["raw"]["SoC"]
        return  None

    @property
    def icon(self):
        return icon_for_battery_level(battery_level=self.native_value, charging=None)


class FoxESSGridConsumptionPower(CoordinatorEntity, SensorEntity):

    _attr_state_class: SensorStateClass = SensorStateClass.MEASUREMENT
    _attr_device_class = SensorDeviceClass.POWER
    _attr_native_unit_of_measurement = POWER_KILO_WATT

    def __init__(self, coordinator, name, deviceID):
        super().__init__(coordinator=coordinator)
        _LOGGER.debug("Initiating Entity - Grid Consumption Power")
        self._attr_name = name+" - Grid Consumption Power"
        self._attr_unique_id = deviceID+"grid-consumption-power"
        self.status = namedtuple(
            "status",
            [
                ATTR_DATE,
                ATTR_TIME,
            ],
        )

    @property
    def native_value(self) -> str | None:
        if self.coordinator.data["online"]:
            return self.coordinator.data["raw"]["gridConsumptionPower"]
        return None


class FoxESSBatDischargePower(CoordinatorEntity, SensorEntity):

    _attr_state_class: SensorStateClass = SensorStateClass.MEASUREMENT
    _attr_device_class = SensorDeviceClass.POWER
    _attr_native_unit_of_measurement = POWER_KILO_WATT

    def __init__(self, coordinator, name, deviceID):
        super().__init__(coordinator=coordinator)
        _LOGGER.debug("Initiating Entity - Bat Discharge Power")
        self._attr_name = name+" - Bat Discharge Power"
        self._attr_unique_id = deviceID+"bat-discharge-power"
        self.status = namedtuple(
            "status",
            [
                ATTR_DATE,
                ATTR_TIME,
            ],
        )

    @property
    def native_value(self) -> str | None:
        if self.coordinator.data["online"]:
            return self.coordinator.data["raw"]["batDischargePower"]
        return None


class FoxESSBatChargePower(CoordinatorEntity, SensorEntity):

    _attr_state_class: SensorStateClass = SensorStateClass.MEASUREMENT
    _attr_device_class = SensorDeviceClass.POWER
    _attr_native_unit_of_measurement = POWER_KILO_WATT

    def __init__(self, coordinator, name, deviceID):
        super().__init__(coordinator=coordinator)
        _LOGGER.debug("Initiating Entity - Bat Charge Power")
        self._attr_name = name+" - Bat Charge Power"
        self._attr_unique_id = deviceID+"bat-charge-power"
        self.status = namedtuple(
            "status",
            [
                ATTR_DATE,
                ATTR_TIME,
            ],
        )

    @property
    def native_value(self) -> str | None:
        if self.coordinator.data["online"]:
            return self.coordinator.data["raw"]["batChargePower"]
        return None
