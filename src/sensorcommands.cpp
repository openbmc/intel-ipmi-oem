/*
// Copyright (c) 2017 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "sensorcommands.hpp"

#include "commandutils.hpp"
#include "ipmi_to_redfish_hooks.hpp"
#include "sdrutils.hpp"
#include "sensorutils.hpp"
#include "storagecommands.hpp"
#include "types.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace ipmi
{
using ManagedObjectType =
    std::map<sdbusplus::message::object_path,
             std::map<std::string, std::map<std::string, DbusVariant>>>;

static constexpr int sensorMapUpdatePeriod = 10;
static constexpr int sensorMapSdrUpdatePeriod = 60;

constexpr size_t maxSDRTotalSize =
    76; // Largest SDR Record Size (type 01) + SDR Overheader Size
constexpr static const uint32_t noTimestamp = 0xFFFFFFFF;

static uint16_t sdrReservationID;
static uint32_t sdrLastAdd = noTimestamp;
static uint32_t sdrLastRemove = noTimestamp;
static constexpr size_t lastRecordIndex = 0xFFFF;

// The IPMI spec defines four Logical Units (LUN), each capable of supporting
// 255 sensors. The 256 values assigned to LUN 2 are special and are not used
// for general purpose sensors. Each LUN reserves location 0xFF. The maximum
// number of IPMI sensors are LUN 0 + LUN 1 + LUN 2, less the reserved
// location.
static constexpr size_t maxIPMISensors = ((3 * 256) - (3 * 1));

static constexpr size_t lun0MaxSensorNum = 0xfe;
static constexpr size_t lun1MaxSensorNum = 0x1fe;
static constexpr size_t lun3MaxSensorNum = 0x3fe;
static constexpr int GENERAL_ERROR = -1;

SensorSubTree sensorTree;

static boost::container::flat_map<std::string, ManagedObjectType> SensorCache;

constexpr static std::array<std::pair<const char*, SensorUnits>, 5> sensorUnits{
    {{"temperature", SensorUnits::degreesC},
     {"voltage", SensorUnits::volts},
     {"current", SensorUnits::amps},
     {"fan_tach", SensorUnits::rpm},
     {"power", SensorUnits::watts}}};

void registerSensorFunctions() __attribute__((constructor));

static sdbusplus::bus::match_t sensorAdded(
    *getSdBus(),
    "type='signal',member='InterfacesAdded',arg0path='/xyz/openbmc_project/"
    "sensors/'",
    [](sdbusplus::message_t&) {
    sensorTree.clear();
    sdrLastAdd = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
});

static sdbusplus::bus::match_t sensorRemoved(
    *getSdBus(),
    "type='signal',member='InterfacesRemoved',arg0path='/xyz/openbmc_project/"
    "sensors/'",
    [](sdbusplus::message_t&) {
    sensorTree.clear();
    sdrLastRemove = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
});

// this keeps track of deassertions for sensor event status command. A
// deasertion can only happen if an assertion was seen first.
static boost::container::flat_map<
    std::string, boost::container::flat_map<std::string, std::optional<bool>>>
    thresholdDeassertMap;

static sdbusplus::bus::match_t thresholdChanged(
    *getSdBus(),
    "type='signal',member='PropertiesChanged',interface='org.freedesktop.DBus."
    "Properties',arg0namespace='xyz.openbmc_project.Sensor.Threshold'",
    [](sdbusplus::message_t& m) {
    boost::container::flat_map<std::string, ipmi::DbusVariant> values;
    m.read(std::string(), values);

    auto findAssert = std::find_if(values.begin(), values.end(),
                                   [](const auto& pair) {
        return pair.first.find("Alarm") != std::string::npos;
    });
    if (findAssert != values.end())
    {
        auto ptr = std::get_if<bool>(&(findAssert->second));
        if (ptr == nullptr)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "thresholdChanged: Assert non bool");
            return;
        }
        if (*ptr)
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "thresholdChanged: Assert",
                phosphor::logging::entry("SENSOR=%s", m.get_path()));
            thresholdDeassertMap[m.get_path()][findAssert->first] = *ptr;
        }
        else
        {
            auto& value = thresholdDeassertMap[m.get_path()][findAssert->first];
            if (value)
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "thresholdChanged: deassert",
                    phosphor::logging::entry("SENSOR=%s", m.get_path()));
                value = *ptr;
            }
        }
    }
});

static void getSensorMaxMin(const SensorMap& sensorMap, double& max,
                            double& min)
{
    max = 127;
    min = -128;

    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");
    auto critical =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    auto warning =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");

    if (sensorObject != sensorMap.end())
    {
        auto maxMap = sensorObject->second.find("MaxValue");
        auto minMap = sensorObject->second.find("MinValue");

        if (maxMap != sensorObject->second.end())
        {
            max = std::visit(VariantToDoubleVisitor(), maxMap->second);
        }
        if (minMap != sensorObject->second.end())
        {
            min = std::visit(VariantToDoubleVisitor(), minMap->second);
        }
    }
    if (critical != sensorMap.end())
    {
        auto lower = critical->second.find("CriticalLow");
        auto upper = critical->second.find("CriticalHigh");
        if (lower != critical->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), lower->second);
            min = std::fmin(value, min);
        }
        if (upper != critical->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), upper->second);
            max = std::fmax(value, max);
        }
    }
    if (warning != sensorMap.end())
    {
        auto lower = warning->second.find("WarningLow");
        auto upper = warning->second.find("WarningHigh");
        if (lower != warning->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), lower->second);
            min = std::fmin(value, min);
        }
        if (upper != warning->second.end())
        {
            double value = std::visit(VariantToDoubleVisitor(), upper->second);
            max = std::fmax(value, max);
        }
    }
}

static bool getSensorMap(boost::asio::yield_context yield,
                         std::string sensorConnection, std::string sensorPath,
                         SensorMap& sensorMap,
                         int updatePeriod = sensorMapUpdatePeriod)
{
    static boost::container::flat_map<
        std::string, std::chrono::time_point<std::chrono::steady_clock>>
        updateTimeMap;

    auto updateFind = updateTimeMap.find(sensorConnection);
    auto lastUpdate = std::chrono::time_point<std::chrono::steady_clock>();
    if (updateFind != updateTimeMap.end())
    {
        lastUpdate = updateFind->second;
    }

    auto now = std::chrono::steady_clock::now();

    if (std::chrono::duration_cast<std::chrono::seconds>(now - lastUpdate)
            .count() > updatePeriod)
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        boost::system::error_code ec;
        auto managedObjects = dbus->yield_method_call<ManagedObjectType>(
            yield, ec, sensorConnection.c_str(), "/xyz/openbmc_project/sensors",
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "GetMangagedObjects for getSensorMap failed",
                phosphor::logging::entry("ERROR=%s", ec.message().c_str()));

            return false;
        }

        SensorCache[sensorConnection] = managedObjects;
        // Update time after finish building the map which allow the
        // data to be cached for updatePeriod plus the build time.
        updateTimeMap[sensorConnection] = std::chrono::steady_clock::now();
    }
    auto connection = SensorCache.find(sensorConnection);
    if (connection == SensorCache.end())
    {
        return false;
    }
    auto path = connection->second.find(sensorPath);
    if (path == connection->second.end())
    {
        return false;
    }
    sensorMap = path->second;

    return true;
}

/* sensor commands */
namespace meHealth
{
constexpr const char* busname = "xyz.openbmc_project.NodeManagerProxy";
constexpr const char* path = "/xyz/openbmc_project/status/me";
constexpr const char* interface = "xyz.openbmc_project.SetHealth";
constexpr const char* method = "SetHealth";
constexpr const char* critical = "critical";
constexpr const char* warning = "warning";
constexpr const char* ok = "ok";
} // namespace meHealth

static void setMeStatus(uint8_t eventData2, uint8_t eventData3, bool disable)
{
    constexpr const std::array<uint8_t, 10> critical = {
        0x1, 0x2, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xD, 0xE};
    constexpr const std::array<uint8_t, 5> warning = {0x3, 0xA, 0x13, 0x19,
                                                      0x1A};

    std::string state;
    if (std::find(critical.begin(), critical.end(), eventData2) !=
        critical.end())
    {
        state = meHealth::critical;
    }
    // special case 0x3 as we only care about a few states
    else if (eventData2 == 0x3)
    {
        if (eventData3 <= 0x2)
        {
            state = meHealth::warning;
        }
        else
        {
            return;
        }
    }
    else if (std::find(warning.begin(), warning.end(), eventData2) !=
             warning.end())
    {
        state = meHealth::warning;
    }
    else
    {
        return;
    }
    if (disable)
    {
        state = meHealth::ok;
    }

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto setHealth = dbus->new_method_call(meHealth::busname, meHealth::path,
                                           meHealth::interface,
                                           meHealth::method);
    setHealth.append(std::to_string(static_cast<size_t>(eventData2)), state);
    try
    {
        dbus->call(setHealth);
    }
    catch (const sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set ME Health");
    }
}

ipmi::RspType<> ipmiSenPlatformEvent(ipmi::Context::ptr ctx,
                                     ipmi::message::Payload& p)
{
    constexpr const uint8_t meId = 0x2C;
    constexpr const uint8_t meSensorNum = 0x17;
    constexpr const uint8_t disabled = 0x80;

    uint8_t sysgeneratorID = 0;
    uint8_t evmRev = 0;
    uint8_t sensorType = 0;
    uint8_t sensorNum = 0;
    uint8_t eventType = 0;
    uint8_t eventData1 = 0;
    std::optional<uint8_t> eventData2 = 0;
    std::optional<uint8_t> eventData3 = 0;
    uint16_t generatorID = 0;
    ipmi::ChannelInfo chInfo;

    if (ipmi::getChannelInfo(ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Channel Info",
            phosphor::logging::entry("CHANNEL=%d", ctx->channel));
        return ipmi::responseUnspecifiedError();
    }

    if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
        ipmi::EChannelMediumType::systemInterface)
    {
        p.unpack(sysgeneratorID, evmRev, sensorType, sensorNum, eventType,
                 eventData1, eventData2, eventData3);
        constexpr const uint8_t isSoftwareID = 0x01;
        if (!(sysgeneratorID & isSoftwareID))
        {
            return ipmi::responseInvalidFieldRequest();
        }
        // Refer to IPMI Spec Table 32: SEL Event Records
        generatorID = (ctx->channel << 12) // Channel
                      | (0x0 << 10)        // Reserved
                      | (0x0 << 8)         // 0x0 for sys-soft ID
                      | sysgeneratorID;
    }
    else
    {
        p.unpack(evmRev, sensorType, sensorNum, eventType, eventData1,
                 eventData2, eventData3);
        // Refer to IPMI Spec Table 32: SEL Event Records
        generatorID = (ctx->channel << 12)      // Channel
                      | (0x0 << 10)             // Reserved
                      | ((ctx->lun & 0x3) << 8) // Lun
                      | (ctx->rqSA << 1);
    }

    if (!p.fullyUnpacked())
    {
        return ipmi::responseReqDataLenInvalid();
    }

    // Check for valid evmRev and Sensor Type(per Table 42 of spec)
    if (evmRev != 0x04)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    if ((sensorType > 0x2C) && (sensorType < 0xC0))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Send this request to the Redfish hooks to log it as a Redfish message
    // instead.  There is no need to add it to the SEL, so just return success.
    intel_oem::ipmi::sel::checkRedfishHooks(
        generatorID, evmRev, sensorType, sensorNum, eventType, eventData1,
        eventData2.value_or(0xFF), eventData3.value_or(0xFF));

    if (static_cast<uint8_t>(generatorID) == meId && sensorNum == meSensorNum &&
        eventData2 && eventData3)
    {
        setMeStatus(*eventData2, *eventData3, (eventType & disabled));
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, std::optional<uint8_t>>
    ipmiSenGetSensorReading(ipmi::Context::ptr ctx, uint8_t sensnum)
{
    std::string connection;
    std::string path;

    if (sensnum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto status = getSensorConnection(ctx, sensnum, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }

    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }
    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");

    if (sensorObject == sensorMap.end() ||
        sensorObject->second.find("Value") == sensorObject->second.end())
    {
        return ipmi::responseResponseError();
    }
    auto& valueVariant = sensorObject->second["Value"];
    double reading = std::visit(VariantToDoubleVisitor(), valueVariant);

    double max = 0;
    double min = 0;
    getSensorMaxMin(sensorMap, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return ipmi::responseResponseError();
    }

    uint8_t value = scaleIPMIValueFromDouble(reading, mValue, rExp, bValue,
                                             bExp, bSigned);
    uint8_t operation =
        static_cast<uint8_t>(IPMISensorReadingByte2::sensorScanningEnable);
    operation |=
        static_cast<uint8_t>(IPMISensorReadingByte2::eventMessagesEnable);
    bool notReading = std::isnan(reading);

    if (!notReading)
    {
        auto availableObject =
            sensorMap.find("xyz.openbmc_project.State.Decorator.Availability");
        if (availableObject != sensorMap.end())
        {
            auto findAvailable = availableObject->second.find("Available");
            if (findAvailable != availableObject->second.end())
            {
                bool* available = std::get_if<bool>(&(findAvailable->second));
                if (available && !(*available))
                {
                    notReading = true;
                }
            }
        }
    }

    if (notReading)
    {
        operation |= static_cast<uint8_t>(
            IPMISensorReadingByte2::readingStateUnavailable);
    }

    int byteValue;
    if (bSigned)
    {
        byteValue = static_cast<int>(static_cast<int8_t>(value));
    }
    else
    {
        byteValue = static_cast<int>(static_cast<uint8_t>(value));
    }

    // Keep stats on the reading just obtained, even if it is "NaN"
    if (details::sdrStatsTable.updateReading(sensnum, reading, byteValue))
    {
        // This is the first reading, show the coefficients
        double step = (max - min) / 255.0;
        std::cerr << "IPMI sensor " << details::sdrStatsTable.getName(sensnum)
                  << ": Range min=" << min << " max=" << max
                  << ", step=" << step
                  << ", Coefficients mValue=" << static_cast<int>(mValue)
                  << " rExp=" << static_cast<int>(rExp)
                  << " bValue=" << static_cast<int>(bValue)
                  << " bExp=" << static_cast<int>(bExp)
                  << " bSigned=" << static_cast<int>(bSigned) << "\n";
    };

    uint8_t thresholds = 0;

    auto warningObject =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    if (warningObject != sensorMap.end())
    {
        auto alarmHigh = warningObject->second.find("WarningAlarmHigh");
        auto alarmLow = warningObject->second.find("WarningAlarmLow");
        if (alarmHigh != warningObject->second.end())
        {
            if (std::get<bool>(alarmHigh->second))
            {
                thresholds |= static_cast<uint8_t>(
                    IPMISensorReadingByte3::upperNonCritical);
            }
        }
        if (alarmLow != warningObject->second.end())
        {
            if (std::get<bool>(alarmLow->second))
            {
                thresholds |= static_cast<uint8_t>(
                    IPMISensorReadingByte3::lowerNonCritical);
            }
        }
    }

    auto criticalObject =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    if (criticalObject != sensorMap.end())
    {
        auto alarmHigh = criticalObject->second.find("CriticalAlarmHigh");
        auto alarmLow = criticalObject->second.find("CriticalAlarmLow");
        if (alarmHigh != criticalObject->second.end())
        {
            if (std::get<bool>(alarmHigh->second))
            {
                thresholds |=
                    static_cast<uint8_t>(IPMISensorReadingByte3::upperCritical);
            }
        }
        if (alarmLow != criticalObject->second.end())
        {
            if (std::get<bool>(alarmLow->second))
            {
                thresholds |=
                    static_cast<uint8_t>(IPMISensorReadingByte3::lowerCritical);
            }
        }
    }

    // no discrete as of today so optional byte is never returned
    return ipmi::responseSuccess(value, operation, thresholds, std::nullopt);
}

/** @brief implements the Set Sensor threshold command
 *  @param sensorNumber        - sensor number
 *  @param lowerNonCriticalThreshMask
 *  @param lowerCriticalThreshMask
 *  @param lowerNonRecovThreshMask
 *  @param upperNonCriticalThreshMask
 *  @param upperCriticalThreshMask
 *  @param upperNonRecovThreshMask
 *  @param reserved
 *  @param lowerNonCritical    - lower non-critical threshold
 *  @param lowerCritical       - Lower critical threshold
 *  @param lowerNonRecoverable - Lower non recovarable threshold
 *  @param upperNonCritical    - Upper non-critical threshold
 *  @param upperCritical       - Upper critical
 *  @param upperNonRecoverable - Upper Non-recoverable
 *
 *  @returns IPMI completion code
 */
ipmi::RspType<> ipmiSenSetSensorThresholds(
    ipmi::Context::ptr ctx, uint8_t sensorNum, bool lowerNonCriticalThreshMask,
    bool lowerCriticalThreshMask, bool lowerNonRecovThreshMask,
    bool upperNonCriticalThreshMask, bool upperCriticalThreshMask,
    bool upperNonRecovThreshMask, uint2_t reserved, uint8_t lowerNonCritical,
    uint8_t lowerCritical, [[maybe_unused]] uint8_t lowerNonRecoverable,
    uint8_t upperNonCritical, uint8_t upperCritical,
    [[maybe_unused]] uint8_t upperNonRecoverable)
{
    if (sensorNum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (reserved)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // lower nc and upper nc not suppported on any sensor
    if (lowerNonRecovThreshMask || upperNonRecovThreshMask)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // if none of the threshold mask are set, nothing to do
    if (!(lowerNonCriticalThreshMask | lowerCriticalThreshMask |
          lowerNonRecovThreshMask | upperNonCriticalThreshMask |
          upperCriticalThreshMask | upperNonRecovThreshMask))
    {
        return ipmi::responseSuccess();
    }

    std::string connection;
    std::string path;

    ipmi::Cc status = getSensorConnection(ctx, sensorNum, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }
    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }

    double max = 0;
    double min = 0;
    getSensorMaxMin(sensorMap, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return ipmi::responseResponseError();
    }

    // store a vector of property name, value to set, and interface
    std::vector<std::tuple<std::string, uint8_t, std::string>> thresholdsToSet;

    // define the indexes of the tuple
    constexpr uint8_t propertyName = 0;
    constexpr uint8_t thresholdValue = 1;
    constexpr uint8_t interface = 2;
    // verifiy all needed fields are present
    if (lowerCriticalThreshMask || upperCriticalThreshMask)
    {
        auto findThreshold =
            sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
        if (findThreshold == sensorMap.end())
        {
            return ipmi::responseInvalidFieldRequest();
        }
        if (lowerCriticalThreshMask)
        {
            auto findLower = findThreshold->second.find("CriticalLow");
            if (findLower == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("CriticalLow", lowerCritical,
                                         findThreshold->first);
        }
        if (upperCriticalThreshMask)
        {
            auto findUpper = findThreshold->second.find("CriticalHigh");
            if (findUpper == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("CriticalHigh", upperCritical,
                                         findThreshold->first);
        }
    }
    if (lowerNonCriticalThreshMask || upperNonCriticalThreshMask)
    {
        auto findThreshold =
            sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
        if (findThreshold == sensorMap.end())
        {
            return ipmi::responseInvalidFieldRequest();
        }
        if (lowerNonCriticalThreshMask)
        {
            auto findLower = findThreshold->second.find("WarningLow");
            if (findLower == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("WarningLow", lowerNonCritical,
                                         findThreshold->first);
        }
        if (upperNonCriticalThreshMask)
        {
            auto findUpper = findThreshold->second.find("WarningHigh");
            if (findUpper == findThreshold->second.end())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            thresholdsToSet.emplace_back("WarningHigh", upperNonCritical,
                                         findThreshold->first);
        }
    }
    for (const auto& property : thresholdsToSet)
    {
        // from section 36.3 in the IPMI Spec, assume all linear
        double valueToSet = ((mValue * std::get<thresholdValue>(property)) +
                             (bValue * std::pow(10.0, bExp))) *
                            std::pow(10.0, rExp);
        setDbusProperty(
            *getSdBus(), connection, path, std::get<interface>(property),
            std::get<propertyName>(property), ipmi::Value(valueToSet));
    }
    return ipmi::responseSuccess();
}

IPMIThresholds getIPMIThresholds(const SensorMap& sensorMap)
{
    IPMIThresholds resp;
    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");

    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()))
    {
        auto sensorPair = sensorMap.find("xyz.openbmc_project.Sensor.Value");

        if (sensorPair == sensorMap.end())
        {
            // should not have been able to find a sensor not implementing
            // the sensor object
            throw std::runtime_error("Invalid sensor map");
        }

        double max = 0;
        double min = 0;
        getSensorMaxMin(sensorMap, max, min);

        int16_t mValue = 0;
        int16_t bValue = 0;
        int8_t rExp = 0;
        int8_t bExp = 0;
        bool bSigned = false;

        if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
        {
            throw std::runtime_error("Invalid sensor atrributes");
        }
        if (warningInterface != sensorMap.end())
        {
            auto& warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningHigh");
            auto warningLow = warningMap.find("WarningLow");

            if (warningHigh != warningMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          warningHigh->second);
                if (std::isfinite(value))
                {
                    resp.warningHigh = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
            if (warningLow != warningMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          warningLow->second);
                if (std::isfinite(value))
                {
                    resp.warningLow = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto& criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalHigh");
            auto criticalLow = criticalMap.find("CriticalLow");

            if (criticalHigh != criticalMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          criticalHigh->second);
                if (std::isfinite(value))
                {
                    resp.criticalHigh = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
            if (criticalLow != criticalMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          criticalLow->second);
                if (std::isfinite(value))
                {
                    resp.criticalLow = scaleIPMIValueFromDouble(
                        value, mValue, rExp, bValue, bExp, bSigned);
                }
            }
        }
    }
    return resp;
}

ipmi::RspType<uint8_t, // readable
              uint8_t, // lowerNCrit
              uint8_t, // lowerCrit
              uint8_t, // lowerNrecoverable
              uint8_t, // upperNC
              uint8_t, // upperCrit
              uint8_t> // upperNRecoverable
    ipmiSenGetSensorThresholds(ipmi::Context::ptr ctx, uint8_t sensorNumber)
{
    std::string connection;
    std::string path;

    if (sensorNumber == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto status = getSensorConnection(ctx, sensorNumber, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }

    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }

    IPMIThresholds thresholdData;
    try
    {
        thresholdData = getIPMIThresholds(sensorMap);
    }
    catch (const std::exception&)
    {
        return ipmi::responseResponseError();
    }

    uint8_t readable = 0;
    uint8_t lowerNC = 0;
    uint8_t lowerCritical = 0;
    uint8_t lowerNonRecoverable = 0;
    uint8_t upperNC = 0;
    uint8_t upperCritical = 0;
    uint8_t upperNonRecoverable = 0;

    if (thresholdData.warningHigh)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::upperNonCritical);
        upperNC = *thresholdData.warningHigh;
    }
    if (thresholdData.warningLow)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::lowerNonCritical);
        lowerNC = *thresholdData.warningLow;
    }

    if (thresholdData.criticalHigh)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::upperCritical);
        upperCritical = *thresholdData.criticalHigh;
    }
    if (thresholdData.criticalLow)
    {
        readable |=
            1 << static_cast<uint8_t>(IPMIThresholdRespBits::lowerCritical);
        lowerCritical = *thresholdData.criticalLow;
    }

    return ipmi::responseSuccess(readable, lowerNC, lowerCritical,
                                 lowerNonRecoverable, upperNC, upperCritical,
                                 upperNonRecoverable);
}

/** @brief implements the get Sensor event enable command
 *  @param sensorNumber - sensor number
 *
 *  @returns IPMI completion code plus response data
 *   - enabled               - Sensor Event messages
 *   - assertionEnabledLsb   - Assertion event messages
 *   - assertionEnabledMsb   - Assertion event messages
 *   - deassertionEnabledLsb - Deassertion event messages
 *   - deassertionEnabledMsb - Deassertion event messages
 */

ipmi::RspType<uint8_t, // enabled
              uint8_t, // assertionEnabledLsb
              uint8_t, // assertionEnabledMsb
              uint8_t, // deassertionEnabledLsb
              uint8_t> // deassertionEnabledMsb
    ipmiSenGetSensorEventEnable(ipmi::Context::ptr ctx, uint8_t sensorNum)
{
    std::string connection;
    std::string path;

    uint8_t enabled = 0;
    uint8_t assertionEnabledLsb = 0;
    uint8_t assertionEnabledMsb = 0;
    uint8_t deassertionEnabledLsb = 0;
    uint8_t deassertionEnabledMsb = 0;

    if (sensorNum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    auto status = getSensorConnection(ctx, sensorNum, connection, path);
    if (status)
    {
        return ipmi::response(status);
    }

    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap))
    {
        return ipmi::responseResponseError();
    }

    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()))
    {
        enabled = static_cast<uint8_t>(
            IPMISensorEventEnableByte2::sensorScanningEnable);
        if (warningInterface != sensorMap.end())
        {
            auto& warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningHigh");
            auto warningLow = warningMap.find("WarningLow");
            if (warningHigh != warningMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          warningHigh->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperNonCriticalGoingHigh);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperNonCriticalGoingLow);
                }
            }
            if (warningLow != warningMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          warningLow->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerNonCriticalGoingLow);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerNonCriticalGoingHigh);
                }
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto& criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalHigh");
            auto criticalLow = criticalMap.find("CriticalLow");

            if (criticalHigh != criticalMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          criticalHigh->second);
                if (std::isfinite(value))
                {
                    assertionEnabledMsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            upperCriticalGoingHigh);
                    deassertionEnabledMsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::upperCriticalGoingLow);
                }
            }
            if (criticalLow != criticalMap.end())
            {
                double value = std::visit(VariantToDoubleVisitor(),
                                          criticalLow->second);
                if (std::isfinite(value))
                {
                    assertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
                    deassertionEnabledLsb |= static_cast<uint8_t>(
                        IPMISensorEventEnableThresholds::
                            lowerCriticalGoingHigh);
                }
            }
        }
    }

    return ipmi::responseSuccess(enabled, assertionEnabledLsb,
                                 assertionEnabledMsb, deassertionEnabledLsb,
                                 deassertionEnabledMsb);
}

/** @brief implements the get Sensor event status command
 *  @param sensorNumber - sensor number, FFh = reserved
 *
 *  @returns IPMI completion code plus response data
 *   - sensorEventStatus - Sensor Event messages state
 *   - assertions        - Assertion event messages
 *   - deassertions      - Deassertion event messages
 */
ipmi::RspType<uint8_t,         // sensorEventStatus
              std::bitset<16>, // assertions
              std::bitset<16>  // deassertion
              >
    ipmiSenGetSensorEventStatus(ipmi::Context::ptr ctx, uint8_t sensorNum)
{
    if (sensorNum == reservedSensorNumber)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::string connection;
    std::string path;
    auto status = getSensorConnection(ctx, sensorNum, connection, path);
    if (status)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSenGetSensorEventStatus: Sensor connection Error",
            phosphor::logging::entry("SENSOR=%d", sensorNum));
        return ipmi::response(status);
    }

    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiSenGetSensorEventStatus: Sensor Mapping Error",
            phosphor::logging::entry("SENSOR=%s", path.c_str()));
        return ipmi::responseResponseError();
    }
    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");

    uint8_t sensorEventStatus =
        static_cast<uint8_t>(IPMISensorEventEnableByte2::sensorScanningEnable);

    std::optional<bool> criticalDeassertHigh =
        thresholdDeassertMap[path]["CriticalAlarmHigh"];
    std::optional<bool> criticalDeassertLow =
        thresholdDeassertMap[path]["CriticalAlarmLow"];
    std::optional<bool> warningDeassertHigh =
        thresholdDeassertMap[path]["WarningAlarmHigh"];
    std::optional<bool> warningDeassertLow =
        thresholdDeassertMap[path]["WarningAlarmLow"];

    std::bitset<16> assertions = 0;
    std::bitset<16> deassertions = 0;

    if (criticalDeassertHigh && !*criticalDeassertHigh)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::upperCriticalGoingHigh));
    }
    if (criticalDeassertLow && !*criticalDeassertLow)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::upperCriticalGoingLow));
    }
    if (warningDeassertHigh && !*warningDeassertHigh)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::upperNonCriticalGoingHigh));
    }
    if (warningDeassertLow && !*warningDeassertLow)
    {
        deassertions.set(static_cast<size_t>(
            IPMIGetSensorEventEnableThresholds::lowerNonCriticalGoingHigh));
    }
    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()))
    {
        sensorEventStatus = static_cast<size_t>(
            IPMISensorEventEnableByte2::eventMessagesEnable);
        if (warningInterface != sensorMap.end())
        {
            auto& warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningAlarmHigh");
            auto warningLow = warningMap.find("WarningAlarmLow");
            auto warningHighAlarm = false;
            auto warningLowAlarm = false;

            if (warningHigh != warningMap.end())
            {
                warningHighAlarm = std::get<bool>(warningHigh->second);
            }
            if (warningLow != warningMap.end())
            {
                warningLowAlarm = std::get<bool>(warningLow->second);
            }
            if (warningHighAlarm)
            {
                assertions.set(
                    static_cast<size_t>(IPMIGetSensorEventEnableThresholds::
                                            upperNonCriticalGoingHigh));
            }
            if (warningLowAlarm)
            {
                assertions.set(
                    static_cast<size_t>(IPMIGetSensorEventEnableThresholds::
                                            lowerNonCriticalGoingLow));
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto& criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalAlarmHigh");
            auto criticalLow = criticalMap.find("CriticalAlarmLow");
            auto criticalHighAlarm = false;
            auto criticalLowAlarm = false;

            if (criticalHigh != criticalMap.end())
            {
                criticalHighAlarm = std::get<bool>(criticalHigh->second);
            }
            if (criticalLow != criticalMap.end())
            {
                criticalLowAlarm = std::get<bool>(criticalLow->second);
            }
            if (criticalHighAlarm)
            {
                assertions.set(
                    static_cast<size_t>(IPMIGetSensorEventEnableThresholds::
                                            upperCriticalGoingHigh));
            }
            if (criticalLowAlarm)
            {
                assertions.set(static_cast<size_t>(
                    IPMIGetSensorEventEnableThresholds::lowerCriticalGoingLow));
            }
        }
    }

    return ipmi::responseSuccess(sensorEventStatus, assertions, deassertions);
}

static inline uint16_t getNumberOfSensors(void)
{
    return sensorTree.size() > maxIPMISensors ? maxIPMISensors
                                              : sensorTree.size();
}

static int getSensorDataRecord(ipmi::Context::ptr ctx,
                               std::vector<uint8_t>& recordData,
                               uint16_t recordID)
{
    size_t fruCount = 0;
    ipmi::Cc ret = ipmi::storage::getFruSdrCount(ctx, fruCount);
    if (ret != ipmi::ccSuccess)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: getFruSdrCount error");
        return GENERAL_ERROR;
    }

    size_t lastRecord = getNumberOfSensors() + fruCount +
                        ipmi::storage::type12Count +
                        ipmi::storage::nmDiscoverySDRCount - 1;
    if (recordID == lastRecordIndex)
    {
        recordID = lastRecord;
    }
    if (recordID > lastRecord)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: recordID > lastRecord error");
        return GENERAL_ERROR;
    }

    if (recordID >= getNumberOfSensors())
    {
        size_t fruIndex = recordID - getNumberOfSensors();
        size_t type12End = fruCount + ipmi::storage::type12Count;

        if (fruIndex >= type12End)
        {
            // NM discovery SDR
            size_t nmDiscoveryIndex = fruIndex - type12End;
            if (nmDiscoveryIndex >= ipmi::storage::nmDiscoverySDRCount)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "getSensorDataRecord: NM DiscoveryIndex error");
                return GENERAL_ERROR;
            }
            recordData = ipmi::storage::getNMDiscoverySDR(nmDiscoveryIndex,
                                                          recordID);
        }
        else if (fruIndex >= fruCount)
        {
            // handle type 12 hardcoded records
            size_t type12Index = fruIndex - fruCount;
            if (type12Index >= ipmi::storage::type12Count)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "getSensorDataRecord: type12Index error");
                return GENERAL_ERROR;
            }
            recordData = ipmi::storage::getType12SDRs(type12Index, recordID);
        }
        else
        {
            // handle fru records
            get_sdr::SensorDataFruRecord data;
            ret = ipmi::storage::getFruSdrs(ctx, fruIndex, data);
            if (ret != IPMI_CC_OK)
            {
                return GENERAL_ERROR;
            }
            data.header.record_id_msb = recordID >> 8;
            data.header.record_id_lsb = recordID & 0xFF;
            recordData.insert(recordData.end(), (uint8_t*)&data,
                              ((uint8_t*)&data) + sizeof(data));
        }

        return 0;
    }

    // Perform a incremental scan of the SDR Record ID's and translate the
    // first 765 SDR records (i.e. maxIPMISensors) into IPMI Sensor
    // Numbers. The IPMI sensor numbers are not linear, and have a reserved
    // gap at 0xff. This code creates 254 sensors per LUN, excepting LUN 2
    // which has special meaning.
    std::string connection;
    std::string path;
    uint16_t sensNumFromRecID{recordID};
    if ((recordID > lun0MaxSensorNum) && (recordID < lun1MaxSensorNum))
    {
        // LUN 0 has one reserved sensor number. Compensate here by adding one
        // to the record ID
        sensNumFromRecID = recordID + 1;
        ctx->lun = 1;
    }
    else if ((recordID >= lun1MaxSensorNum) && (recordID < maxIPMISensors))
    {
        // LUN 0, 1 have a reserved sensor number. Compensate here by adding 2
        // to the record ID. Skip all 256 sensors in LUN 2, as it has special
        // rules governing its use.
        sensNumFromRecID = recordID + (maxSensorsPerLUN + 1) + 2;
        ctx->lun = 3;
    }

    auto status = getSensorConnection(
        ctx, static_cast<uint8_t>(sensNumFromRecID), connection, path);
    if (status)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: getSensorConnection error");
        return GENERAL_ERROR;
    }
    SensorMap sensorMap;
    if (!getSensorMap(ctx->yield, connection, path, sensorMap,
                      sensorMapUpdatePeriod))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: getSensorMap error");
        return GENERAL_ERROR;
    }
    uint16_t sensorNum = getSensorNumberFromPath(path);
    // Return an error on LUN 2 assingments, and any sensor number beyond the
    // range of LUN 3
    if (((sensorNum > lun1MaxSensorNum) && (sensorNum <= maxIPMISensors)) ||
        (sensorNum > lun3MaxSensorNum))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: invalidSensorNumber");
        return GENERAL_ERROR;
    }
    uint8_t sensornumber = static_cast<uint8_t>(sensorNum);
    uint8_t lun = static_cast<uint8_t>(sensorNum >> 8);

    if ((sensornumber != static_cast<uint8_t>(sensNumFromRecID)) &&
        (lun != ctx->lun))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: sensor record mismatch");
        return GENERAL_ERROR;
    }
    get_sdr::SensorDataFullRecord record = {{}, {}, {}};

    get_sdr::header::set_record_id(
        recordID, reinterpret_cast<get_sdr::SensorDataRecordHeader*>(&record));

    record.header.sdr_version = ipmiSdrVersion;
    record.header.record_type = get_sdr::SENSOR_DATA_FULL_RECORD;
    record.header.record_length = sizeof(get_sdr::SensorDataFullRecord) -
                                  sizeof(get_sdr::SensorDataRecordHeader);
    record.key.owner_id = 0x20;
    record.key.owner_lun = lun;
    record.key.sensor_number = sensornumber;

    record.body.sensor_capabilities = 0x68; // auto rearm - todo hysteresis
    record.body.sensor_type = getSensorTypeFromPath(path);
    std::string type = getSensorTypeStringFromPath(path);
    for (const auto& [unitsType, units] : sensorUnits)
    {
        if (type == unitsType)
        {
            record.body.sensor_units_2_base = static_cast<uint8_t>(units);
        }
    }

    record.body.event_reading_type = getSensorEventTypeFromPath(path);

    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");
    if (sensorObject == sensorMap.end())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: sensorObject error");
        return GENERAL_ERROR;
    }

    uint8_t entityId = 0;
    uint8_t entityInstance = 0x01;

    // follow the association chain to get the parent board's entityid and
    // entityInstance
    updateIpmiFromAssociation(path, sensorMap, entityId, entityInstance);

    record.body.entity_id = entityId;
    record.body.entity_instance = entityInstance;

    auto maxObject = sensorObject->second.find("MaxValue");
    auto minObject = sensorObject->second.find("MinValue");

    // If min and/or max are left unpopulated,
    // then default to what a signed byte would be, namely (-128,127) range.
    auto max = static_cast<double>(std::numeric_limits<int8_t>::max());
    auto min = static_cast<double>(std::numeric_limits<int8_t>::lowest());
    if (maxObject != sensorObject->second.end())
    {
        max = std::visit(VariantToDoubleVisitor(), maxObject->second);
    }

    if (minObject != sensorObject->second.end())
    {
        min = std::visit(VariantToDoubleVisitor(), minObject->second);
    }

    int16_t mValue = 0;
    int8_t rExp = 0;
    int16_t bValue = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: getSensorAttributes error");
        return GENERAL_ERROR;
    }

    // The record.body is a struct SensorDataFullRecordBody
    // from sensorhandler.hpp in phosphor-ipmi-host.
    // The meaning of these bits appears to come from
    // table 43.1 of the IPMI spec.
    // The above 5 sensor attributes are stuffed in as follows:
    // Byte 21 = AA000000 = analog interpretation, 10 signed, 00 unsigned
    // Byte 22-24 are for other purposes
    // Byte 25 = MMMMMMMM = LSB of M
    // Byte 26 = MMTTTTTT = MSB of M (signed), and Tolerance
    // Byte 27 = BBBBBBBB = LSB of B
    // Byte 28 = BBAAAAAA = MSB of B (signed), and LSB of Accuracy
    // Byte 29 = AAAAEE00 = MSB of Accuracy, exponent of Accuracy
    // Byte 30 = RRRRBBBB = rExp (signed), bExp (signed)

    // apply M, B, and exponents, M and B are 10 bit values, exponents are 4
    record.body.m_lsb = mValue & 0xFF;

    uint8_t mBitSign = (mValue < 0) ? 1 : 0;
    uint8_t mBitNine = (mValue & 0x0100) >> 8;

    // move the smallest bit of the MSB into place (bit 9)
    // the MSbs are bits 7:8 in m_msb_and_tolerance
    record.body.m_msb_and_tolerance = (mBitSign << 7) | (mBitNine << 6);

    record.body.b_lsb = bValue & 0xFF;

    uint8_t bBitSign = (bValue < 0) ? 1 : 0;
    uint8_t bBitNine = (bValue & 0x0100) >> 8;

    // move the smallest bit of the MSB into place (bit 9)
    // the MSbs are bits 7:8 in b_msb_and_accuracy_lsb
    record.body.b_msb_and_accuracy_lsb = (bBitSign << 7) | (bBitNine << 6);

    uint8_t rExpSign = (rExp < 0) ? 1 : 0;
    uint8_t rExpBits = rExp & 0x07;

    uint8_t bExpSign = (bExp < 0) ? 1 : 0;
    uint8_t bExpBits = bExp & 0x07;

    // move rExp and bExp into place
    record.body.r_b_exponents = (rExpSign << 7) | (rExpBits << 4) |
                                (bExpSign << 3) | bExpBits;

    // Set the analog reading byte interpretation accordingly
    record.body.sensor_units_1 = (bSigned ? 1 : 0) << 7;

    // TODO(): Perhaps care about Tolerance, Accuracy, and so on
    // These seem redundant, but derivable from the above 5 attributes
    // Original comment said "todo fill out rest of units"

    // populate sensor name from path
    std::string name;
    size_t nameStart = path.rfind("/");
    if (nameStart != std::string::npos)
    {
        name = path.substr(nameStart + 1, std::string::npos - nameStart);
    }

    std::replace(name.begin(), name.end(), '_', ' ');
    if (name.size() > FULL_RECORD_ID_STR_MAX_LENGTH)
    {
        // try to not truncate by replacing common words
        constexpr std::array<std::pair<const char*, const char*>, 2>
            replaceWords = {std::make_pair("Output", "Out"),
                            std::make_pair("Input", "In")};
        for (const auto& [find, replace] : replaceWords)
        {
            boost::replace_all(name, find, replace);
        }

        name.resize(FULL_RECORD_ID_STR_MAX_LENGTH);
    }
    get_sdr::body::set_id_strlen(name.size(), &record.body);
    get_sdr::body::set_id_type(3, &record.body); // "8-bit ASCII + Latin 1"
    std::strncpy(record.body.id_string, name.c_str(),
                 sizeof(record.body.id_string));

    // Remember the sensor name, as determined for this sensor number
    details::sdrStatsTable.updateName(sensornumber, name);

    IPMIThresholds thresholdData;
    try
    {
        thresholdData = getIPMIThresholds(sensorMap);
    }
    catch (const std::exception&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSensorDataRecord: getIPMIThresholds error");
        return GENERAL_ERROR;
    }

    if (thresholdData.criticalHigh)
    {
        record.body.upper_critical_threshold = *thresholdData.criticalHigh;
        record.body.supported_deassertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::criticalThreshold);
        record.body.supported_deassertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperCriticalGoingHigh);
        record.body.supported_assertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperCriticalGoingHigh);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::upperCritical);
    }
    if (thresholdData.warningHigh)
    {
        record.body.upper_noncritical_threshold = *thresholdData.warningHigh;
        record.body.supported_deassertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::nonCriticalThreshold);
        record.body.supported_deassertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperNonCriticalGoingHigh);
        record.body.supported_assertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperNonCriticalGoingHigh);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::upperNonCritical);
    }
    if (thresholdData.criticalLow)
    {
        record.body.lower_critical_threshold = *thresholdData.criticalLow;
        record.body.supported_assertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::criticalThreshold);
        record.body.supported_deassertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
        record.body.supported_assertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::lowerCritical);
    }
    if (thresholdData.warningLow)
    {
        record.body.lower_noncritical_threshold = *thresholdData.warningLow;
        record.body.supported_assertions[1] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::nonCriticalThreshold);
        record.body.supported_deassertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerNonCriticalGoingLow);
        record.body.supported_assertions[0] |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerNonCriticalGoingLow);
        record.body.discrete_reading_setting_mask[0] |=
            static_cast<uint8_t>(IPMISensorReadingByte3::lowerNonCritical);
    }

    // everything that is readable is setable
    record.body.discrete_reading_setting_mask[1] =
        record.body.discrete_reading_setting_mask[0];
    recordData.insert(recordData.end(), (uint8_t*)&record,
                      ((uint8_t*)&record) + sizeof(record));
    return 0;
}

/** @brief implements the get SDR Info command
 *  @param count - Operation
 *
 *  @returns IPMI completion code plus response data
 *   - sdrCount - sensor/SDR count
 *   - lunsAndDynamicPopulation - static/Dynamic sensor population flag
 */
static ipmi::RspType<uint8_t, // respcount
                     uint8_t, // dynamic population flags
                     uint32_t // last time a sensor was added
                     >
    ipmiSensorGetDeviceSdrInfo(ipmi::Context::ptr ctx,
                               std::optional<uint8_t> count)
{
    uint8_t sdrCount = 0;
    uint16_t recordID = 0;
    std::vector<uint8_t> record;
    // Sensors are dynamically allocated, and there is at least one LUN
    uint8_t lunsAndDynamicPopulation = 0x80;
    constexpr uint8_t getSdrCount = 0x01;
    constexpr uint8_t getSensorCount = 0x00;

    if (!getSensorSubtree(sensorTree) || sensorTree.empty())
    {
        return ipmi::responseResponseError();
    }
    uint16_t numSensors = getNumberOfSensors();
    if (count.value_or(0) == getSdrCount)
    {
        // Count the number of Type 1 SDR entries assigned to the LUN
        while (!getSensorDataRecord(ctx, record, recordID++))
        {
            get_sdr::SensorDataRecordHeader* hdr =
                reinterpret_cast<get_sdr::SensorDataRecordHeader*>(
                    record.data());
            if (hdr->record_type == get_sdr::SENSOR_DATA_FULL_RECORD)
            {
                get_sdr::SensorDataFullRecord* recordData =
                    reinterpret_cast<get_sdr::SensorDataFullRecord*>(
                        record.data());
                if (ctx->lun == recordData->key.owner_lun)
                {
                    sdrCount++;
                }
            }
        }
    }
    else if (count.value_or(0) == getSensorCount)
    {
        // Return the number of sensors attached to the LUN
        if ((ctx->lun == 0) && (numSensors > 0))
        {
            sdrCount = (numSensors > maxSensorsPerLUN) ? maxSensorsPerLUN
                                                       : numSensors;
        }
        else if ((ctx->lun == 1) && (numSensors > maxSensorsPerLUN))
        {
            sdrCount = (numSensors > (2 * maxSensorsPerLUN))
                           ? maxSensorsPerLUN
                           : (numSensors - maxSensorsPerLUN) & maxSensorsPerLUN;
        }
        else if (ctx->lun == 3)
        {
            if (numSensors <= maxIPMISensors)
            {
                sdrCount = (numSensors - (2 * maxSensorsPerLUN)) &
                           maxSensorsPerLUN;
            }
            else
            {
                // error
                throw std::out_of_range(
                    "Maximum number of IPMI sensors exceeded.");
            }
        }
    }
    else
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Get Sensor count. This returns the number of sensors
    if (numSensors > 0)
    {
        lunsAndDynamicPopulation |= 1;
    }
    if (numSensors > maxSensorsPerLUN)
    {
        lunsAndDynamicPopulation |= 2;
    }
    if (numSensors >= (maxSensorsPerLUN * 2))
    {
        lunsAndDynamicPopulation |= 8;
    }
    if (numSensors > maxIPMISensors)
    {
        // error
        throw std::out_of_range("Maximum number of IPMI sensors exceeded.");
    }

    return ipmi::responseSuccess(sdrCount, lunsAndDynamicPopulation,
                                 sdrLastAdd);
}

/* end sensor commands */

/* storage commands */

ipmi::RspType<uint8_t,  // sdr version
              uint16_t, // record count
              uint16_t, // free space
              uint32_t, // most recent addition
              uint32_t, // most recent erase
              uint8_t   // operationSupport
              >
    ipmiStorageGetSDRRepositoryInfo(ipmi::Context::ptr ctx)
{
    constexpr const uint16_t unspecifiedFreeSpace = 0xFFFF;
    if (!getSensorSubtree(sensorTree) && sensorTree.empty())
    {
        return ipmi::responseResponseError();
    }

    size_t fruCount = 0;
    ipmi::Cc ret = ipmi::storage::getFruSdrCount(ctx, fruCount);
    if (ret != ipmi::ccSuccess)
    {
        return ipmi::response(ret);
    }

    uint16_t recordCount = getNumberOfSensors() + fruCount +
                           ipmi::storage::type12Count +
                           ipmi::storage::nmDiscoverySDRCount;

    uint8_t operationSupport = static_cast<uint8_t>(
        SdrRepositoryInfoOps::overflow); // write not supported

    operationSupport |=
        static_cast<uint8_t>(SdrRepositoryInfoOps::allocCommandSupported);
    operationSupport |= static_cast<uint8_t>(
        SdrRepositoryInfoOps::reserveSDRRepositoryCommandSupported);
    return ipmi::responseSuccess(ipmiSdrVersion, recordCount,
                                 unspecifiedFreeSpace, sdrLastAdd,
                                 sdrLastRemove, operationSupport);
}

/** @brief implements the get SDR allocation info command
 *
 *  @returns IPMI completion code plus response data
 *   - allocUnits    - Number of possible allocation units
 *   - allocUnitSize - Allocation unit size in bytes.
 *   - allocUnitFree - Number of free allocation units
 *   - allocUnitLargestFree - Largest free block in allocation units
 *   - maxRecordSize    - Maximum record size in allocation units.
 */
ipmi::RspType<uint16_t, // allocUnits
              uint16_t, // allocUnitSize
              uint16_t, // allocUnitFree
              uint16_t, // allocUnitLargestFree
              uint8_t   // maxRecordSize
              >
    ipmiStorageGetSDRAllocationInfo()
{
    // 0000h unspecified number of alloc units
    constexpr uint16_t allocUnits = 0;

    constexpr uint16_t allocUnitFree = 0;
    constexpr uint16_t allocUnitLargestFree = 0;
    // only allow one block at a time
    constexpr uint8_t maxRecordSize = 1;

    return ipmi::responseSuccess(allocUnits, maxSDRTotalSize, allocUnitFree,
                                 allocUnitLargestFree, maxRecordSize);
}

/** @brief implements the reserve SDR command
 *  @returns IPMI completion code plus response data
 *   - sdrReservationID
 */
ipmi::RspType<uint16_t> ipmiStorageReserveSDR()
{
    sdrReservationID++;
    if (sdrReservationID == 0)
    {
        sdrReservationID++;
    }

    return ipmi::responseSuccess(sdrReservationID);
}

ipmi::RspType<uint16_t,            // next record ID
              std::vector<uint8_t> // payload
              >
    ipmiStorageGetSDR(ipmi::Context::ptr ctx, uint16_t reservationID,
                      uint16_t recordID, uint8_t offset, uint8_t bytesToRead)
{
    size_t fruCount = 0;
    // reservation required for partial reads with non zero offset into
    // record
    if ((sdrReservationID == 0 || reservationID != sdrReservationID) && offset)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiStorageGetSDR: responseInvalidReservationId");
        return ipmi::responseInvalidReservationId();
    }
    ipmi::Cc ret = ipmi::storage::getFruSdrCount(ctx, fruCount);
    if (ret != ipmi::ccSuccess)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiStorageGetSDR: getFruSdrCount error");
        return ipmi::response(ret);
    }

    size_t lastRecord = getNumberOfSensors() + fruCount +
                        ipmi::storage::type12Count +
                        ipmi::storage::nmDiscoverySDRCount - 1;
    uint16_t nextRecordId = lastRecord > recordID ? recordID + 1 : 0XFFFF;

    if (!getSensorSubtree(sensorTree) && sensorTree.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiStorageGetSDR: getSensorSubtree error");
        return ipmi::responseResponseError();
    }

    std::vector<uint8_t> record;
    if (getSensorDataRecord(ctx, record, recordID))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiStorageGetSDR: fail to get SDR");
        return ipmi::responseInvalidFieldRequest();
    }
    get_sdr::SensorDataRecordHeader* hdr =
        reinterpret_cast<get_sdr::SensorDataRecordHeader*>(record.data());
    if (!hdr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiStorageGetSDR: record header is null");
        return ipmi::responseSuccess(nextRecordId, record);
    }

    size_t sdrLength = sizeof(get_sdr::SensorDataRecordHeader) +
                       hdr->record_length;
    if (offset >= sdrLength)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiStorageGetSDR: offset is outside the record");
        return ipmi::responseParmOutOfRange();
    }
    if (sdrLength < (offset + bytesToRead))
    {
        bytesToRead = sdrLength - offset;
    }

    uint8_t* respStart = reinterpret_cast<uint8_t*>(hdr) + offset;
    if (!respStart)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiStorageGetSDR: record is null");
        return ipmi::responseSuccess(nextRecordId, record);
    }
    std::vector<uint8_t> recordData(respStart, respStart + bytesToRead);

    return ipmi::responseSuccess(nextRecordId, recordData);
}
/* end storage commands */

void registerSensorFunctions()
{
    // <Platform Event>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdPlatformEvent,
                          ipmi::Privilege::Operator, ipmiSenPlatformEvent);

    // <Get Sensor Reading>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorReading,
                          ipmi::Privilege::User, ipmiSenGetSensorReading);

    // <Get Sensor Threshold>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorThreshold,
                          ipmi::Privilege::User, ipmiSenGetSensorThresholds);

    // <Set Sensor Threshold>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdSetSensorThreshold,
                          ipmi::Privilege::Operator,
                          ipmiSenSetSensorThresholds);

    // <Get Sensor Event Enable>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorEventEnable,
                          ipmi::Privilege::User, ipmiSenGetSensorEventEnable);

    // <Get Sensor Event Status>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetSensorEventStatus,
                          ipmi::Privilege::User, ipmiSenGetSensorEventStatus);

    // register all storage commands for both Sensor and Storage command
    // versions

    // <Get SDR Repository Info>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdrRepositoryInfo,
                          ipmi::Privilege::User,
                          ipmiStorageGetSDRRepositoryInfo);

    // <Get Device SDR Info>
    ipmi::registerHandler(ipmi::prioOpenBmcBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetDeviceSdrInfo,
                          ipmi::Privilege::User, ipmiSensorGetDeviceSdrInfo);

    // <Get SDR Allocation Info>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdrRepositoryAllocInfo,
                          ipmi::Privilege::User,
                          ipmiStorageGetSDRAllocationInfo);

    // <Reserve SDR Repo>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdReserveDeviceSdrRepository,
                          ipmi::Privilege::User, ipmiStorageReserveSDR);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdReserveSdrRepository,
                          ipmi::Privilege::User, ipmiStorageReserveSDR);

    // <Get Sdr>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdGetDeviceSdr,
                          ipmi::Privilege::User, ipmiStorageGetSDR);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnStorage,
                          ipmi::storage::cmdGetSdr, ipmi::Privilege::User,
                          ipmiStorageGetSDR);
}
} // namespace ipmi
