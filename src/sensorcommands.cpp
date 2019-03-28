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

#include <ipmid/api.h>

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <chrono>
#include <cmath>
#include <commandutils.hpp>
#include <iostream>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdrutils.hpp>
#include <sensorcommands.hpp>
#include <sensorutils.hpp>
#include <storagecommands.hpp>
#include <string>

namespace ipmi
{
using ManagedObjectType =
    std::map<sdbusplus::message::object_path,
             std::map<std::string, std::map<std::string, DbusVariant>>>;

using SensorMap = std::map<std::string, std::map<std::string, DbusVariant>>;
namespace variant_ns = sdbusplus::message::variant_ns;

static constexpr int sensorListUpdatePeriod = 10;
static constexpr int sensorMapUpdatePeriod = 2;

constexpr size_t maxSDRTotalSize =
    76; // Largest SDR Record Size (type 01) + SDR Overheader Size
constexpr static const uint32_t noTimestamp = 0xFFFFFFFF;

static uint16_t sdrReservationID;
static uint32_t sdrLastAdd = noTimestamp;
static uint32_t sdrLastRemove = noTimestamp;

SensorSubTree sensorTree;
static boost::container::flat_map<std::string, ManagedObjectType> SensorCache;

// Specify the comparison required to sort and find char* map objects
struct CmpStr
{
    bool operator()(const char *a, const char *b) const
    {
        return std::strcmp(a, b) < 0;
    }
};
const static boost::container::flat_map<const char *, SensorUnits, CmpStr>
    sensorUnits{{{"temperature", SensorUnits::degreesC},
                 {"voltage", SensorUnits::volts},
                 {"current", SensorUnits::amps},
                 {"fan_tach", SensorUnits::rpm},
                 {"power", SensorUnits::watts}}};

void registerSensorFunctions() __attribute__((constructor));
static sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());

static sdbusplus::bus::match::match sensorAdded(
    dbus,
    "type='signal',member='InterfacesAdded',arg0path='/xyz/openbmc_project/"
    "sensors/'",
    [](sdbusplus::message::message &m) {
        sensorTree.clear();
        sdrLastAdd = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    });

static sdbusplus::bus::match::match sensorRemoved(
    dbus,
    "type='signal',member='InterfacesRemoved',arg0path='/xyz/openbmc_project/"
    "sensors/'",
    [](sdbusplus::message::message &m) {
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

static sdbusplus::bus::match::match thresholdChanged(
    dbus,
    "type='signal',member='PropertiesChanged',interface='org.freedesktop.DBus."
    "Properties',arg0namespace='xyz.openbmc_project.Sensor.Threshold'",
    [](sdbusplus::message::message &m) {
        boost::container::flat_map<std::string, std::variant<bool, double>>
            values;
        m.read(std::string(), values);

        auto findAssert =
            std::find_if(values.begin(), values.end(), [](const auto &pair) {
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
                auto &value =
                    thresholdDeassertMap[m.get_path()][findAssert->first];
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

static void
    getSensorMaxMin(const std::map<std::string, DbusVariant> &sensorPropertyMap,
                    double &max, double &min)
{
    auto maxMap = sensorPropertyMap.find("MaxValue");
    auto minMap = sensorPropertyMap.find("MinValue");
    max = 127;
    min = -128;

    if (maxMap != sensorPropertyMap.end())
    {
        max = variant_ns::visit(VariantToDoubleVisitor(), maxMap->second);
    }
    if (minMap != sensorPropertyMap.end())
    {
        min = variant_ns::visit(VariantToDoubleVisitor(), minMap->second);
    }
}

static bool getSensorMap(std::string sensorConnection, std::string sensorPath,
                         SensorMap &sensorMap)
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
            .count() > sensorMapUpdatePeriod)
    {
        updateTimeMap[sensorConnection] = now;

        auto managedObj = dbus.new_method_call(
            sensorConnection.c_str(), "/", "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects");

        ManagedObjectType managedObjects;
        try
        {
            auto reply = dbus.call(managedObj);
            reply.read(managedObjects);
        }
        catch (sdbusplus::exception_t &)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error getting managed objects from connection",
                phosphor::logging::entry("CONNECTION=%s",
                                         sensorConnection.c_str()));
            return false;
        }

        SensorCache[sensorConnection] = managedObjects;
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
ipmi_ret_t ipmiSensorWildcardHandler(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                     ipmi_request_t request,
                                     ipmi_response_t response,
                                     ipmi_data_len_t dataLen,
                                     ipmi_context_t context)
{
    *dataLen = 0;
    printCommand(+netfn, +cmd);
    return IPMI_CC_INVALID;
}

ipmi_ret_t ipmiSenGetSensorReading(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t dataLen,
                                   ipmi_context_t context)
{
    if (*dataLen != 1)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error

    uint8_t sensnum = *(static_cast<uint8_t *>(request));

    std::string connection;
    std::string path;

    auto status = getSensorConnection(sensnum, connection, path);
    if (status)
    {
        return status;
    }

    SensorMap sensorMap;
    if (!getSensorMap(connection, path, sensorMap))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");

    if (sensorObject == sensorMap.end() ||
        sensorObject->second.find("Value") == sensorObject->second.end())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    auto &value = sensorObject->second["Value"];
    double reading = variant_ns::visit(VariantToDoubleVisitor(), value);

    double max;
    double min;
    getSensorMaxMin(sensorObject->second, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    SensorReadingResp *msgReply = static_cast<SensorReadingResp *>(response);
    *dataLen = sizeof(SensorReadingResp);

    msgReply->value =
        scaleIPMIValueFromDouble(reading, mValue, rExp, bValue, bExp, bSigned);
    msgReply->operation =
        static_cast<uint8_t>(IPMISensorReadingByte2::sensorScanningEnable);
    msgReply->operation |=
        static_cast<uint8_t>(IPMISensorReadingByte2::eventMessagesEnable);
    msgReply->indication[0] = 0; // ignore for non-threshold sensors
    msgReply->indication[1] = 0;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiSenSetSensorThresholds(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                      ipmi_request_t request,
                                      ipmi_response_t response,
                                      ipmi_data_len_t dataLen,
                                      ipmi_context_t context)
{
    if (*dataLen != 8)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0;

    SensorThresholdReq *req = static_cast<SensorThresholdReq *>(request);

    // upper two bits reserved
    if (req->mask & 0xC0)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // lower nc and upper nc not suppported on any sensor
    if ((req->mask & static_cast<uint8_t>(
                         SensorThresholdReqEnable::setLowerNonRecoverable)) ||
        (req->mask & static_cast<uint8_t>(
                         SensorThresholdReqEnable::setUpperNonRecoverable)))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // if no bits are set in the mask, nothing to do
    if (!(req->mask))
    {
        return IPMI_CC_OK;
    }

    std::string connection;
    std::string path;

    ipmi_ret_t status = getSensorConnection(req->sensorNum, connection, path);
    if (status)
    {
        return status;
    }
    SensorMap sensorMap;
    if (!getSensorMap(connection, path, sensorMap))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");

    if (sensorObject == sensorMap.end())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    double max = 0;
    double min = 0;
    getSensorMaxMin(sensorObject->second, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    bool setLowerCritical =
        req->mask &
        static_cast<uint8_t>(SensorThresholdReqEnable::setLowerCritical);
    bool setUpperCritical =
        req->mask &
        static_cast<uint8_t>(SensorThresholdReqEnable::setUpperCritical);

    bool setLowerWarning =
        req->mask &
        static_cast<uint8_t>(SensorThresholdReqEnable::setLowerNonCritical);
    bool setUpperWarning =
        req->mask &
        static_cast<uint8_t>(SensorThresholdReqEnable::setUpperNonCritical);

    // store a vector of property name, value to set, and interface
    std::vector<std::tuple<std::string, uint8_t, std::string>> thresholdsToSet;

    // define the indexes of the tuple
    constexpr uint8_t propertyName = 0;
    constexpr uint8_t thresholdValue = 1;
    constexpr uint8_t interface = 2;
    // verifiy all needed fields are present
    if (setLowerCritical || setUpperCritical)
    {
        auto findThreshold =
            sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");
        if (findThreshold == sensorMap.end())
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        if (setLowerCritical)
        {
            auto findLower = findThreshold->second.find("CriticalLow");
            if (findLower == findThreshold->second.end())
            {
                return IPMI_CC_INVALID_FIELD_REQUEST;
            }
            thresholdsToSet.emplace_back("CriticalLow", req->lowerCritical,
                                         findThreshold->first);
        }
        if (setUpperCritical)
        {
            auto findUpper = findThreshold->second.find("CriticalHigh");
            if (findUpper == findThreshold->second.end())
            {
                return IPMI_CC_INVALID_FIELD_REQUEST;
            }
            thresholdsToSet.emplace_back("CriticalHigh", req->upperCritical,
                                         findThreshold->first);
        }
    }
    if (setLowerWarning || setUpperWarning)
    {
        auto findThreshold =
            sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
        if (findThreshold == sensorMap.end())
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        if (setLowerWarning)
        {
            auto findLower = findThreshold->second.find("WarningLow");
            if (findLower == findThreshold->second.end())
            {
                return IPMI_CC_INVALID_FIELD_REQUEST;
            }
            thresholdsToSet.emplace_back("WarningLow", req->lowerNonCritical,
                                         findThreshold->first);
        }
        if (setUpperWarning)
        {
            auto findUpper = findThreshold->second.find("WarningHigh");
            if (findUpper == findThreshold->second.end())
            {
                return IPMI_CC_INVALID_FIELD_REQUEST;
            }
            thresholdsToSet.emplace_back("WarningHigh", req->upperNonCritical,
                                         findThreshold->first);
        }
    }

    for (const auto &property : thresholdsToSet)
    {
        // from section 36.3 in the IPMI Spec, assume all linear
        double valueToSet = ((mValue * std::get<thresholdValue>(property)) +
                             (bValue * std::pow(10, bExp))) *
                            std::pow(10, rExp);
        setDbusProperty(dbus, connection, path, std::get<interface>(property),
                        std::get<propertyName>(property),
                        ipmi::Value(valueToSet));
    }

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiSenGetSensorThresholds(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                      ipmi_request_t request,
                                      ipmi_response_t response,
                                      ipmi_data_len_t dataLen,
                                      ipmi_context_t context)
{
    if (*dataLen != 1)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error

    uint8_t sensnum = *(static_cast<uint8_t *>(request));

    std::string connection;
    std::string path;

    auto status = getSensorConnection(sensnum, connection, path);
    if (status)
    {
        return status;
    }

    SensorMap sensorMap;
    if (!getSensorMap(connection, path, sensorMap))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    // zero out response buff
    auto responseClear = static_cast<uint8_t *>(response);
    std::fill(responseClear, responseClear + sizeof(SensorThresholdResp), 0);

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
            return IPMI_CC_RESPONSE_ERROR;
        }

        double max;
        double min;
        getSensorMaxMin(sensorPair->second, max, min);

        int16_t mValue = 0;
        int16_t bValue = 0;
        int8_t rExp = 0;
        int8_t bExp = 0;
        bool bSigned = false;

        if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
        {
            return IPMI_CC_RESPONSE_ERROR;
        }

        auto msgReply = static_cast<SensorThresholdResp *>(response);

        if (warningInterface != sensorMap.end())
        {
            auto &warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningHigh");
            auto warningLow = warningMap.find("WarningLow");

            if (warningHigh != warningMap.end())
            {
                msgReply->readable |=
                    1 << static_cast<int>(
                        IPMIhresholdRespBits::upperNonCritical);
                double value = variant_ns::visit(VariantToDoubleVisitor(),
                                                 warningHigh->second);
                msgReply->uppernc = scaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
            }
            if (warningLow != warningMap.end())
            {
                msgReply->readable |=
                    1 << static_cast<int>(
                        IPMIhresholdRespBits::lowerNonCritical);
                double value = variant_ns::visit(VariantToDoubleVisitor(),
                                                 warningLow->second);
                msgReply->lowernc = scaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto &criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalHigh");
            auto criticalLow = criticalMap.find("CriticalLow");

            if (criticalHigh != criticalMap.end())
            {
                msgReply->readable |=
                    1 << static_cast<int>(IPMIhresholdRespBits::upperCritical);
                double value = variant_ns::visit(VariantToDoubleVisitor(),
                                                 criticalHigh->second);
                msgReply->uppercritical = scaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
            }
            if (criticalLow != criticalMap.end())
            {
                msgReply->readable |=
                    1 << static_cast<int>(IPMIhresholdRespBits::lowerCritical);
                double value = variant_ns::visit(VariantToDoubleVisitor(),
                                                 criticalLow->second);
                msgReply->lowercritical = scaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
            }
        }
    }

    *dataLen = sizeof(SensorThresholdResp);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiSenGetSensorEventEnable(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t dataLen,
                                       ipmi_context_t context)
{
    if (*dataLen != 1)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error

    uint8_t sensnum = *(static_cast<uint8_t *>(request));

    std::string connection;
    std::string path;

    auto status = getSensorConnection(sensnum, connection, path);
    if (status)
    {
        return status;
    }

    SensorMap sensorMap;
    if (!getSensorMap(connection, path, sensorMap))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");

    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()))
    {
        // zero out response buff
        auto responseClear = static_cast<uint8_t *>(response);
        std::fill(responseClear, responseClear + sizeof(SensorEventEnableResp),
                  0);

        // assume all threshold sensors
        auto resp = static_cast<SensorEventEnableResp *>(response);

        resp->enabled = static_cast<uint8_t>(
            IPMISensorEventEnableByte2::sensorScanningEnable);
        if (warningInterface != sensorMap.end())
        {
            auto &warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningHigh");
            auto warningLow = warningMap.find("WarningLow");
            if (warningHigh != warningMap.end())
            {
                resp->assertionEnabledLSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::upperNonCriticalGoingHigh);
                resp->deassertionEnabledLSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::upperNonCriticalGoingLow);
            }
            if (warningLow != warningMap.end())
            {
                resp->assertionEnabledLSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::lowerNonCriticalGoingLow);
                resp->deassertionEnabledLSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::lowerNonCriticalGoingHigh);
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto &criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalHigh");
            auto criticalLow = criticalMap.find("CriticalLow");

            if (criticalHigh != criticalMap.end())
            {
                resp->assertionEnabledMSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::upperCriticalGoingHigh);
                resp->deassertionEnabledMSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::upperCriticalGoingLow);
            }
            if (criticalLow != criticalMap.end())
            {
                resp->assertionEnabledLSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
                resp->deassertionEnabledLSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::lowerCriticalGoingHigh);
            }
        }
        *dataLen =
            sizeof(SensorEventEnableResp); // todo only return needed bytes
    }
    // no thresholds enabled
    else
    {
        *dataLen = 1;
        auto resp = static_cast<uint8_t *>(response);
        *resp = static_cast<uint8_t>(
            IPMISensorEventEnableByte2::eventMessagesEnable);
        *resp |= static_cast<uint8_t>(
            IPMISensorEventEnableByte2::sensorScanningEnable);
    }
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiSenGetSensorEventStatus(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t dataLen,
                                       ipmi_context_t context)
{
    if (*dataLen != 1)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error

    uint8_t sensnum = *(static_cast<uint8_t *>(request));

    std::string connection;
    std::string path;

    auto status = getSensorConnection(sensnum, connection, path);
    if (status)
    {
        return status;
    }

    SensorMap sensorMap;
    if (!getSensorMap(connection, path, sensorMap))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");

    // zero out response buff
    auto responseClear = static_cast<uint8_t *>(response);
    std::fill(responseClear, responseClear + sizeof(SensorEventStatusResp), 0);
    auto resp = static_cast<SensorEventStatusResp *>(response);
    resp->enabled =
        static_cast<uint8_t>(IPMISensorEventEnableByte2::sensorScanningEnable);

    std::optional<bool> criticalDeassertHigh =
        thresholdDeassertMap[path]["CriticalAlarmHigh"];
    std::optional<bool> criticalDeassertLow =
        thresholdDeassertMap[path]["CriticalAlarmLow"];
    std::optional<bool> warningDeassertHigh =
        thresholdDeassertMap[path]["WarningAlarmHigh"];
    std::optional<bool> warningDeassertLow =
        thresholdDeassertMap[path]["WarningAlarmLow"];

    if (criticalDeassertHigh && !*criticalDeassertHigh)
    {
        resp->deassertionsMSB |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperCriticalGoingHigh);
    }
    if (criticalDeassertLow && !*criticalDeassertLow)
    {
        resp->deassertionsMSB |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperCriticalGoingLow);
    }
    if (warningDeassertHigh && !*warningDeassertHigh)
    {
        resp->deassertionsLSB |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::upperNonCriticalGoingHigh);
    }
    if (warningDeassertLow && !*warningDeassertLow)
    {
        resp->deassertionsLSB |= static_cast<uint8_t>(
            IPMISensorEventEnableThresholds::lowerNonCriticalGoingHigh);
    }

    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()))
    {
        resp->enabled = static_cast<uint8_t>(
            IPMISensorEventEnableByte2::eventMessagesEnable);
        if (warningInterface != sensorMap.end())
        {
            auto &warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningAlarmHigh");
            auto warningLow = warningMap.find("WarningAlarmLow");
            auto warningHighAlarm = false;
            auto warningLowAlarm = false;

            if (warningHigh != warningMap.end())
            {
                warningHighAlarm = sdbusplus::message::variant_ns::get<bool>(
                    warningHigh->second);
            }
            if (warningLow != warningMap.end())
            {
                warningLowAlarm = sdbusplus::message::variant_ns::get<bool>(
                    warningLow->second);
            }
            if (warningHighAlarm)
            {
                resp->assertionsLSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::upperNonCriticalGoingHigh);
            }
            if (warningLowAlarm)
            {
                resp->assertionsLSB |= 1; // lower nc going low
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto &criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalAlarmHigh");
            auto criticalLow = criticalMap.find("CriticalAlarmLow");
            auto criticalHighAlarm = false;
            auto criticalLowAlarm = false;

            if (criticalHigh != criticalMap.end())
            {
                criticalHighAlarm = sdbusplus::message::variant_ns::get<bool>(
                    criticalHigh->second);
            }
            if (criticalLow != criticalMap.end())
            {
                criticalLowAlarm = sdbusplus::message::variant_ns::get<bool>(
                    criticalLow->second);
            }
            if (criticalHighAlarm)
            {
                resp->assertionsMSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::upperCriticalGoingHigh);
            }
            if (criticalLowAlarm)
            {
                resp->assertionsLSB |= static_cast<uint8_t>(
                    IPMISensorEventEnableThresholds::lowerCriticalGoingLow);
            }
        }
        *dataLen = sizeof(SensorEventStatusResp);
    }

    // no thresholds enabled, don't need assertionMSB
    else
    {
        *dataLen = sizeof(SensorEventStatusResp) - 1;
    }

    return IPMI_CC_OK;
}

/* end sensor commands */

/* storage commands */

ipmi_ret_t ipmiStorageGetSDRRepositoryInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                           ipmi_request_t request,
                                           ipmi_response_t response,
                                           ipmi_data_len_t dataLen,
                                           ipmi_context_t context)
{
    printCommand(+netfn, +cmd);

    if (*dataLen)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error

    if (sensorTree.empty() && !getSensorSubtree(sensorTree))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    // zero out response buff
    auto responseClear = static_cast<uint8_t *>(response);
    std::fill(responseClear, responseClear + sizeof(GetSDRInfoResp), 0);

    auto resp = static_cast<GetSDRInfoResp *>(response);
    resp->sdrVersion = ipmiSdrVersion;
    uint16_t recordCount = sensorTree.size();

    // todo: for now, sdr count is number of sensors
    resp->recordCountLS = recordCount & 0xFF;
    resp->recordCountMS = recordCount >> 8;

    // free space unspcified
    resp->freeSpace[0] = 0xFF;
    resp->freeSpace[1] = 0xFF;

    resp->mostRecentAddition = sdrLastAdd;
    resp->mostRecentErase = sdrLastRemove;
    resp->operationSupport = static_cast<uint8_t>(
        SdrRepositoryInfoOps::overflow); // write not supported
    resp->operationSupport |=
        static_cast<uint8_t>(SdrRepositoryInfoOps::allocCommandSupported);
    resp->operationSupport |= static_cast<uint8_t>(
        SdrRepositoryInfoOps::reserveSDRRepositoryCommandSupported);
    *dataLen = sizeof(GetSDRInfoResp);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageGetSDRAllocationInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                           ipmi_request_t request,
                                           ipmi_response_t response,
                                           ipmi_data_len_t dataLen,
                                           ipmi_context_t context)
{
    if (*dataLen)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error
    GetAllocInfoResp *resp = static_cast<GetAllocInfoResp *>(response);

    // 0000h unspecified number of alloc units
    resp->allocUnitsLSB = 0;
    resp->allocUnitsMSB = 0;

    // max unit size is size of max record
    resp->allocUnitSizeLSB = maxSDRTotalSize & 0xFF;
    resp->allocUnitSizeMSB = maxSDRTotalSize >> 8;
    // read only sdr, no free alloc blocks
    resp->allocUnitFreeLSB = 0;
    resp->allocUnitFreeMSB = 0;
    resp->allocUnitLargestFreeLSB = 0;
    resp->allocUnitLargestFreeMSB = 0;
    // only allow one block at a time
    resp->maxRecordSize = 1;

    *dataLen = sizeof(GetAllocInfoResp);

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageReserveSDR(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t dataLen,
                                 ipmi_context_t context)
{
    printCommand(+netfn, +cmd);

    if (*dataLen)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *dataLen = 0; // default to 0 in case of an error
    sdrReservationID++;
    if (sdrReservationID == 0)
    {
        sdrReservationID++;
    }
    *dataLen = 2;
    auto resp = static_cast<uint8_t *>(response);
    resp[0] = sdrReservationID & 0xFF;
    resp[1] = sdrReservationID >> 8;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiStorageGetSDR(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t dataLen, ipmi_context_t context)
{
    printCommand(+netfn, +cmd);

    if (*dataLen != 6)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    auto requestedSize = *dataLen;
    *dataLen = 0; // default to 0 in case of an error

    constexpr uint16_t lastRecordIndex = 0xFFFF;
    auto req = static_cast<GetSDRReq *>(request);

    // reservation required for partial reads with non zero offset into
    // record
    if ((sdrReservationID == 0 || req->reservationID != sdrReservationID) &&
        req->offset)
    {
        return IPMI_CC_INVALID_RESERVATION_ID;
    }

    if (sensorTree.empty() && !getSensorSubtree(sensorTree))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    size_t fruCount = 0;
    ipmi_ret_t ret = ipmi::storage::getFruSdrCount(fruCount);
    if (ret != IPMI_CC_OK)
    {
        return ret;
    }

    size_t lastRecord = sensorTree.size() + fruCount - 1;
    if (req->recordID == lastRecordIndex)
    {
        req->recordID = lastRecord;
    }
    if (req->recordID > lastRecord)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    uint16_t nextRecord =
        lastRecord > req->recordID ? req->recordID + 1 : 0XFFFF;

    auto responseClear = static_cast<uint8_t *>(response);
    std::fill(responseClear, responseClear + requestedSize, 0);

    auto resp = static_cast<get_sdr::GetSdrResp *>(response);
    resp->next_record_id_lsb = nextRecord & 0xFF;
    resp->next_record_id_msb = nextRecord >> 8;

    if (req->recordID >= sensorTree.size())
    {
        size_t fruIndex = req->recordID - sensorTree.size();
        if (fruIndex >= fruCount)
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        get_sdr::SensorDataFruRecord data;
        if (req->offset > sizeof(data))
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        ret = ipmi::storage::getFruSdrs(fruIndex, data);
        if (ret != IPMI_CC_OK)
        {
            return ret;
        }
        data.header.record_id_msb = req->recordID << 8;
        data.header.record_id_lsb = req->recordID & 0xFF;
        if (sizeof(data) < (req->offset + req->bytesToRead))
        {
            req->bytesToRead = sizeof(data) - req->offset;
        }
        *dataLen = req->bytesToRead + 2; // next record
        std::memcpy(&resp->record_data, (char *)&data + req->offset,
                    req->bytesToRead);
        return IPMI_CC_OK;
    }

    std::string connection;
    std::string path;
    uint16_t sensorIndex = req->recordID;
    for (const auto &sensor : sensorTree)
    {
        if (sensorIndex-- == 0)
        {
            if (!sensor.second.size())
            {
                return IPMI_CC_RESPONSE_ERROR;
            }
            connection = sensor.second.begin()->first;
            path = sensor.first;
            break;
        }
    }

    SensorMap sensorMap;
    if (!getSensorMap(connection, path, sensorMap))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    uint8_t sensornumber = (req->recordID & 0xFF);
    get_sdr::SensorDataFullRecord record = {0};

    record.header.record_id_msb = req->recordID << 8;
    record.header.record_id_lsb = req->recordID & 0xFF;
    record.header.sdr_version = ipmiSdrVersion;
    record.header.record_type = get_sdr::SENSOR_DATA_FULL_RECORD;
    record.header.record_length = sizeof(get_sdr::SensorDataFullRecord) -
                                  sizeof(get_sdr::SensorDataRecordHeader);
    record.key.owner_id = 0x20;
    record.key.owner_lun = 0x0;
    record.key.sensor_number = sensornumber;

    record.body.entity_id = 0x0;
    record.body.entity_instance = 0x01;
    record.body.sensor_capabilities = 0x68; // auto rearm - todo hysteresis
    record.body.sensor_type = getSensorTypeFromPath(path);
    std::string type = getSensorTypeStringFromPath(path);
    auto typeCstr = type.c_str();
    auto findUnits = sensorUnits.find(typeCstr);
    if (findUnits != sensorUnits.end())
    {
        record.body.sensor_units_2_base =
            static_cast<uint8_t>(findUnits->second);
    } // else default 0x0 unspecified

    record.body.event_reading_type = getSensorEventTypeFromPath(path);

    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");
    if (sensorObject == sensorMap.end())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    auto maxObject = sensorObject->second.find("MaxValue");
    auto minObject = sensorObject->second.find("MinValue");
    double max = 128;
    double min = -127;
    if (maxObject != sensorObject->second.end())
    {
        max = variant_ns::visit(VariantToDoubleVisitor(), maxObject->second);
    }

    if (minObject != sensorObject->second.end())
    {
        min = variant_ns::visit(VariantToDoubleVisitor(), minObject->second);
    }

    int16_t mValue;
    int8_t rExp;
    int16_t bValue;
    int8_t bExp;
    bool bSigned;

    if (!getSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    // apply M, B, and exponents, M and B are 10 bit values, exponents are 4
    record.body.m_lsb = mValue & 0xFF;

    // move the smallest bit of the MSB into place (bit 9)
    // the MSbs are bits 7:8 in m_msb_and_tolerance
    uint8_t mMsb = (mValue & (1 << 8)) > 0 ? (1 << 6) : 0;

    // assign the negative
    if (mValue < 0)
    {
        mMsb |= (1 << 7);
    }
    record.body.m_msb_and_tolerance = mMsb;

    record.body.b_lsb = bValue & 0xFF;

    // move the smallest bit of the MSB into place
    // the MSbs are bits 7:8 in b_msb_and_accuracy_lsb
    uint8_t bMsb = (bValue & (1 << 8)) > 0 ? (1 << 6) : 0;

    // assign the negative
    if (bValue < 0)
    {
        bMsb |= (1 << 7);
    }
    record.body.b_msb_and_accuracy_lsb = bMsb;

    record.body.r_b_exponents = bExp & 0x7;
    if (bExp < 0)
    {
        record.body.r_b_exponents |= 1 << 3;
    }
    record.body.r_b_exponents = (rExp & 0x7) << 4;
    if (rExp < 0)
    {
        record.body.r_b_exponents |= 1 << 7;
    }

    // todo fill out rest of units
    if (bSigned)
    {
        record.body.sensor_units_1 = 1 << 7;
    }

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
        name.resize(FULL_RECORD_ID_STR_MAX_LENGTH);
    }
    record.body.id_string_info = name.size();
    std::strncpy(record.body.id_string, name.c_str(),
                 sizeof(record.body.id_string));

    if (sizeof(get_sdr::SensorDataFullRecord) <
        (req->offset + req->bytesToRead))
    {
        req->bytesToRead = sizeof(get_sdr::SensorDataFullRecord) - req->offset;
    }

    *dataLen =
        2 + req->bytesToRead; // bytesToRead + MSB and LSB of next record id

    std::memcpy(&resp->record_data, (char *)&record + req->offset,
                req->bytesToRead);

    return IPMI_CC_OK;
}
/* end storage commands */

void registerSensorFunctions()
{
    // get firmware version information
    ipmiPrintAndRegister(NETFUN_SENSOR, IPMI_CMD_WILDCARD, nullptr,
                         ipmiSensorWildcardHandler, PRIVILEGE_USER);

    // <Get Sensor Type>
    ipmiPrintAndRegister(
        NETFUN_SENSOR,
        static_cast<ipmi_cmd_t>(IPMINetfnSensorCmds::ipmiCmdGetSensorType),
        nullptr, ipmiSensorWildcardHandler, PRIVILEGE_USER);

    // <Set Sensor Reading and Event Status>
    ipmiPrintAndRegister(
        NETFUN_SENSOR,
        static_cast<ipmi_cmd_t>(
            IPMINetfnSensorCmds::ipmiCmdSetSensorReadingAndEventStatus),
        nullptr, ipmiSensorWildcardHandler, PRIVILEGE_OPERATOR);

    // <Get Sensor Reading>
    ipmiPrintAndRegister(
        NETFUN_SENSOR,
        static_cast<ipmi_cmd_t>(IPMINetfnSensorCmds::ipmiCmdGetSensorReading),
        nullptr, ipmiSenGetSensorReading, PRIVILEGE_USER);

    // <Get Sensor Threshold>
    ipmiPrintAndRegister(
        NETFUN_SENSOR,
        static_cast<ipmi_cmd_t>(IPMINetfnSensorCmds::ipmiCmdGetSensorThreshold),
        nullptr, ipmiSenGetSensorThresholds, PRIVILEGE_USER);

    ipmiPrintAndRegister(
        NETFUN_SENSOR,
        static_cast<ipmi_cmd_t>(IPMINetfnSensorCmds::ipmiCmdSetSensorThreshold),
        nullptr, ipmiSenSetSensorThresholds, PRIVILEGE_OPERATOR);

    // <Get Sensor Event Enable>
    ipmiPrintAndRegister(NETFUN_SENSOR,
                         static_cast<ipmi_cmd_t>(
                             IPMINetfnSensorCmds::ipmiCmdGetSensorEventEnable),
                         nullptr, ipmiSenGetSensorEventEnable, PRIVILEGE_USER);

    // <Get Sensor Event Status>
    ipmiPrintAndRegister(NETFUN_SENSOR,
                         static_cast<ipmi_cmd_t>(
                             IPMINetfnSensorCmds::ipmiCmdGetSensorEventStatus),
                         nullptr, ipmiSenGetSensorEventStatus, PRIVILEGE_USER);

    // register all storage commands for both Sensor and Storage command
    // versions

    // <Get SDR Repository Info>
    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdGetRepositoryInfo),
        nullptr, ipmiStorageGetSDRRepositoryInfo, PRIVILEGE_USER);

    // <Get SDR Allocation Info>
    ipmiPrintAndRegister(NETFUN_STORAGE,
                         static_cast<ipmi_cmd_t>(
                             IPMINetfnStorageCmds::ipmiCmdGetSDRAllocationInfo),
                         nullptr, ipmiStorageGetSDRAllocationInfo,
                         PRIVILEGE_USER);

    // <Reserve SDR Repo>
    ipmiPrintAndRegister(NETFUN_SENSOR,
                         static_cast<ipmi_cmd_t>(
                             IPMINetfnSensorCmds::ipmiCmdReserveDeviceSDRRepo),
                         nullptr, ipmiStorageReserveSDR, PRIVILEGE_USER);

    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdReserveSDR),
        nullptr, ipmiStorageReserveSDR, PRIVILEGE_USER);

    // <Get Sdr>
    ipmiPrintAndRegister(
        NETFUN_SENSOR,
        static_cast<ipmi_cmd_t>(IPMINetfnSensorCmds::ipmiCmdGetDeviceSDR),
        nullptr, ipmiStorageGetSDR, PRIVILEGE_USER);

    ipmiPrintAndRegister(
        NETFUN_STORAGE,
        static_cast<ipmi_cmd_t>(IPMINetfnStorageCmds::ipmiCmdGetSDR), nullptr,
        ipmiStorageGetSDR, PRIVILEGE_USER);
    return;
}
} // namespace ipmi
