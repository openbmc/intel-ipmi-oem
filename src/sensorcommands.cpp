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

#include <host-ipmid/ipmid-api.h>

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <chrono>
#include <cmath>
#include <commandutils.hpp>
#include <iostream>
#include <phosphor-ipmi-host/utils.hpp>
#include <sdbusplus/bus.hpp>
#include <sensorcommands.hpp>
#include <sensorutils.hpp>
#include <storagecommands.hpp>
#include <string>
#include <variantvisitors.hpp>

namespace ipmi
{
using ManagedObjectType =
    std::map<sdbusplus::message::object_path,
             std::map<std::string, std::map<std::string, DbusVariant>>>;
using GetSubTreeType = std::vector<
    std::pair<std::string,
              std::vector<std::pair<std::string, std::vector<std::string>>>>>;

using SensorMap = std::map<std::string, std::map<std::string, DbusVariant>>;

static constexpr int SENSOR_LIST_UPDATE_PERIOD = 10;
static constexpr int SENSOR_MAP_UPDATE_PERIOD = 2;

constexpr size_t MAX_SDR_TOTAL_SIZE =
    76; // Largest SDR Record Size (type 01) + SDR Overheader Size

static uint16_t SDRReservationId;
static uint32_t SDRLastUpdate = 0;
static auto SDRLastCheck = std::chrono::time_point<std::chrono::steady_clock>();

static GetSubTreeType SensorConnectionCache;
static boost::container::flat_map<std::string, ManagedObjectType> SensorCache;

struct cmp_str
{
    bool operator()(const char *a, const char *b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

const static boost::container::flat_map<const char *, sensor_type_codes,
                                        cmp_str>
    SENSOR_TYPES{{{"temperature", TEMPERATURE},
                  {"voltage", VOLTAGE},
                  {"current", CURRENT},
                  {"fan_tach", FAN},
                  {"power", OTHER}}};

const static boost::container::flat_map<const char *, sensor_units, cmp_str>
    SENSOR_UNITS{{{"temperature", DEGREES_C},
                  {"voltage", VOLTS},
                  {"current", AMPS},
                  {"fan_tach", RPM},
                  {"power", WATTS}}};

enum ipmi_netfn_sen_cmds
{
    IPMI_CMD_GET_SDR_INFO = 0x20,
    IPMI_CMD_GET_SDR = 0x21,
    IPMI_CMD_RESERVE_SDR_REPO = 0x22,
    IPMI_CMD_GET_SENSOR_THRESHOLDS = 0x27,
    IPMI_CMD_SET_SENSOR_THRESHOLDS = 0x28,
    IPMI_CMD_GET_SENSOR_EVENT_ENABLE = 0x29,
    IPMI_CMD_GET_SENSOR_EVENT_STATUS = 0x2B,
    IPMI_CMD_GET_SENSOR_READING = 0x2D,
    IPMI_CMD_GET_SENSOR_TYPE = 0x2F,
    IPMI_CMD_SET_SENSOR = 0x30,
};

void register_netfn_firmware_functions() __attribute__((constructor));
sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());

static void
    GetSensorMaxMin(const std::map<std::string, DbusVariant> &sensorPropertyMap,
                    double &max, double &min)
{
    auto maxMap = sensorPropertyMap.find("MaxValue");
    auto minMap = sensorPropertyMap.find("MinValue");
    max = 127;
    min = -128;

    if (maxMap != sensorPropertyMap.end())
    {
        max = apply_visitor(VariantToDoubleVisitor(), maxMap->second);
        if (DEBUG)
            std::cout << "GetSensorMValue Max " << max << "\n";
    }
    if (minMap != sensorPropertyMap.end())
    {
        min = apply_visitor(VariantToDoubleVisitor(), minMap->second);
        if (DEBUG)
            std::cout << "GetSensorMValue Min " << min << "\n";
    }
}

static bool GetSensorSubtree(GetSubTreeType &subtree, bool &updated)
{
    auto subtreeCopy = subtree;
    auto mapperCall =
        dbus.new_method_call("xyz.openbmc_project.ObjectMapper",
                             "/xyz/openbmc_project/object_mapper",
                             "xyz.openbmc_project.ObjectMapper", "GetSubTree");
    static const auto depth = 2;
    static constexpr std::array<const char *, 3> interfaces = {
        "xyz.openbmc_project.Sensor.Value",
        "xyz.openbmc_project.Sensor.Threshold.Warning",
        "xyz.openbmc_project.Sensor.Threshold.Critical"};
    mapperCall.append("/xyz/openbmc_project/sensors", depth, interfaces);

    auto mapperReply = dbus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        std::cerr << "GetSensorSubtree: Error calling mapper\n";
        return false;
    }
    subtree.clear();
    mapperReply.read(subtree);

    // sort by sensor path
    std::sort(subtree.begin(), subtree.end(), [](auto &left, auto &right) {
        return boost::ilexicographical_compare<std::string, std::string>(
            left.first, right.first);
    });
    updated = false;
    if (subtreeCopy.empty())
    {
        updated = true;
    }
    else if (subtreeCopy.size() != subtree.size())
    {
        updated = true;
    }
    else
    {
        for (int ii = 0; ii < subtreeCopy.size(); ii++)
        {
            // if the path or the connection has changed
            if (subtreeCopy[ii] != subtree[ii])
            {
                updated = true;
                break;
            }
        }
    }
    return true;
}

static ipmi_ret_t GetSensorConnection(uint8_t sensnum, std::string &connection,
                                      std::string &path)
{
    auto now = std::chrono::steady_clock::now();

    if (std::chrono::duration_cast<std::chrono::seconds>(now - SDRLastCheck)
                .count() > SENSOR_LIST_UPDATE_PERIOD ||
        SensorConnectionCache.empty())
    {
        SDRLastCheck = now;
        bool updated;
        if (!GetSensorSubtree(SensorConnectionCache, updated))
        {
            return IPMI_CC_RESPONSE_ERROR;
        }
        if (updated)
            SDRLastUpdate =
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count();
    }

    if (SensorConnectionCache.size() < (sensnum + 1))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (!SensorConnectionCache[sensnum].second.size())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    connection = SensorConnectionCache[sensnum].second[0].first;
    path = SensorConnectionCache[sensnum].first;

    if (DEBUG)
        std::cout << "Get sensor connection sensor: " << path << "\n";

    return 0;
}

static bool GetSensorMap(std::string sensorConnection, std::string sensorPath,
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
            .count() > SENSOR_MAP_UPDATE_PERIOD)
    {
        updateTimeMap[sensorConnection] = now;

        auto managedObj = dbus.new_method_call(
            sensorConnection.c_str(), "/", "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects");
        auto reply = dbus.call(managedObj);

        if (reply.is_method_error())
        {
            std::cerr << "Error getting managed objects from connection "
                      << sensorConnection << "\n";
            return false;
        }
        ManagedObjectType managedObjects;

        reply.read(managedObjects);
        SensorCache[sensorConnection] = managedObjects;
    }
    auto connection = SensorCache.find(sensorConnection);
    if (connection == SensorCache.end())
        return false;
    auto path = connection->second.find(sensorPath);
    if (path == connection->second.end())
        return false;
    sensorMap = path->second;

    return true;
}

/* sensor commands */
ipmi_ret_t ipmi_sensor_wildcard_handler(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t data_len,
                                        ipmi_context_t context)
{
    *data_len = 0;

    if (DEBUG)
        std::cout << "IPMI Sensor Wildcard Netfn:" << std::hex << std::uppercase
                  << (unsigned int)netfn << " Cmd:" << (unsigned int)cmd
                  << "\n";
    return IPMI_CC_INVALID;
}

ipmi_ret_t ipmi_sen_get_sensor_reading(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t data_len,
                                       ipmi_context_t context)
{
    if (*data_len != 1)
        return IPMI_CC_REQ_DATA_LEN_INVALID;

    uint8_t sensnum = *(static_cast<uint8_t *>(request));
    if (DEBUG)
        std::cout << "IPMI Get Sensor Reading Sens 0x" << std::hex
                  << (int)sensnum << "\n";

    std::string connection;
    std::string path;

    auto status = GetSensorConnection(sensnum, connection, path);
    if (status)
        return status;

    SensorMap sensorMap;
    if (!GetSensorMap(connection, path, sensorMap))
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
    double reading = apply_visitor(VariantToDoubleVisitor(), value);

    double max;
    double min;
    GetSensorMaxMin(sensorObject->second, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!GetSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
        return IPMI_CC_RESPONSE_ERROR;

    if (DEBUG)
        std::cout << "Reading : " << reading << "\n";

    sensorreadingresp_t *msg_reply =
        static_cast<sensorreadingresp_t *>(response);
    *data_len = sizeof(sensorreadingresp_t);

    msg_reply->value =
        ScaleIPMIValueFromDouble(reading, mValue, rExp, bValue, bExp, bSigned);
    msg_reply->operation = 1 << 6; // scanning enabled
    msg_reply->indication[0] = 0;  // ignore for non-threshold sensors
    msg_reply->indication[1] = 0;

    return 0;
}

ipmi_ret_t ipmi_sen_set_sensor_thresholds(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                          ipmi_request_t request,
                                          ipmi_response_t response,
                                          ipmi_data_len_t data_len,
                                          ipmi_context_t context)
{
    if (*data_len != 8)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    *data_len = 0;

    sensorThresholdReq_t *req = static_cast<sensorThresholdReq_t *>(request);

    // upper two bits reserved
    if (req->mask & 0xC0)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // lower nc and upper nc not suppported on any sensor
    if ((req->mask & static_cast<uint8_t>(
                         sensorThresholdReqEnable::setLowerNonRecoverable)) ||
        (req->mask & static_cast<uint8_t>(
                         sensorThresholdReqEnable::setUpperNonRecoverable)))
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

    ipmi_ret_t status = GetSensorConnection(req->sensorNum, connection, path);
    if (status)
    {
        return status;
    }
    SensorMap sensorMap;
    if (!GetSensorMap(connection, path, sensorMap))
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
    GetSensorMaxMin(sensorObject->second, max, min);

    int16_t mValue = 0;
    int16_t bValue = 0;
    int8_t rExp = 0;
    int8_t bExp = 0;
    bool bSigned = false;

    if (!GetSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    bool setLowerCritical =
        req->mask &
        static_cast<uint8_t>(sensorThresholdReqEnable::setLowerCritical);
    bool setUpperCritical =
        req->mask &
        static_cast<uint8_t>(sensorThresholdReqEnable::setUpperCritical);

    bool setLowerWarning =
        req->mask &
        static_cast<uint8_t>(sensorThresholdReqEnable::setLowerNonCritical);
    bool setUpperWarning =
        req->mask &
        static_cast<uint8_t>(sensorThresholdReqEnable::setUpperNonCritical);

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

ipmi_ret_t ipmi_sen_get_sensor_thresholds(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                          ipmi_request_t request,
                                          ipmi_response_t response,
                                          ipmi_data_len_t data_len,
                                          ipmi_context_t context)
{
    if (*data_len != 1)
        return IPMI_CC_REQ_DATA_LEN_INVALID;

    uint8_t sensnum = *(static_cast<uint8_t *>(request));
    if (DEBUG)
        std::cout << "IPMI Get Sensor Thresholds Sens 0x" << std::hex
                  << (int)sensnum << "\n";

    std::string connection;
    std::string path;

    auto status = GetSensorConnection(sensnum, connection, path);
    if (status)
        return status;

    SensorMap sensorMap;
    if (!GetSensorMap(connection, path, sensorMap))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    *data_len = sizeof(sensorthresholdresp_t);

    // zero out response buff
    auto response_clear = static_cast<uint8_t *>(response);
    std::fill(response_clear, response_clear + *data_len, 0);

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
            // should not have been able to find a sensor not implementing the
            // sensor object
            return IPMI_CC_RESPONSE_ERROR;
        }

        double max;
        double min;
        GetSensorMaxMin(sensorPair->second, max, min);

        int16_t mValue = 0;
        int16_t bValue = 0;
        int8_t rExp = 0;
        int8_t bExp = 0;
        bool bSigned = false;

        if (!GetSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
            return IPMI_CC_RESPONSE_ERROR;

        auto msg_reply = static_cast<sensorthresholdresp_t *>(response);

        if (warningInterface != sensorMap.end())
        {
            auto &warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningHigh");
            auto warningLow = warningMap.find("WarningLow");

            if (warningHigh != warningMap.end())
            {
                msg_reply->readable |= 1 << UPPER_NON_CRITICAL;
                double value = apply_visitor(VariantToDoubleVisitor(),
                                             warningHigh->second);
                msg_reply->uppernc = ScaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
            }
            if (warningLow != warningMap.end())
            {
                msg_reply->readable |= 1 << LOWER_NON_CRITICAL;
                double value =
                    apply_visitor(VariantToDoubleVisitor(), warningLow->second);
                msg_reply->lowernc = ScaleIPMIValueFromDouble(
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
                msg_reply->readable |= 1 << UPPER_CRITICAL;
                double value = apply_visitor(VariantToDoubleVisitor(),
                                             criticalHigh->second);
                msg_reply->uppercritical = ScaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
            }
            if (criticalLow != criticalMap.end())
            {
                msg_reply->readable |= 1 << LOWER_CRITICAL;
                double value = apply_visitor(VariantToDoubleVisitor(),
                                             criticalLow->second);
                msg_reply->lowercritical = ScaleIPMIValueFromDouble(
                    value, mValue, rExp, bValue, bExp, bSigned);
            }
        }
    }

    return 0;
}

ipmi_ret_t ipmi_sen_get_sensor_event_enable(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                            ipmi_request_t request,
                                            ipmi_response_t response,
                                            ipmi_data_len_t data_len,
                                            ipmi_context_t context)
{
    if (*data_len != 1)
        return IPMI_CC_REQ_DATA_LEN_INVALID;

    uint8_t sensnum = *(static_cast<uint8_t *>(request));
    if (DEBUG)
        std::cout << "IPMI Get Sensor Event Enable Sens 0x" << std::hex
                  << (int)sensnum << "\n";

    std::string connection;
    std::string path;

    auto status = GetSensorConnection(sensnum, connection, path);
    if (status)
        return status;

    SensorMap sensorMap;
    if (!GetSensorMap(connection, path, sensorMap))
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
        *data_len =
            sizeof(sensoreventenableresp_t); // todo only return needed bytes
        // zero out response buff
        auto response_clear = static_cast<uint8_t *>(response);
        std::fill(response_clear, response_clear + *data_len, 0);

        // assume all threshold sensors
        auto resp = static_cast<sensoreventenableresp_t *>(response);

        resp->enabled = (1 << 6); // sensor scanning enabled
        if (warningInterface != sensorMap.end())
        {
            auto &warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningHigh");
            auto warningLow = warningMap.find("WarningLow");
            if (warningHigh != warningMap.end())
            {
                resp->assertionEnabledLSB |= (1 << 7); // upper nc going high en
                resp->deassertionEnabledLSB |= (1 << 6); // upper nc going low
            }
            if (warningLow != warningMap.end())
            {
                resp->assertionEnabledLSB |= 1; // lower nc going low en
                resp->deassertionEnabledLSB |= (1 << 1); // lower nc going high
            }
        }
        if (criticalInterface != sensorMap.end())
        {
            auto &criticalMap = criticalInterface->second;

            auto criticalHigh = criticalMap.find("CriticalHigh");
            auto criticalLow = criticalMap.find("CriticalLow");

            if (criticalHigh != criticalMap.end())
            {
                resp->assertionEnabledMSB |=
                    (1 << 5); // upper critical going high
                resp->deassertionEnabledMSB |=
                    (1 << 4); // uppper critical going low
            }
            if (criticalLow != criticalMap.end())
            {
                resp->assertionEnabledLSB |=
                    (1 << 2); // lower critical going low
                resp->deassertionEnabledLSB |=
                    (1 << 3); // lower critical going high
            }
        }
    }
    // no thresholds enabled
    else
    {
        *data_len = 1;
        auto resp = static_cast<uint8_t *>(response);
        *resp = (1 << 7);  // event messages disabled for this sensor
        *resp |= (1 << 6); // sensor scanning enabled
    }
    return 0;
}

ipmi_ret_t ipmi_sen_get_sensor_event_status(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                            ipmi_request_t request,
                                            ipmi_response_t response,
                                            ipmi_data_len_t data_len,
                                            ipmi_context_t context)
{
    if (*data_len != 1)
        return IPMI_CC_REQ_DATA_LEN_INVALID;

    uint8_t sensnum = *(static_cast<uint8_t *>(request));
    if (DEBUG)
        std::cout << "IPMI Get Sensor Event Status Sens 0x" << std::hex
                  << (int)sensnum << "\n";

    std::string connection;
    std::string path;

    auto status = GetSensorConnection(sensnum, connection, path);
    if (status)
        return status;

    SensorMap sensorMap;
    if (!GetSensorMap(connection, path, sensorMap))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    auto warningInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Warning");
    auto criticalInterface =
        sensorMap.find("xyz.openbmc_project.Sensor.Threshold.Critical");

    *data_len = sizeof(sensoreventstatusresp_t);
    // zero out response buff
    auto response_clear = static_cast<uint8_t *>(response);
    std::fill(response_clear, response_clear + *data_len, 0);
    auto resp = static_cast<sensoreventstatusresp_t *>(response);
    resp->enabled = (1 << 6); // sensor scanning enabled

    if ((warningInterface != sensorMap.end()) ||
        (criticalInterface != sensorMap.end()))
    {
        resp->enabled = (1 << 7); // event messages enabled
        if (warningInterface != sensorMap.end())
        {
            auto &warningMap = warningInterface->second;

            auto warningHigh = warningMap.find("WarningAlarmHigh");
            auto warningLow = warningMap.find("WarningAlarmLow");
            auto warningHighAlarm = false;
            auto warningLowAlarm = false;

            if (warningHigh != warningMap.end())
            {
                warningHighAlarm = warningHigh->second.get<bool>();
            }
            if (warningLow != warningMap.end())
            {
                warningLowAlarm = warningLow->second.get<bool>();
            }
            if (warningHighAlarm)
            {
                resp->assertionsLSB |= (1 << 7); // upper nc going high
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
                criticalHighAlarm = criticalHigh->second.get<bool>();
            }
            if (criticalLow != criticalMap.end())
            {
                criticalLowAlarm = criticalLow->second.get<bool>();
            }
            if (criticalHighAlarm)
            {
                resp->assertionsMSB |= (1 << 5); // upper critical going high
            }
            if (criticalLowAlarm)
            {
                resp->assertionsLSB |= (1 << 2); // lower critical going low
            }
        }
    }

    // no thresholds enabled, don't need assertionMSB
    else
    {
        *data_len--;
    }

    return 0;
}

/* end sensor commands */

/* storage commands */

ipmi_ret_t ipmi_storage_get_sdr_repository_info(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (DEBUG)
        std::cout << "IPMI Get Sdr Repository Info \n";

    if (*data_len)
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    bool updated = false;
    if (!GetSensorSubtree(SensorConnectionCache, updated))
        return IPMI_CC_RESPONSE_ERROR;
    if (updated)
        SDRLastUpdate = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();
    SDRLastCheck = std::chrono::steady_clock::now();

    *data_len = sizeof(getsdrinforesp_t);
    // zero out response buff
    auto response_clear = static_cast<uint8_t *>(response);
    std::fill(response_clear, response_clear + *data_len, 0);

    auto resp = static_cast<getsdrinforesp_t *>(response);
    resp->sdr_version = IPMI_SDR_VERSION;
    uint16_t recordCount = SensorConnectionCache.size();

    // todo: for now, sdr count is number of sensors
    resp->record_count_ls = recordCount & 0xFF;
    resp->record_count_ms = recordCount >> 8;

    // free space unspcified
    resp->free_space[0] = 0xFF;
    resp->free_space[1] = 0xFF;

    for (int ii = 0; ii < 4; ii++)
    {
        resp->most_recent_addition[ii] = (SDRLastUpdate >> ii) & 0xFF;
        resp->most_recent_erase[ii] = (SDRLastUpdate >> ii) & 0xFF;
    }
    resp->operation_support = static_cast<uint8_t>(
        SdrRepositoryInfoOps::Overflow); // write not supported
    resp->operation_support |=
        static_cast<uint8_t>(SdrRepositoryInfoOps::AllocCommandSupported);
    resp->operation_support |= static_cast<uint8_t>(
        SdrRepositoryInfoOps::ReserveSDRRepositoryCommandSupported);
    return 0;
}

ipmi_ret_t ipmi_storage_get_sdr_allocation_info(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (*data_len)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    getallocinforesp_t *resp = static_cast<getallocinforesp_t *>(response);

    // 0000h unspecified number of alloc units
    resp->alloc_units_lsb = 0;
    resp->alloc_units_msb = 0;

    // max unit size is size of max record
    resp->alloc_unit_size_lsb = MAX_SDR_TOTAL_SIZE & 0xFF;
    resp->alloc_unit_size_msb = MAX_SDR_TOTAL_SIZE >> 8;
    // read only sdr, no free alloc blocks
    resp->alloc_unit_free_lsb = 0;
    resp->alloc_unit_free_msb = 0;
    resp->alloc_unit_largest_free_lsb = 0;
    resp->alloc_unit_largest_free_msb = 0;
    // only allow one block at a time
    resp->max_record_size = 1;

    *data_len = sizeof(getallocinforesp_t);

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_storage_reserve_sdr(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    if (DEBUG)
        std::cout << "IPMI Reserve SDR \n";
    if (*data_len)
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    SDRReservationId++;
    *data_len = 2;
    auto resp = static_cast<uint8_t *>(response);
    resp[0] = SDRReservationId & 0xFF;
    resp[1] = SDRReservationId >> 8;

    return 0;
}

ipmi_ret_t ipmi_storage_get_sdr(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    if (DEBUG)
        std::cout << "IPMI Get SDR \n";
    if (*data_len != 6)
        return IPMI_CC_REQ_DATA_LEN_INVALID;

    constexpr uint16_t LAST_RECORD_INDEX = 0xFFFF;
    auto req = static_cast<uint8_t *>(request);

    uint16_t reservation = (req[1] << 8) | (req[0] & 0xFF);
    uint8_t offset = req[4];
    uint8_t bytesToRead = req[5];

    // reservation required for partial reads with non zero offset into record
    if (reservation != SDRReservationId && offset)
    {
        return IPMI_CC_INVALID_RESERVATION_ID;
    }
    uint16_t recordId = (req[3] << 8) | (req[2] & 0xFF);

    auto now = std::chrono::steady_clock::now();
    // for now, only have sensor sdrs
    if (SensorConnectionCache.empty() ||
        (std::chrono::duration_cast<std::chrono::seconds>(now - SDRLastCheck)
             .count() > SENSOR_LIST_UPDATE_PERIOD))
    {
        bool updated = false;
        if (!GetSensorSubtree(SensorConnectionCache, updated))
            return IPMI_CC_RESPONSE_ERROR;
        if (updated)
            SDRLastUpdate =
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count();
        SDRLastCheck = std::chrono::steady_clock::now();
    }

    size_t fruCount = 0;
    ipmi_ret_t ret = ipmi::storage::getFruSdrCount(fruCount);
    if (ret != IPMI_CC_OK)
    {
        return ret;
    }

    size_t lastRecord = SensorConnectionCache.size() + fruCount - 1;
    if (recordId == LAST_RECORD_INDEX)
    {
        recordId = lastRecord;
    }
    if (recordId > lastRecord)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    uint16_t nextRecord = lastRecord > (recordId + 1) ? recordId + 1 : 0XFFFF;

    auto response_clear = static_cast<uint8_t *>(response);
    std::fill(response_clear, response_clear + *data_len, 0);

    auto resp = static_cast<get_sdr::GetSdrResp *>(response);
    resp->next_record_id_lsb = nextRecord & 0xFF;
    resp->next_record_id_msb = nextRecord >> 8;

    if (recordId >= SensorConnectionCache.size())
    {
        size_t fruIndex = recordId - SensorConnectionCache.size();
        if (fruIndex >= fruCount)
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        get_sdr::SensorDataFruRecord data;
        if (offset > sizeof(data))
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        ret = ipmi::storage::getFruSdrs(fruIndex, data);
        if (ret != IPMI_CC_OK)
        {
            return ret;
        }
        data.header.record_id_msb = recordId << 8;
        data.header.record_id_lsb = recordId & 0xFF;
        if (sizeof(data) < (offset + bytesToRead))
        {
            bytesToRead = sizeof(data) - offset;
        }
        *data_len = bytesToRead + 2; // next record
        std::memcpy(&resp->record_data, (char *)&data + offset, bytesToRead);
        return IPMI_CC_OK;
    }

    auto connection = SensorConnectionCache[recordId].second[0].first;
    auto path = SensorConnectionCache[recordId].first;

    SensorMap sensorMap;
    if (!GetSensorMap(connection, path, sensorMap))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    uint8_t sensornumber = (recordId & 0xFF);
    get_sdr::SensorDataFullRecord record = {0};

    record.header.record_id_msb = recordId << 8;
    record.header.record_id_lsb = recordId & 0xFF;
    record.header.sdr_version = IPMI_SDR_VERSION;
    record.header.record_type = get_sdr::SENSOR_DATA_FULL_RECORD;
    record.header.record_length = sizeof(get_sdr::SensorDataFullRecord) -
                                  sizeof(get_sdr::SensorDataRecordHeader);
    record.key.owner_id = 0x20;
    record.key.owner_lun = 0x0;
    record.key.sensor_number = sensornumber;

    // get sensor type string from path, path is defined as
    // /xyz/openbmc_project/sensors/<type>/label
    auto type = SensorConnectionCache[recordId].first;
    auto lastSlash = type.rfind(std::string("/"));
    // delete everything after last slash inclusive
    if (lastSlash != std::string::npos)
    {
        type.erase(lastSlash);
    }
    // delete everything before new last slash inclusive
    lastSlash = type.rfind(std::string("/"));
    if (lastSlash != std::string::npos)
    {
        type.erase(0, lastSlash + 1);
    }

    record.body.entity_id = 0x0;
    record.body.entity_instance = 0x01;
    record.body.sensor_capabilities = 0x60; // auto rearm - todo hysteresis
    auto typeCstr = type.c_str();
    auto findSensor = SENSOR_TYPES.find(typeCstr);
    if (findSensor != SENSOR_TYPES.end())
    {
        record.body.sensor_type = findSensor->second;
    } // else default 0x0 RESERVED

    auto findUnits = SENSOR_UNITS.find(typeCstr);
    if (findUnits != SENSOR_UNITS.end())
    {
        record.body.sensor_units_2_base = findUnits->second;
    } // else default 0x0 UNSPECIFIED

    record.body.event_reading_type = 0x1; // reading type = threshold

    auto sensorObject = sensorMap.find("xyz.openbmc_project.Sensor.Value");
    if (sensorObject == sensorMap.end())
        return IPMI_CC_RESPONSE_ERROR;

    auto maxObject = sensorObject->second.find("MaxValue");
    auto minObject = sensorObject->second.find("MinValue");
    double max = 128;
    double min = -127;
    if (maxObject != sensorObject->second.end())
        max = apply_visitor(VariantToDoubleVisitor(), maxObject->second);

    if (minObject != sensorObject->second.end())
        min = apply_visitor(VariantToDoubleVisitor(), minObject->second);

    int16_t mValue;
    int8_t rExp;
    int16_t bValue;
    int8_t bExp;
    bool bSigned;

    if (!GetSensorAttributes(max, min, mValue, rExp, bValue, bExp, bSigned))
        return IPMI_CC_RESPONSE_ERROR;

    // apply M, B, and exponents, M and B are 10 bit values, exponents are 4
    record.body.m_lsb = mValue & 0xFF;

    // move the smallest bit of the MSB into place (bit 9)
    // the MSbs are bits 7:8 in m_msb_and_tolerance
    uint8_t mMsb = (mValue & (1 << 8)) > 0 ? (1 << 6) : 0;

    // assign the negative
    if (mValue < 0)
        mMsb |= (1 << 7);
    record.body.m_msb_and_tolerance = mMsb;

    record.body.b_lsb = bValue & 0xFF;

    // move the smallest bit of the MSB into place
    // the MSbs are bits 7:8 in b_msb_and_accuracy_lsb
    uint8_t bMsb = (bValue & (1 << 8)) > 0 ? (1 << 6) : 0;

    // assign the negative
    if (bValue < 0)
        bMsb |= (1 << 7);
    record.body.b_msb_and_accuracy_lsb = bMsb;

    record.body.r_b_exponents = bExp & 0x7;
    if (bExp < 0)
        record.body.r_b_exponents |= 1 << 3;
    record.body.r_b_exponents = (rExp & 0x7) << 4;
    if (rExp < 0)
        record.body.r_b_exponents |= 1 << 7;

    // todo fill out rest of units
    if (bSigned)
        record.body.sensor_units_1 = 1 << 7;

    // populate sensor name from path
    auto name = SensorConnectionCache[recordId].first;
    lastSlash = name.rfind(std::string("/"));
    if (lastSlash != std::string::npos)
    {
        name.erase(0, lastSlash + 1);
    }
    std::replace(name.begin(), name.end(), '_', ' ');
    if (name.size() > FULL_RECORD_ID_STR_MAX_LENGTH)
        name.resize(FULL_RECORD_ID_STR_MAX_LENGTH);
    record.body.id_string_info = name.size();
    strncpy(record.body.id_string, name.c_str(), sizeof(record.body.id_string));

    if (sizeof(get_sdr::SensorDataFullRecord) < (offset + bytesToRead))
    {
        bytesToRead = sizeof(get_sdr::SensorDataFullRecord) - offset;
    }

    *data_len = 2 + bytesToRead; // bytesToRead + MSB and LSB of next record id

    std::memcpy(&resp->record_data, (char *)&record + offset, bytesToRead);

    return 0;
}
/* end storage commands */

void register_netfn_firmware_functions()
{
    // get firmware version information
    print_registration(NETFUN_SENSOR, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_WILDCARD, NULL,
                           ipmi_sensor_wildcard_handler, PRIVILEGE_USER);

    // <Get Sensor Type>
    print_registration(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_TYPE);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_TYPE, nullptr,
                           ipmi_sensor_wildcard_handler, PRIVILEGE_USER);

    // <Set Sensor Reading and Event Status>
    print_registration(NETFUN_SENSOR, IPMI_CMD_SET_SENSOR);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_SET_SENSOR, nullptr,
                           ipmi_sensor_wildcard_handler, PRIVILEGE_OPERATOR);

    // <Get Sensor Reading>
    print_registration(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_READING);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_READING, nullptr,
                           ipmi_sen_get_sensor_reading, PRIVILEGE_USER);

    // <Get Sensor Thresholds>
    print_registration(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_THRESHOLDS);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_THRESHOLDS,
                           nullptr, ipmi_sen_get_sensor_thresholds,
                           PRIVILEGE_USER);

    print_registration(NETFUN_SENSOR, IPMI_CMD_SET_SENSOR_THRESHOLDS);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_SET_SENSOR_THRESHOLDS,
                           nullptr, ipmi_sen_set_sensor_thresholds,
                           PRIVILEGE_OPERATOR);

    // <Get Sensor Event Enable>
    print_registration(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_EVENT_ENABLE);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_EVENT_ENABLE,
                           nullptr, ipmi_sen_get_sensor_event_enable,
                           PRIVILEGE_USER);

    // <Get Sensor Event Status>
    print_registration(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_EVENT_STATUS);
    ipmi_register_callback(NETFUN_SENSOR, IPMI_CMD_GET_SENSOR_EVENT_STATUS,
                           nullptr, ipmi_sen_get_sensor_event_status,
                           PRIVILEGE_USER);

    // register all storage commands for both Sensor and Storage command
    // versions

    // <Get SDR Repository Info>
    print_registration(NETFUN_STORAGE,
                       ipmi_netfn_storage_cmds::IPMI_CMD_GET_REPOSITORY_INFO);
    ipmi_register_callback(
        NETFUN_STORAGE, ipmi_netfn_storage_cmds::IPMI_CMD_GET_REPOSITORY_INFO,
        NULL, ipmi_storage_get_sdr_repository_info, PRIVILEGE_USER);

    // <Get SDR Allocation Info>
    print_registration(
        NETFUN_STORAGE,
        ipmi_netfn_storage_cmds::IPMI_CMD_GET_SDR_ALLOCATION_INFO);
    ipmi_register_callback(
        NETFUN_STORAGE,
        ipmi_netfn_storage_cmds::IPMI_CMD_GET_SDR_ALLOCATION_INFO, NULL,
        ipmi_storage_get_sdr_allocation_info, PRIVILEGE_USER);

    // <Reserve SDR Repo>
    print_registration(NETFUN_SENSOR,
                       ipmi_netfn_sen_cmds::IPMI_CMD_RESERVE_SDR_REPO);
    ipmi_register_callback(NETFUN_SENSOR,
                           ipmi_netfn_sen_cmds::IPMI_CMD_RESERVE_SDR_REPO, NULL,
                           ipmi_storage_reserve_sdr, PRIVILEGE_USER);

    print_registration(NETFUN_STORAGE,
                       ipmi_netfn_storage_cmds::IPMI_CMD_RESERVE_SDR);
    ipmi_register_callback(NETFUN_STORAGE,
                           ipmi_netfn_storage_cmds::IPMI_CMD_RESERVE_SDR, NULL,
                           ipmi_storage_reserve_sdr, PRIVILEGE_USER);

    // <Get Sdr>
    print_registration(NETFUN_SENSOR, ipmi_netfn_sen_cmds::IPMI_CMD_GET_SDR);
    ipmi_register_callback(NETFUN_SENSOR, ipmi_netfn_sen_cmds::IPMI_CMD_GET_SDR,
                           NULL, ipmi_storage_get_sdr, PRIVILEGE_USER);

    print_registration(NETFUN_STORAGE,
                       ipmi_netfn_storage_cmds::IPMI_CMD_GET_SDR);
    ipmi_register_callback(NETFUN_STORAGE,
                           ipmi_netfn_storage_cmds::IPMI_CMD_GET_SDR, NULL,
                           ipmi_storage_get_sdr, PRIVILEGE_USER);
    return;
}
} // namespace ipmi
