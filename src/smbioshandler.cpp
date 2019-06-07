/*
// Copyright (c) 2018 Intel Corporation
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

#include <commandutils.hpp>
#include <cstdint>
#include <iostream>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <smbioshandler.hpp>
#include <string>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using level = phosphor::logging::level;

constexpr const char* DBUS_PROPERTIES = "org.freedesktop.DBus.Properties";
constexpr const char* MDRV1_PATH = "/xyz/openbmc_project/Smbios/MDR_V1";
constexpr const char* MDRV1_INTERFACE = "xyz.openbmc_project.Smbios.MDR_V1";

static void register_netfn_smbios_functions() __attribute__((constructor));
static sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

ipmi_ret_t cmd_region_status(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const RegionStatusRequest*>(request);
    std::vector<uint8_t> status;

    if (*data_len != sizeof(RegionStatusRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t regionId = requestData->regionId - 1;
    *data_len = 0;

    if (regionId >= maxMDRId)
    {
        phosphor::logging::log<level::ERR>("Invalid region");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    std::string service = ipmi::getService(bus, MDRV1_INTERFACE, MDRV1_PATH);

    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      MDRV1_INTERFACE, "RegionStatus");
    method.append(regionId);
    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error get region status",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV1_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(status);

    if (status.size() != sizeof(MDRState))
    {
        phosphor::logging::log<level::ERR>(
            "Error get region status, return length invalid");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    *data_len = static_cast<size_t>(status.size());
    auto dataOut = reinterpret_cast<uint8_t*>(response);
    std::copy(&status[0], &status[*data_len], dataOut);
    return IPMI_CC_OK;
}

int sdplus_mdrv1_get_property(
    const std::string& name,
    sdbusplus::message::variant<uint8_t, uint16_t>& value, std::string& service)
{
    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      DBUS_PROPERTIES, "Get");
    method.append(MDRV1_INTERFACE, name);
    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error getting property, sdbusplus call failed");
        return -1;
    }
    reply.read(value);

    return 0;
}

static int set_regionId(uint8_t regionId, std::string& service)
{
    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      DBUS_PROPERTIES, "Set");
    sdbusplus::message::variant<uint8_t> value{regionId};
    method.append(MDRV1_INTERFACE, "RegionId", value);
    auto region = bus.call(method);
    if (region.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error setting regionID, sdbusplus call failed");
        return -1;
    }
    return 0;
}

/** @brief implements bmc region update Complete command
 *  @param sessionId - session Lock Handle
 *  @param regionId - data Region
 *
 *  @returns IPMI completion code
 */
ipmi::RspType<> bmcRegionUpdateComplete(uint8_t sessionId, uint8_t regionId)
{
    sdbusplus::message::variant<uint8_t, uint16_t> value;
    uint8_t regionIdLocal = regionId - 1;

    if (regionIdLocal >= maxMDRId)
    {
        phosphor::logging::log<level::ERR>("Invalid region");
        return ipmi::responseParmOutOfRange();
    }

    std::string service = ipmi::getService(bus, MDRV1_INTERFACE, MDRV1_PATH);

    if (set_regionId(regionIdLocal, service) < 0)
    {
        phosphor::logging::log<level::ERR>("Error setting regionId");
        return ipmi::responseUnspecifiedError();
    }

    if (0 > sdplus_mdrv1_get_property("LockPolicy", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting lockPolicy");
        return ipmi::responseUnspecifiedError();
    }
    if (regionLockUnlocked ==
        sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        return ipmi::responseCommandNotAvailable();
    }

    if (0 > sdplus_mdrv1_get_property("SessionId", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting sessionId");
        return ipmi::responseUnspecifiedError();
    }
    if (sessionId != sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        return ipmi::response(IPMI_CC_OEM_SET_IN_PROCESS);
    }

    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      MDRV1_INTERFACE, "RegionComplete");

    method.append(regionIdLocal);

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error set region complete",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV1_PATH));
        return ipmi::responseUnspecifiedError();
    }
    uint8_t status;
    reply.read(status);

    if (status != 0)
    {
        phosphor::logging::log<level::ERR>(
            "Error set region complete, unexpected error");
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

ipmi_ret_t cmd_region_read(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                           ipmi_request_t request, ipmi_response_t response,
                           ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const RegionReadRequest*>(request);
    auto responseData = reinterpret_cast<RegionReadResponse*>(response);
    sdbusplus::message::variant<uint8_t, uint16_t> regUsedVal;
    sdbusplus::message::variant<uint8_t, uint16_t> lockPolicyVal;
    std::vector<uint8_t> res;

    if (*data_len < sizeof(RegionReadRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t regionId = requestData->regionId - 1;

    *data_len = 0;

    if (regionId >= maxMDRId)
    {
        phosphor::logging::log<level::ERR>("Invalid region");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    std::string service = ipmi::getService(bus, MDRV1_INTERFACE, MDRV1_PATH);
    // TODO to make sure the interface can get correct LockPolicy even
    // regionId changed by another task.
    if (set_regionId(regionId, service) < 0)
    {
        phosphor::logging::log<level::ERR>("Error setting regionId");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (0 > sdplus_mdrv1_get_property("RegionUsed", regUsedVal, service))
    {
        phosphor::logging::log<level::ERR>("Error getting regionUsed");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (requestData->offset + requestData->length >
        sdbusplus::message::variant_ns::get<uint16_t>(regUsedVal))
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    if (0 > sdplus_mdrv1_get_property("LockPolicy", lockPolicyVal, service))
    {
        phosphor::logging::log<level::ERR>("Error getting lockPolicy");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (regionLockUnlocked !=
        sdbusplus::message::variant_ns::get<uint8_t>(lockPolicyVal))
    {
        return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
    }

    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      MDRV1_INTERFACE, "RegionRead");

    method.append(regionId, requestData->length, requestData->offset);

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error read region data",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV1_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(res);

    *data_len = responseData->length = res[0];
    responseData->updateCount = res[1];

    if ((*data_len == 0) || (*data_len >= 254))
    {
        phosphor::logging::log<level::ERR>(
            "Data length send from service is invalid");
        *data_len = 0;
        return IPMI_CC_RESPONSE_ERROR;
    }

    *data_len += 2 * sizeof(uint8_t);
    std::copy(&res[2], &res[*data_len], responseData->data);
    return IPMI_CC_OK;
}

/** @brief implements bmc region write command
 *  @parameter
 *   - sessionId - session Lock Handle
 *   - regionId - data Region
 *   - length - data Length
 *   - offset - data Offset
 *   - data - data to be written
 *
 *  @returns IPMI completion code plus response data
 *   - writeData - contains data Region, valid Data,
 *                 lock Status, max Region Length, region Used (in bytes)
 */
ipmi::RspType<std::vector<uint8_t>>
    bmcRegionWrite(uint8_t sessionId, uint8_t regionId, uint8_t length,
                   uint16_t offset, std::vector<uint8_t> data)
{
    sdbusplus::message::variant<uint8_t, uint16_t> value;

    uint8_t regionIdLocal = regionId - 1;
    if (regionIdLocal >= maxMDRId)
    {
        phosphor::logging::log<level::ERR>("Invalid region");
        return ipmi::responseParmOutOfRange();
    }

    std::string service = ipmi::getService(bus, MDRV1_INTERFACE, MDRV1_PATH);

    if (set_regionId(regionIdLocal, service) < 0)
    {
        phosphor::logging::log<level::ERR>("Error setting regionId");
        return ipmi::responseUnspecifiedError();
    }

    if (0 > sdplus_mdrv1_get_property("LockPolicy", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting lockPolicy");
        return ipmi::responseUnspecifiedError();
    }
    if (regionLockUnlocked ==
        sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        return ipmi::responseCommandNotAvailable();
    }

    if (0 > sdplus_mdrv1_get_property("SessionId", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting sessionId");
        return ipmi::responseUnspecifiedError();
    }
    if (sessionId != sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        return ipmi::response(IPMI_CC_OEM_SET_IN_PROCESS);
    }

    uint8_t tmp[255];
    std::copy(&(length), &(data[length]), tmp);
    std::vector<uint8_t> writeData;
    writeData.push_back(regionIdLocal);
    size_t minInputLen = data[0] - sessionId + 1;

    for (uint16_t index = 0; index < minInputLen + length - 2; index++)
    {
        writeData.push_back(tmp[index]);
    }

    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      MDRV1_INTERFACE, "RegionWrite");

    method.append(writeData);

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error write region data",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV1_PATH));
        return ipmi::responseUnspecifiedError();
    }
    std::string res;
    reply.read(res);

    if (res == "NoData")
    {
        return ipmi::responseParmOutOfRange();
    }
    else if (res != "Success")
    {
        phosphor::logging::log<level::ERR>(
            "Error write region data, unexpected error");
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(writeData);
}

/** @brief implements bmc region lock command
 *  @parameter
 *   - sessionId - session Lock Handle
 *   - regionId - data Region
 *   - lockPolicy - Lock Type
 *   - msTimeout - timeout. Number of milliseconds allowed before lock is
 * released
 *
 *  @returns IPMI completion code plus response data
 *   - lockResponse - session Lock Handle
 */
ipmi::RspType<uint8_t> // lockResponse
    bmcRegionLock(uint8_t sessionId, uint8_t regionId, uint8_t lockPolicy,
                  uint16_t msTimeout)
{
    sdbusplus::message::variant<uint8_t, uint16_t> value;

    uint8_t regionIdLocal = regionId - 1;
    if (regionIdLocal >= maxMDRId)
    {
        phosphor::logging::log<level::ERR>("Invalid region");
        return ipmi::responseParmOutOfRange();
    }

    std::string service = ipmi::getService(bus, MDRV1_INTERFACE, MDRV1_PATH);

    if (set_regionId(regionIdLocal, service) < 0)
    {
        phosphor::logging::log<level::ERR>("Error setting regionId");
        return ipmi::responseUnspecifiedError();
    }

    if (0 > sdplus_mdrv1_get_property("LockPolicy", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting lockPolicy");
        return ipmi::responseUnspecifiedError();
    }
    if (lockPolicy == regionLockUnlocked)
    {
        if (regionLockUnlocked ==
            sdbusplus::message::variant_ns::get<uint8_t>(value))
        {
            return ipmi::responseCommandNotAvailable();
        }
    }
    if (regionLockUnlocked !=
        sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        if (0 > sdplus_mdrv1_get_property("SessionId", value, service))
        {
            phosphor::logging::log<level::ERR>("Error getting sessionId");
            return ipmi::responseUnspecifiedError();
        }
        if (sessionId != sdbusplus::message::variant_ns::get<uint8_t>(value))
        {
            if (lockPolicy != regionLockStrict)
            {
                return ipmi::response(IPMI_CC_OEM_SET_IN_PROCESS);
            }
        }
    }
    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      MDRV1_INTERFACE, "RegionLock");

    method.append(sessionId, regionIdLocal, lockPolicy, msTimeout);

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error lock region ",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV1_PATH));
        return ipmi::responseUnspecifiedError();
    }
    uint8_t lockResponse;
    reply.read(lockResponse);

    return ipmi::responseSuccess(lockResponse);
}

static void register_netfn_smbios_functions(void)
{
    // MDR V1 Command
    // <Get MDR Status Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDR_STATUS, NULL,
                           cmd_region_status, PRIVILEGE_OPERATOR);

    // <Update Complete Status Command>
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_INTEL_APP_OEM,
                          IPMI_NETFN_INTEL_OEM_APP_CMD::MDR_COMPLETE,
                          ipmi::Privilege::Operator, bmcRegionUpdateComplete);

    // <Read MDR Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDR_READ, NULL,
                           cmd_region_read, PRIVILEGE_OPERATOR);

    // <Write MDR Command>
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_INTEL_APP_OEM,
                          IPMI_NETFN_INTEL_OEM_APP_CMD::MDR_WRITE,
                          ipmi::Privilege::Operator, bmcRegionWrite);

    // <Lock MDR Command>
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_INTEL_APP_OEM,
                          IPMI_NETFN_INTEL_OEM_APP_CMD::MDR_LOCK,
                          ipmi::Privilege::Operator, bmcRegionLock);
}
