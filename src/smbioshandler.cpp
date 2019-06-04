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

/** @brief implements BMC region status command
 *  @param regionId - data Region
 *
 *  @returns IPMI completion code plus response data
 *   - dataOut -  MDR Version, Data Region, Valid Data, Update Count,
 *                Lock Status, Maximum Region Length,  Region Size Used,
 *                Region Checksum
 */
ipmi::RspType<std::vector<uint8_t>> bmcRegionStatus(uint8_t regionId)
{
    uint8_t regionIdLocal = regionId - 1;
    if (regionIdLocal >= maxMDRId)
    {
        phosphor::logging::log<level::ERR>("Invalid region");
        return ipmi::responseParmOutOfRange();
    }
    std::string service = ipmi::getService(bus, MDRV1_INTERFACE, MDRV1_PATH);
    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      MDRV1_INTERFACE, "RegionStatus");
    method.append(regionIdLocal);
    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error get region status",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV1_PATH));
        return ipmi::responseUnspecifiedError();
    }
    std::vector<uint8_t> dataOut;
    reply.read(dataOut);
    if (dataOut.size() != sizeof(MDRState))
    {
        phosphor::logging::log<level::ERR>(
            "Error get region status, return length invalid");
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(dataOut);
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

ipmi_ret_t cmd_region_complete(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const RegionCompleteRequest*>(request);
    uint8_t status;

    sdbusplus::message::variant<uint8_t, uint16_t> value;

    if (*data_len != sizeof(RegionCompleteRequest))
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

    if (set_regionId(regionId, service) < 0)
    {
        phosphor::logging::log<level::ERR>("Error setting regionId");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    if (0 > sdplus_mdrv1_get_property("LockPolicy", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting lockPolicy");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (regionLockUnlocked ==
        sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
    }

    if (0 > sdplus_mdrv1_get_property("SessionId", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting sessionId");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (requestData->sessionId !=
        sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        return IPMI_CC_OEM_SET_IN_PROCESS;
    }

    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      MDRV1_INTERFACE, "RegionComplete");

    method.append(regionId);

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error set region complete",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV1_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(status);

    if (status != 0)
        phosphor::logging::log<level::ERR>(
            "Error set region complete, unexpected error");
    return IPMI_CC_UNSPECIFIED_ERROR;

    return IPMI_CC_OK;
}

/** @brief implements BMC region read command
 *  @parameter
 *   - regionId - data Region
 *   - length  - data Length to Read
 *   - offset  - Offset to read
 *
 *  @returns IPMI completion code plus response data
 *   - responseLength - read Length
 *   - updateCount - update Count
 *   - data
 */
ipmi::RspType<uint8_t, uint8_t, std::vector<uint8_t>>
    bmcRegionRead(uint8_t regionId, uint8_t length, uint16_t offset)
{
    sdbusplus::message::variant<uint8_t, uint16_t> regUsedVal;
    sdbusplus::message::variant<uint8_t, uint16_t> lockPolicyVal;
    std::vector<uint8_t> res;
    uint8_t regionIdLocal = regionId - 1;

    if (regionIdLocal >= maxMDRId)
    {
        phosphor::logging::log<level::ERR>("Invalid region");
        return ipmi::responseParmOutOfRange();
    }

    std::string service = ipmi::getService(bus, MDRV1_INTERFACE, MDRV1_PATH);
    // TODO to make sure the interface can get correct LockPolicy even
    // regionId changed by another task.
    if (set_regionId(regionIdLocal, service) < 0)
    {
        phosphor::logging::log<level::ERR>("Error setting regionId");
        return ipmi::responseUnspecifiedError();
    }
    if (0 > sdplus_mdrv1_get_property("RegionUsed", regUsedVal, service))
    {
        phosphor::logging::log<level::ERR>("Error getting regionUsed");
        return ipmi::responseUnspecifiedError();
    }
    if (offset + length >
        sdbusplus::message::variant_ns::get<uint16_t>(regUsedVal))
    {
        return ipmi::responseReqDataLenInvalid();
    }

    if (0 > sdplus_mdrv1_get_property("LockPolicy", lockPolicyVal, service))
    {
        phosphor::logging::log<level::ERR>("Error getting lockPolicy");
        return ipmi::responseUnspecifiedError();
    }
    if (regionLockUnlocked !=
        sdbusplus::message::variant_ns::get<uint8_t>(lockPolicyVal))
    {
        return ipmi::responseCommandNotAvailable();
    }

    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      MDRV1_INTERFACE, "RegionRead");

    method.append(regionIdLocal, length, offset);

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error read region data",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV1_PATH));
        return ipmi::responseUnspecifiedError();
    }
    reply.read(res);

    uint8_t responseLength = res[0];
    uint8_t updateCount = res[1];

    if ((responseLength == 0) || (responseLength >= 254))
    {
        phosphor::logging::log<level::ERR>(
            "Data length send from service is invalid");
        responseLength = 0;
        return ipmi::responseResponseError();
    }

    responseLength += 2 * sizeof(uint8_t);
    std::vector<uint8_t> data;
    std::copy(&res[2], &res[responseLength], data.begin());

    return ipmi::responseSuccess(responseLength, updateCount, data);
}

ipmi_ret_t cmd_region_write(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const RegionWriteRequest*>(request);
    uint8_t regionId = requestData->regionId - 1;
    std::string res;
    std::vector<uint8_t> writeData;
    uint16_t index;
    uint8_t tmp[255];

    size_t minInputLen = &requestData->data[0] - &requestData->sessionId + 1;
    if (*data_len < minInputLen)
    { // this command need at least 6 bytes input
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    sdbusplus::message::variant<uint8_t, uint16_t> value;

    *data_len = 0;

    if (regionId >= maxMDRId)
    {
        phosphor::logging::log<level::ERR>("Invalid region");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    std::string service = ipmi::getService(bus, MDRV1_INTERFACE, MDRV1_PATH);

    if (set_regionId(regionId, service) < 0)
    {
        phosphor::logging::log<level::ERR>("Error setting regionId");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    if (0 > sdplus_mdrv1_get_property("LockPolicy", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting lockPolicy");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (regionLockUnlocked ==
        sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
    }

    if (0 > sdplus_mdrv1_get_property("SessionId", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting sessionId");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (requestData->sessionId !=
        sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        return IPMI_CC_OEM_SET_IN_PROCESS;
    }

    std::copy(&(requestData->length), &(requestData->data[requestData->length]),
              tmp);
    writeData.push_back(regionId);
    for (index = 0; index < minInputLen + requestData->length - 2; index++)
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
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(res);

    if (res == "NoData")
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    else if (res != "Success")
    {
        phosphor::logging::log<level::ERR>(
            "Error write region data, unexpected error");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    return IPMI_CC_OK;
}

ipmi_ret_t cmd_region_lock(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                           ipmi_request_t request, ipmi_response_t response,
                           ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const RegionLockRequest*>(request);
    uint8_t regionId = requestData->regionId - 1;
    sdbusplus::message::variant<uint8_t, uint16_t> value;
    auto res = reinterpret_cast<uint8_t*>(response);
    uint8_t lockResponse;

    if (*data_len != sizeof(RegionLockRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    if (regionId >= maxMDRId)
    {
        phosphor::logging::log<level::ERR>("Invalid region");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    std::string service = ipmi::getService(bus, MDRV1_INTERFACE, MDRV1_PATH);

    if (set_regionId(regionId, service) < 0)
    {
        phosphor::logging::log<level::ERR>("Error setting regionId");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    if (0 > sdplus_mdrv1_get_property("LockPolicy", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting lockPolicy");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (requestData->lockPolicy == regionLockUnlocked)
    {
        if (regionLockUnlocked ==
            sdbusplus::message::variant_ns::get<uint8_t>(value))
        {
            return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
        }
    }
    if (regionLockUnlocked !=
        sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        if (0 > sdplus_mdrv1_get_property("SessionId", value, service))
        {
            phosphor::logging::log<level::ERR>("Error getting sessionId");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        if (requestData->sessionId !=
            sdbusplus::message::variant_ns::get<uint8_t>(value))
        {
            if (requestData->lockPolicy != regionLockStrict)
            {
                return IPMI_CC_OEM_SET_IN_PROCESS;
            }
        }
    }
    auto method = bus.new_method_call(service.c_str(), MDRV1_PATH,
                                      MDRV1_INTERFACE, "RegionLock");

    method.append(requestData->sessionId, regionId, requestData->lockPolicy,
                  requestData->msTimeout);

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<level::ERR>(
            "Error lock region ",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV1_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(lockResponse);

    *data_len = sizeof(lockResponse);
    *res = lockResponse;
    return IPMI_CC_OK;
}

static void register_netfn_smbios_functions(void)
{
    // MDR V1 Command
    // <Get MDR Status Command>
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_INTEL_APP_OEM,
                          IPMI_NETFN_INTEL_OEM_APP_CMD::MDR_STATUS,
                          ipmi::Privilege::Operator, bmcRegionStatus);

    // <Update Complete Status Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDR_COMPLETE, NULL,
                           cmd_region_complete, PRIVILEGE_OPERATOR);

    // <Read MDR Command>
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_INTEL_APP_OEM,
                          IPMI_NETFN_INTEL_OEM_APP_CMD::MDR_READ,
                          ipmi::Privilege::Operator, bmcRegionRead);

    // <Write MDR Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDR_WRITE, NULL,
                           cmd_region_write, PRIVILEGE_OPERATOR);

    // <Lock MDR Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDR_LOCK, NULL,
                           cmd_region_lock, PRIVILEGE_OPERATOR);
}
