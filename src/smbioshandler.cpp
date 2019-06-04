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

#include <commandutils.hpp>
#include <cstdint>
#include <iostream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
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

constexpr const char* dbusProperties = "org.freedesktop.DBus.Properties";
constexpr const char* mdrv1Path = "/xyz/openbmc_project/Smbios/MDR_V1";
constexpr const char* mdrv1Interface = "xyz.openbmc_project.Smbios.MDR_V1";

static void register_netfn_smbios_functions() __attribute__((constructor));

/** @brief implements BMC region status command
 *  @param ctx       - ctx pointer
 *  @param regionId - data Region
 *
 *  @returns IPMI completion code plus response data
 *   - mdrVersion - mdr Version
 *   - dataRegion -  data Region
 *   - valid  - valid Data
 *   - reserved
 *   - updateCount - update Count
 *   - lockPolicy - lock Status
 *   - regionLength - maximum Region Length
 *   - regionUsed - region Size Used
 *   - regionCheckSum  - region Checksum
 */
ipmi::RspType<uint8_t,  // mdrVersion
              uint8_t,  // dataRegion
              bool,     // valid
              uint7_t,  // reserved
              uint8_t,  // updateCount
              uint8_t,  // lockPolicy
              uint16_t, // regionLength
              uint16_t, // regionUsed
              uint8_t   // regionCheckSum
              >
    bmcRegionStatus(ipmi::Context::ptr ctx, uint8_t regionId)
{
    if ((regionId >= maxMDRId) || (regionId == 0))
    {
        phosphor::logging::log<level::INFO>("Invalid region");
        return ipmi::responseParmOutOfRange();
    }

    std::string service =
        ipmi::getService(*(ctx->bus), mdrv1Interface, mdrv1Path);

    uint8_t regionIdLocal = regionId - 1;
    boost::system::error_code ec;
    auto dataOut = ctx->bus->yield_method_call<std::vector<uint8_t>>(
        ctx->yield, ec, service.c_str(), mdrv1Path, mdrv1Interface,
        "RegionStatus", regionIdLocal);

    if (ec)
    {
        phosphor::logging::log<level::ERR>(
            "bmcRegionStatus: Error get region status",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }

    if (dataOut.size() != sizeof(MDRState))
    {
        phosphor::logging::log<level::ERR>(
            "Error get region status, return length invalid");
        return ipmi::responseUnspecifiedError();
    }

    constexpr uint8_t mdrVersionResp = 0;
    constexpr uint8_t dataRegionResp = 1;
    constexpr uint8_t validResp = 2;
    constexpr uint8_t validRespMask = 0x01;
    constexpr uint8_t reservedMask = 0xFE;
    constexpr uint8_t updateCountResp = 3;
    constexpr uint8_t lockPolicyResp = 4;
    constexpr uint8_t regionLengthRespLsb = 5;
    constexpr uint8_t regionLengthRespMsb = 6;
    constexpr uint8_t regionLengthRespMask = 0x08;
    constexpr uint8_t regionUsedRespLsb = 7;
    constexpr uint8_t regionUsedRespMsb = 8;
    constexpr uint8_t regionCheckSumResp = 9;
    uint8_t mdrVersion = static_cast<uint8_t>(dataOut.at(mdrVersionResp));
    uint8_t dataRegion = static_cast<uint8_t>(dataOut.at(dataRegionResp));
    bool valid = static_cast<bool>(dataOut.at(validResp) & validRespMask);
    uint7_t reserved =
        static_cast<uint7_t>(dataOut.at(validResp) & reservedMask);
    uint8_t updateCount = static_cast<uint8_t>(dataOut.at(updateCountResp));
    uint8_t lockPolicy = static_cast<uint8_t>(dataOut.at(lockPolicyResp));
    uint16_t regionLength = static_cast<uint16_t>(
        (dataOut.at(regionLengthRespMsb) << regionLengthRespMask) |
        (dataOut.at(regionLengthRespLsb)));
    uint16_t regionUsed = static_cast<uint16_t>(
        (dataOut.at(regionUsedRespMsb) << regionLengthRespMask) |
        (dataOut.at(regionUsedRespLsb)));
    uint8_t regionCheckSum =
        static_cast<uint8_t>(dataOut.at(regionCheckSumResp));

    return ipmi::responseSuccess(mdrVersion, dataRegion, valid, reserved,
                                 updateCount, lockPolicy, regionLength,
                                 regionUsed, regionCheckSum);
}

int sdplusMdrv1GetProperty(ipmi::Context::ptr ctx, const std::string& name,
                           std::variant<uint8_t, uint16_t>& value,
                           std::string& service)
{
    boost::system::error_code ec;
    value = ctx->bus->yield_method_call<std::variant<uint8_t, uint16_t>>(
        ctx->yield, ec, service.c_str(), mdrv1Path, dbusProperties, "Get",
        mdrv1Interface, name);
    if (ec)
    {
        phosphor::logging::log<level::ERR>(
            "sdplusMdrv1GetProperty: Error getting property, sdbusplus call "
            "failed",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return -1;
    }
    return 0;
}

static int setRegionId(ipmi::Context::ptr ctx, uint8_t regionId,
                       std::string& service)
{
    boost::system::error_code ec;
    std::variant<uint8_t> value{regionId};
    ctx->bus->yield_method_call<void>(ctx->yield, ec, service.c_str(),
                                      mdrv1Path, dbusProperties, "Set",
                                      mdrv1Interface, "RegionId", value);
    if (ec)
    {
        phosphor::logging::log<level::ERR>(
            "setRegionId: Error getting property, sdbusplus call failed",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return -1;
    }
    return 0;
}

int sdplus_mdrv1_get_property(
    const std::string& name,
    sdbusplus::message::variant<uint8_t, uint16_t>& value, std::string& service)
{
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    auto method = bus->new_method_call(service.c_str(), MDRV1_PATH,
                                       DBUS_PROPERTIES, "Get");
    method.append(MDRV1_INTERFACE, name);
    auto reply = bus->call(method);
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
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    auto method = bus->new_method_call(service.c_str(), MDRV1_PATH,
                                       DBUS_PROPERTIES, "Set");
    sdbusplus::message::variant<uint8_t> value{regionId};
    method.append(MDRV1_INTERFACE, "RegionId", value);
    auto region = bus->call(method);
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

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    std::string service = ipmi::getService(*bus, MDRV1_INTERFACE, MDRV1_PATH);

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
    if (regionLockUnlocked == std::get<uint8_t>(value))
    {
        return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
    }

    if (0 > sdplus_mdrv1_get_property("SessionId", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting sessionId");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (requestData->sessionId != std::get<uint8_t>(value))
    {
        return IPMI_CC_OEM_SET_IN_PROCESS;
    }

    auto method = bus->new_method_call(service.c_str(), MDRV1_PATH,
                                       MDRV1_INTERFACE, "RegionComplete");

    method.append(regionId);

    auto reply = bus->call(method);
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
 *  @param ctx       - ctx pointer
 *  @param regionId  - data Region
 *  @param length    - data Length to Read
 *  @param offset    - Offset to read
 *
 *  @returns IPMI completion code plus response data
 *   - response - read Length, update Count, data
 */
ipmi::RspType<std::vector<uint8_t>> bmcRegionRead(ipmi::Context::ptr ctx,
                                                  uint8_t regionId,
                                                  uint8_t length,
                                                  uint16_t offset)
{
    if ((regionId >= maxMDRId) || (regionId == 0))
    {
        phosphor::logging::log<level::INFO>("Invalid region");
        return ipmi::responseParmOutOfRange();
    }

    std::string service =
        ipmi::getService(*(ctx->bus), mdrv1Interface, mdrv1Path);
    uint8_t regionIdLocal = regionId - 1;

    // TODO to make sure the interface can get correct LockPolicy even
    // regionId changed by another task.
    if (setRegionId(ctx, regionIdLocal, service) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }

    std::variant<uint8_t, uint16_t> regUsedVal;
    if (sdplusMdrv1GetProperty(ctx, "RegionUsed", regUsedVal, service) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }
    if (offset + length > std::get<uint16_t>(regUsedVal))
    {
        return ipmi::responseReqDataLenInvalid();
    }

    std::variant<uint8_t, uint16_t> lockPolicyVal;
    if (sdplusMdrv1GetProperty(ctx, "LockPolicy", lockPolicyVal, service) < 0)
    {
        return ipmi::responseUnspecifiedError();
    }
    if (regionLockUnlocked != std::get<uint8_t>(lockPolicyVal))
    {
        return ipmi::responseCommandNotAvailable();
    }

    boost::system::error_code ec;
    auto res = ctx->bus->yield_method_call<std::vector<uint8_t>>(
        ctx->yield, ec, service.c_str(), mdrv1Path, mdrv1Interface,
        "RegionRead", regionIdLocal, length, offset);

    if (ec)
    {
        phosphor::logging::log<level::ERR>(
            "bmcRegionRead: Error read region data",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }

    if (res.size() < 2)
    {
        phosphor::logging::log<level::ERR>(
            "Data length send from service is invalid");
        return ipmi::responseResponseError();
    }

    uint8_t responseLength = res[0];
    if ((responseLength == 0) || (responseLength >= 254) ||
        (res.size() != (responseLength + 2)))
    {
        phosphor::logging::log<level::ERR>(
            "Data length send from service is invalid");
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(res);
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

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    std::string service = ipmi::getService(*bus, MDRV1_INTERFACE, MDRV1_PATH);

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
    if (regionLockUnlocked == std::get<uint8_t>(value))
    {
        return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
    }

    if (0 > sdplus_mdrv1_get_property("SessionId", value, service))
    {
        phosphor::logging::log<level::ERR>("Error getting sessionId");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (requestData->sessionId != std::get<uint8_t>(value))
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

    auto method = bus->new_method_call(service.c_str(), MDRV1_PATH,
                                       MDRV1_INTERFACE, "RegionWrite");

    method.append(writeData);

    auto reply = bus->call(method);
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

    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    std::string service = ipmi::getService(*bus, MDRV1_INTERFACE, MDRV1_PATH);

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
        if (regionLockUnlocked == std::get<uint8_t>(value))
        {
            return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
        }
    }
    if (regionLockUnlocked != std::get<uint8_t>(value))
    {
        if (0 > sdplus_mdrv1_get_property("SessionId", value, service))
        {
            phosphor::logging::log<level::ERR>("Error getting sessionId");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        if (requestData->sessionId != std::get<uint8_t>(value))
        {
            if (requestData->lockPolicy != regionLockStrict)
            {
                return IPMI_CC_OEM_SET_IN_PROCESS;
            }
        }
    }
    auto method = bus->new_method_call(service.c_str(), MDRV1_PATH,
                                       MDRV1_INTERFACE, "RegionLock");

    method.append(requestData->sessionId, regionId, requestData->lockPolicy,
                  requestData->msTimeout);

    auto reply = bus->call(method);
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
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrStatus,
                          ipmi::Privilege::Operator, bmcRegionStatus);

    // <Update Complete Status Command>
    ipmi_register_callback(ipmi::intel::netFnApp,
                           ipmi::intel::app::cmdMdrComplete, NULL,
                           cmd_region_complete, PRIVILEGE_OPERATOR);

    // <Read MDR Command>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::intel::netFnApp,
                          ipmi::intel::app::cmdMdrRead,
                          ipmi::Privilege::Operator, bmcRegionRead);

    // <Write MDR Command>
    ipmi_register_callback(ipmi::intel::netFnApp, ipmi::intel::app::cmdMdrWrite,
                           NULL, cmd_region_write, PRIVILEGE_OPERATOR);

    // <Lock MDR Command>
    ipmi_register_callback(ipmi::intel::netFnApp, ipmi::intel::app::cmdMdrLock,
                           NULL, cmd_region_lock, PRIVILEGE_OPERATOR);
}
