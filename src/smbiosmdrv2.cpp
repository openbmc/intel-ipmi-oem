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

#include <errno.h>
#include <ipmid/api.h>

#include <commandutils.hpp>
#include <cstdint>
#include <ipmid/utils.hpp>
#include <phosphor-ipmi-host/ipmid.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <smbiosmdrv2.hpp>
#include <string>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>

constexpr const char* DBUS_PROPERTIES = "org.freedesktop.DBus.Properties";
constexpr const char* MDRV2_PATH = "/xyz/openbmc_project/Smbios/MDR_V2";
constexpr const char* MDRV2_INTERFACE = "xyz.openbmc_project.Smbios.MDR_V2";
constexpr const int LAST_AGENT_INDEX = -1;
constexpr const uint16_t LAST_AGENT_ID = 0xFFFF;

static void register_netfn_smbiosmdrv2_functions() __attribute__((constructor));
static sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

int gentLookup(const uint16_t& agentId, const std::string& service)
{
    int agentIndex = -1;

    if (LAST_AGENT_ID == agentId)
    {
        return LAST_AGENT_INDEX;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "AgentLookup");
    method.append(agentId);
    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get agent index, sdbusplus call failed");
        return -1;
    }
    reply.read(agentIndex);

    return agentIndex;
}

int findLockHandle(const uint16_t& lockHandle, const std::string& service)
{
    int idIndex = -1;
    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "FindLockHandle");
    method.append(lockHandle);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error find lock handle",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return -1;
    }
    reply.read(idIndex);

    return idIndex;
}

int sdplusMdrv2GetProperty(const std::string& name,
                           sdbusplus::message::variant<uint8_t>& value,
                           const std::string& service)
{
    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, DBUS_PROPERTIES, "Get");
    method.append(MDRV2_INTERFACE, name);
    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get property, sdbusplus call failed");
        return -1;
    }
    reply.read(value);

    return 0;
}

int findDataId(const uint8_t* dataInfo, const size_t& len,
               const std::string& service)
{
    int idIndex = -1;
    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "FindIdIndex");
    std::vector<uint8_t> info;
    for (int index = 0; index < len; index++)
    {
        info.push_back(dataInfo[index]);
    }
    method.append(info);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error find id index",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return -1;
    }
    reply.read(idIndex);

    return idIndex;
}

ipmi_ret_t cmd_mdr2_agent_status(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t data_len,
                                 ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const MDRiiGetAgentStatus*>(request);
    auto dataOut = reinterpret_cast<uint8_t*>(response);
    std::vector<uint8_t> status;

    if (*data_len != sizeof(MDRiiGetAgentStatus))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "AgentStatus");
    method.append(requestData->dirVersion);
    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get agent status",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(status);

    if (status.size() != sizeof(MDRiiAgentStatusResponse))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get agent status response length not valid");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    *data_len = static_cast<size_t>(status.size());
    std::copy(&status[0], &status[*data_len], dataOut);
    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_get_dir(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const MDRiiGetDirRequest*>(request);
    auto dataOut = reinterpret_cast<uint8_t*>(response);
    std::vector<uint8_t> dirInfo;

    if (*data_len != sizeof(MDRiiGetDirRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::variant<uint8_t> value = 0;
    if (0 != sdplusMdrv2GetProperty("DirEntries", value, service))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error getting DirEnries");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (requestData->dirIndex >
        sdbusplus::message::variant_ns::get<uint8_t>(value))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "GetDir");

    method.append(requestData->dirIndex);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get dir",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(dirInfo);

    if (dirInfo.size() < sizeof(MDRiiGetDirResponse))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get dir, response length invalid");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    auto responseData = reinterpret_cast<MDRiiGetDirResponse*>(dirInfo.data());

    *data_len = dirInfo.size();

    if (*data_len > MAX_IPMI_BUFFER) // length + completion code should no more
                                     // than MAX_IPMI_BUFFER
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Data length send from service is invalid");
        *data_len = 0;
        return IPMI_CC_RESPONSE_ERROR;
    }

    std::copy(&dirInfo[0], &dirInfo[*data_len], dataOut);

    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_get_data_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    auto requestData =
        reinterpret_cast<const MDRiiGetDataInfoRequest*>(request);
    auto dataOut = reinterpret_cast<uint8_t*>(response);
    std::vector<uint8_t> res;

    if (*data_len < sizeof(MDRiiGetDataInfoRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex =
        findDataId(requestData->dataSetInfo.dataInfo,
                   sizeof(requestData->dataSetInfo.dataInfo), service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "GetDataInfo");

    method.append(idIndex);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get data info",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(res);

    if (res.size() != sizeof(MDRiiGetDataInfoResponse))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get data info response length not invalid");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    *data_len = static_cast<size_t>(res.size());
    std::copy(&res[0], &res[*data_len], dataOut);

    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_lock_data(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const MDRiiLockDataRequest*>(request);
    auto responseData = reinterpret_cast<MDRiiLockDataResponse*>(response);

    std::tuple<bool, uint8_t, uint16_t, uint32_t, uint32_t, uint32_t> res;

    if (*data_len < sizeof(MDRiiLockDataRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex =
        findDataId(requestData->dataSetInfo.dataInfo,
                   sizeof(requestData->dataSetInfo.dataInfo), service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "LockData");

    method.append((uint8_t)idIndex, requestData->timeout);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        if (reply.get_errno() == EBUSY)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Lock Data failed - cannot lock idIndex");
            return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
        }
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error lock data",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(res);

    if (std::get<0>(res) == false)
    {
        return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
    }

    *data_len = sizeof(MDRiiLockDataResponse);

    responseData->mdrVersion = std::get<1>(res);
    responseData->lockHandle = std::get<2>(res);
    responseData->dataLength = std::get<3>(res);
    responseData->xferAddress = std::get<4>(res);
    responseData->xferLength = std::get<5>(res);

    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_unlock_data(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const MDRiiUnlockDataRequest*>(request);
    std::string resStatus;

    if (*data_len != sizeof(MDRiiUnlockDataRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex = findLockHandle(requestData->lockHandle, service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "UnLockData");
    method.append((uint8_t)idIndex);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        if (reply.get_errno() == EBUSY)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unlock Data failed - cannot unlock idIndex");
            return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
        }
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error unlock data",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(resStatus);

    if (resStatus != "success")
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Agent unlock Invalid lock status.");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_get_data_block(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    auto requestData =
        reinterpret_cast<const MDRiiGetDataBlockRequest*>(request);
    auto responseData = reinterpret_cast<MDRiiGetDataBlockResponse*>(response);
    std::tuple<uint8_t, uint32_t, uint32_t, std::vector<uint8_t>> res;
    std::vector<uint8_t> resData;
    uint8_t status = 1;

    if (*data_len != sizeof(MDRiiGetDataBlockRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex = findLockHandle(requestData->lockHandle, service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "GetDataBlock");
    method.append((uint8_t)idIndex, requestData->xferOffset,
                  requestData->xferLength);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get data block",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(res);

    // Get the status of get data block, 0 means succeed
    status = std::get<0>(res);
    if (status == 1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Request data offset is outside of range.");
        return IPMI_CC_CANNOT_RETURN_NUMBER_OF_REQUESTED_DATA_BYTES;
    }
    else if (status != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get data block unexpected error.");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    responseData->xferLength = std::get<1>(res);
    if (responseData->xferLength > requestData->xferLength)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get data block unexpected error.");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    responseData->checksum = std::get<2>(res);

    resData = std::get<3>(res);

    *data_len = sizeof(responseData->xferLength) +
                sizeof(responseData->checksum) + resData.size();

    if (*data_len > MAX_IPMI_BUFFER) // length + completion code should no more
                                     // than MAX_IPMI_BUFFER
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Data length send from service is invalid");
        *data_len = 0;
        return IPMI_CC_RESPONSE_ERROR;
    }

    std::copy(resData.begin(), resData.end(), responseData->data);

    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_send_dir(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const MDRiiSendDirRequest*>(request);
    std::vector<uint8_t> idVector;
    bool teminate = false;

    if (*data_len != sizeof(MDRiiSendDirRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    if ((requestData->dirIndex + requestData->returnedEntries) > maxDirEntries)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Too many directory entries");
        return IPMI_CC_STORGE_LEAK;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "SendDir");
    method.append(requestData->dirVersion, requestData->dirIndex,
                  requestData->returnedEntries, requestData->remainingEntries);
    uint8_t* reqPoint;
    for (int index = 0; index < requestData->returnedEntries; index++)
    {
        reqPoint = (uint8_t*)&(requestData->data[index]);
        std::copy(reqPoint, sizeof(Mdr2DirEntry) + reqPoint, idVector.data());
    }
    method.append(idVector);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send dir",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(teminate);

    *data_len = 1;
    if (teminate == false)
        *(static_cast<uint8_t*>(response)) = 0;
    else
        *(static_cast<uint8_t*>(response)) = 1;
    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_data_info_offer(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const MDRiiOfferDataInfo*>(request);
    auto dataOut = reinterpret_cast<uint8_t*>(response);
    std::vector<uint8_t> dataInfo;

    if (*data_len != sizeof(MDRiiOfferDataInfo))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "GetDataOffer");

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        if (reply.get_errno() == EBUSY)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send data info offer failed - not available to update data "
                "into agent at present");
            return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
        }
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send data info offer",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(dataInfo);
    if (dataInfo.size() != sizeof(MDRiiOfferDataInfoResponse))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send data info offer, return length invalid");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    *data_len = dataInfo.size();
    std::copy(dataInfo.begin(), dataInfo.end(), dataOut);
    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_send_data_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    auto requestData =
        reinterpret_cast<const MDRiiSendDataInfoRequest*>(request);
    bool entryChanged = true;

    if (*data_len != sizeof(MDRiiSendDataInfoRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    if (requestData->dataLength > smbiosTableStorageSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Requested data length is out of SMBIOS Table storage size.");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex =
        findDataId(requestData->dataSetInfo.dataInfo,
                   sizeof(requestData->dataSetInfo.dataInfo), service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "SendDataInfo");

    method.append((uint8_t)idIndex, requestData->validFlag,
                  requestData->dataLength, requestData->dataVersion,
                  requestData->timeStamp);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send data info",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(entryChanged);

    *data_len = 1;

    if (entryChanged)
    {
        *(static_cast<uint8_t*>(response)) = 1;
    }
    else
    {
        *(static_cast<uint8_t*>(response)) = 0;
    }

    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_data_start(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const MDRiiDataStartRequest*>(request);
    auto responseData = reinterpret_cast<MDRiiDataStartResponse*>(response);
    std::vector<uint8_t> idVector;

    if (*data_len != sizeof(MDRiiDataStartRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    if (requestData->dataLength > smbiosTableStorageSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Requested data length is out of SMBIOS Table storage size.");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    if ((requestData->xferLength + requestData->xferAddress) > mdriiSMSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid data address and size");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex =
        findDataId(requestData->dataSetInfo.dataInfo,
                   sizeof(requestData->dataSetInfo.dataInfo), service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "DataStart");

    for (uint8_t infoIndex = 0; infoIndex < sizeof(DataIdStruct); infoIndex++)
    {
        idVector.push_back(requestData->dataSetInfo.dataInfo[infoIndex]);
    }
    method.append((uint8_t)idIndex, idVector, requestData->dataLength,
                  requestData->xferAddress, requestData->xferLength,
                  requestData->timeout);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        int errNumber = reply.get_errno();
        if (errNumber == ENOMEM)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send data start failed - cannot map share memory");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        else if (errNumber == EINVAL)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Invalid data address and size");
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error Send Data Start",
                phosphor::logging::entry("SERVICE=%s", service.c_str()),
                phosphor::logging::entry("PATH=%s", MDRV2_PATH));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    uint8_t xferStartAck = 0;
    uint16_t sessionHandle = 0;
    reply.read(xferStartAck, sessionHandle);
    responseData->sessionHandle = sessionHandle;
    responseData->xferStartAck = xferStartAck;
    if (responseData->xferStartAck == 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send data start unexpected error");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    *data_len = sizeof(MDRiiDataStartResponse);
    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_data_done(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const MDRiiDataDoneRequest*>(request);
    std::string resStatus;

    if (*data_len != sizeof(MDRiiDataDoneRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex = findLockHandle(requestData->lockHandle, service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "DataDone");
    method.append((uint8_t)idIndex);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        if (reply.get_errno() == EBUSY)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send data done failed - cannot unlock idIndex");
            return IPMI_CC_DESTINATION_UNAVAILABLE;
        }
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error Send Data done",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", MDRV2_PATH));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    reply.read(resStatus);

    if (resStatus != "success")
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Data done failure.");
        return IPMI_CC_DESTINATION_UNAVAILABLE;
    }

    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_send_data_block(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    auto requestData =
        reinterpret_cast<const MDRiiSendDataBlockRequest*>(request);
    std::string resStatus;

    if (*data_len != sizeof(MDRiiSendDataBlockRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, MDRV2_INTERFACE, MDRV2_PATH);

    int agentIndex = agentLookup(requestData->agentId, service);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex = findLockHandle(requestData->lockHandle, service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), MDRV2_PATH, MDRV2_INTERFACE, "SendDataBlock");
    method.append((uint8_t)idIndex, requestData->xferOffset,
                  requestData->xferLength, requestData->checksum);

    sdbusplus::message::message reply = bus.call(method);
    if (reply.is_method_error())
    {
        int errNumber = reply.get_errno();
        if (errNumber == EINVAL)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send data block Invalid checksum");
            return IPMI_CC_OEM_INVALID_CHECKSUM;
        }
        else if (errNumber == ENOBUFS)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send data block Invalid offset/length");
            return IPMI_CC_REQUEST_DATA_FIELD_LENGTH_LIMIT_EXCEEDED;
        }
        else if (errNumber == EBUSY)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send data block failed, other data is updating");
            return IPMI_CC_DESTINATION_UNAVAILABLE;
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error Send data block",
                phosphor::logging::entry("SERVICE=%s", service.c_str()),
                phosphor::logging::entry("PATH=%s", MDRV2_PATH));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    reply.read(resStatus);

    if (resStatus != "success")
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "send data block failure.");
        return IPMI_CC_DESTINATION_UNAVAILABLE;
    }

    return IPMI_CC_OK;
}

static void register_netfn_smbiosmdrv2_functions(void)
{
    // MDR V2 Command
    // <Get MDRII Status Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_AGENT_STATUS,
                           NULL, cmd_mdr2_agent_status, PRIVILEGE_OPERATOR);

    // <Get MDRII Directory Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_GET_DIR, NULL,
                           cmd_mdr2_get_dir, PRIVILEGE_OPERATOR);

    // <Get MDRII Data Info Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_GET_DATA_INFO,
                           NULL, cmd_mdr2_get_data_info, PRIVILEGE_OPERATOR);

    // <Lock MDRII Data Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_LOCK_DATA, NULL,
                           cmd_mdr2_lock_data, PRIVILEGE_OPERATOR);

    // <Unlock MDRII Data Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_UNLOCK_DATA,
                           NULL, cmd_mdr2_unlock_data, PRIVILEGE_OPERATOR);

    // <Get MDRII Data Block Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_GET_DATA_BLOCK,
                           NULL, cmd_mdr2_get_data_block, PRIVILEGE_OPERATOR);

    // <Send MDRII Directory Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_SEND_DIR, NULL,
                           cmd_mdr2_send_dir, PRIVILEGE_OPERATOR);

    // <Send MDRII Info Offer>
    ipmi_register_callback(
        NETFUN_INTEL_APP_OEM,
        IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_SEND_DATA_INFO_OFFER, NULL,
        cmd_mdr2_data_info_offer, PRIVILEGE_OPERATOR);

    // <Send MDRII Data Info>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_SEND_DATA_INFO,
                           NULL, cmd_mdr2_send_data_info, PRIVILEGE_OPERATOR);

    // <Send MDRII Data Start>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_DATA_START, NULL,
                           cmd_mdr2_data_start, PRIVILEGE_OPERATOR);

    // <Send MDRII Data Done>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_DATA_DONE, NULL,
                           cmd_mdr2_data_done, PRIVILEGE_OPERATOR);

    // <Send MDRII Data Block>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_SEND_DATA_BLOCK,
                           NULL, cmd_mdr2_send_data_block, PRIVILEGE_OPERATOR);
}
