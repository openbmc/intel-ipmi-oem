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
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <commandutils.hpp>
#include <cstdint>
#include <fstream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>
#include <smbiosmdrv2handler.hpp>
#include <string>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Smbios/MDR_V2/error.hpp>

std::unique_ptr<MDRV2> mdrv2 = nullptr;

namespace variant_ns = sdbusplus::message::variant_ns;

static void register_netfn_smbiosmdrv2_functions() __attribute__((constructor));
static sdbusplus::bus::bus bus(ipmid_get_sd_bus_connection());

int MDRV2::agentLookup(const uint16_t &agentId)
{
    int agentIndex = -1;

    if (lastAgentId == agentId)
    {
        return lastAgentIndex;
    }

    if (agentId == smbiosAgentId)
    {
        return firstAgentIndex;
    }

    return agentIndex;
}

int MDRV2::sdplusMdrv2GetProperty(const std::string &name,
                                  sdbusplus::message::variant<uint8_t> &value,
                                  const std::string &service)
{
    sdbusplus::message::message method =
        bus.new_method_call(service.c_str(), mdrv2Path, dbusProperties, "Get");
    method.append(mdrv2Interface, name);

    sdbusplus::message::message reply = bus.call(method);

    try
    {
        sdbusplus::message::message reply = bus.call(method);
        reply.read(value);
    }
    catch (sdbusplus::exception_t &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get property, sdbusplus call failed");
        return -1;
    }

    return 0;
}

int MDRV2::syncDirCommonData(uint8_t idIndex, uint32_t size,
                             const std::string &service)
{
    std::vector<uint32_t> commonData;
    sdbusplus::message::message method =
        bus.new_method_call(service.c_str(), mdrv2Path, mdrv2Interface,
                            "SynchronizeDirectoryCommonData");
    method.append(idIndex, size);

    try
    {
        sdbusplus::message::message reply = bus.call(method);
        reply.read(commonData);
    }
    catch (sdbusplus::exception_t &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error sync dir common data with service");
        return -1;
    }

    if (commonData.size() < syncDirCommonSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error sync dir common data - data length invalid");
        return -1;
    }
    smbiosDir.dir[idIndex].common.dataSetSize = commonData.at(0);
    smbiosDir.dir[idIndex].common.dataVersion = commonData.at(1);
    smbiosDir.dir[idIndex].common.timestamp = commonData.at(2);

    return 0;
}

int MDRV2::findDataId(const uint8_t *dataInfo, const size_t &len,
                      const std::string &service)
{
    int idIndex = -1;

    if (dataInfo == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error dataInfo, input is null point");
        return -1;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), mdrv2Path, mdrv2Interface, "FindIdIndex");
    std::vector<uint8_t> info;
    info.resize(len);
    std::copy(dataInfo, dataInfo + len, info.data());
    method.append(info);

    try
    {
        sdbusplus::message::message reply = bus.call(method);
        reply.read(idIndex);
    }
    catch (sdbusplus::exception_t &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error find id index",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", mdrv2Path));
        return -1;
    }

    return idIndex;
}

uint16_t MDRV2::getSessionHandle(Mdr2DirStruct *dir)
{
    if (dir == NULL)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Empty dir point");
        return 0;
    }
    dir->sessionHandle++;
    if (dir->sessionHandle == 0)
    {
        dir->sessionHandle = 1;
    }

    return dir->sessionHandle;
}

int MDRV2::findLockHandle(const uint16_t &lockHandle)
{
    int idIndex = -1;

    for (int index = 0; index < smbiosDir.dirEntries; index++)
    {
        if (lockHandle == smbiosDir.dir[index].lockHandle)
        {
            return index;
        }
    }

    return idIndex;
}

bool MDRV2::smbiosIsUpdating(uint8_t index)
{
    if (index > maxDirEntries)
    {
        return false;
    }
    if (smbiosDir.dir[index].stage == MDR2SMBIOSStatusEnum::mdr2Updating)
    {
        return true;
    }

    return false;
}

uint32_t MDRV2::calcChecksum32(uint8_t *buf, uint32_t len)
{
    uint32_t sum = 0;

    if (buf == nullptr)
    {
        return invalidChecksum;
    }

    for (uint32_t index = 0; index < len; index++)
    {
        sum += buf[index];
    }

    return sum;
}

/** @brief implements mdr2 agent status command
 *  @param agentId
 *  @param dirVersion
 *
 *  @returns IPMI completion code plus response data
 *  - mdrVersion
 *  - agentVersion
 *  - dirVersion
 *  - dirEntries
 *  - dataRequest
 */
ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t, uint8_t>
    mdr2AgentStatus(uint16_t agentId, uint8_t dirVersion)
{
    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    constexpr uint8_t mdrVersion = mdr2Version;
    constexpr uint8_t agentVersion = smbiosAgentVersion;
    uint8_t dirVersionResp = mdrv2->smbiosDir.dirVersion;
    uint8_t dirEntries = mdrv2->smbiosDir.dirEntries;
    uint8_t dataRequest;

    if (mdrv2->smbiosDir.remoteDirVersion != dirVersion)
    {
        mdrv2->smbiosDir.remoteDirVersion = dirVersion;
        dataRequest =
            static_cast<uint8_t>(DirDataRequestEnum::dirDataRequested);
    }
    else
    {
        dataRequest =
            static_cast<uint8_t>(DirDataRequestEnum::dirDataNotRequested);
    }

    return ipmi::responseSuccess(mdrVersion, agentVersion, dirVersionResp,
                                 dirEntries, dataRequest);
}

ipmi_ret_t cmd_mdr2_get_dir(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const MDRiiGetDirRequest *>(request);
    auto dataOut = reinterpret_cast<uint8_t *>(response);
    std::vector<uint8_t> dirInfo;

    if (*data_len != sizeof(MDRiiGetDirRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(requestData->agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::variant<uint8_t> value = 0;
    if (0 != mdrv2->sdplusMdrv2GetProperty("DirectoryEntries", value, service))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error getting DirEnries");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    if (requestData->dirIndex > variant_ns::get<uint8_t>(value))
    {
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), mdrv2Path, mdrv2Interface, "GetDirectoryInformation");

    method.append(requestData->dirIndex);

    try
    {
        sdbusplus::message::message reply = bus.call(method);
        reply.read(dirInfo);
    }
    catch (sdbusplus::xyz::openbmc_project::Smbios::MDR_V2::Error::
               InvalidParameter)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get dir - Invalid parameter");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    catch (sdbusplus::exception_t &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get dir",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", mdrv2Path));
        return IPMI_CC_RESPONSE_ERROR;
    }

    if (dirInfo.size() < sizeof(MDRiiGetDirResponse))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get dir, response length invalid");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    auto responseData = reinterpret_cast<MDRiiGetDirResponse *>(dirInfo.data());

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

ipmi::RspType<bool> mdr2SendDir(uint16_t agentId, uint8_t dirVersion,
                                      uint8_t dirIndex, uint8_t returnedEntries,
                                      uint8_t remainingEntries,
                                      std::array<uint8_t, 16> dataInfo,
                                      uint32_t size, uint32_t dataSetSize,
                                      uint32_t dataVersion, uint32_t timestamp)
{
    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);
    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    if ((dirIndex + returnedEntries) > maxDirEntries)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Too many directory entries");
        return ipmi::response(IPMI_CC_STORGE_LEAK);
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), mdrv2Path, mdrv2Interface, "SendDirectoryInformation");
    method.append(dirVersion, dirIndex, returnedEntries, remainingEntries,
                  dataInfo, size, dataSetSize, dataVersion, timestamp);

    bool teminate = false;
    try
    {
        sdbusplus::message::message reply = bus.call(method);
        reply.read(teminate);
    }
    catch (sdbusplus::xyz::openbmc_project::Smbios::MDR_V2::Error::
               InvalidParameter)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send dir - Invalid parameter");
        return ipmi::responseParmOutOfRange();
    }
    catch (sdbusplus::exception_t &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send dir",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", mdrv2Path));
        return ipmi::responseResponseError();
    }

    bool response = false;
    if (teminate == false)
    {
        response = 0;
    }
    else
    {
        response = 1;
    }

    return ipmi::responseSuccess(response);
}

ipmi_ret_t cmd_mdr2_get_data_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t data_len,
                                  ipmi_context_t context)
{
    auto requestData =
        reinterpret_cast<const MDRiiGetDataInfoRequest *>(request);
    auto dataOut = reinterpret_cast<uint8_t *>(response);
    std::vector<uint8_t> res;

    if (*data_len < sizeof(MDRiiGetDataInfoRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(requestData->agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex =
        mdrv2->findDataId(requestData->dataSetInfo.dataInfo,
                          sizeof(requestData->dataSetInfo.dataInfo), service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), mdrv2Path, mdrv2Interface, "GetDataInformation");

    method.append(idIndex);

    try
    {
        sdbusplus::message::message reply = bus.call(method);
        reply.read(res);
    }
    catch (sdbusplus::exception_t &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error get data info",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", mdrv2Path));
        return IPMI_CC_RESPONSE_ERROR;
    }

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

/** @brief implements mdr2 data info offer command
 *  @param agentId - Offer a agent ID to get the "Data Set ID"
 *
 *  @returns IPMI completion code plus response data
 *  - dataInfo
 */
ipmi::RspType<std::vector<uint8_t>> mdr2DataInfoOffer(uint16_t agentId)
{
    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), mdrv2Path, mdrv2Interface, "GetDataOffer");

    std::vector<uint8_t> dataInfo;
    try
    {
        sdbusplus::message::message reply = bus.call(method);
        reply.read(dataInfo);
    }
    catch (
        sdbusplus::xyz::openbmc_project::Smbios::MDR_V2::Error::UpdateInProgress
            &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send data info offer failed - not available to update data "
            "into agent at present");
        return ipmi::responseCommandNotAvailable();
    }
    catch (sdbusplus::exception_t &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send data info offer",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", mdrv2Path));
        return ipmi::responseResponseError();
    }

    if (dataInfo.size() != sizeof(MDRiiOfferDataInfoResponse))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send data info offer, return length invalid");
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(dataInfo);
}

ipmi_ret_t cmd_mdr2_send_data_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    auto requestData =
        reinterpret_cast<const MDRiiSendDataInfoRequest *>(request);
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

    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(requestData->agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex =
        mdrv2->findDataId(requestData->dataSetInfo.dataInfo,
                          sizeof(requestData->dataSetInfo.dataInfo), service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), mdrv2Path, mdrv2Interface, "SendDataInformation");

    method.append((uint8_t)idIndex, requestData->validFlag,
                  requestData->dataLength, requestData->dataVersion,
                  requestData->timeStamp);

    try
    {
        sdbusplus::message::message reply = bus.call(method);
        reply.read(entryChanged);
    }
    catch (sdbusplus::exception_t &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error send data info",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", mdrv2Path));
        return IPMI_CC_RESPONSE_ERROR;
    }

    *data_len = 1;

    if (entryChanged)
    {
        *(static_cast<uint8_t *>(response)) = 1;
    }
    else
    {
        *(static_cast<uint8_t *>(response)) = 0;
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
        reinterpret_cast<const MDRiiGetDataBlockRequest *>(request);
    auto responseData = reinterpret_cast<MDRiiGetDataBlockResponse *>(response);
    std::tuple<uint8_t, uint32_t, uint32_t, std::vector<uint8_t>> res;
    std::vector<uint8_t> resData;
    uint8_t status = 1;

    if (*data_len != sizeof(MDRiiGetDataBlockRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(requestData->agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex = mdrv2->findLockHandle(requestData->lockHandle);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    if (requestData->xferOffset >= mdrv2->smbiosDir.dir[idIndex].common.size)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Offset is outside of range.");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    size_t outSize =
        (requestData->xferLength > mdrv2->smbiosDir.dir[idIndex].xferSize)
            ? mdrv2->smbiosDir.dir[idIndex].xferSize
            : requestData->xferLength;
    if (outSize > UINT_MAX - requestData->xferOffset)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Out size and offset are out of range");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
    if ((requestData->xferOffset + outSize) >
        mdrv2->smbiosDir.dir[idIndex].common.size)
    {
        outSize =
            mdrv2->smbiosDir.dir[idIndex].common.size - requestData->xferOffset;
    }

    responseData->xferLength = outSize;
    if (responseData->xferLength > requestData->xferLength)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get data block unexpected error.");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    if ((requestData->xferOffset + outSize) >
        UINT_MAX -
            reinterpret_cast<size_t>(mdrv2->smbiosDir.dir[idIndex].dataStorage))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Input data to calculate checksum is out of range");
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    uint32_t u32Checksum = mdrv2->calcChecksum32(
        mdrv2->smbiosDir.dir[idIndex].dataStorage + requestData->xferOffset,
        outSize);
    if (u32Checksum == invalidChecksum)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Get data block failed - invalid checksum");
        return IPMI_CC_OEM_INVALID_CHECKSUM;
    }
    responseData->checksum = u32Checksum;

    *data_len = sizeof(responseData->xferLength) +
                sizeof(responseData->checksum) + outSize;

    if (*data_len > MAX_IPMI_BUFFER) // length + completion code should no more
                                     // than MAX_IPMI_BUFFER
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Data length send from service is invalid");
        *data_len = 0;
        return IPMI_CC_RESPONSE_ERROR;
    }

    std::copy(
        &mdrv2->smbiosDir.dir[idIndex].dataStorage[requestData->xferOffset],
        &mdrv2->smbiosDir.dir[idIndex]
             .dataStorage[requestData->xferOffset + outSize],
        responseData->data);

    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_send_data_block(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    auto requestData =
        reinterpret_cast<const MDRiiSendDataBlockRequest *>(request);

    if (*data_len != sizeof(MDRiiSendDataBlockRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(requestData->agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex = mdrv2->findLockHandle(requestData->lockHandle);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    if (mdrv2->smbiosIsUpdating(idIndex))
    {
        if (requestData->xferOffset > UINT_MAX - requestData->xferLength)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Offset and length are out of range");
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }
        if (((requestData->xferOffset + requestData->xferLength) >
             mdrv2->smbiosDir.dir[idIndex].maxDataSize) ||
            ((requestData->xferOffset + requestData->xferLength) >
             mdrv2->smbiosDir.dir[idIndex].common.dataSetSize))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send data block Invalid offset/length");
            return IPMI_CC_REQUEST_DATA_FIELD_LENGTH_LIMIT_EXCEEDED;
        }
        if (reinterpret_cast<size_t>(
                mdrv2->smbiosDir.dir[idIndex].dataStorage) >
            UINT_MAX - requestData->xferOffset)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Offset is out of range");
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }
        uint8_t *destAddr =
            mdrv2->smbiosDir.dir[idIndex].dataStorage + requestData->xferOffset;
        uint8_t *sourceAddr = reinterpret_cast<uint8_t *>(mdrv2->area->vPtr);
        uint32_t calcChecksum =
            mdrv2->calcChecksum32(sourceAddr, requestData->xferLength);
        if (calcChecksum != requestData->checksum)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Send data block Invalid checksum");
            return IPMI_CC_OEM_INVALID_CHECKSUM;
        }
        else
        {
            if (reinterpret_cast<size_t>(sourceAddr) >
                UINT_MAX - requestData->xferLength)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Length is out of range");
                return IPMI_CC_PARM_OUT_OF_RANGE;
            }
            std::copy(sourceAddr, sourceAddr + requestData->xferLength,
                      destAddr);
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send data block failed, other data is updating");
        return IPMI_CC_DESTINATION_UNAVAILABLE;
    }

    return IPMI_CC_OK;
}

bool MDRV2::storeDatatoFlash(MDRSMBIOSHeader *mdrHdr, uint8_t *data)
{
    std::ofstream smbiosFile(mdrType2File,
                             std::ios_base::binary | std::ios_base::trunc);
    if (!smbiosFile.good())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Write data from flash error - Open MDRV2 table file failure");
        return false;
    }

    try
    {
        smbiosFile.write(reinterpret_cast<char *>(mdrHdr),
                         sizeof(MDRSMBIOSHeader));
        smbiosFile.write(reinterpret_cast<char *>(data), mdrHdr->dataSize);
    }
    catch (std::ofstream::failure &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Write data from flash error - write data error");
        return false;
    }

    return true;
}

void SharedMemoryArea::Initialize(uint32_t addr, uint32_t areaSize)
{
    int memDriver = 0;

    // open mem driver for the system memory access
    memDriver = open("/dev/vgasharedmem", O_RDONLY);
    if (memDriver < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Cannot access mem driver");
        throw std::system_error(EIO, std::generic_category());
    }

    // map the system memory
    vPtr = mmap(NULL,                       // where to map to: don't mind
                areaSize,                   // how many bytes ?
                PROT_READ,                  // want to read and write
                MAP_SHARED,                 // no copy on write
                memDriver,                  // handle to /dev/mem
                (physicalAddr & pageMask)); // hopefully the Text-buffer :-)

    close(memDriver);
    if (vPtr == MAP_FAILED)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to map share memory");
        throw std::system_error(EIO, std::generic_category());
    }
    size = areaSize;
    physicalAddr = addr;
}

bool MDRV2::smbiosUnlock(uint8_t index)
{
    bool ret;
    switch (smbiosDir.dir[index].stage)
    {
        case MDR2SMBIOSStatusEnum::mdr2Updating:
            smbiosDir.dir[index].stage = MDR2SMBIOSStatusEnum::mdr2Updated;
            smbiosDir.dir[index].lock = MDR2DirLockEnum::mdr2DirUnlock;

            timer->stop();
            smbiosDir.dir[index].lockHandle = 0;
            ret = true;
            break;

        case MDR2SMBIOSStatusEnum::mdr2Updated:
        case MDR2SMBIOSStatusEnum::mdr2Loaded:
            smbiosDir.dir[index].lock = MDR2DirLockEnum::mdr2DirUnlock;

            timer->stop();

            smbiosDir.dir[index].lockHandle = 0;
            ret = true;
            break;

        default:
            break;
    }

    return ret;
}

bool MDRV2::smbiosTryLock(uint8_t flag, uint8_t index, uint16_t *session,
                          uint16_t timeout)
{
    bool ret = false;
    uint32_t u32Status = 0;

    if (timeout == 0)
    {
        timeout = defaultTimeout;
    }
    std::chrono::microseconds usec(timeout * sysClock);

    switch (smbiosDir.dir[index].stage)
    {
        case MDR2SMBIOSStatusEnum::mdr2Updating:
            if (smbiosDir.dir[index].lock != MDR2DirLockEnum::mdr2DirLock)
            {
                smbiosDir.dir[index].lock = MDR2DirLockEnum::mdr2DirLock;
                timer->start(usec);
                lockIndex = index;

                *session = getSessionHandle(&smbiosDir);
                smbiosDir.dir[index].lockHandle = *session;
                ret = true;
            }
            break;
        case MDR2SMBIOSStatusEnum::mdr2Init:
            if (flag)
            {
                smbiosDir.dir[index].stage = MDR2SMBIOSStatusEnum::mdr2Updating;
                smbiosDir.dir[index].lock = MDR2DirLockEnum::mdr2DirUnlock;
                timer->start(usec);
                lockIndex = index;

                *session = getSessionHandle(&smbiosDir);
                smbiosDir.dir[index].lockHandle = *session;
                ret = true;
            }
            break;

        case MDR2SMBIOSStatusEnum::mdr2Updated:
        case MDR2SMBIOSStatusEnum::mdr2Loaded:
            if (smbiosDir.dir[index].lock != MDR2DirLockEnum::mdr2DirLock)
            {
                if (flag)
                {
                    smbiosDir.dir[index].stage =
                        MDR2SMBIOSStatusEnum::mdr2Updating;
                    smbiosDir.dir[index].lock = MDR2DirLockEnum::mdr2DirUnlock;
                }
                else
                {
                    smbiosDir.dir[index].lock = MDR2DirLockEnum::mdr2DirLock;
                }

                timer->start(usec);
                lockIndex = index;

                *session = getSessionHandle(&smbiosDir);
                smbiosDir.dir[index].lockHandle = *session;
                ret = true;
            }
            break;

        default:
            break;
    }
    return ret;
}

void MDRV2::timeoutHandler()
{
    smbiosUnlock(lockIndex);
    mdrv2->area.reset(nullptr);
}

ipmi_ret_t cmd_mdr2_lock_data(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t data_len, ipmi_context_t context)
{
    auto requestData = reinterpret_cast<const MDRiiLockDataRequest *>(request);
    auto responseData = reinterpret_cast<MDRiiLockDataResponse *>(response);
    uint16_t session = 0;

    std::tuple<bool, uint8_t, uint16_t, uint32_t, uint32_t, uint32_t> res;

    if (*data_len < sizeof(MDRiiLockDataRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(requestData->agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);

    int idIndex =
        mdrv2->findDataId(requestData->dataSetInfo.dataInfo,
                          sizeof(requestData->dataSetInfo.dataInfo), service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    if (!mdrv2->smbiosTryLock(0, idIndex, &session, requestData->timeout))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Lock Data failed - cannot lock idIndex");
        return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
    }

    *data_len = sizeof(MDRiiLockDataResponse);

    responseData->mdrVersion = mdr2Version;
    responseData->lockHandle = session;
    responseData->dataLength = mdrv2->smbiosDir.dir[idIndex].common.size;
    responseData->xferAddress = mdrv2->smbiosDir.dir[idIndex].xferBuff;
    responseData->xferLength = mdrv2->smbiosDir.dir[idIndex].xferSize;

    return IPMI_CC_OK;
}

ipmi_ret_t cmd_mdr2_unlock_data(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    phosphor::logging::log<phosphor::logging::level::ERR>("unlock data");
    auto requestData =
        reinterpret_cast<const MDRiiUnlockDataRequest *>(request);

    if (*data_len != sizeof(MDRiiUnlockDataRequest))
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(requestData->agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id",
            phosphor::logging::entry("ID=%x", requestData->agentId));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    int idIndex = mdrv2->findLockHandle(requestData->lockHandle);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    if (!mdrv2->smbiosUnlock(idIndex))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unlock Data failed - cannot unlock idIndex");
        return IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE;
    }

    return IPMI_CC_OK;
}

/**
@brief This command is executed after POST BIOS to get the session info.

@param - agentId, dataInfo, dataLength, xferAddress, xferLength, timeout.

@return xferStartAck and session on success.
**/
ipmi::RspType<uint8_t, uint16_t>
    cmd_mdr2_data_start(uint16_t agentId, std::array<uint8_t, 16> dataInfo,
                        uint32_t dataLength, uint32_t xferAddress,
                        uint32_t xferLength, uint16_t timeout)
{
    uint16_t session = 0;

    if (dataLength > smbiosTableStorageSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Requested data length is out of SMBIOS Table storage size.");
        return ipmi::responseParmOutOfRange();
    }
    if ((xferLength + xferAddress) > mdriiSMSize)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid data address and size");
        return ipmi::responseParmOutOfRange();
    }

    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    int idIndex = mdrv2->findDataId(dataInfo.data(), sizeof(dataInfo), service);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return ipmi::responseParmOutOfRange();
    }

    if (mdrv2->smbiosTryLock(1, idIndex, &session, timeout))
    {
        try
        {
            mdrv2->area =
                std::make_unique<SharedMemoryArea>(xferAddress, xferLength);
        }
        catch (const std::system_error &e)
        {
            mdrv2->smbiosUnlock(idIndex);
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unable to access share memory");
            return ipmi::responseUnspecifiedError();
        }
        mdrv2->smbiosDir.dir[idIndex].common.size = dataLength;
        mdrv2->smbiosDir.dir[idIndex].lockHandle = session;
        if (-1 ==
            mdrv2->syncDirCommonData(
                idIndex, mdrv2->smbiosDir.dir[idIndex].common.size, service))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Unable to sync data to service");
            return ipmi::responseResponseError();
        }
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Canot lock smbios");
        return ipmi::responseUnspecifiedError();
    }

    static constexpr uint8_t xferStartAck = 1;

    return ipmi::responseSuccess(xferStartAck, session);
}

/**
@brief This command is executed to close the session.

@param - agentId, lockHandle.

@return completion code on success.
**/
ipmi::RspType<> cmd_mdr2_data_done(uint16_t agentId, uint16_t lockHandle)
{

    if (mdrv2 == nullptr)
    {
        mdrv2 = std::make_unique<MDRV2>();
    }

    int agentIndex = mdrv2->agentLookup(agentId);
    if (agentIndex == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Unknown agent id", phosphor::logging::entry("ID=%x", agentId));
        return ipmi::responseParmOutOfRange();
    }

    int idIndex = mdrv2->findLockHandle(lockHandle);

    if ((idIndex < 0) || (idIndex >= maxDirEntries))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid Data ID", phosphor::logging::entry("IDINDEX=%x", idIndex));
        return ipmi::responseParmOutOfRange();
    }

    if (!mdrv2->smbiosUnlock(idIndex))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Send data done failed - cannot unlock idIndex");
        return ipmi::responseDestinationUnavailable();
    }

    mdrv2->area.reset(nullptr);
    MDRSMBIOSHeader mdr2Smbios;
    mdr2Smbios.mdrType = mdrTypeII;
    mdr2Smbios.dirVer = mdrv2->smbiosDir.dir[0].common.dataVersion;
    mdr2Smbios.timestamp = mdrv2->smbiosDir.dir[0].common.timestamp;
    mdr2Smbios.dataSize = mdrv2->smbiosDir.dir[0].common.size;

    if (access(smbiosPath, 0) == -1)
    {
        int flag = mkdir(smbiosPath, S_IRWXU);
        if (flag != 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "create folder failed for writting smbios file");
        }
    }
    if (!mdrv2->storeDatatoFlash(
            &mdr2Smbios, mdrv2->smbiosDir.dir[smbiosDirIndex].dataStorage))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "MDR2 Store data to flash failed");
        return ipmi::responseDestinationUnavailable();
    }
    bool status = false;
    std::string service = ipmi::getService(bus, mdrv2Interface, mdrv2Path);
    sdbusplus::message::message method = bus.new_method_call(
        service.c_str(), mdrv2Path, mdrv2Interface, "AgentSynchronizeData");

    try
    {
        sdbusplus::message::message reply = bus.call(method);
        reply.read(status);
    }
    catch (sdbusplus::exception_t &)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error Sync data with service",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("PATH=%s", mdrv2Path));
        return ipmi::responseResponseError();
    }

    if (!status)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Sync data with service failure");
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

static void register_netfn_smbiosmdrv2_functions(void)
{
    // MDR V2 Command
    // <Get MDRII Status Command>
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_INTEL_APP_OEM,
                          IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_AGENT_STATUS,
                          ipmi::Privilege::Operator, mdr2AgentStatus);

    // <Get MDRII Directory Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_GET_DIR, NULL,
                           cmd_mdr2_get_dir, PRIVILEGE_OPERATOR);

    // <Send MDRII Directory Command>
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_INTEL_APP_OEM,
                          IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_SEND_DIR,
                          ipmi::Privilege::Operator, mdr2SendDir);

    // <Get MDRII Data Info Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_GET_DATA_INFO,
                           NULL, cmd_mdr2_get_data_info, PRIVILEGE_OPERATOR);

    // <Send MDRII Info Offer>
    ipmi::registerHandler(
        ipmi::prioOemBase, NETFUN_INTEL_APP_OEM,
        IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_SEND_DATA_INFO_OFFER,
        ipmi::Privilege::Operator, mdr2DataInfoOffer);

    // <Send MDRII Data Info>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_SEND_DATA_INFO,
                           NULL, cmd_mdr2_send_data_info, PRIVILEGE_OPERATOR);

    // <Get MDRII Data Block Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_GET_DATA_BLOCK,
                           NULL, cmd_mdr2_get_data_block, PRIVILEGE_OPERATOR);

    // <Send MDRII Data Block>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_SEND_DATA_BLOCK,
                           NULL, cmd_mdr2_send_data_block, PRIVILEGE_OPERATOR);

    // <Lock MDRII Data Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_LOCK_DATA, NULL,
                           cmd_mdr2_lock_data, PRIVILEGE_OPERATOR);

    // <Unlock MDRII Data Command>
    ipmi_register_callback(NETFUN_INTEL_APP_OEM,
                           IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_UNLOCK_DATA,
                           NULL, cmd_mdr2_unlock_data, PRIVILEGE_OPERATOR);

    // <Send MDRII Data Start>
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_INTEL_APP_OEM,
                          IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_DATA_START,
                          ipmi::Privilege::Operator, cmd_mdr2_data_start);

    // <Send MDRII Data Done>
    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_INTEL_APP_OEM,
                          IPMI_NETFN_INTEL_OEM_APP_CMD::MDRII_DATA_DONE,
                          ipmi::Privilege::Operator, cmd_mdr2_data_done);
}
