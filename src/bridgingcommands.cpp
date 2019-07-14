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

#include <bitset>
#include <bridgingcommands.hpp>
#include <cstring>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>
#include <vector>

static constexpr const char *wdtService = "xyz.openbmc_project.Watchdog";
static constexpr const char *wdtInterface =
    "xyz.openbmc_project.State.Watchdog";
static constexpr const char *wdtObjPath = "/xyz/openbmc_project/watchdog/host0";
static constexpr const char *wdtInterruptFlagProp =
    "PreTimeoutInterruptOccurFlag";

static constexpr const char *ipmbBus = "xyz.openbmc_project.Ipmi.Channel.Ipmb";
static constexpr const char *ipmbObj = "/xyz/openbmc_project/Ipmi/Channel/Ipmb";
static constexpr const char *ipmbIntf = "org.openbmc.Ipmb";

static Bridging bridging;

/**
 * @brief utils for checksum
 */
static bool ipmbChecksumValidate(uint8_t *data, uint8_t length)
{
    if (data == nullptr)
    {
        return false;
    }

    uint8_t checksum = 0;

    for (uint8_t idx = 0; idx < length; idx++)
    {
        checksum += data[idx];
    }

    if (0 == checksum)
    {
        return true;
    }

    return false;
}

static uint8_t ipmbChecksumCompute(uint8_t *data, uint8_t length)
{
    if (data == nullptr)
    {
        return 0;
    }

    uint8_t checksum = 0;

    for (uint8_t idx = 0; idx < length; idx++)
    {
        checksum += data[idx];
    }

    checksum = (~checksum) + 1;
    return checksum;
}

static inline bool ipmbConnectionHeaderChecksumValidate(ipmbHeader *ipmbHeader)
{
    return ipmbChecksumValidate(reinterpret_cast<uint8_t *>(ipmbHeader),
                                ipmbConnectionHeaderLength);
}

static inline bool ipmbDataChecksumValidate(ipmbHeader *ipmbHeader,
                                            uint8_t length)
{
    return ipmbChecksumValidate(
        (reinterpret_cast<uint8_t *>(ipmbHeader) + ipmbConnectionHeaderLength),
        (length - ipmbConnectionHeaderLength));
}

static bool isFrameValid(ipmbHeader *frame, uint8_t length)
{
    if ((length < ipmbMinFrameLength) || (length > ipmbMaxFrameLength))
    {
        return false;
    }

    if (false == ipmbConnectionHeaderChecksumValidate(frame))
    {
        return false;
    }

    if (false == ipmbDataChecksumValidate(frame, length))
    {
        return false;
    }

    return true;
}

IpmbRequest::IpmbRequest(const ipmbHeader *ipmbBuffer, size_t bufferLength)
{
    address = ipmbBuffer->Header.Req.address;
    netFn = ipmbNetFnGet(ipmbBuffer->Header.Req.rsNetFnLUN);
    rsLun = ipmbLunFromNetFnLunGet(ipmbBuffer->Header.Req.rsNetFnLUN);
    rqSA = ipmbBuffer->Header.Req.rqSA;
    seq = ipmbSeqGet(ipmbBuffer->Header.Req.rqSeqLUN);
    rqLun = ipmbLunFromSeqLunGet(ipmbBuffer->Header.Req.rqSeqLUN);
    cmd = ipmbBuffer->Header.Req.cmd;

    size_t dataLength =
        bufferLength - (ipmbConnectionHeaderLength +
                        ipmbRequestDataHeaderLength + ipmbChecksumSize);

    if (dataLength > 0)
    {
        data.insert(data.end(), ipmbBuffer->Header.Req.data,
                    &ipmbBuffer->Header.Req.data[dataLength]);
    }
}

IpmbResponse::IpmbResponse(uint8_t address, uint8_t netFn, uint8_t rqLun,
                           uint8_t rsSA, uint8_t seq, uint8_t rsLun,
                           uint8_t cmd, uint8_t completionCode,
                           std::vector<uint8_t> &inputData) :
    address(address),
    netFn(netFn), rqLun(rqLun), rsSA(rsSA), seq(seq), rsLun(rsLun), cmd(cmd),
    completionCode(completionCode)
{
    data.reserve(ipmbMaxDataSize);

    if (inputData.size() > 0)
    {
        data = std::move(inputData);
    }
}

void IpmbResponse::ipmbToi2cConstruct(uint8_t *buffer, size_t *bufferLength)
{
    ipmbHeader *ipmbBuffer = (ipmbHeader *)buffer;

    ipmbBuffer->Header.Resp.address = address;
    ipmbBuffer->Header.Resp.rqNetFnLUN = ipmbNetFnLunSet(netFn, rqLun);
    ipmbBuffer->Header.Resp.rsSA = rsSA;
    ipmbBuffer->Header.Resp.rsSeqLUN = ipmbSeqLunSet(seq, rsLun);
    ipmbBuffer->Header.Resp.cmd = cmd;
    ipmbBuffer->Header.Resp.completionCode = completionCode;

    ipmbBuffer->Header.Resp.checksum1 = ipmbChecksumCompute(
        buffer, ipmbConnectionHeaderLength - ipmbChecksumSize);

    if (data.size() > 0)
    {
        std::copy(
            data.begin(), data.end(),
            &buffer[ipmbConnectionHeaderLength + ipmbResponseDataHeaderLength]);
    }

    *bufferLength = data.size() + ipmbResponseDataHeaderLength +
                    ipmbConnectionHeaderLength + ipmbChecksumSize;

    buffer[*bufferLength - ipmbChecksumSize] =
        ipmbChecksumCompute(&buffer[ipmbChecksum2StartOffset],
                            (ipmbResponseDataHeaderLength + data.size()));
}

void IpmbRequest::prepareRequest(sdbusplus::message::message &mesg)
{
    mesg.append(ipmbMeChannelNum, netFn, rqLun, cmd, data);
}

ipmi::Cc Bridging::handleIpmbChannel(uint4_t channelType, uint8_t *msgData,
                                     uint8_t msgLen, uint8_t rspData[],
                                     size_t *dataLength)
{

    auto sendMsgReqData = reinterpret_cast<ipmbHeader *>(msgData);
    // TODO: check privilege lvl. Bridging to ME requires Administrator lvl

    // allow bridging to ME only
    if (sendMsgReqData->Header.Req.address != ipmbMeSlaveAddress)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "handleIpmbChannel, IPMB address invalid");
        return ipmi::ccParmOutOfRange;
    }

    // check allowed modes
    if (channelType != modeNoTracking && channelType != modeTrackRequest)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "handleIpmbChannel, mode not supported");
        return ipmi::ccParmOutOfRange;
    }

    // check if request contains valid IPMB frame
    if (!isFrameValid(sendMsgReqData, msgLen))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "handleIpmbChannel, IPMB frame invalid");
        return ipmi::ccParmOutOfRange;
    }

    auto ipmbRequest = IpmbRequest(sendMsgReqData, msgLen);

    std::tuple<int, uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>
        ipmbResponse;

    // send request to IPMB
    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        auto mesg =
            dbus->new_method_call(ipmbBus, ipmbObj, ipmbIntf, "sendRequest");
        ipmbRequest.prepareRequest(mesg);
        auto ret = dbus->call(mesg);
        ret.read(ipmbResponse);
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "handleIpmbChannel, dbus call exception");
        return ipmi::ccUnspecifiedError;
    }

    std::vector<uint8_t> dataReceived(0);
    int status = -1;
    uint8_t netFn = 0, lun = 0, cmd = 0, cc = 0;

    std::tie(status, netFn, lun, cmd, cc, dataReceived) = ipmbResponse;

    auto respReceived =
        IpmbResponse(ipmbRequest.rqSA, netFn, lun, ipmbRequest.address,
                     ipmbRequest.seq, lun, cmd, cc, dataReceived);

    // check IPMB layer status
    if (status)
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "handleIpmbChannel, ipmb returned non zero status");
        return ipmi::ccResponseError;
    }

    auto channelNo = static_cast<uint8_t>(channelType);
    switch (channelNo)
    {
        case modeNoTracking:
            if (getResponseQueueSize() == responseQueueMaxSize)
            {
                return ipmi::ccBusy;
            }
            insertMessageInQueue(respReceived);
            return ipmi::ccSuccess;

            break;
        case modeTrackRequest:
            respReceived.ipmbToi2cConstruct(rspData, dataLength);
            return ipmi::ccSuccess;

            break;
        default:
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "handleIpmbChannel, mode not supported");
            return ipmi::ccParmOutOfRange;
    }

    return ipmi::ccUnspecifiedError;
}

ipmi_return_codes Bridging::clearMessageFlagsHandler(ipmi_request_t request,
                                                     ipmi_response_t response,
                                                     ipmi_data_len_t dataLen)
{
    if (*dataLen != sizeof(sClearMessageFlagsReq))
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    auto clearMsgFlagsReq = reinterpret_cast<sClearMessageFlagsReq *>(request);

    if (clearMsgFlagsReq->receiveMessageBitGet() == 1)
    {
        responseQueue.clear();
    }

    return IPMI_CC_OK;
}

void Bridging::insertMessageInQueue(IpmbResponse msg)
{
    responseQueue.insert(responseQueue.end(), std::move(msg));
}

void Bridging::eraseMessageFromQueue()
{
    responseQueue.erase(responseQueue.begin());
}

IpmbResponse Bridging::getMessageFromQueue()
{
    return responseQueue.front();
}

/**
 * @brief This command is used for bridging ipmi message between channels.
 * @param channel number
 * @param Message Data.
 *
 * @return IPMI completion code plus response data on success.
 * - response data
 **/
ipmi::RspType<std::vector<uint8_t> // responseData
              >
    ipmiAppSendMessage(uint2_t tracking, bool encryptionEnabled,
                       bool authenticationEnabled, uint4_t channelType,
                       std::vector<uint8_t> msg)
{
    // check message fields:
    // encryption not supported
    if (encryptionEnabled)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "sendMessageHandler, encryption not supported");
        return ipmi::responseParmOutOfRange();
    }

    // authentication not supported
    if (authenticationEnabled)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "sendMessageHandler, authentication not supported");
        return ipmi::responseParmOutOfRange();
    }

    ipmbHeader data[] = {0};
    size_t dataLength = 0;
    ipmi::Cc returnVal;

    uint8_t msgLen = msg.size();
    uint8_t msgData[msgLen];
    std::copy(msg.begin(), msg.end(), msgData);

    auto channelNo = static_cast<uint8_t>(channelType);
    // Get the channel number
    switch (channelNo)
    {
        // we only handle ipmb for now
        case targetChannelIpmb:
        case targetChannelOtherLan:
            returnVal = bridging.handleIpmbChannel(
                channelType, msgData, msgLen, reinterpret_cast<uint8_t *>(data),
                &dataLength);
            break;
        // fall through to default
        case targetChannelIcmb10:
        case targetChannelIcmb09:
        case targetChannelLan:
        case targetChannelSerialModem:
        case targetChannelPciSmbus:
        case targetChannelSmbus10:
        case targetChannelSmbus20:
        case targetChannelSystemInterface:
        default:
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "sendMessageHandler, TargetChannel invalid");
            return ipmi::responseParmOutOfRange();
    }
    if (returnVal != ipmi::ccSuccess)
        return ipmi::response(returnVal);

    std::vector<uint8_t> rspData;
    uint8_t *tempData = reinterpret_cast<uint8_t *>(data);
    std::copy(tempData, tempData + dataLength, rspData.begin());

    return ipmi::responseSuccess(rspData);
}

std::vector<IpmbResponse> Bridging::getResponseQueue()
{
    return responseQueue;
}

/**
 * @brief This command is used to Get data from the receive message queue.
 *
 * @return IPMI completion code plus response data on success.
 * - channelNumber
 * - messageData
 **/

ipmi::RspType<uint8_t,             // channelNumber
              std::vector<uint8_t> // messageData
              >
    ipmiAppGetMessage()
{
    uint8_t channelData = 0;
    ipmbHeader data[] = {0};
    size_t dataLength = 0;

    if (bridging.getResponseQueueSize() == 0)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "getMessageHandler, no data available");
        return ipmi::response(ipmiGetMessageCmdDataNotAvailable);
    }

    // channel number set.
    channelData |= static_cast<uint8_t>(targetChannelSystemInterface) & 0x0F;

    // Priviledge level set.
    channelData |= SYSTEM_INTERFACE & 0xF0;

    // Get the first message from queue
    auto respQueueItem = bridging.getMessageFromQueue();

    // construct response data.
    respQueueItem.ipmbToi2cConstruct(reinterpret_cast<uint8_t *>(data),
                                     &dataLength);

    // Remove the message from queue
    bridging.eraseMessageFromQueue();

    std::vector<uint8_t> msgData;
    uint8_t *tempData = reinterpret_cast<uint8_t *>(data);
    std::copy(tempData, tempData + dataLength, msgData.begin());

    return ipmi::responseSuccess(channelData, msgData);
}

std::size_t Bridging::getResponseQueueSize()
{
    return responseQueue.size();
}

/**
@brief This command is used to retrive present message available states.

@return IPMI completion code plus Flags as response data on success.
**/
ipmi::RspType<std::bitset<8>> ipmiAppGetMessageFlags()
{
    std::bitset<8> getMsgFlagsRes;

    getMsgFlagsRes.set(getMsgFlagEventMessageBit);

    // set message fields
    if (bridging.getResponseQueueSize() > 0)
    {
        getMsgFlagsRes.set(getMsgFlagReceiveMessageBit);
    }
    else
    {
        getMsgFlagsRes.reset(getMsgFlagReceiveMessageBit);
    }

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        ipmi::Value variant = ipmi::getDbusProperty(
            *dbus, wdtService, wdtObjPath, wdtInterface, wdtInterruptFlagProp);
        if (std::get<bool>(variant))
        {
            getMsgFlagsRes.set(getMsgFlagWatchdogPreTimeOutBit);
        }
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiAppGetMessageFlags, dbus call exception");
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(getMsgFlagsRes);
}

ipmi_ret_t ipmiAppClearMessageFlags(ipmi_netfn_t netFn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen,
                                    ipmi_context_t context)
{
    ipmi_ret_t retCode = IPMI_CC_OK;
    retCode = bridging.clearMessageFlagsHandler(request, response, dataLen);

    *dataLen = 0;

    return retCode;
}

static void register_bridging_functions() __attribute__((constructor));
static void register_bridging_functions()
{
    ipmi_register_callback(
        NETFUN_APP, Bridging::IpmiAppBridgingCmds::ipmiCmdClearMessageFlags,
        NULL, ipmiAppClearMessageFlags, PRIVILEGE_USER);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdGetMessageFlags, ipmi::Privilege::User,
                          ipmiAppGetMessageFlags);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdGetMessage, ipmi::Privilege::User,
                          ipmiAppGetMessage);

    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnApp,
                          ipmi::app::cmdSendMessage, ipmi::Privilege::User,
                          ipmiAppSendMessage);

    return;
}
