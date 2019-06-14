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

#include <bridgingcommands.hpp>
#include <cstring>
#include <ipmid/api.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>
#include <vector>

static constexpr const char *ipmbBus = "xyz.openbmc_project.Ipmi.Channel.Ipmb";
static constexpr const char *ipmbObj = "/xyz/openbmc_project/Ipmi/Channel/Ipmb";
static constexpr const char *ipmbIntf = "org.openbmc.Ipmb";

static Bridging bridging;

std::vector<IpmbResponse> Bridging::getResponseQueue()
{
    return responseQueue;
}

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

Bridging::Bridging() : dbus(ipmid_get_sd_bus_connection())
{
}

ipmi_return_codes Bridging::handleIpmbChannel(sSendMessageReq *sendMsgReq,
                                              ipmi_response_t response,
                                              ipmi_data_len_t dataLen)
{
    if ((*dataLen < (sizeof(sSendMessageReq) + ipmbMinFrameLength)) ||
        (*dataLen > (sizeof(sSendMessageReq) + ipmbMaxFrameLength)))
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    auto sendMsgReqData = reinterpret_cast<ipmbHeader *>(sendMsgReq->data);

    // TODO: check privilege lvl. Bridging to ME requires Administrator lvl

    // allow bridging to ME only
    if (sendMsgReqData->Header.Req.address != ipmbMeSlaveAddress)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "handleIpmbChannel, IPMB address invalid");
        *dataLen = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    // check allowed modes
    if (sendMsgReq->modeGet() != modeNoTracking &&
        sendMsgReq->modeGet() != modeTrackRequest)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "handleIpmbChannel, mode not supported");
        *dataLen = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    // check if request contains valid IPMB frame
    if (!isFrameValid(sendMsgReqData, (*dataLen - sizeof(sSendMessageReq))))
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "handleIpmbChannel, IPMB frame invalid");
        *dataLen = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    auto ipmbRequest =
        IpmbRequest(sendMsgReqData, (*dataLen - sizeof(sSendMessageReq)));

    std::tuple<int, uint8_t, uint8_t, uint8_t, uint8_t, std::vector<uint8_t>>
        ipmbResponse;

    // send request to IPMB
    try
    {
        auto mesg =
            dbus.new_method_call(ipmbBus, ipmbObj, ipmbIntf, "sendRequest");
        ipmbRequest.prepareRequest(mesg);
        auto ret = dbus.call(mesg);
        ret.read(ipmbResponse);
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "handleIpmbChannel, dbus call exception");
        *dataLen = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
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
        *dataLen = 0;
        return IPMI_CC_RESPONSE_ERROR;
    }

    auto sendMsgRes = reinterpret_cast<uint8_t *>(response);

    switch (sendMsgReq->modeGet())
    {
        case modeNoTracking:
            if (responseQueue.size() == responseQueueMaxSize)
            {
                *dataLen = 0;
                return IPMI_CC_BUSY;
            }
            responseQueue.insert(responseQueue.end(), std::move(respReceived));
            *dataLen = 0;
            return IPMI_CC_OK;

            break;
        case modeTrackRequest:
            respReceived.ipmbToi2cConstruct(sendMsgRes, dataLen);
            return IPMI_CC_OK;

            break;
        default:
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "handleIpmbChannel, mode not supported");
            *dataLen = 0;
            return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    *dataLen = 0;
    return IPMI_CC_UNSPECIFIED_ERROR;
}

ipmi_return_codes Bridging::sendMessageHandler(ipmi_request_t request,
                                               ipmi_response_t response,
                                               ipmi_data_len_t dataLen)
{
    ipmi_return_codes retCode = IPMI_CC_OK;

    if (*dataLen < sizeof(sSendMessageReq))
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    auto sendMsgReq = reinterpret_cast<sSendMessageReq *>(request);

    // check message fields:
    // encryption not supported
    if (sendMsgReq->encryptionGet() != 0)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "sendMessageHandler, encryption not supported");
        *dataLen = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    // authentication not supported
    if (sendMsgReq->authenticationGet() != 0)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "sendMessageHandler, authentication not supported");
        *dataLen = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    switch (sendMsgReq->channelNumGet())
    {
        // we only handle ipmb for now
        case targetChannelIpmb:
        case targetChannelOtherLan:
            retCode = handleIpmbChannel(sendMsgReq, response, dataLen);
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
            *dataLen = 0;
            return IPMI_CC_PARM_OUT_OF_RANGE;
    }

    return retCode;
}

ipmi_return_codes Bridging::getMessageHandler(ipmi_request_t request,
                                              ipmi_response_t response,
                                              ipmi_data_len_t dataLen)
{
    if (*dataLen != 0)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    auto getMsgRes = reinterpret_cast<sGetMessageRes *>(response);
    auto getMsgResData = static_cast<uint8_t *>(getMsgRes->data);

    std::memset(getMsgRes, 0, sizeof(sGetMessageRes));

    auto respQueueItem = responseQueue.begin();

    if (respQueueItem == responseQueue.end())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "getMessageHandler, no data available");
        *dataLen = 0;
        return ipmiGetMessageCmdDataNotAvailable;
    }

    // set message fields
    getMsgRes->privilegeLvlSet(SYSTEM_INTERFACE);
    getMsgRes->channelNumSet(targetChannelSystemInterface);

    // construct response
    respQueueItem->ipmbToi2cConstruct(getMsgResData, dataLen);
    responseQueue.erase(respQueueItem);

    *dataLen = *dataLen + sizeof(sGetMessageRes);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiAppSendMessage(ipmi_netfn_t netFn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t dataLen, ipmi_context_t context)
{
    ipmi_ret_t retCode = IPMI_CC_OK;
    retCode = bridging.sendMessageHandler(request, response, dataLen);

    return retCode;
}

ipmi_ret_t ipmiAppGetMessage(ipmi_netfn_t netFn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t dataLen, ipmi_context_t context)
{
    ipmi_ret_t retCode = IPMI_CC_OK;
    retCode = bridging.getMessageHandler(request, response, dataLen);

    return retCode;
}

/**
@brief This command is used to retrive present message available states.

@return IPMI completion code plus Flags as response data on success.
**/
ipmi::RspType<uint8_t // Flags
              >
    ipmiAppGetMessageFlags()
{
    sGetMessageFlagsResp getMsgFlagsRes;

    // preserve current (legacy) behaviour
    getMsgFlagsRes.eventMessageBitSet(1);

    // set message fields
    if (bridging.getResponseQueue().size() > 0)
    {
        getMsgFlagsRes.receiveMessageBitSet(1);
    }
    else
    {
        getMsgFlagsRes.receiveMessageBitSet(0);
    }

    uint8_t flags = getMsgFlagsRes.flags;

    return ipmi::responseSuccess(flags);
}

/**
@brief This command is used to Flush unread data from the Retrive message queue.

@param flush_info.

@return IPMI completion code on success.
**/
ipmi::RspType<> ipmiAppClearMessageFlags(uint8_t flags)
{
    sClearMessageFlagsReq clearMsgFlagsReq;
    clearMsgFlagsReq.flags = flags;

    if (clearMsgFlagsReq.receiveMessageBitGet() == 1)
    {
        bridging.getResponseQueue().clear();
    }
    return ipmi::responseSuccess();
}

static void register_bridging_functions() __attribute__((constructor));
static void register_bridging_functions()
{

    ipmi::registerHandler(ipmi::prioOemBase, NETFUN_APP,
                          Bridging::IpmiAppBridgingCmds::ipmiCmdGetMessageFlags,
                          ipmi::Privilege::User, ipmiAppGetMessageFlags);

    ipmi::registerHandler(
        ipmi::prioOemBase, NETFUN_APP,
        Bridging::IpmiAppBridgingCmds::ipmiCmdClearMessageFlags,
        ipmi::Privilege::User, ipmiAppClearMessageFlags);

    ipmi_register_callback(NETFUN_APP,
                           Bridging::IpmiAppBridgingCmds::ipmiCmdGetMessage,
                           NULL, ipmiAppGetMessage, PRIVILEGE_USER);

    ipmi_register_callback(NETFUN_APP,
                           Bridging::IpmiAppBridgingCmds::ipmiCmdSendMessage,
                           NULL, ipmiAppSendMessage, PRIVILEGE_USER);

    return;
}
