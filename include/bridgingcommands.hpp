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
#pragma once
#include <sdbusplus/message.hpp>
#include <sdbusplus/server/interface.hpp>

/**
 * @brief Response queue defines
 */
constexpr int responseQueueMaxSize = 20;

/**
 * @brief Ipmb misc
 */
constexpr uint8_t ipmbLunMask = 0x03;
constexpr uint8_t ipmbSeqMask = 0x3F;
constexpr uint8_t ipmbMeSlaveAddress = 0x2C;
constexpr uint8_t ipmbMeChannelNum = 1;

/**
 * @brief Ipmb getters
 */
constexpr uint8_t ipmbNetFnGet(uint8_t netFnLun)
{
    return netFnLun >> 2;
}

constexpr uint8_t ipmbLunFromNetFnLunGet(uint8_t netFnLun)
{
    return netFnLun & ipmbLunMask;
}

constexpr uint8_t ipmbSeqGet(uint8_t seqNumLun)
{
    return seqNumLun >> 2;
}

constexpr uint8_t ipmbLunFromSeqLunGet(uint8_t seqNumLun)
{
    return seqNumLun & ipmbLunMask;
}

/**
 * @brief Ipmb setters
 */
constexpr uint8_t ipmbNetFnLunSet(uint8_t netFn, uint8_t lun)
{
    return ((netFn << 2) | (lun & ipmbLunMask));
}

constexpr uint8_t ipmbSeqLunSet(uint8_t seq, uint8_t lun)
{
    return ((seq << 2) | (lun & ipmbLunMask));
}

constexpr size_t ipmbMaxDataSize = 256;
constexpr size_t ipmbConnectionHeaderLength = 3;
constexpr size_t ipmbResponseDataHeaderLength = 4;
constexpr size_t ipmbRequestDataHeaderLength = 3;
constexpr size_t ipmbChecksum2StartOffset = 3;
constexpr size_t ipmbChecksumSize = 1;
constexpr size_t ipmbMinFrameLength = 7;
constexpr size_t ipmbMaxFrameLength = ipmbConnectionHeaderLength +
                                      ipmbResponseDataHeaderLength +
                                      ipmbChecksumSize + ipmbMaxDataSize;

/**
 * @brief Channel types
 */
constexpr uint8_t targetChannelIpmb = 0x1;
constexpr uint8_t targetChannelIcmb10 = 0x2;
constexpr uint8_t targetChannelIcmb09 = 0x3;
constexpr uint8_t targetChannelLan = 0x4;
constexpr uint8_t targetChannelSerialModem = 0x5;
constexpr uint8_t targetChannelOtherLan = 0x6;
constexpr uint8_t targetChannelPciSmbus = 0x7;
constexpr uint8_t targetChannelSmbus10 = 0x8;
constexpr uint8_t targetChannelSmbus20 = 0x9;
constexpr uint8_t targetChannelSystemInterface = 0xC;

/**
 * @brief Channel modes
 */
constexpr uint8_t modeNoTracking = 0x0;
constexpr uint8_t modeTrackRequest = 0x1;
constexpr uint8_t modeSendRaw = 0x2;

/**
 * @brief Command specific codes
 */
constexpr ipmi_return_codes ipmiGetMessageCmdDataNotAvailable =
    static_cast<ipmi_return_codes>(0x80);

/**
 * @brief Ipmb frame
 */
typedef struct
{
    /// @brief IPMB frame header
    union
    {
        /// @brief IPMB request header
        struct
        {
            /** @brief IPMB Connection Header Format */
            uint8_t address;
            uint8_t rsNetFnLUN;
            uint8_t checksum1;
            /** @brief IPMB Header */
            uint8_t rqSA;
            uint8_t rqSeqLUN;
            uint8_t cmd;
            uint8_t data[];
        } Req;
        /// @brief IPMB response header
        struct
        {
            uint8_t address;
            /** @brief IPMB Connection Header Format */
            uint8_t rqNetFnLUN;
            uint8_t checksum1;
            /** @brief IPMB Header */
            uint8_t rsSA;
            uint8_t rsSeqLUN;
            uint8_t cmd;
            uint8_t completionCode;
            uint8_t data[];
        } Resp;
    } Header;
} __attribute__((packed)) ipmbHeader;

/**
 * @brief Ipmb messages
 */
struct IpmbRequest
{
    uint8_t address;
    uint8_t netFn;
    uint8_t rsLun;
    uint8_t rqSA;
    uint8_t seq;
    uint8_t rqLun;
    uint8_t cmd;
    std::vector<uint8_t> data;

    IpmbRequest(const ipmbHeader *ipmbBuffer, size_t bufferLength);

    void prepareRequest(sdbusplus::message::message &mesg);
};

struct IpmbResponse
{
    uint8_t address;
    uint8_t netFn;
    uint8_t rqLun;
    uint8_t rsSA;
    uint8_t seq;
    uint8_t rsLun;
    uint8_t cmd;
    uint8_t completionCode;
    std::vector<uint8_t> data;

    IpmbResponse(uint8_t address, uint8_t netFn, uint8_t rqLun, uint8_t rsSA,
                 uint8_t seq, uint8_t rsLun, uint8_t cmd,
                 uint8_t completionCode, std::vector<uint8_t> &inputData);

    void ipmbToi2cConstruct(uint8_t *buffer, size_t *bufferLength);
};

/**
 * @brief Send Message Request
 */
typedef struct
{
    uint8_t channelData;
    uint8_t data[];

    constexpr uint8_t channelNumGet()
    {
        return (channelData & 0xF);
    }

    constexpr uint8_t authenticationGet()
    {
        return ((channelData & 0x10) >> 4);
    }

    constexpr uint8_t encryptionGet()
    {
        return ((channelData & 0x20) >> 5);
    }

    constexpr uint8_t modeGet()
    {
        return ((channelData & 0xC0) >> 6);
    }
} __attribute__((packed)) sSendMessageReq;

/**
 * @brief Get Message Response
 */
typedef struct
{
    uint8_t channelData;
    uint8_t data[];

    constexpr void channelNumSet(uint8_t num)
    {
        channelData |= num & 0xF;
    }

    constexpr void privilegeLvlSet(CommandPrivilege privLvl)
    {
        channelData |= static_cast<uint8_t>(privLvl) & 0xF0;
    }
} __attribute__((packed)) sGetMessageRes;

/**
 * @brief Get Message Flags Response
 */
typedef struct
{
    uint8_t flags;

    constexpr void receiveMessageBitSet(uint8_t value)
    {
        flags |= (value & 1);
    }

    constexpr void eventMessageBitSet(uint8_t value)
    {
        flags |= (value & 1) << 1;
    }

    constexpr void watchdogTimeoutBitSet(uint8_t value)
    {
        flags |= (value & 1) << 3;
    }

    constexpr void oem0BitSet(uint8_t value)
    {
        flags |= (value & 1) << 5;
    }

    constexpr void oem1BitSet(uint8_t value)
    {
        flags |= (value & 1) << 6;
    }

    constexpr void oem2BitSet(uint8_t value)
    {
        flags |= (value & 1) << 7;
    }
} __attribute__((packed)) sGetMessageFlagsResp;

/**
 * @brief Clear Message Flags Request
 */
typedef struct
{
    uint8_t flags;

    constexpr uint8_t receiveMessageBitGet()
    {
        return (flags & 0x1);
    }

    constexpr uint8_t eventMessageBitGet()
    {
        return ((flags & 0x2) >> 1);
    }

    constexpr uint8_t watchdogTimeoutBitGet()
    {
        return ((flags & 0x8) >> 3);
    }

    constexpr uint8_t oem0BitGet()
    {
        return ((flags & 0x20) >> 5);
    }

    constexpr uint8_t oem1BitGet()
    {
        return ((flags & 0x40) >> 6);
    }

    constexpr uint8_t oem2BitGet()
    {
        return ((flags & 0x80) >> 7);
    }
} __attribute__((packed)) sClearMessageFlagsReq;

/** @class Bridging
 *
 *  @brief Implement commands to support IPMI bridging.
 */
class Bridging
{
  public:
    Bridging();

    std::vector<IpmbResponse> getResponseQueue();

    ipmi_return_codes sendMessageHandler(ipmi_request_t request,
                                         ipmi_response_t response,
                                         ipmi_data_len_t dataLen);

    ipmi_return_codes getMessageHandler(ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t dataLen);
    enum IpmiAppBridgingCmds
    {
        ipmiCmdClearMessageFlags = 0x30,
        ipmiCmdGetMessageFlags = 0x31,
        ipmiCmdGetMessage = 0x33,
        ipmiCmdSendMessage = 0x34,
    };

  private:
    std::vector<IpmbResponse> responseQueue;
    sdbusplus::bus::bus dbus;

    ipmi_return_codes handleIpmbChannel(sSendMessageReq *sendMsgReq,
                                        ipmi_response_t response,
                                        ipmi_data_len_t dataLen);
};
