/*
// Copyright (c) 2020 Intel Corporation
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

#include "xyz/openbmc_project/Common/error.hpp"

#include <openssl/sha.h>

#include <array>
#include <biosconfigcommands.hpp>
#include <boost/crc.hpp>
#include <commandutils.hpp>
#include <fstream>
#include <iostream>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/message/types.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <oemcommands.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>
#include <string>
#include <variant>
#include <vector>
#include <xyz/openbmc_project/BIOSConfig/BIOSConfigMgr/server.hpp>

namespace ipmi
{
static void registerBIOSConfigFunctions() __attribute__((constructor));

static constexpr const char* BiosConfigBaseMgrPath =
    "/xyz/openbmc_project/BIOSConfig/BIOSConfigMgr";
static constexpr const char* BiosConfigIntf =
    "xyz.openbmc_project.BIOSConfig.BIOSConfigMgr";
static constexpr const char* BIOSConfigCapabilityProperty = "RBCCapability";
static constexpr const char* dBusPropertyIntf =
    "org.freedesktop.DBus.Properties";
static constexpr const char* BiosConfigPayloadBasePath =
    "/xyz/openbmc_project/BIOSConfig/BIOSConfigMgr/Payload";
static constexpr const char* BiosConfigPayloadIntf =
    "xyz.openbmc_project.BIOSConfig.Payload";
static constexpr const char* dBusPropertyGetMethod = "Get";
static constexpr const char* dBusPropertySetMethod = "Set";

static constexpr uint8_t SetPayloadValidResponseLength = 0x3;
static constexpr uint8_t maxPayloadSupported = 0x7;
// we want to restrict no of bytes in GetPayload because of KCS interface
static constexpr uint16_t maxGetPayloadDataSize = 4096;

// Define BIOS config related Completion Code
using Cc = uint8_t;
static constexpr Cc ipmiCCPayloadPayloadPacketMissed = 0x80;
static constexpr Cc ipmiCCPayloadChecksumFailed = 0x81;
static constexpr Cc ipmiCCNotSupportedInCurrentState = 0x82;
static constexpr Cc ipmiCCPayloadPayloadInComplete = 0x83;
static constexpr Cc ipmiCCBIOSCapabilityInitNotDone = 0x85;
static constexpr Cc ipmiCCPayloadLengthIllegal = 0x85;

PayloadInfo DataInfo[maxPayloadSupported] = {0};

using namespace sdbusplus::xyz::openbmc_project::BIOSConfig::server;
std::map<BIOSConfigMgr::PayloadTState, uint8_t> payloadTStateDbusToIpmi = {
    {BIOSConfigMgr::PayloadTState::StartTransfer, 0},
    {BIOSConfigMgr::PayloadTState::InProgress, 1},
    {BIOSConfigMgr::PayloadTState::EndTransfer, 2},
    {BIOSConfigMgr::PayloadTState::UserAbort, 3}};

std::map<BIOSConfigMgr::PayloadStatus, uint8_t> payloadStatusDbusToIpmi = {
    {BIOSConfigMgr::PayloadStatus::Unknown, 0},
    {BIOSConfigMgr::PayloadStatus::Valid, 1},
    {BIOSConfigMgr::PayloadStatus::Corrupted, 2}};

std::map<BIOSConfigMgr::PayloadType, uint8_t> payloadTypeDbusToIpmi = {
    {BIOSConfigMgr::PayloadType::IntelXMLType0, 0},
    {BIOSConfigMgr::PayloadType::IntelXMLType1, 1},
    {BIOSConfigMgr::PayloadType::AttributeRegistry, 2},
    {BIOSConfigMgr::PayloadType::AttributeStringTable, 3},
    {BIOSConfigMgr::PayloadType::AttributeNameTable, 4},
    {BIOSConfigMgr::PayloadType::AttributeValueTable, 5},
    {BIOSConfigMgr::PayloadType::AttributePendingTable, 6}};

std::map<uint8_t, BIOSConfigMgr::PayloadTState> payloadTStateIpmiToDbus = {
    {0, BIOSConfigMgr::PayloadTState::StartTransfer},
    {1, BIOSConfigMgr::PayloadTState::InProgress},
    {2, BIOSConfigMgr::PayloadTState::EndTransfer},
    {3, BIOSConfigMgr::PayloadTState::UserAbort}};
std::map<uint8_t, BIOSConfigMgr::PayloadType> payloadTypeIpmiToDbus = {
    {0, BIOSConfigMgr::PayloadType::IntelXMLType0},
    {1, BIOSConfigMgr::PayloadType::IntelXMLType1},
    {2, BIOSConfigMgr::PayloadType::AttributeRegistry},
    {3, BIOSConfigMgr::PayloadType::AttributeStringTable},
    {4, BIOSConfigMgr::PayloadType::AttributeNameTable},
    {5, BIOSConfigMgr::PayloadType::AttributeValueTable},
    {6, BIOSConfigMgr::PayloadType::AttributePendingTable}};

std::map<uint8_t, BIOSConfigMgr::PayloadStatus> payloadStatusIpmiToDbus = {
    {0, BIOSConfigMgr::PayloadStatus::Unknown},
    {1, BIOSConfigMgr::PayloadStatus::Valid},
    {2, BIOSConfigMgr::PayloadStatus::Corrupted}};

//
// GetPayload Payload status enumeration
//
enum class GetPayloadParameter
{
    GetPayloadInfo = 0, // 0
    GetPayloadData = 1, // 1
    GetPayloadStatus = 2
};

int sendSetPayload(ipmi::Context::ptr ctx, uint32_t& retValue,
                   uint8_t payloadTState, uint8_t payloadType,
                   uint32_t reservationID, uint16_t payloadVersion,
                   uint32_t payloadOffset, uint32_t payloadSize,
                   uint32_t payloadChecksum, uint32_t totalSize,
                   uint32_t totalChecksum, std::vector<uint8_t> data,
                   std::chrono::microseconds timeout = ipmi::IPMI_DBUS_TIMEOUT)
{
    boost::system::error_code ec;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, BiosConfigIntf, BiosConfigBaseMgrPath);
    ec.clear();
    retValue = ctx->bus->yield_method_call<uint32_t>(
        ctx->yield, ec, service, BiosConfigBaseMgrPath, BiosConfigIntf,
        "SetPayload", payloadTState, payloadType, reservationID, payloadVersion,
        payloadOffset, payloadSize, payloadChecksum, totalSize, totalChecksum,
        data);

    if (ec)
    {
        FILE* fp = fopen("/tmp/BIOSConfig/Error.log", "a+");
        fprintf(fp,
                "ERROR=%s Status : %x Type : %x Current Size: %d  Total: %d \n",
                ec.message().c_str(), payloadTState, payloadType, payloadSize,
                totalSize);
        fclose(fp);
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to setBiosPayload");
        return -1;
    }
    return 0;
}

int getBiosConfigCapability(
    uint8_t& biosCapProp,
    std::chrono::microseconds timeout = ipmi::IPMI_DBUS_TIMEOUT)
{
    boost::system::error_code ec;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, BiosConfigIntf, BiosConfigBaseMgrPath);

    Value variant =
        getDbusProperty(*dbus, service, BiosConfigBaseMgrPath, BiosConfigIntf,
                        BIOSConfigCapabilityProperty);
    biosCapProp = static_cast<uint8_t>(std::get<std::uint32_t>(variant));

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to getBiosCap");
        return -1;
    }
    return 0;
}

ipmi::RspType<> ipmiOEMSetBIOSCap(ipmi::Context::ptr ctx,
                                  uint8_t BIOSCapabilties, uint8_t reserved1,
                                  uint8_t reserved2, uint8_t reserved3)
{
    boost::system::error_code ec;
    uint32_t oobCap;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, BiosConfigIntf, BiosConfigBaseMgrPath);

    if (reserved1 != 0 || reserved2 != 0 || reserved3 != 0)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // call set oob capability method to set the OOB capability

    ec.clear();
    ctx->bus->yield_method_call<std::variant<std::uint32_t>>(
        ctx->yield, ec, service, BiosConfigBaseMgrPath, dBusPropertyIntf,
        dBusPropertySetMethod, BiosConfigIntf, BIOSConfigCapabilityProperty,
        static_cast<std::variant<std::uint32_t>>(BIOSCapabilties));

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetBIOSCap: failed to set BIOSConfigCapability property",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return ipmi::response(ipmiCCNotSupportedInCurrentState);
    }

    ec.clear();
    ctx->bus->yield_method_call<std::variant<std::uint8_t>>(
        ctx->yield, ec, service, BiosConfigBaseMgrPath, dBusPropertyIntf,
        dBusPropertySetMethod, BiosConfigIntf, "IsBIOSInitDone",
        static_cast<std::variant<std::uint8_t>>(1));

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t>
    ipmiOEMGetBIOSCap(ipmi::Context::ptr ctx)
{
    uint8_t BIOSCapabilties = 0;
    if (getBiosConfigCapability(BIOSCapabilties))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOOBGetBIOSCap: failed to getBiosConfigCapability");
        return ipmi::response(ipmiCCBIOSCapabilityInitNotDone);
    }
    return ipmi::responseSuccess(BIOSCapabilties, 0, 0, 0);
}

ipmi::RspType<uint32_t> ipmiOEMSetPayload(ipmi::Context::ptr ctx,
                                          uint8_t paramSel, uint8_t payloadType,
                                          std::vector<uint8_t> payload)
{
    using namespace sdbusplus::xyz::openbmc_project::BIOSConfig::server;

    uint8_t BIOSCapabilties = 0;
    uint8_t BIOSCapOffsetBit = 2; // BIT:1 0-OOB BIOS config not supported
                                  //      1-OOB BIOS config is supported
    uint32_t retValue;

    if (getBiosConfigCapability(BIOSCapabilties))
    {
        return ipmi::response(ipmiCCNotSupportedInCurrentState);
    }
    if (!(BIOSCapabilties & (BIOSCapOffsetBit)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "BIOS capability is not supported");
        return ipmi::response(ipmiCCBIOSCapabilityInitNotDone);
    }

    // Validate the Payload Type
    if (payloadType > maxPayloadSupported)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    switch (payloadTStateIpmiToDbus.at(paramSel))
    {
        case BIOSConfigMgr::PayloadTState::StartTransfer:
        {
            if (payload.size() < sizeof(PayloadStartTransfer))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "BIOS Config Payload size is not correct");
                return ipmi::responseReqDataLenInvalid();
            }

            PayloadStartTransfer* pPayloadStartTransfer =
                reinterpret_cast<PayloadStartTransfer*>(payload.data());

            if (sendSetPayload(ctx, retValue, paramSel, payloadType, 0,
                               pPayloadStartTransfer->payloadVersion, 0, 0, 0,
                               pPayloadStartTransfer->payloadTotalSize,
                               pPayloadStartTransfer->payloadTotalChecksum,
                               payload))
            {
                return ipmi::responseResponseError();
            }
            DataInfo[payloadType].payloadReservationID = retValue;
            DataInfo[payloadType].payloadTotalChecksum =
                pPayloadStartTransfer->payloadTotalChecksum;
            DataInfo[payloadType].payloadTotalSize =
                pPayloadStartTransfer->payloadTotalSize;
            DataInfo[payloadType].payloadVersion =
                pPayloadStartTransfer->payloadVersion;
            DataInfo[payloadType].actualTotalPayloadWritten = 0;
            DataInfo[payloadType].payloadStatus = payloadStatusDbusToIpmi.at(
                BIOSConfigMgr::PayloadStatus::Unknown);
            return ipmi::responseSuccess(retValue);
        }
        break;

        case BIOSConfigMgr::PayloadTState::InProgress:
        {
            PayloadInProgress* pPayloadInProgress =
                reinterpret_cast<PayloadInProgress*>(payload.data());
            PayloadInfo payloadInfo = DataInfo[payloadType];

            if (payload.size() < sizeof(PayloadInProgress))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "BIOS Config Payload size is not correct");
                return ipmi::responseReqDataLenInvalid();
            }

            if (pPayloadInProgress->payloadReservationID !=
                payloadInfo.payloadReservationID)
            {
                return ipmi::responseInvalidReservationId();
            }
            // Need to verify the current Payload Checksum
            const uint8_t* data =
                reinterpret_cast<const uint8_t*>(payload.data());
            // we have to remove the current size, current offset, current
            // length,checksum bytes , reservation bytes
            boost::crc_32_type calcChecksum;
            calcChecksum.process_bytes(data + 16, payload.size() - 16);
            if (calcChecksum.checksum() !=
                pPayloadInProgress->payloadCurrentChecksum)
            {
                // TODO return ipmiCCPayloadChecksumFailed 0x81 For this error
                // Commented out for unit testing and manual validation
                FILE* fp = fopen("/tmp/BIOSConfig/Error.log", "a+");
                fprintf(fp,
                        "SetPayloadError: Computed Checksum Status : %x Given "
                        "Checksum  : %x \n",
                        calcChecksum.checksum(),
                        pPayloadInProgress->payloadCurrentChecksum);
                fclose(fp);
            }
            if (sendSetPayload(ctx, retValue, paramSel, payloadType,
                               pPayloadInProgress->payloadReservationID,
                               payloadInfo.payloadVersion,
                               pPayloadInProgress->payloadOffset,
                               pPayloadInProgress->payloadCurrentSize,
                               pPayloadInProgress->payloadCurrentChecksum,
                               payloadInfo.payloadTotalSize,
                               payloadInfo.payloadTotalChecksum, payload))
            {
                return ipmi::responseResponseError();
            }
            DataInfo[payloadType].payloadStatus = payloadStatusDbusToIpmi.at(
                BIOSConfigMgr::PayloadStatus::Unknown);
            DataInfo[payloadType].actualTotalPayloadWritten += retValue;
            return ipmi::responseSuccess(retValue);
        }
        break;
        case BIOSConfigMgr::PayloadTState::EndTransfer:
        {
            PayloadEndTransfer* pPayloadEndTransfer =
                reinterpret_cast<PayloadEndTransfer*>(payload.data());
            PayloadInfo payloadInfo = DataInfo[payloadType];
            if (pPayloadEndTransfer->payloadReservationID !=
                payloadInfo.payloadReservationID)
            {
                return ipmi::responseInvalidReservationId();
            }
            if (sendSetPayload(ctx, retValue, paramSel, payloadType,
                               pPayloadEndTransfer->payloadReservationID, 0, 0,
                               0, 0, 0, 0, payload))
            {
                return ipmi::responseResponseError();
            }
            DataInfo[payloadType].payloadStatus = payloadStatusDbusToIpmi.at(
                BIOSConfigMgr::PayloadStatus::Unknown);

            if (DataInfo[payloadType].actualTotalPayloadWritten !=
                DataInfo[payloadType].payloadTotalSize)
            {
                return ipmi::response(ipmiCCPayloadPayloadInComplete);
            }
            DataInfo[payloadType].payloadStatus =
                payloadStatusDbusToIpmi.at(BIOSConfigMgr::PayloadStatus::Valid);
            return ipmi::responseSuccess(retValue);
        }
        break;
        case BIOSConfigMgr::PayloadTState::UserAbort:
        {
            PayloadEndTransfer* pPayloadEndTransfer =
                reinterpret_cast<PayloadEndTransfer*>(payload.data());
            PayloadInfo payloadInfo = DataInfo[payloadType];
            if (pPayloadEndTransfer->payloadReservationID !=
                payloadInfo.payloadReservationID)
            {
                return ipmi::responseInvalidReservationId();
            }
            if (!sendSetPayload(ctx, retValue, paramSel, payloadType,
                                pPayloadEndTransfer->payloadReservationID, 0, 0,
                                0, 0, 0, 0, payload))
            {
                DataInfo[payloadType].payloadStatus =
                    payloadStatusDbusToIpmi.at(
                        BIOSConfigMgr::PayloadStatus::Corrupted);
                return ipmi::responseSuccess(retValue);
            }
        }
        break;
        default:
            return ipmi::responseInvalidFieldRequest();
    }
    return ipmi::responseResponseError();
}

static uint8_t fillGetPayloadInfoRes(const std::string& objPath,
                                     struct PayloadInfo& resp)
{
    try
    {

        boost::system::error_code ec;
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, BiosConfigIntf, BiosConfigBaseMgrPath);

        ipmi::PropertyMap Props = ipmi::getAllDbusProperties(
            *dbus, service, objPath, BiosConfigPayloadIntf);

        resp.payloadStatus = std::get<uint8_t>(Props.at("PayloadStatus"));
        resp.payloadVersion = std::get<uint16_t>(Props.at("PayloadVersion"));
        resp.payloadTotalSize =
            std::get<uint32_t>(Props.at("PayloadTotalSize"));
        resp.payloadTotalChecksum =
            std::get<uint32_t>(Props.at("PayloadTotalChecksum"));
        resp.payloadflag = 0;
        resp.payloadTimeStamp =
            std::get<uint32_t>(Props.at("PayloadCreationTime"));

        resp.payloadFilePath =
            std::get<std::string>(Props.at("PayloadFilePath"));
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        return ipmi::ccUnspecifiedError;
    }

    return ipmi::ccSuccess;
}

RspType<message::Payload> ipmiOEMGetPayload(ipmi::Context::ptr ctx,
                                            uint8_t paramSel,
                                            uint8_t payloadType,
                                            ipmi::message::Payload& payload)
{

    using namespace sdbusplus::xyz::openbmc_project::BIOSConfig::server;
    uint8_t BIOSCapabilties = 0;
    uint8_t BIOSCapOffsetBit = 2; // BIT:1 0-OOB BIOS config not supported
                                  //      1-OOB BIOS config is supported
    message::Payload retValue;

    if (getBiosConfigCapability(BIOSCapabilties))
    {
        return ipmi::response(ipmiCCNotSupportedInCurrentState);
    }
    if (!(BIOSCapabilties & (BIOSCapOffsetBit)))
    {
        return ipmi::response(ipmiCCBIOSCapabilityInitNotDone);
    }
    // Validate the Payload Type
    if (payloadType > maxPayloadSupported)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    struct PayloadInfo res = {0};

    if (fillGetPayloadInfoRes(
            BiosConfigPayloadBasePath + std::to_string(payloadType), res))
    {
        // Temp as payload object is not created.
        return ipmi::responseInvalidFieldRequest();
    }
    res.payloadType = payloadType;

    switch (static_cast<GetPayloadParameter>(paramSel))
    {
        case GetPayloadParameter::GetPayloadInfo:
        {
            retValue.pack(res.payloadVersion);
            retValue.pack(res.payloadType);
            retValue.pack(res.payloadTotalSize);
            retValue.pack(res.payloadTotalChecksum);
            retValue.pack(res.payloadflag);
            retValue.pack(res.payloadStatus);
            retValue.pack(res.payloadTimeStamp);

            return ipmi::responseSuccess(std::move(retValue));
        }

        break;
        case GetPayloadParameter::GetPayloadData:
        {
            if (res.payloadStatus ==
                payloadStatusDbusToIpmi.at(BIOSConfigMgr::PayloadStatus::Valid))
            {
                std::vector<uint32_t> reqData;
                if (payload.unpack(reqData) || !payload.fullyUnpacked())
                {
                    return ipmi::responseReqDataLenInvalid();
                }
                uint32_t offset = reqData.at(0);
                uint32_t length = reqData.at(1);

                std::ifstream ifs(res.payloadFilePath, std::ios::in |
                                                           std::ios::binary |
                                                           std::ios::ate);
                std::ifstream::pos_type fileSize = ifs.tellg();
                // Total file data within given offset
                if (fileSize < static_cast<uint64_t>(offset))
                {
                    ifs.close();
                    return ipmi::responseInvalidFieldRequest();
                }

                ifs.seekg(offset, std::ios::beg);
                std::array<uint8_t, maxGetPayloadDataSize> Buffer;
                ifs.read(reinterpret_cast<char*>(Buffer.data()), length);
                uint32_t readCount = ifs.gcount();
                ifs.close();

                boost::crc_32_type calcChecksum;
                calcChecksum.process_bytes(
                    reinterpret_cast<char*>(Buffer.data()), readCount);
                uint32_t chkSum = calcChecksum.checksum();
                retValue.pack(payloadType);
                retValue.pack(readCount);
                retValue.pack(chkSum);

                for (int i = 0; i < readCount; i++)
                {
                    retValue.pack(Buffer.at(i));
                }
                return ipmi::responseSuccess(std::move(retValue));
            }
            else
            {
                return ipmi::responseResponseError();
            }
        }
        break;
        case GetPayloadParameter::GetPayloadStatus:
        {
            retValue.pack(DataInfo[payloadType].payloadStatus);
            return ipmi::responseSuccess(std::move(retValue));
        }
        break;
        default:
            return ipmi::responseInvalidFieldRequest();
    }
    return ipmi::responseInvalidFieldRequest();
}
static void registerBIOSConfigFunctions(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "BIOSConfig module initialization");

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetBIOSCap, Privilege::Admin,
                    ipmiOEMSetBIOSCap);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetBIOSCap, Privilege::Admin,
                    ipmiOEMGetBIOSCap);
    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetPayload, Privilege::Admin,
                    ipmiOEMSetPayload);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetPayload, Privilege::Admin,
                    ipmiOEMGetPayload);

    return;
}

} // namespace ipmi
