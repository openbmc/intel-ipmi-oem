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
#include <commandutils.hpp>
#include <iostream>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/utils.hpp>
#include <oemcommands.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>
#include <string>
#include <variant>
#include <vector>
#include <xyz/openbmc_project/BIOSConfig/BIOSConfigMgr/server.hpp>

namespace ipmi
{
static void initBIOSconfig() __attribute__((constructor));

static constexpr const char* BiosConfigBaseMgrPath =
    "/xyz/openbmc_project/BIOSConfig/BIOSConfigMgr";
static constexpr const char* BiosConfigIntf =
    "xyz.openbmc_project.BIOSConfig.BIOSConfigMgr";
static constexpr const char* BIOSConfigCapabilityProperty = "RBCCapability";
static constexpr const char* dBusPropertyIntf =
    "org.freedesktop.DBus.Properties";
static constexpr const char* dBusPropertyGetMethod = "Get";
static constexpr const char* dBusPropertySetMethod = "Set";

static constexpr uint8_t SetPayloadValidResponseLength = 0x3;
static constexpr uint8_t maxPayloadSupported = 0x7;

PayloadInfo DataInfo[maxPayloadSupported];

namespace biosconfig
{
using namespace sdbusplus::xyz::openbmc_project::BIOSConfig::server;
std::map<BIOSConfigMgr::PayloadStatus, uint8_t> payloadStatusDbusToIpmi = {
    {BIOSConfigMgr::PayloadStatus::StartTransfer, 0},
    {BIOSConfigMgr::PayloadStatus::InProgress, 1},
    {BIOSConfigMgr::PayloadStatus::EndTransfer, 2},
    {BIOSConfigMgr::PayloadStatus::UserAbort, 3},
    {BIOSConfigMgr::PayloadStatus::Valid, 4},
    {BIOSConfigMgr::PayloadStatus::Corrupted, 5}};
std::map<BIOSConfigMgr::PayloadType, uint8_t> payloadTypeDbusToIpmi = {
    {BIOSConfigMgr::PayloadType::Payload0, 0},
    {BIOSConfigMgr::PayloadType::Payload1, 1},
    {BIOSConfigMgr::PayloadType::Payload2, 2},
    {BIOSConfigMgr::PayloadType::Payload3, 3},
    {BIOSConfigMgr::PayloadType::Payload4, 4},
    {BIOSConfigMgr::PayloadType::Payload5, 5},
    {BIOSConfigMgr::PayloadType::Payload6, 6}};
std::map<uint8_t,BIOSConfigMgr::PayloadStatus> payloadStatusIpmiToDbus = {
    {0, BIOSConfigMgr::PayloadStatus::StartTransfer},
    {1, BIOSConfigMgr::PayloadStatus::InProgress},
    {2, BIOSConfigMgr::PayloadStatus::EndTransfer},
    {3, BIOSConfigMgr::PayloadStatus::UserAbort},
    {4, BIOSConfigMgr::PayloadStatus::Valid},
    {5, BIOSConfigMgr::PayloadStatus::Corrupted}};
std::map<uint8_t, BIOSConfigMgr::PayloadType> payloadTypeIpmiToDbus = {
    {0, BIOSConfigMgr::PayloadType::Payload0},
    {1, BIOSConfigMgr::PayloadType::Payload1},
    {2, BIOSConfigMgr::PayloadType::Payload2},
    {3, BIOSConfigMgr::PayloadType::Payload3},
    {4, BIOSConfigMgr::PayloadType::Payload4},
    {5, BIOSConfigMgr::PayloadType::Payload5},
    {6, BIOSConfigMgr::PayloadType::Payload6}};
} // namespace biosconfig

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
        ctx->yield, ec, service, BiosConfigBaseMgrPath,
        dBusPropertyIntf, dBusPropertySetMethod, BiosConfigIntf,
        BIOSConfigCapabilityProperty,
        static_cast<std::variant<std::uint32_t>>(BIOSCapabilties));

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOOBGetBIOSCap: failed to set BIOSConfigCapability property",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return ipmi::responseUnspecifiedError();
    }

    ec.clear();
    ctx->bus->yield_method_call<std::variant<std::uint8_t>>(
        ctx->yield, ec, service, BiosConfigBaseMgrPath,
        dBusPropertyIntf, dBusPropertySetMethod, BiosConfigIntf,
        "IsBIOSInitDone", static_cast<std::variant<std::uint8_t>>(1));

    return responseSuccess();
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t>
    ipmiOEMGetBIOSCap(ipmi::Context::ptr ctx)
{

    boost::system::error_code ec;
    uint8_t InitFlag;
    uint32_t oobCap;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, BiosConfigIntf, BiosConfigBaseMgrPath);
    auto flag = ctx->bus->yield_method_call<std::variant<std::uint8_t>>(
        ctx->yield, ec, service, BiosConfigBaseMgrPath,
        dBusPropertyIntf, dBusPropertyGetMethod, BiosConfigIntf,
        "IsBIOSInitDone");
    InitFlag = std::get<std::uint8_t>(flag);
    if (InitFlag)
    {
        auto cap = ctx->bus->yield_method_call<std::variant<std::uint32_t>>(
            ctx->yield, ec, service, BiosConfigBaseMgrPath,
            dBusPropertyIntf, dBusPropertyGetMethod, BiosConfigIntf,
            BIOSConfigCapabilityProperty);
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOOBGetBIOSCap: failed to get BIOSConfigCapability "
                "property",
                phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
            return ipmi::responseUnspecifiedError();
        }
        oobCap = std::get<std::uint32_t>(cap);
        return ipmi::responseSuccess(static_cast<uint8_t>(oobCap), 0, 0, 0);
    }
    else
    {
        return ipmi::responseRetBytesUnavailable();
    }
}

int sendSetPayload(ipmi::Context::ptr ctx, std::vector<uint32_t>& retValue,
                   uint8_t payloadStatus, uint8_t payloadType,
                   uint32_t reservationID, uint16_t payloadVersion,
                   uint32_t payloadSize, uint32_t payloadChecksum,
                   uint32_t totalSize, uint32_t totalChecksum,
                   std::vector<uint8_t> data,
                   std::chrono::microseconds timeout = ipmi::IPMI_DBUS_TIMEOUT)
{
    boost::system::error_code ec;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, BiosConfigIntf, BiosConfigBaseMgrPath);
    retValue = ctx->bus->yield_method_call<std::vector<uint32_t>>(
        ctx->yield, ec, service, BiosConfigBaseMgrPath, BiosConfigIntf,
        "SetPayload", payloadStatus,
        payloadType, payloadVersion, payloadSize,
        payloadChecksum, totalSize, totalChecksum, data);

    if (ec)
    {
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

ipmi::RspType<uint32_t> ipmiOEMSetPayload(ipmi::Context::ptr ctx,
                                          uint8_t paramSel, uint8_t payloadType,
                                          std::vector<uint8_t> payload)
{
    using namespace sdbusplus::xyz::openbmc_project::BIOSConfig::server;
    using namespace biosconfig;
    uint8_t BIOSCapabilties = 0;
    uint8_t BIOSCapOffsetBit = 2; // BIT:1 0-OOB BIOS config not supported
                                  //      1-OOB BIOS config is supported
    std::vector<uint32_t> retValue;

    if (getBiosConfigCapability(BIOSCapabilties))
    {
        return ipmi::responseResponseError();
    }
    if (!(BIOSCapabilties & (BIOSCapOffsetBit)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "BIOS capability is not supported");
        return ipmi::responseUnspecifiedError();
    }

    // Validate the Payload Type
    if (payloadType > maxPayloadSupported)
    {
        return ipmi::responseResponseError();
    }
    switch (payloadStatusIpmiToDbus.at(paramSel))
    {
        case BIOSConfigMgr::PayloadStatus::StartTransfer:
        {
            if (payload.size() < sizeof(PayloadStartTransfer))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "BIOS Config Payload size is not correct");
                return ipmi::responseUnspecifiedError();
            }

            PayloadStartTransfer* pPayloadStartTransfer =
                reinterpret_cast<PayloadStartTransfer*>(payload.data());

            if (sendSetPayload(
                    ctx, retValue, paramSel, payloadType, 0,
                    pPayloadStartTransfer->payloadVersion, 0, 0,
                    pPayloadStartTransfer->payloadTotalSize,
                    pPayloadStartTransfer->payloadTotalChecksum, payload))
            {
                return ipmi::responseResponseError();
            }
            if (retValue.size() == SetPayloadValidResponseLength)
            {
                // We have to return only Reservation ID for startTransfer.
                SetPayloadRetValue* pSetPayloadRetValue =
                    (SetPayloadRetValue*)retValue.data();
                DataInfo[payloadType].payloadReservationID =
                    pSetPayloadRetValue->reservationToken;
                DataInfo[payloadType].payloadTotalChecksum =
                    pPayloadStartTransfer->payloadTotalChecksum;
                DataInfo[payloadType].payloadTotalSize =
                    pPayloadStartTransfer->payloadTotalSize;
                DataInfo[payloadType].payloadVersion =
                    pPayloadStartTransfer->payloadVersion;
                return ipmi::responseSuccess(
                    pSetPayloadRetValue->reservationToken);
            }
        }
        break;

        case BIOSConfigMgr::PayloadStatus::InProgress:
        {
            PayloadInProgress* pPayloadInProgress =
                reinterpret_cast<PayloadInProgress*>(payload.data());
            PayloadInfo payloadInfo = DataInfo[payloadType];
            if (pPayloadInProgress->payloadReservationID !=
                payloadInfo.payloadReservationID)
            {
                return ipmi::responseInvalidReservationId();
            }
            if (sendSetPayload(ctx, retValue, paramSel, payloadType,
                               pPayloadInProgress->payloadReservationID,
                               payloadInfo.payloadVersion,
                               pPayloadInProgress->payloadCurrentSize,
                               pPayloadInProgress->payloadCurrentChecksum,
                               payloadInfo.payloadTotalSize,
                               payloadInfo.payloadTotalChecksum, payload))
            {
                return ipmi::responseResponseError();
            }
            if (retValue.size() == SetPayloadValidResponseLength)
            {
                // We have to return only Actual bytes written for InProgress.
                SetPayloadRetValue* pSetPayloadRetValue =
                    (SetPayloadRetValue*)retValue.data();
                DataInfo[payloadType].actualTotalPayloadWritten +=
                    pSetPayloadRetValue->actualPayloadWritten;
                return ipmi::responseSuccess(
                    pSetPayloadRetValue->actualPayloadWritten);
            }
        }
        break;
        case BIOSConfigMgr::PayloadStatus::EndTransfer:
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
                               0, 0, 0, payload))
            {
                return ipmi::responseResponseError();
            }
            if (retValue.size() == SetPayloadValidResponseLength)
            {
                // We have to return only Total Transfer.
                SetPayloadRetValue* pSetPayloadRetValue =
                    (SetPayloadRetValue*)retValue.data();
                DataInfo[payloadType].actualTotalPayloadWritten +=
                    pSetPayloadRetValue->actualPayloadWritten;
                if (DataInfo[payloadType].actualTotalPayloadWritten !=
                    DataInfo[payloadType].payloadTotalSize)
                {
                    return ipmi::responseResponseError();
                }
                return ipmi::responseSuccess(
                    pSetPayloadRetValue->actualPayloadWritten);
            }
        }
        break;
        case BIOSConfigMgr::PayloadStatus::UserAbort:
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
                                0, 0, 0, payload))
            {
                return ipmi::responseSuccess();
            }
        }
        break;
        default:
            return ipmi::responseInvalidFieldRequest();
    }
    return ipmi::responseResponseError();
}

static void initBIOSConfig(void)
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

    return;
}

} // namespace ipmi
