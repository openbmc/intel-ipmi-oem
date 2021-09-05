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

#include "biosxml.hpp"

#include <openssl/sha.h>

#include <biosconfigcommands.hpp>
#include <boost/crc.hpp>
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/message/types.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <oemcommands.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>

#include <filesystem>
#include <string_view>

namespace ipmi
{
static bool flushNVOOBdata();
static void registerBIOSConfigFunctions() __attribute__((constructor));

// Define BIOS config related Completion Code
using Cc = uint8_t;
static constexpr Cc ipmiCCPayloadPayloadPacketMissed = 0x80;
static constexpr Cc ipmiCCBIOSPasswordInitNotDone = 0x80;
static constexpr Cc ipmiCCPayloadChecksumFailed = 0x81;
static constexpr Cc ipmiCCNotSupportedInCurrentState = 0x82;
static constexpr Cc ipmiCCPayloadPayloadInComplete = 0x83;
static constexpr Cc ipmiCCBIOSCapabilityInitNotDone = 0x85;
static constexpr Cc ipmiCCPayloadLengthIllegal = 0x85;

static constexpr uint8_t userPasswordChanged = (1 << 5);
static constexpr uint8_t adminPasswordChanged = (1 << 4);

static constexpr const char* biosConfigFolder = "/var/oob";
static constexpr const char* biosConfigNVPath = "/var/oob/nvoobdata.dat";
static constexpr const uint8_t algoSHA384 = 2;
static constexpr const uint8_t algoSHA256 = 1;
static constexpr const uint8_t biosCapOffsetBit = 0x3;
static constexpr uint16_t maxGetPayloadDataSize = 4096;
static constexpr const char* biosXMLFilePath = "/var/oob/bios.xml";
static constexpr const char* biosXMLFilePath1 = "/var/oob/tempbios.xml";

static constexpr const char* biosConfigBaseMgrPath =
    "/xyz/openbmc_project/bios_config/manager";
static constexpr const char* biosConfigIntf =
    "xyz.openbmc_project.BIOSConfig.Manager";
static constexpr const char* resetBIOSSettingsProp = "ResetBIOSSettings";

bios::BiosBaseTableType attributesData;

NVOOBdata gNVOOBdata;

enum class PTState : uint8_t
{
    StartTransfer = 0,
    InProgress = 1,
    EndTransfer = 2,
    UserAbort = 3
};
enum class PStatus : uint8_t
{
    Unknown = 0,
    Valid = 1,
    Corrupted = 2
};
enum class PType : uint8_t
{
    IntelXMLType0 = 0,
    IntelXMLType1 = 1,
    OTAPayload = 5,
};

//
// GetPayload Payload status enumeration
//
enum class GetPayloadParameter : uint8_t
{
    GetPayloadInfo = 0, // 0
    GetPayloadData = 1, // 1
    GetPayloadStatus = 2
};

namespace payload1
{
using PendingAttributesType =
    std::map<std::string,
             std::tuple<std::string, std::variant<int64_t, std::string>>>;

std::string mapAttrTypeToRedfish(const std::string_view typeDbus)
{
    std::string ret;
    if (typeDbus == "xyz.openbmc_project.BIOSConfig.Manager."
                    "AttributeType.Enumeration")
    {
        ret = "Enumeration";
    }
    else if (typeDbus == "xyz.openbmc_project.BIOSConfig."
                         "Manager.AttributeType.String")
    {
        ret = "String";
    }
    else if (typeDbus == "xyz.openbmc_project.BIOSConfig."
                         "Manager.AttributeType.Password")
    {
        ret = "Password";
    }
    else if (typeDbus == "xyz.openbmc_project.BIOSConfig."
                         "Manager.AttributeType.Integer")
    {
        ret = "Integer";
    }
    else if (typeDbus == "xyz.openbmc_project.BIOSConfig."
                         "Manager.AttributeType.Boolean")
    {
        ret = "Boolean";
    }
    else
    {
        ret = "UNKNOWN";
    }

    return ret;
}

bool getPendingList(std::string& patloadData, ipmi::Context::ptr ctx)
{
    std::variant<PendingAttributesType> pendingAttributesData;
    boost::system::error_code ec;
    bool isFirst = true;

    patloadData.clear();

    auto dbus = getSdBus();
    if (!dbus)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getPayload: getSdBus() failed");
        return false;
    }

    std::string service =
        getService(*dbus, biosConfigIntf, biosConfigBaseMgrPath);

    try
    {
        pendingAttributesData =
            dbus->yield_method_call<std::variant<PendingAttributesType>>(
                ctx->yield, ec, service,
                "/xyz/openbmc_project/bios_config/manager",
                "org.freedesktop.DBus.Properties", "Get",
                "xyz.openbmc_project.BIOSConfig.Manager", "PendingAttributes");
    }
    catch (std::exception& ex)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(ex.what());
        return false;
    }

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getPendingList: error while trying to get "
            "PendingAttributes");
        return false;
    }

    const PendingAttributesType* pendingAttributes =
        std::get_if<PendingAttributesType>(&pendingAttributesData);
    if (!pendingAttributes)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getPendingList: pendingAttributes is null");
        return false;
    }

    for (const auto& [key, attributes] : *pendingAttributes)
    {
        const std::string& itemType = std::get<0>(attributes);
        std::string attrType = mapAttrTypeToRedfish(itemType);

        if (attrType == "String")
        {
            const std::string* currValue =
                std::get_if<std::string>(&std::get<1>(attributes));

            if (!currValue)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "getPendingList: currValue == null");
                return false;
            }

            if (isFirst)
            {
                isFirst = false;
            }
            else
            {
                patloadData += "\n";
            }

            patloadData += key;
            patloadData += "=";
            patloadData += *currValue;
        }
        else if (attrType == "Integer")
        {
            const int64_t* currValue =
                std::get_if<int64_t>(&std::get<1>(attributes));

            if (!currValue)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "getPendingList: currValue == null");
                return false;
            }

            if (isFirst)
            {
                isFirst = false;
            }
            else
            {
                patloadData += "\n";
            }

            patloadData += key;
            patloadData += " = ";
            patloadData += std::to_string(*currValue);
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "getPendingList: Unsupported attribute type");
            return false;
        }
    }

    if (patloadData.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getPendingList: patloadData is empty");
        return false;
    }

    return true;
}
bool updatePayloadFile(std::string& payloadFilePath, std::string patloadData)
{
    std::ofstream payloadFile(payloadFilePath,
                              std::ios::out | std::ios::binary);

    payloadFile << patloadData;

    if (payloadFile.bad())
    {
        return false;
    }

    payloadFile.close();

    return true;
}

bool computeCheckSum(std::string& payloadFilePath,
                     boost::crc_32_type& calcChecksum)
{
    std::ifstream payloadFile(payloadFilePath.c_str(),
                              std::ios::in | std::ios::binary | std::ios::ate);

    if (payloadFile.bad())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "computeCheckSum: Cannot open Payload1 file");
        return false;
    }

    payloadFile.seekg(0, payloadFile.end);
    int length = payloadFile.tellg();
    payloadFile.seekg(0, payloadFile.beg);

    std::array<uint8_t, maxGetPayloadDataSize> payloadBuffer;
    payloadFile.read(reinterpret_cast<char*>(payloadBuffer.data()), length);
    uint32_t readCount = payloadFile.gcount();

    calcChecksum.process_bytes(reinterpret_cast<char*>(payloadBuffer.data()),
                               readCount);

    return true;
}

bool updatePayloadInfo(std::string& payloadFilePath)
{
    boost::crc_32_type calcChecksum;

    uint8_t payloadType = static_cast<uint8_t>(ipmi::PType::IntelXMLType1);
    auto& payloadInfo = gNVOOBdata.payloadInfo[payloadType];

    if (!computeCheckSum(payloadFilePath, calcChecksum))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "updatePayloadInfo: Cannot compute checksum for Payload1 file");
        return false;
    }

    payloadInfo.payloadVersion = 0;
    payloadInfo.payloadflag = 0;
    payloadInfo.payloadReservationID = rand();

    payloadInfo.payloadType = static_cast<uint8_t>(ipmi::PType::IntelXMLType1);

    payloadInfo.payloadTotalChecksum = calcChecksum.checksum();
    payloadInfo.payloadCurrentChecksum = payloadInfo.payloadTotalChecksum;

    payloadInfo.payloadStatus = (static_cast<uint8_t>(ipmi::PStatus::Valid));

    struct stat filestat;
    /* Get entry's information. */
    if (!stat(payloadFilePath.c_str(), &filestat))
    {
        payloadInfo.payloadTimeStamp = filestat.st_mtime;
        payloadInfo.payloadTotalSize = filestat.st_size;
        payloadInfo.payloadCurrentSize = filestat.st_size;
        payloadInfo.actualTotalPayloadWritten = filestat.st_size;
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "updatePayloadInfo: Cannot get file status for Payload1 file");
        return false;
    }

    if (!flushNVOOBdata())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "updatePayloadInfo: flushNVOOBdata failed");
        return false;
    }

    return true;
}

bool update(ipmi::Context::ptr ctx)
{
    std::string payloadFilePath =
        "/var/oob/Payload" +
        std::to_string(static_cast<uint8_t>(ipmi::PType::IntelXMLType1));

    std::string patloadData;

    if (!getPendingList(patloadData, ctx))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "payload1::update : getPendingList() failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "payload1::update : getPendingList() is success");

    if (!updatePayloadFile(payloadFilePath, patloadData))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "payload1::update : updatePayloadFile() failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "payload1::update : updatePayloadFile() is success");

    if (!updatePayloadInfo(payloadFilePath))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "payload1::update : updatePayloadInfo() failed");
        return false;
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "payload1::update : updatePayloadInfo() is success");

    return true;
}
} // namespace payload1

/** @brief implement to set the BaseBIOSTable property
 *  @returns status
 */
static bool sendAllAttributes(std::string service)
{
    std::shared_ptr<sdbusplus::asio::connection> pSdBusPlus = getSdBus();

    if (pSdBusPlus)
    {
        try
        {
            pSdBusPlus->async_method_call(
                [](const boost::system::error_code ec) {
                    /* No more need to keep attributes data in memory */
                    attributesData.clear();

                    if (ec)
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "sendAllAttributes error: send all attributes - "
                            "failed");
                        return;
                    }

                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "sendAllAttributes: send all attributes - done");
                },
                service, biosConfigBaseMgrPath,
                "org.freedesktop.DBus.Properties", "Set", biosConfigIntf,
                "BaseBIOSTable",
                std::variant<bios::BiosBaseTableType>(attributesData));

            return true;
        }
        catch (std::exception& ex)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(ex.what());
        }
    }

    return false;
}

/** @brief implement to flush the updated data in nv space
 *  @returns status
 */
static bool flushNVOOBdata()
{
    std::ofstream outFile(biosConfigNVPath, std::ios::binary);
    if (outFile.good())
    {
        outFile.seekp(std::ios_base::beg);
        const char* writedata = reinterpret_cast<const char*>(&gNVOOBdata);
        outFile.write(writedata, sizeof(struct NVOOBdata));
        outFile.close();

        return true;
    }

    return false;
}

/** @brief implement to get the System State
 *  @returns status
 */

static int getSystemOSState(std::string& OsStatus)
{

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        Value variant =
            getDbusProperty(*dbus, "xyz.openbmc_project.State.OperatingSystem",
                            "/xyz/openbmc_project/state/os",
                            "xyz.openbmc_project.State.OperatingSystem.Status",
                            "OperatingSystemState");
        OsStatus = std::get<std::string>(variant);
        return ipmi::ccSuccess;
    }
    catch (const std::exception& e)
    {
        return ipmi::ccUnspecifiedError;
    }
}

/** @brief implement to get the Rest BIOS property
 *  @returns status
 */
static int getResetBIOSSettings(uint8_t& ResetFlag)
{

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, biosConfigIntf, biosConfigBaseMgrPath);
        Value variant = getDbusProperty(*dbus, service, biosConfigBaseMgrPath,
                                        biosConfigIntf, resetBIOSSettingsProp);

        std::string_view ResetStr = std::get<std::string>(variant);
        if (ResetStr ==
            "xyz.openbmc_project.BIOSConfig.Manager.ResetFlag.NoAction")
        {
            ResetFlag = 0;
        }
        else if (ResetStr == "xyz.openbmc_project.BIOSConfig.Manager.ResetFlag."
                             "FactoryDefaults")
        {
            ResetFlag = 1;
        }
        else if (ResetStr == "xyz.openbmc_project.BIOSConfig.Manager.ResetFlag."
                             "FailSafeDefaults")
        {
            ResetFlag = 2;
        }
        else
        {
            return ipmi::ccUnspecifiedError;
        }

        return ipmi::ccSuccess;
    }
    catch (const std::exception& e)
    {
        return ipmi::ccUnspecifiedError;
    }
}

/** @brief Get attributes data (bios base table) from bios.xml
 */
static bool generateAttributesData()
{
    try
    {
        bios::Xml biosxml(biosXMLFilePath);

        if (!biosxml.doDepexCompute())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "'depex' compute failed");
        }

        if (!biosxml.getBaseTable(attributesData))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get bios base table");
        }
    }
    catch (std::exception& ex)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(ex.what());
        return false;
    }

    return true;
}

/** @brief Generate attributes data from bios.xml
 * and send attributes data (bios base table) to dbus using set method.
 */
static void generateAndSendAttributesData(std::string service,
                                          uint8_t payloadType)
{
    if (!generateAttributesData())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "generateAndSendAttributesData: generateAttributesData - failed");
        gNVOOBdata.payloadInfo[payloadType].payloadStatus =
            static_cast<uint8_t>(ipmi::PStatus::Corrupted);
        return;
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "generateAndSendAttributesData : generateAttributesData is done");

    if (!sendAllAttributes(service))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "generateAndSendAttributesData: sendAllAttributes - failed");
        gNVOOBdata.payloadInfo[payloadType].payloadStatus =
            static_cast<uint8_t>(ipmi::PStatus::Corrupted);
        return;
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "generateAndSendAttributesData : sendAllAttributes is done");
    gNVOOBdata.payloadInfo[payloadType].payloadStatus =
        static_cast<uint8_t>(ipmi::PStatus::Valid);
}

/** @brief implement executing the linux command to uncompress and generate the
 * xmlfile
 *  @param[in] linux command
 *  @returns status
 */
template <typename... ArgTypes>
static int generateBIOSXMLFile(const char* path, ArgTypes&&... tArgs)
{

    boost::process::child execProg(path, const_cast<char*>(tArgs)...,
                                   boost::process::std_out > biosXMLFilePath);
    execProg.wait();
    return execProg.exit_code();
}

/** @brief implements to clean up the temp/ existing payload file
 **/
static void cleanUpPayloadFile(uint8_t& payloadType)
{
    // Clear the payload Information
    std::string FilePath = "/var/oob/temp" + std::to_string(payloadType);
    unlink(FilePath.c_str());
    FilePath = "/var/oob/Payload" + std::to_string(payloadType);
    unlink(FilePath.c_str());
    if (payloadType == static_cast<uint8_t>(ipmi::PType::IntelXMLType0))
    {
        unlink("/var/oob/Payload1");
        gNVOOBdata.payloadInfo[static_cast<uint8_t>(ipmi::PType::IntelXMLType1)]
            .payloadStatus = static_cast<uint8_t>(ipmi::PStatus::Unknown);
    }
}

/** @brief implements to create the oob folders and nv space
 **/
static Cc InitNVOOBdata()
{
    FILE* fptr;
    uint16_t size;

    if (!(std::filesystem::exists(biosConfigFolder)))
    {
        std::filesystem::create_directory(biosConfigFolder);
    }

    std::ifstream ifs(biosConfigNVPath, std::ios::in | std::ios::binary);

    if (ifs.good())
    {

        ifs.seekg(std::ios_base::beg);
        ifs.read(reinterpret_cast<char*>(&gNVOOBdata),
                 sizeof(struct NVOOBdata));
        ifs.close();
        return ipmi::ccSuccess;
    }
    return ipmi::ccResponseError;
}

/** @brief implements check the command interface is
 ** system interface or not
 **  true mean System interface and false mean LAN or IPMB
 **/
static bool IsSystemInterface(ipmi::Context::ptr ctx)
{
    ChannelInfo chInfo;
    Cc status = false;

    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e)
    {
        return false;
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(EChannelMediumType::systemInterface))
    {
        return false;
    }
    return true;
}

ipmi::RspType<> ipmiOEMSetBIOSCap(ipmi::Context::ptr ctx,
                                  uint8_t BIOSCapabilties, uint8_t reserved1,
                                  uint8_t reserved2, uint8_t reserved3)
{
    std::string OSState;
    getSystemOSState(OSState);

    if (OSState != "OperatingState" && IsSystemInterface(ctx))
    {
        if (reserved1 != 0 || reserved2 != 0 || reserved3 != 0)
        {
            return ipmi::responseInvalidFieldRequest();
        }

        gNVOOBdata.mBIOSCapabilities.OOBCapability = BIOSCapabilties;
        gNVOOBdata.mIsBIOSCapInitDone = true;

        flushNVOOBdata();
        return ipmi::responseSuccess();
    }
    else
    {
        return ipmi::response(ipmiCCNotSupportedInCurrentState);
    }
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t>
    ipmiOEMGetBIOSCap(ipmi::Context::ptr ctx)
{
    uint8_t payloadType = 0;
    auto io = getIoContext();
    auto dbus = getSdBus();
    if (io && dbus)
    {
        std::string service =
            getService(*dbus, biosConfigIntf, biosConfigBaseMgrPath);

        boost::asio::post(*io, [service, payloadType] {
            generateAndSendAttributesData(service, payloadType);
        });
    }

    if (gNVOOBdata.mIsBIOSCapInitDone)
    {
        return ipmi::responseSuccess(gNVOOBdata.mBIOSCapabilities.OOBCapability,
                                     0, 0, 0);
    }
    else
    {
        return ipmi::response(ipmiCCBIOSCapabilityInitNotDone);
    }
}

ipmi::RspType<uint32_t> ipmiOEMSetPayload(ipmi::Context::ptr ctx,
                                          uint8_t paramSel, uint8_t payloadType,
                                          std::vector<uint8_t> payload)
{
    uint8_t biosCapOffsetBit = 2; // BIT:1 0-OOB BIOS config not supported
                                  //      1-OOB BIOS config is supported

    if (!(gNVOOBdata.mBIOSCapabilities.OOBCapability & (biosCapOffsetBit)))
    {
        return ipmi::response(ipmiCCBIOSCapabilityInitNotDone);
    }
    // Validate the Payload Type
    if (payloadType > maxPayloadSupported)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // We should support this Payload type 0 command only in KCS Interface
    if (payloadType == static_cast<uint8_t>(ipmi::PType::IntelXMLType0))
    {
        std::string OSState;

        getSystemOSState(OSState);
        if (!IsSystemInterface(ctx) || OSState == "OperatingState")
        {
            return ipmi::responseCommandNotAvailable();
        }
    }

    switch (static_cast<PTState>(paramSel))
    {
        case ipmi::PTState::StartTransfer:
        {
            PayloadStartTransfer* pPayloadStartTransfer =
                reinterpret_cast<PayloadStartTransfer*>(payload.data());
            if (payload.size() < sizeof(PayloadStartTransfer))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetPayload: BIOS Config Payload size is not "
                    "correct");
                return ipmi::responseReqDataLenInvalid();
            }
            cleanUpPayloadFile(payloadType);

            gNVOOBdata.payloadInfo[payloadType].payloadReservationID = rand();
            gNVOOBdata.payloadInfo[payloadType].payloadTotalChecksum =
                pPayloadStartTransfer->payloadTotalChecksum;
            gNVOOBdata.payloadInfo[payloadType].payloadTotalSize =
                pPayloadStartTransfer->payloadTotalSize;
            gNVOOBdata.payloadInfo[payloadType].payloadVersion =
                pPayloadStartTransfer->payloadVersion;
            gNVOOBdata.payloadInfo[payloadType].actualTotalPayloadWritten = 0;
            gNVOOBdata.payloadInfo[payloadType].payloadStatus =
                static_cast<uint8_t>(ipmi::PStatus::Unknown);
            gNVOOBdata.payloadInfo[payloadType].payloadType = payloadType;

            return ipmi::responseSuccess(
                gNVOOBdata.payloadInfo[payloadType].payloadReservationID);
        }
        break;

        case ipmi::PTState::InProgress:
        {
            PayloadInProgress* pPayloadInProgress =
                reinterpret_cast<PayloadInProgress*>(payload.data());
            PayloadInfo payloadInfo = gNVOOBdata.payloadInfo[payloadType];

            if (payload.size() < sizeof(PayloadInProgress))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "BIOS Config Payload size is not correct");
                return ipmi::responseReqDataLenInvalid();
            }

            if (pPayloadInProgress->payloadReservationID !=
                payloadInfo.payloadReservationID)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "BIOS Config Payload reservation ID is not correct");
                return ipmi::responseInvalidReservationId();
            }
            payloadInfo.payloadCurrentSize =
                pPayloadInProgress->payloadCurrentSize;
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
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetPayload: Payload Checksum Failed");
                return ipmi::response(ipmiCCPayloadChecksumFailed);
            }
            // store the data in temp file
            std::string FilePath =
                "/var/oob/temp" + std::to_string(payloadType);

#if 0
            std::ofstream outFile(FilePath, std::ios::binary | std::ios::app);
            outFile.seekp(pPayloadInProgress->payloadOffset);
            // we have to remove the current size, current offset, current
            // length,checksum bytes , reservation bytes

            const char* writedata =
                reinterpret_cast<const char*>(payload.data());
            outFile.write(writedata + 16, payload.size() - 16);
            outFile.close();
#else

            std::ofstream outFile(FilePath, std::ios::binary | std::ios::app);
            outFile.seekp(pPayloadInProgress->payloadOffset);
            // we have to remove the current size, current offset, current
            // length,checksum bytes , reservation bytes

            const char* writedata =
                reinterpret_cast<const char*>(payload.data());

            if (!writedata)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetPayload: payload.data() is null");
                return ipmi::responseUnspecifiedError();
            }

            if (outFile.bad())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetPayload: ofstream outFile is bad");
                return ipmi::responseUnspecifiedError();
            }

            outFile.write(writedata + 16, payload.size() - 16);
            outFile.close();

#endif

            gNVOOBdata.payloadInfo[payloadType].payloadStatus =
                static_cast<uint8_t>(ipmi::PStatus::Unknown);
            gNVOOBdata.payloadInfo[payloadType].actualTotalPayloadWritten +=
                payloadInfo.payloadCurrentSize;
            return ipmi::responseSuccess(payloadInfo.payloadCurrentSize);
        }
        break;
        case ipmi::PTState::EndTransfer:
        {
            PayloadEndTransfer* pPayloadEndTransfer =
                reinterpret_cast<PayloadEndTransfer*>(payload.data());
            PayloadInfo payloadInfo = gNVOOBdata.payloadInfo[payloadType];
            if (pPayloadEndTransfer->payloadReservationID !=
                payloadInfo.payloadReservationID)
            {
                return ipmi::responseInvalidReservationId();
            }
            gNVOOBdata.payloadInfo[payloadType].payloadStatus =
                static_cast<uint8_t>(ipmi::PStatus::Unknown);

            if (gNVOOBdata.payloadInfo[payloadType].actualTotalPayloadWritten !=
                gNVOOBdata.payloadInfo[payloadType].payloadTotalSize)
            {
                return ipmi::response(ipmiCCPayloadPayloadInComplete);
            }
            std::string tempFilePath =
                "/var/oob/temp" + std::to_string(payloadType);
            std::string payloadFilePath =
                "/var/oob/Payload" + std::to_string(payloadType);
            auto renamestatus =
                std::rename(tempFilePath.c_str(), payloadFilePath.c_str());
            if (renamestatus)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetPayload: Renaming Payload file - failed");
            }

            if (payloadType == static_cast<uint8_t>(ipmi::PType::IntelXMLType0))
            {
                // Unzip the Intel format XML file type 0
                auto response = generateBIOSXMLFile("/usr/bin/lzcat", "-d",
                                                    payloadFilePath.c_str());
                if (response)
                {

                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "ipmiOEMSetPayload: generateBIOSXMLFile - failed");
                    gNVOOBdata.payloadInfo[payloadType].payloadStatus =
                        static_cast<uint8_t>(ipmi::PStatus::Corrupted);
                    return ipmi::response(ipmiCCPayloadPayloadPacketMissed);
                }
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    " ipmiOEMSetPayload : Convert XML into native-dbus DONE");

                /* So that we don't block the call */
                auto io = getIoContext();
                auto dbus = getSdBus();
                if (io && dbus)
                {
                    std::string service = getService(*dbus, biosConfigIntf,
                                                     biosConfigBaseMgrPath);

                    boost::asio::post(*io, [service, payloadType] {
                        generateAndSendAttributesData(service, payloadType);
                    });
                }
                else
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "ipmiOEMSetPayload: Unable to get io context or sdbus");
                    return ipmi::responseResponseError();
                }
            }

            struct stat filestat;

            /* Get entry's information. */
            if (!stat(payloadFilePath.c_str(), &filestat))
            {
                gNVOOBdata.payloadInfo[payloadType].payloadTimeStamp =
                    filestat.st_mtime;
                gNVOOBdata.payloadInfo[payloadType].payloadTotalSize =
                    filestat.st_size;
            }
            else
            {
                return ipmi::responseResponseError();
            }
            flushNVOOBdata();
            return ipmi::responseSuccess(
                gNVOOBdata.payloadInfo[payloadType].actualTotalPayloadWritten);
        }
        break;
        case ipmi::PTState::UserAbort:
        {
            PayloadEndTransfer* pPayloadEndTransfer =
                reinterpret_cast<PayloadEndTransfer*>(payload.data());
            PayloadInfo payloadInfo = gNVOOBdata.payloadInfo[payloadType];
            if (pPayloadEndTransfer->payloadReservationID !=
                payloadInfo.payloadReservationID)
            {
                return ipmi::responseInvalidReservationId();
            }
            gNVOOBdata.payloadInfo[payloadType].payloadReservationID = 0;
            gNVOOBdata.payloadInfo[payloadType].payloadType = 0;
            gNVOOBdata.payloadInfo[payloadType].payloadTotalSize = 0;
            // Delete the temp file
            std::string tempFilePath =
                "/var/oob/temp" + std::to_string(payloadType);
            unlink(tempFilePath.c_str());
            flushNVOOBdata();
            return ipmi::responseSuccess();
        }
        break;
        default:
            return ipmi::responseInvalidFieldRequest();
    }
    return ipmi::responseResponseError();
}

ipmi::RspType<message::Payload>
    ipmiOEMGetPayload(ipmi::Context::ptr ctx, uint8_t paramSel,
                      uint8_t payloadType, ipmi::message::Payload& payload)
{
    //      1-OOB BIOS config is supported
    message::Payload retValue;

    if (!(gNVOOBdata.mBIOSCapabilities.OOBCapability & (biosCapOffsetBit)))
    {
        return ipmi::response(ipmiCCBIOSCapabilityInitNotDone);
    }
    // Validate the Payload Type
    if (payloadType > maxPayloadSupported)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (payloadType == static_cast<uint8_t>(ipmi::PType::IntelXMLType1))
    {
        if (!payload1::update(ctx))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetPayload: unable to update NVOOBdata for payloadType "
                "= IntelXMLType1");
            return ipmi::response(ipmi::ccUnspecifiedError);
        }
    }

    struct PayloadInfo res = gNVOOBdata.payloadInfo[payloadType];

    switch (static_cast<GetPayloadParameter>(paramSel))
    {
        case ipmi::GetPayloadParameter::GetPayloadInfo:
        {
            std::string payloadFilePath =
                "/var/oob/Payload" + std::to_string(payloadType);

            std::ifstream ifs(payloadFilePath,
                              std::ios::in | std::ios::binary | std::ios::ate);

            if (!ifs.good())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMGetPayload: Payload File Error");
                // File does not exist code here
                return ipmi::response(ipmi::ccUnspecifiedError);
            }

            ifs.close();
            retValue.pack(res.payloadVersion);
            retValue.pack(payloadType);
            retValue.pack(res.payloadTotalSize);
            retValue.pack(res.payloadTotalChecksum);
            retValue.pack(res.payloadStatus);
            retValue.pack(res.payloadflag);
            retValue.pack(res.payloadTimeStamp);

            return ipmi::responseSuccess(std::move(retValue));
        }

        break;
        case ipmi::GetPayloadParameter::GetPayloadData:
        {
            if (res.payloadStatus ==
                (static_cast<uint8_t>(ipmi::PStatus::Valid)))
            {
                std::vector<uint32_t> reqData;
                if (payload.unpack(reqData) || !payload.fullyUnpacked())
                {
                    return ipmi::responseReqDataLenInvalid();
                }
                uint32_t offset = reqData.at(0);
                uint32_t length = reqData.at(1);
                std::string payloadFilePath =
                    "/var/oob/Payload" + std::to_string(payloadType);

                std::ifstream ifs(payloadFilePath, std::ios::in |
                                                       std::ios::binary |
                                                       std::ios::ate);

                if (!ifs.good())
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "ipmiOEMGetPayload: Payload File Error");
                    // File does not exist code here
                    return ipmi::response(ipmi::ccUnspecifiedError);
                }
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
        case ipmi::GetPayloadParameter::GetPayloadStatus:
        {
            retValue.pack(gNVOOBdata.payloadInfo[payloadType].payloadStatus);
            return ipmi::responseSuccess(std::move(retValue));
        }
        break;
        default:
            return ipmi::responseInvalidFieldRequest();
    }
    return ipmi::responseInvalidFieldRequest();
}

ipmi::RspType<> ipmiOEMSetBIOSHashInfo(
    ipmi::Context::ptr ctx, std::array<uint8_t, maxSeedSize>& pwdSeed,
    uint8_t algoInfo, std::array<uint8_t, maxHashSize>& adminPwdHash)
{

    std::string OSState;

    // We should support this command only in KCS Interface
    if (!IsSystemInterface(ctx))
    {
        return ipmi::responseCommandNotAvailable();
    }
    getSystemOSState(OSState);
    // We should not support this command after System Booted - After Exit Boot
    // service called

    if (OSState == "OperatingState")
    {
        return ipmi::response(ipmiCCNotSupportedInCurrentState);
    }

    nlohmann::json json;

    if ((algoInfo & 0xF) == algoSHA384)
    {
        json["HashAlgo"] = "SHA384";
    }
    else if ((algoInfo & 0xF) == algoSHA256)
    {
        json["HashAlgo"] = "SHA256";
    }
    else
    {
        return ipmi::responseInvalidFieldRequest();
    }

    json["Seed"] = pwdSeed;
    json["IsAdminPwdChanged"] = false;
    json["AdminPwdHash"] = adminPwdHash;
    json["IsUserPwdChanged"] = false;

    std::array<uint8_t, maxHashSize> userPwdHash;
    userPwdHash.fill({}); // initializing with 0 as user password hash field
                          // is not used presently
    json["UserPwdHash"] = userPwdHash;
    json["StatusFlag"] = algoInfo;

    std::string hashFilePath = "/var/lib/bios-settings-manager/seedData";
    std::ofstream ofs(hashFilePath, std::ios::out);
    const auto& writeData = json.dump();
    ofs << writeData;
    ofs.close();
    return ipmi::responseSuccess();
}

ipmi::RspType<std::array<uint8_t, maxSeedSize>, uint8_t,
              std::array<uint8_t, maxHashSize>>
    ipmiOEMGetBIOSHash(ipmi::Context::ptr ctx)
{

    std::string OSState;
    nlohmann::json data = nullptr;

    // We should support this command only in KCS Interface
    if (!IsSystemInterface(ctx))
    {
        return ipmi::responseCommandNotAvailable();
    }

    getSystemOSState(OSState);
    // We should not support this command after System Booted - After Exit Boot
    // service called

    if (OSState != "OperatingState")
    {
        std::string HashFilePath = "/var/lib/bios-settings-manager/seedData";

        std::ifstream devIdFile(HashFilePath);
        if (devIdFile.is_open())
        {

            try
            {
                data = nlohmann::json::parse(devIdFile, nullptr, false);
            }
            catch (const nlohmann::json::parse_error& e)
            {
                return ipmi::responseResponseError();
            }

            if (data.is_discarded())
            {
                return ipmi::responseResponseError();
            }

            std::array<uint8_t, maxHashSize> newAdminHash;
            std::array<uint8_t, maxSeedSize> seed;

            uint8_t flag = 0;
            uint8_t adminPwdChangedFlag = 0;
            if (!data.is_discarded())
            {

                adminPwdChangedFlag = data["IsAdminPwdChanged"];
                newAdminHash = data["AdminPwdHash"];
                seed = data["Seed"];
            }

            auto status = getResetBIOSSettings(flag);
            if (status)
            {
                return ipmi::responseResponseError();
            }
            if (adminPwdChangedFlag)
            {
                flag |= adminPasswordChanged;
            }

            std::copy(std::begin(newAdminHash), std::end(newAdminHash),
                      std::begin(newAdminHash));

            return ipmi::responseSuccess(seed, flag, newAdminHash);
        }
        else
        {
            return ipmi::responseResponseError();
        }
    }
    else
    {

        return ipmi::response(ipmiCCNotSupportedInCurrentState);
    }
}

static void registerBIOSConfigFunctions(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "BIOSConfig module initialization");
    InitNVOOBdata();

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetBIOSCap, Privilege::Admin,
                    ipmiOEMSetBIOSCap);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetBIOSCap, Privilege::User,
                    ipmiOEMGetBIOSCap);
    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetBIOSPwdHashInfo, Privilege::Admin,
                    ipmiOEMSetBIOSHashInfo);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetBIOSPwdHash, Privilege::User,
                    ipmiOEMGetBIOSHash);

    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdGetPayload, Privilege::User,
                    ipmiOEMGetPayload);
    registerHandler(prioOemBase, intel::netFnGeneral,
                    intel::general::cmdSetPayload, Privilege::Admin,
                    ipmiOEMSetPayload);

    return;
}
} // namespace ipmi
