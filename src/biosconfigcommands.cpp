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
static constexpr uint8_t restoreDefaultValues = (1 << 7);

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
/*baseBIOSTable
map{attributeName,struct{attributeType,readonlyStatus,displayname,
              description,menuPath,current,default,
              array{struct{optionstring,optionvalue}}}}
*/

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
    GetPayloadStatus = 2,
    MaxPayloadParameters
};

namespace payload1
{

enum class AttributesType : uint8_t
{
    unknown = 0,
    string,
    integer,
    enumeration
};

using PendingAttributesType =
    std::map<std::string, std::tuple<std::string, ipmi::DbusVariant>>;

AttributesType getAttrType(const std::string_view typeDbus)
{
    if (typeDbus == "xyz.openbmc_project.BIOSConfig.Manager."
                    "AttributeType.String")
    {
        return AttributesType::string;
    }
    else if (typeDbus == "xyz.openbmc_project.BIOSConfig."
                         "Manager.AttributeType.Integer")
    {
        return AttributesType::integer;
    }
    else if (typeDbus == "xyz.openbmc_project.BIOSConfig."
                         "Manager.AttributeType.Enumeration")
    {
        return AttributesType::enumeration;
    }

    return AttributesType::unknown;
}

bool fillPayloadData(std::string& payloadData,
                     const ipmi::DbusVariant& attributes,
                     const std::string_view key, AttributesType& attrType)
{
    payloadData += key;
    payloadData += '=';

    if (attrType == AttributesType::string ||
        attrType == AttributesType::enumeration)
    {
        if (!std::holds_alternative<std::string>(attributes))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "fillPayloadData: No string data in attributes");
            return false;
        }
        payloadData += std::get<std::string>(attributes);
    }
    else if (attrType == AttributesType::integer)
    {
        if (!std::holds_alternative<int64_t>(attributes))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "fillPayloadData: No int64_t data in attributes");
            return false;
        }
        payloadData += std::to_string(std::get<int64_t>(attributes));
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "fillPayloadData: Unsupported attribute type");
        return false;
    }

    payloadData += '\n';

    return true;
}

bool getPendingList(ipmi::Context::ptr ctx, std::string& payloadData)
{
    std::variant<PendingAttributesType> pendingAttributesData;
    boost::system::error_code ec;

    payloadData.clear();

    auto dbus = getSdBus();
    if (!dbus)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getPendingList: getSdBus() failed");
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
    catch (const std::exception& ex)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(ex.what());
        return false;
    }

    if (ec)
    {
        std::string err = "getPendingList: error while trying to get "
                          "PendingAttributes, error = ";
        err += ec.message();

        phosphor::logging::log<phosphor::logging::level::ERR>(err.c_str());

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
        AttributesType attrType = getAttrType(itemType);

        if (!fillPayloadData(payloadData, std::get<1>(attributes), key,
                             attrType))
        {
            return false;
        }
    }

    if (payloadData.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getPendingList: payloadData is empty");
        return false;
    }

    return true;
}
bool updatePayloadFile(std::string& payloadFilePath, std::string payloadData)
{
    std::ofstream payloadFile(payloadFilePath,
                              std::ios::out | std::ios::binary);

    payloadFile << payloadData;

    if (!payloadFile.good())
    {
        return false;
    }

    return true;
}

bool computeCheckSum(std::string& payloadFilePath,
                     boost::crc_32_type& calcChecksum)
{
    std::ifstream payloadFile(payloadFilePath.c_str(),
                              std::ios::in | std::ios::binary | std::ios::ate);

    if (!payloadFile.good())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "computeCheckSum: Cannot open Payload1 file");
        return false;
    }

    payloadFile.seekg(0, payloadFile.end);
    int length = payloadFile.tellg();
    payloadFile.seekg(0, payloadFile.beg);

    if (maxGetPayloadDataSize < length)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "computeCheckSum: length > maxGetPayloadDataSize");
        return false;
    }

    std::unique_ptr<char[]> payloadBuffer(new char[length]);

    payloadFile.read(payloadBuffer.get(), length);
    uint32_t readCount = payloadFile.gcount();

    calcChecksum.process_bytes(payloadBuffer.get(), readCount);

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

    payloadInfo.payloadType = payloadType;

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

    std::string payloadData;

    if (!getPendingList(ctx, payloadData))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "payload1::update : getPendingList() failed");
        return false;
    }

    if (!updatePayloadFile(payloadFilePath, payloadData))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "payload1::update : updatePayloadFile() failed");
        return false;
    }

    if (!updatePayloadInfo(payloadFilePath))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "payload1::update : updatePayloadInfo() failed");
        return false;
    }

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
        catch (const std::exception& ex)
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

    outFile.seekp(std::ios_base::beg);
    const char* writedata = reinterpret_cast<const char*>(&gNVOOBdata);
    outFile.write(writedata, sizeof(struct NVOOBdata));

    if (!outFile.good())
    {
        return false;
    }

    return true;
}

/** @brief implement to get the System State
 *  @returns status
 */
static bool getPostCompleted()
{
    /*
     * In case of failure we treat postCompleted as true.
     * So that BIOS config commands is not accepted by BMC by mistake.
     */
    bool postCompleted = true;

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        Value variant =
            getDbusProperty(*dbus, "xyz.openbmc_project.State.OperatingSystem",
                            "/xyz/openbmc_project/state/os",
                            "xyz.openbmc_project.State.OperatingSystem.Status",
                            "OperatingSystemState");
        auto& value = std::get<std::string>(variant);

        // The short strings "Standby" is deprecated in favor of the
        // full enum strings. Support for the short strings will be
        // removed in the future.
        postCompleted = (value == "Standby") ||
                        (value == "xyz.openbmc_project.State.OperatingSystem."
                                  "Status.OSStatus.Standby");
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "'getDbusProperty' failed to read "
            "xyz.openbmc_project.State.OperatingSystem");
    }

    return postCompleted;
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
    catch (const std::exception& ex)
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

ipmi::RspType<> ipmiOEMSetBIOSCap(ipmi::Context::ptr ctx,
                                  uint8_t BIOSCapabilties, uint8_t reserved1,
                                  uint8_t reserved2, uint8_t reserved3)
{
    if (getPostCompleted())
    {
        return ipmi::response(ipmiCCNotSupportedInCurrentState);
    }

    if (reserved1 != 0 || reserved2 != 0 || reserved3 != 0)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    gNVOOBdata.mBIOSCapabilities.OOBCapability = BIOSCapabilties;
    gNVOOBdata.mIsBIOSCapInitDone = true;

    flushNVOOBdata();
    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t, uint8_t, uint8_t, uint8_t>
    ipmiOEMGetBIOSCap(ipmi::Context::ptr ctx)
{
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
        if (getPostCompleted())
        {
            return ipmi::response(ipmiCCNotSupportedInCurrentState);
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

            std::ofstream outFile(FilePath, std::ios::binary | std::ios::app);
            outFile.seekp(pPayloadInProgress->payloadOffset);
            // we have to remove the current size, current offset, current
            // length,checksum bytes , reservation bytes

            const char* writedata =
                reinterpret_cast<const char*>(payload.data());
            outFile.write(writedata + 16, payload.size() - 16);
            outFile.close();

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
                gNVOOBdata.payloadInfo[payloadType].payloadStatus =
                    static_cast<uint8_t>(ipmi::PStatus::Valid);
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

    if (static_cast<GetPayloadParameter>(paramSel) >=
        ipmi::GetPayloadParameter::MaxPayloadParameters)
    {
        return ipmi::responseInvalidFieldRequest();
    }

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
            retValue.pack(res.payloadflag);
            retValue.pack(res.payloadStatus);
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

                if (length > static_cast<uint32_t>(maxGetPayloadDataSize))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "ipmiOEMGetPayload: length > maxGetPayloadDataSize",
                        phosphor::logging::entry("LENGTH=%d", length),
                        phosphor::logging::entry("maxGetPayloadDataSize=%d",
                                                 maxGetPayloadDataSize));
                    return ipmi::responseInvalidFieldRequest();
                }

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
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "ipmiOEMGetPayload: filesize < offset");
                    return ipmi::responseInvalidFieldRequest();
                }

                if ((static_cast<uint64_t>(fileSize) - offset) < length)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "ipmiOEMGetPayload: (filesize - offset) < length ");
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
    // We should not support this command after System Booted - After Exit Boot
    // service called
    if (getPostCompleted())
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
    nlohmann::json data = nullptr;

    // We should not support this command after System Booted - After Exit Boot
    // service called
    if (getPostCompleted())
    {
        return ipmi::response(ipmiCCNotSupportedInCurrentState);
    }

    std::string HashFilePath = "/var/lib/bios-settings-manager/seedData";

    std::ifstream devIdFile(HashFilePath);
    if (!devIdFile.is_open())
    {
        return ipmi::responseResponseError();
    }

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
    if (flag)
    {
        flag |= restoreDefaultValues;
    }
    if (adminPwdChangedFlag)
    {
        flag |= adminPasswordChanged;
    }

    std::copy(std::begin(newAdminHash), std::end(newAdminHash),
              std::begin(newAdminHash));

    return ipmi::responseSuccess(seed, flag, newAdminHash);
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
