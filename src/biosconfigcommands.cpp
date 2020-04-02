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

#include <openssl/sha.h>
#include <tinyxml2.h>

#include <biosconfigcommands.hpp>
#include <boost/crc.hpp>
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>
#include <ipmid/message.hpp>
#include <ipmid/message/types.hpp>
#include <ipmid/types.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <oemcommands.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>

#include <filesystem>

namespace ipmi
{
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

static constexpr uint8_t BIOSUserPasswordChanged = (1 << 5);
static constexpr uint8_t BIOSAdminPasswordChanged = (1 << 4);

static constexpr const char* BIOSConfigFolder = "/var/oob";
static constexpr const uint8_t algoSHA384 = 2;
static constexpr const uint8_t BIOSCapOffsetBit = 0x3;
static constexpr uint16_t maxGetPayloadDataSize = 4096;
static constexpr const char* biosXMLFilePath = "/var/oob/bios.xml";
static constexpr const char* biosXMLFilePath1 = "/var/oob/tempbios.xml";

static constexpr const char* BiosConfigBaseMgrPath =
    "/xyz/openbmc_project/bios_config/manager";
static constexpr const char* BiosConfigIntf =
    "xyz.openbmc_project.BIOSConfig.Manager";
static constexpr const char* ResetBIOSSettingsProp = "ResetBIOSSettings";
/*baseBIOSTable
map{attributeName,struct{attributeType,readonlyStatus,displayname,
              description,menuPath,current,default,
              array{struct{optionstring,optionvalue}}}}
*/
std::map<std::string,
         std::tuple<std::string, bool, std::string, std::string, std::string,
                    std::variant<int64_t, std::string>,
                    std::variant<int64_t, std::string>,
                    std::map<std::string, std::variant<int64_t, std::string>>>>
    AttributesData;

nvOOBdata gNVOOBdata;

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

static int sendAllAttributes(
    ipmi::Context::ptr ctx,
    std::chrono::microseconds timeout = ipmi::IPMI_DBUS_TIMEOUT)
{

    FILE* fp = fopen("/tmp/BIOSConfig/Error.log", "a+");
    fprintf(fp, "sendAllAttributes: Enter\n");
    fclose(fp);

    boost::system::error_code ec;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, BiosConfigIntf, BiosConfigBaseMgrPath);
    ec.clear();
    ctx->bus->yield_method_call<>(
        ctx->yield, ec, service, BiosConfigBaseMgrPath,
        "org.freedesktop.DBus.Properties", "Set", BiosConfigIntf,
        "BaseBIOSTable", AttributesData);
    if (ec)
    {
        FILE* fp = fopen("/tmp/BIOSConfig/Error.log", "a+");
        fprintf(fp, "Error in Sending the Attributes\n");
        fclose(fp);
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to sendAllAttributes");
        return -1;
    }
    return 0;
}

static uint8_t flushNVOOBdata()
{
    FILE* fptr;
    uint16_t size; // open file for writing
    fptr = fopen("/var/oob/nvoobdata.dat", "w");
    if (fptr == NULL)
    {
        return -1;
    }
    size = fwrite(&gNVOOBdata, sizeof(struct nvOOBdata), 1, fptr);
    if (size != sizeof(struct nvOOBdata))
    {
        fclose(fptr);
        return -1;
    }
    // close file
    fclose(fptr);
    return 0;
}

int getSystemOSState(std::string& OsStatus, std::chrono::microseconds timeout =
                                                ipmi::IPMI_DBUS_TIMEOUT)
{
    boost::system::error_code ec;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    ec.clear();
    Value variant =
        getDbusProperty(*dbus, "xyz.openbmc_project.State.OperatingSystem",
                        "/xyz/openbmc_project/state/os",
                        "xyz.openbmc_project.State.OperatingSystem.Status",
                        "OperatingSystemState");
    OsStatus = std::get<std::string>(variant);

    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getSystemOSState: Failed to get OSStatus");
        return -1;
    }
    return 0;
}

ipmi::RspType<> ipmiOEMSetBIOSCap(ipmi::Context::ptr ctx,
                                  uint8_t BIOSCapabilties, uint8_t reserved1,
                                  uint8_t reserved2, uint8_t reserved3)
{
    std::string OSState;
    getSystemOSState(OSState);

    if (OSState != "OperatingState")
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

static int generateAttributesData()
{
    // Open the bios.xml and parse it
    // Extract the needed data and store it in AttributesData variable
    // Close the bios.xml

    FILE* fp;
    fp = fopen("/tmp/BIOSConfig/Error.log", "a+");
    fprintf(fp, "generateAttributesData Enter\n");
    fclose(fp);

    tinyxml2::XMLDocument xmlDoc;

    xmlDoc.LoadFile(biosXMLFilePath);
    tinyxml2::XMLNode* pRoot = xmlDoc.FirstChild();
    if (pRoot == nullptr)
    {
        return 0;
    }
    tinyxml2::XMLElement* pElement = pRoot->FirstChildElement("biosknobs");
    if (pElement == nullptr)
    {
        return 0;
    }
    tinyxml2::XMLElement* pKnobsElement = pElement->FirstChildElement("knob");

    while (pKnobsElement != nullptr)
    {
        bool readOnlyStatus = false;
        std::string attrType =
            "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.String";
        const std::string name = pKnobsElement->Attribute("name");
        const std::string curvalue = pKnobsElement->Attribute("CurrentVal");
        const std::string dname = pKnobsElement->Attribute("prompt");
        const std::string menupath = pKnobsElement->Attribute("SetupPgPtr");
        const std::string defaultvalue = pKnobsElement->Attribute("default");
        const std::string description = pKnobsElement->Attribute("description");

        if (!name.empty() && !curvalue.empty() && !dname.empty() &&
            !menupath.empty() && !defaultvalue.empty())
        {
            std::string rootPath = "./" + std::string(menupath);

            std::map<std::string, std::variant<int64_t, std::string>> optionMap;
            tinyxml2::XMLElement* pOptionsElement =
                pKnobsElement->FirstChildElement("options");
            nlohmann::json optionsArray = nlohmann::json::array();
            if (pOptionsElement != nullptr)
            {
                tinyxml2::XMLElement* pOptionElement =
                    pOptionsElement->FirstChildElement("option");
                while (pOptionElement != nullptr)
                {
                    const std::string text = pOptionElement->Attribute("text");
                    const std::string attrValue =
                        pOptionElement->Attribute("value");
                    if (!text.empty() && !attrValue.empty())
                    {

                        optionMap.emplace(std::make_pair(std::move(text),
                                                         std::move(attrValue)));
                    }
                    pOptionElement =
                        pOptionElement->NextSiblingElement("option");
                }
            }
            fp = fopen("/tmp/BIOSConfig/Error.log", "a+");
            fprintf(fp, "%s\n", name.c_str());
            fclose(fp);

            AttributesData.emplace(std::make_pair(
                name,
                std::make_tuple(attrType, readOnlyStatus, dname, description,
                                rootPath, curvalue, defaultvalue, optionMap)));
        }
        pKnobsElement = pKnobsElement->NextSiblingElement("knob");
    }

    fp = fopen("/tmp/BIOSConfig/Error.log", "a+");
    fprintf(fp, "generateAttributesData Exit\n");
    fclose(fp);

    return 0;
}

/** @brief implementes executing the linux command
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

ipmi::RspType<uint32_t> ipmiOEMSetPayload(ipmi::Context::ptr ctx,
                                          uint8_t paramSel, uint8_t payloadType,
                                          std::vector<uint8_t> payload)
{
    uint8_t BIOSCapabilties = 0;
    uint8_t BIOSCapOffsetBit = 2; // BIT:1 0-OOB BIOS config not supported
                                  //      1-OOB BIOS config is supported

    if (!(gNVOOBdata.mBIOSCapabilities.OOBCapability & (BIOSCapOffsetBit)))
    {
        return ipmi::response(ipmiCCBIOSCapabilityInitNotDone);
    }
    // Validate the Payload Type
    if (payloadType > maxPayloadSupported)
    {
        return ipmi::responseInvalidFieldRequest();
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
                // TODO return ipmiCCPayloadChecksumFailed 0x81 For this
                // error Commented out for unit testing and manual
                // validation
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetPayload: Payload Checksum Failed");
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
            std::string PayloadFilePath =
                "/var/oob/Payload" + std::to_string(payloadType);
            auto renamestatus =
                std::rename(tempFilePath.c_str(), PayloadFilePath.c_str());
            if (renamestatus)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetPayload: Renaming Payload file - failed");
            }

            gNVOOBdata.payloadInfo[payloadType].payloadFilePath =
                PayloadFilePath;
            if (payloadType == static_cast<uint8_t>(ipmi::PType::IntelXMLType0))
            {
                // Unzip the Intel format XML file type 0
                auto response = generateBIOSXMLFile("/usr/bin/lzcat", "-d",
                                                    PayloadFilePath.c_str());
                if (response)
                {

                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "ipmiOEMSetPayload: generateBIOSXMLFile - failed");
                    gNVOOBdata.payloadInfo[payloadType].payloadStatus =
                        static_cast<uint8_t>(ipmi::PStatus::Corrupted);
                    return ipmi::response(ipmiCCPayloadPayloadPacketMissed);
                }
            }
            gNVOOBdata.payloadInfo[payloadType].payloadStatus =
                static_cast<uint8_t>(ipmi::PStatus::Valid);

            struct stat filestat;

            /* Get entry's information. */
            if (!stat(PayloadFilePath.c_str(), &filestat))
            {
                gNVOOBdata.payloadInfo[payloadType].payloadTimeStamp =
                    filestat.st_mtime;
                gNVOOBdata.payloadInfo[payloadType].payloadTotalSize =
                    filestat.st_size;
                gNVOOBdata.payloadInfo[payloadType].payloadFilePath =
                    PayloadFilePath;
            }
            else
            {
                return ipmi::responseResponseError();
            }

            phosphor::logging::log<phosphor::logging::level::INFO>(
                " ipmiOEMSetPayload : Convert XML into native-dbus DONE");
            generateAttributesData();

            phosphor::logging::log<phosphor::logging::level::INFO>(
                " ipmiOEMSetPayload : BaseBIOSTable Property  is set");
            sendAllAttributes(ctx);

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

    if (!(gNVOOBdata.mBIOSCapabilities.OOBCapability & (BIOSCapOffsetBit)))
    {
        return ipmi::response(ipmiCCBIOSCapabilityInitNotDone);
    }
    // Validate the Payload Type
    if (payloadType > maxPayloadSupported)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    struct PayloadInfo res = gNVOOBdata.payloadInfo[payloadType];

    switch (static_cast<GetPayloadParameter>(paramSel))
    {
        case ipmi::GetPayloadParameter::GetPayloadInfo:
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

static uint8_t InitNVOOBdata()
{
    FILE* fptr;
    uint16_t size;

    if (!(std::filesystem::exists("/var/oob")))
    {
        std::filesystem::create_directory("/var/oob");
    }
    // open file for writing
    fptr = fopen("/var/oob/nvoobdata.dat", "r");
    if (fptr == NULL)
    {
        return -1;
    }
    size = fread(&gNVOOBdata, sizeof(struct nvOOBdata), 1, fptr);
    if (size != sizeof(struct nvOOBdata))
    {
        fclose(fptr);
        return -1;
    }
    // close file
    fclose(fptr);
    return 0;
}

static uint8_t IsSystemInterface(ipmi::Context::ptr ctx)
{
    ChannelInfo chInfo;
    Cc status = ipmi::ccSuccess;

    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e)
    {
        return ipmi::ccUnspecifiedError;
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(EChannelMediumType::systemInterface))
    {
        return ipmi::ccCommandNotAvailable;
    }
    return ipmi::ccSuccess;
}

ipmi::RspType<> ipmiOEMSetBIOSHashInfo(
    ipmi::Context::ptr ctx, std::array<uint8_t, maxSeedSize>& pwdSeed,
    uint8_t algoInfo, std::array<uint8_t, maxHashSize>& adminPwdHash,
    std::array<uint8_t, maxHashSize>& userPwdHash)
{

    std::string OSState;

    // We should support this command only in KCS Interface
    if (IsSystemInterface(ctx))
    {
        return ipmi::responseCommandNotAvailable();
    }
    getSystemOSState(OSState);
    // We should not support this command after System Booted - After Exit Boot
    // service called

    if (OSState != "OperatingState")
    {

        if (algoInfo != algoSHA384 && algoInfo != 0)
        {
            // Atpresent, we are supporting only SHA384- HASH algo in BIOS side
            return ipmi::responseInvalidFieldRequest();
        }
        std::string HashFilePath = "/var/lib/bios-settings-manager/hash.json";

        nlohmann::json json;
        json["Seed"] = pwdSeed;
        json["HashAlgo"] = "SHA384";
        json["IsAdminPwdChanged"] = false;
        json["AdminPwdHash"] = adminPwdHash;
        json["IsUserPwdChanged"] = false;
        json["UserPwdHash"] = userPwdHash;
        std::ofstream ofs(HashFilePath, std::ios::out);
        const auto& writeData = json.dump();
        ofs << writeData;
        ofs.close();
        return ipmi::responseSuccess();
    }
    else
    {

        return ipmi::response(ipmiCCNotSupportedInCurrentState);
    }
}

static int getResetBIOSSettings(
    uint8_t& ResetFlag,
    std::chrono::microseconds timeout = ipmi::IPMI_DBUS_TIMEOUT)
{
    boost::system::error_code ec;
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, BiosConfigIntf, BiosConfigBaseMgrPath);
    Value variant = getDbusProperty(*dbus, service, BiosConfigBaseMgrPath,
                                    BiosConfigIntf, ResetBIOSSettingsProp);
    ResetFlag = static_cast<uint8_t>(std::get<std::uint8_t>(variant));
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to ResetBIOSSettings");
        return -1;
    }
    return 0;
}

ipmi::RspType<uint8_t, std::array<uint8_t, maxHashSize>,
              std::array<uint8_t, maxHashSize>>
    ipmiOEMGetBIOSHash(ipmi::Context::ptr ctx)
{

    std::string OSState;

    // We should support this command only in KCS Interface
    if (IsSystemInterface(ctx))
    {
        return ipmi::responseCommandNotAvailable();
    }

    getSystemOSState(OSState);
    // We should not support this command after System Booted - After Exit Boot
    // service called

    if (OSState != "OperatingState")
    {
        std::string HashFilePath = "/var/lib/bios-settings-manager/hash.json";

        std::ifstream devIdFile(HashFilePath);
        if (devIdFile.is_open())
        {
            auto data = nlohmann::json::parse(devIdFile, nullptr, false);

            std::array<uint8_t, maxHashSize> newAdminHash;
            std::array<uint8_t, maxHashSize> newUserHash;
            uint8_t flag = 0;
            uint8_t adminPwdChangedFlag = 0;
            uint8_t userPwdChangedFlag = 0;
            if (!data.is_discarded())
            {

                adminPwdChangedFlag = data["IsAdminPwdChanged"];
                newAdminHash = data["AdminPwdHash"];
                newUserHash = data["UserPwdHash"];
                userPwdChangedFlag = data["IsUserPwdChanged"];
            }

            // 0: BIT 4 - New Admin Password Not Present
            // 1: BIT 4 - New Admin Password Hash Present
            // 0: BIT 5 - New User Password Not Present
            // 1: BIT 5 - New User Password Hash Present
            // 0: BIT 0 - Default Setting flag is not set
            // 1: BIT 0 - Default Setting flag is set
            auto status = getResetBIOSSettings(flag);
            if (status)
            {
                return ipmi::responseResponseError();
            }
            if (adminPwdChangedFlag)
            {
                flag |= BIOSAdminPasswordChanged;
            }
            if (userPwdChangedFlag)
            {
                flag |= BIOSUserPasswordChanged;
            }

            std::copy(std::begin(newAdminHash), std::end(newAdminHash),
                      std::begin(newAdminHash));
            std::copy(std::begin(newUserHash), std::end(newUserHash),
                      std::begin(newUserHash));
            return ipmi::responseSuccess(flag, newAdminHash, newUserHash);
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
