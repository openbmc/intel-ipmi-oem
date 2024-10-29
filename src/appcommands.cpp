/*
// Copyright (c) 2019 Intel Corporation
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

#include <byteswap.h>

#include <appcommands.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <types.hpp>

#include <fstream>
#include <regex>

using namespace phosphor::logging;
using namespace sdbusplus::error::xyz::openbmc_project::common;

namespace ipmi
{

static void registerAPPFunctions() __attribute__((constructor));

static constexpr const char* bmcStateIntf = "xyz.openbmc_project.State.BMC";
static constexpr const char* softwareVerIntf =
    "xyz.openbmc_project.Software.Version";
static constexpr const char* softwareActivationIntf =
    "xyz.openbmc_project.Software.Activation";
static constexpr const char* associationIntf =
    "xyz.openbmc_project.Association";
static constexpr const char* softwareFunctionalPath =
    "/xyz/openbmc_project/software/functional";

static constexpr const char* currentBmcStateProp = "CurrentBMCState";
static constexpr const char* bmcStateReadyStr =
    "xyz.openbmc_project.State.BMC.BMCState.Ready";

static std::unique_ptr<sdbusplus::bus::match_t> bmcStateChangedSignal;
static uint8_t bmcDeviceBusy = true;

int initBMCDeviceState(ipmi::Context::ptr ctx)
{
    DbusObjectInfo objInfo;
    boost::system::error_code ec =
        ipmi::getDbusObject(ctx, bmcStateIntf, "/", "bmc0", objInfo);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "initBMCDeviceState: Failed to perform GetSubTree action",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()),
            phosphor::logging::entry("INTERFACE=%s", bmcStateIntf));
        return -1;
    }

    std::string bmcState;
    ec = ipmi::getDbusProperty(ctx, objInfo.second, objInfo.first, bmcStateIntf,
                               currentBmcStateProp, bmcState);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "initBMCDeviceState: Failed to get CurrentBMCState property",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return -1;
    }

    bmcDeviceBusy = (bmcState != bmcStateReadyStr);

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "BMC device state updated");

    // BMC state may change runtime while doing firmware udpate.
    // Register for property change signal to update state.
    bmcStateChangedSignal = std::make_unique<sdbusplus::bus::match_t>(
        *(ctx->bus),
        sdbusplus::bus::match::rules::propertiesChanged(objInfo.first,
                                                        bmcStateIntf),
        [](sdbusplus::message_t& msg) {
            std::map<std::string, ipmi::DbusVariant> props;
            std::vector<std::string> inVal;
            std::string iface;
            try
            {
                msg.read(iface, props, inVal);
            }
            catch (const std::exception& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Exception caught in Get CurrentBMCState");
                return;
            }

            auto it = props.find(currentBmcStateProp);
            if (it != props.end())
            {
                std::string* state = std::get_if<std::string>(&it->second);
                if (state)
                {
                    bmcDeviceBusy = (*state != bmcStateReadyStr);
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "BMC device state updated");
                }
            }
        });

    return 0;
}

/**
 * @brief Returns the functional firmware version information.
 *
 * It reads the active firmware versions by checking functional
 * endpoints association and matching the input version purpose string.
 * ctx[in]                - ipmi context.
 * reqVersionPurpose[in]  - Version purpose which need to be read.
 * version[out]           - Output Version string.
 *
 * @return Returns '0' on success and '-1' on failure.
 *
 */
int getActiveSoftwareVersionInfo(ipmi::Context::ptr ctx,
                                 const std::string& reqVersionPurpose,
                                 std::string& version)
{
    std::vector<std::string> activeEndPoints;
    boost::system::error_code ec = ipmi::getDbusProperty(
        ctx, ipmi::MAPPER_BUS_NAME, softwareFunctionalPath, associationIntf,
        "endpoints", activeEndPoints);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Active firmware version endpoints.");
        return -1;
    }

    for (auto& activeEndPoint : activeEndPoints)
    {
        std::string serviceName;
        ec = ipmi::getService(ctx, softwareActivationIntf, activeEndPoint,
                              serviceName);
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to perform getService.",
                phosphor::logging::entry("OBJPATH=%s", activeEndPoint.c_str()));
            continue;
        }

        PropertyMap propMap;
        ec = ipmi::getAllDbusProperties(ctx, serviceName, activeEndPoint,
                                        softwareVerIntf, propMap);
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to perform GetAll on Version interface.",
                phosphor::logging::entry("SERVICE=%s", serviceName.c_str()),
                phosphor::logging::entry("PATH=%s", activeEndPoint.c_str()));
            continue;
        }

        std::string* purposeProp =
            std::get_if<std::string>(&propMap["Purpose"]);
        std::string* versionProp =
            std::get_if<std::string>(&propMap["Version"]);
        if (!purposeProp || !versionProp)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to get version or purpose property");
            continue;
        }

        // Check for requested version information and return if found.
        if (*purposeProp == reqVersionPurpose)
        {
            version = *versionProp;
            return 0;
        }
    }

    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Failed to find version information.",
        phosphor::logging::entry("PURPOSE=%s", reqVersionPurpose.c_str()));
    return -1;
}

// Support both 2 solutions:
// 1.Current solution  2.7.0-dev-533-g14dc00e79-5e7d997
//   openbmcTag  2.7.0-dev
//   BuildNo     533
//   openbmcHash 14dc00e79
//   MetaHasg    5e7d997
//
// 2.New solution  wht-0.2-3-gab3500-38384ac or wht-2000.2.3-gab3500-38384ac
//   IdStr        wht
//   Major        0
//   Minor        2
//   buildNo      3
//   MetaHash     ab3500
//   openbmcHash  38384ac
std::optional<MetaRevision> convertIntelVersion(std::string& s)
{
    std::smatch results;
    MetaRevision rev;
    std::regex pattern1("(\\d+?).(\\d+?).\\d+?-\\w*?-(\\d+?)-g(\\w+?)-(\\w+?)");
    constexpr size_t matchedPhosphor = 6;
    if (std::regex_match(s, results, pattern1))
    {
        if (results.size() == matchedPhosphor)
        {
            rev.platform = "whtref";
            rev.major = static_cast<uint8_t>(std::stoi(results[1]));
            rev.minor = static_cast<uint8_t>(std::stoi(results[2]));
            rev.buildNo = static_cast<uint32_t>(std::stoi(results[3]));
            rev.openbmcHash = results[4];
            rev.metaHash = results[5];
            std::string versionString =
                rev.platform + ":" + std::to_string(rev.major) + ":" +
                std::to_string(rev.minor) + ":" + std::to_string(rev.buildNo) +
                ":" + rev.openbmcHash + ":" + rev.metaHash;
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Get BMC version",
                phosphor::logging::entry("VERSION=%s", versionString.c_str()));
            return rev;
        }
    }
    constexpr size_t matchedIntel = 7;
    std::regex pattern2("(\\w+?)-(\\d+?).(\\d+?)[-.](\\d+?)-g(\\w+?)-(\\w+?)");
    if (std::regex_match(s, results, pattern2))
    {
        if (results.size() == matchedIntel)
        {
            rev.platform = results[1];
            std::string majorVer = results[2].str();
            // Take only the last two digits of the major version
            rev.major = static_cast<uint8_t>(
                std::stoi(majorVer.substr(majorVer.size() - 2)));
            rev.minor = static_cast<uint8_t>(std::stoi(results[3]));
            rev.buildNo = static_cast<uint32_t>(std::stoi(results[4]));
            rev.openbmcHash = results[6];
            rev.metaHash = results[5];
            std::string versionString =
                rev.platform + ":" + std::to_string(rev.major) + ":" +
                std::to_string(rev.minor) + ":" + std::to_string(rev.buildNo) +
                ":" + rev.openbmcHash + ":" + rev.metaHash;
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "Get BMC version",
                phosphor::logging::entry("VERSION=%s", versionString.c_str()));
            return rev;
        }
    }

    return std::nullopt;
}

static constexpr size_t uuidLength = 16;
static std::array<uint8_t, uuidLength>
    rfc4122ToIpmiConvesrion(std::string rfc4122)
{
    using Argument = xyz::openbmc_project::common::InvalidArgument;
    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    // Per IPMI Spec 2.0 need to convert to 16 hex bytes and reverse the byte
    // order
    // Ex: 0x2332fc2c40e66298e511f2782395a361
    constexpr size_t uuidHexLength = (2 * uuidLength);
    constexpr size_t uuidRfc4122Length = (uuidHexLength + 4);
    std::array<uint8_t, uuidLength> uuid;
    if (rfc4122.size() == uuidRfc4122Length)
    {
        rfc4122.erase(std::remove(rfc4122.begin(), rfc4122.end(), '-'),
                      rfc4122.end());
    }
    if (rfc4122.size() != uuidHexLength)
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("rfc4122"),
                              Argument::ARGUMENT_VALUE(rfc4122.c_str()));
    }
    for (size_t ind = 0; ind < uuidHexLength; ind += 2)
    {
        char v[3];
        v[0] = rfc4122[ind];
        v[1] = rfc4122[ind + 1];
        v[2] = 0;
        size_t err;
        long b;
        try
        {
            b = std::stoul(v, &err, 16);
        }
        catch (const std::exception& e)
        {
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("rfc4122"),
                                  Argument::ARGUMENT_VALUE(rfc4122.c_str()));
        }
        // check that exactly two ascii bytes were converted
        if (err != 2)
        {
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("rfc4122"),
                                  Argument::ARGUMENT_VALUE(rfc4122.c_str()));
        }
        uuid[uuidLength - (ind / 2) - 1] = static_cast<uint8_t>(b);
    }
    return uuid;
}

ipmi::RspType<std::array<uint8_t, 16>>
    ipmiAppGetSystemGuid(ipmi::Context::ptr& ctx)
{
    static constexpr auto uuidInterface = "xyz.openbmc_project.Common.UUID";
    static constexpr auto uuidProperty = "UUID";
    // Get the Inventory object implementing BMC interface
    ipmi::DbusObjectInfo objectInfo{};
    boost::system::error_code ec =
        ipmi::getDbusObject(ctx, uuidInterface, objectInfo);

    if (ec.value())
    {
        lg2::error("Failed to locate System UUID object, "
                   "interface: {INTERFACE}, error: {ERROR}",
                   "INTERFACE", uuidInterface, "ERROR", ec.message());
        return ipmi::responseUnspecifiedError();
    }

    // Read UUID property value from bmcObject
    // UUID is in RFC4122 format Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    std::string rfc4122Uuid{};
    ec = ipmi::getDbusProperty(ctx, objectInfo.second, objectInfo.first,
                               uuidInterface, uuidProperty, rfc4122Uuid);

    if (ec.value())
    {
        lg2::error("Failed to read System UUID property, "
                   "interface: {INTERFACE}, property: {PROPERTY}, "
                   "error: {ERROR}",
                   "INTERFACE", uuidInterface, "PROPERTY", uuidProperty,
                   "ERROR", ec.message());
        return ipmi::responseUnspecifiedError();
    }
    std::array<uint8_t, 16> uuid;
    try
    {
        // convert to IPMI format
        uuid = rfc4122ToIpmiConvesrion(rfc4122Uuid);
    }
    catch (const InvalidArgument& e)
    {
        lg2::error("Failed in parsing BMC UUID property, "
                   "interface: {INTERFACE}, property: {PROPERTY}, "
                   "value: {VALUE}, error: {ERROR}",
                   "INTERFACE", uuidInterface, "PROPERTY", uuidProperty,
                   "VALUE", rfc4122Uuid, "ERROR", e);
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess(uuid);
}

RspType<uint8_t,  // Device ID
        uint8_t,  // Device Revision
        uint7_t,  // Firmware Revision Major
        bool,     // Device available(0=NormalMode,1=DeviceFirmware)
        uint8_t,  // Firmware Revision minor
        uint8_t,  // IPMI version
        uint8_t,  // Additional device support
        uint24_t, // MFG ID
        uint16_t, // Product ID
        uint32_t  // AUX info
        >
    ipmiAppGetDeviceId(ipmi::Context::ptr ctx)
{
    static struct
    {
        uint8_t id;
        uint8_t revision;
        uint7_t fwMajor;
        bool devBusy;
        uint8_t fwMinor;
        uint8_t ipmiVer = 2;
        uint8_t addnDevSupport;
        uint24_t manufId;
        uint16_t prodId;
        uint32_t aux;
    } devId;
    static bool fwVerInitialized = false;
    static bool devIdInitialized = false;
    static bool bmcStateInitialized = false;
    const char* filename = "/usr/share/ipmi-providers/dev_id.json";
    const char* prodIdFilename = "/var/cache/private/prodID";
    if (!fwVerInitialized)
    {
        std::string versionString;
        if (!getActiveSoftwareVersionInfo(ctx, versionPurposeBMC,
                                          versionString))
        {
            std::optional<MetaRevision> rev =
                convertIntelVersion(versionString);
            if (rev.has_value())
            {
                MetaRevision revision = rev.value();
                devId.fwMajor = static_cast<uint7_t>(revision.major);

                revision.minor = (revision.minor > 99 ? 99 : revision.minor);
                devId.fwMinor = revision.minor % 10 +
                                (revision.minor / 10) * 16;
                try
                {
                    uint32_t hash = std::stoul(revision.metaHash, 0, 16);
                    hash = bswap_32(hash);
                    devId.aux = (revision.buildNo & 0xFF) + (hash & 0xFFFFFF00);
                    fwVerInitialized = true;
                }
                catch (const std::exception& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Failed to convert git hash",
                        phosphor::logging::entry("ERROR=%s", e.what()));
                }
            }
        }
    }

    if (!devIdInitialized)
    {
        std::ifstream devIdFile(filename);
        if (devIdFile.is_open())
        {
            auto data = nlohmann::json::parse(devIdFile, nullptr, false);
            if (!data.is_discarded())
            {
                devId.id = data.value("id", 0);
                devId.revision = data.value("revision", 0);
                devId.addnDevSupport = data.value("addn_dev_support", 0);
                devId.manufId = data.value("manuf_id", 0);
            }
            else
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Device ID JSON parser failure");
                return ipmi::responseUnspecifiedError();
            }
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Device ID file not found");
            return ipmi::responseUnspecifiedError();
        }

        // Determine the Product ID. Using the DBus system is painfully slow at
        // boot time. Avoid using DBus to get the Product ID. The Product ID is
        // stored in a non-volatile file now. The /usr/bin/checkFru.sh script,
        // run during bootup, will populate the productIdFile.
        std::fstream prodIdFile(prodIdFilename);
        if (prodIdFile.is_open())
        {
            std::string id = "0x00";
            char* end;
            prodIdFile.getline(&id[0], id.size() + 1);
            devId.prodId = std::strtol(&id[0], &end, 0);
            devIdInitialized = true;
        }
        else
        {
            // For any exception send out platform id as 0,
            // and make sure to re-query the device id.
            devIdInitialized = false;
            devId.prodId = 0;
        }
    }

    if (!bmcStateInitialized)
    {
        if (!initBMCDeviceState(ctx))
        {
            bmcStateInitialized = true;
        }
    }

    return ipmi::responseSuccess(
        devId.id, devId.revision, devId.fwMajor, bmcDeviceBusy, devId.fwMinor,
        devId.ipmiVer, devId.addnDevSupport, devId.manufId, devId.prodId,
        devId.aux);
}

static void registerAPPFunctions(void)
{
    // <Get Device ID>
    registerHandler(prioOemBase, netFnApp, app::cmdGetDeviceId, Privilege::User,
                    ipmiAppGetDeviceId);
    // <Get System GUID>
    registerHandler(prioOemBase, netFnApp, app::cmdGetSystemGuid,
                    Privilege::User, ipmiAppGetSystemGuid);
}

} // namespace ipmi
