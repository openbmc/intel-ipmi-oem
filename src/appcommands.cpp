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
#include <appcommands.hpp>
#include <fstream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <regex>

namespace ipmi
{

static void registerAPPFunctions() __attribute__((constructor));

using GetObjectType =
    std::vector<std::pair<std::string, std::vector<std::string>>>;
using GetSubTreeType = std::vector<std::pair<std::string, GetObjectType>>;
using PropertyMapType =
    boost::container::flat_map<std::string, std::variant<std::string>>;

static constexpr const char* objMapperService =
    "xyz.openbmc_project.ObjectMapper";
static constexpr const char* objMapperPath =
    "/xyz/openbmc_project/object_mapper";
static constexpr const char* objMapperIntf = "xyz.openbmc_project.ObjectMapper";
static constexpr const char* dbusPropIntf = "org.freedesktop.DBus.Properties";
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

bool isBMCBusy(ipmi::Context::ptr ctx)
{
    boost::system::error_code ec;
    GetSubTreeType subtree = ctx->bus->yield_method_call<GetSubTreeType>(
        ctx->yield, ec, objMapperService, objMapperPath, objMapperIntf,
        "GetSubTree", "/", 5, std::array<const char*, 1>{bmcStateIntf});
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "isBMCBusy: Failed to perform GetSubTree action",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()),
            phosphor::logging::entry("INTERFACE=%s", bmcStateIntf));
        return false;
    }

    if (subtree.size() != 1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "isBMCBusy: Invalid size of objects returned");
        return false;
    }

    std::variant<std::string> bmcState =
        ctx->bus->yield_method_call<std::variant<std::string>>(
            ctx->yield, ec, subtree[0].second[0].first, subtree[0].first,
            dbusPropIntf, "Get", bmcStateIntf, currentBmcStateProp);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "isBMCBusy: Failed to get CurrentBMCState property",
            phosphor::logging::entry("ERROR=%s", ec.message().c_str()));
        return false;
    }

    const std::string* state = std::get_if<std::string>(&bmcState);
    if (!state)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "isBMCBusy: Get CurrentBMCState property type mismatch");
        return false;
    }
    return (*state != bmcStateReadyStr);
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
    boost::system::error_code ec;
    std::variant<std::vector<std::string>> vActiveEndPoints =
        ctx->bus->yield_method_call<std::variant<std::vector<std::string>>>(
            ctx->yield, ec, objMapperService, softwareFunctionalPath,
            dbusPropIntf, "Get", associationIntf, "endpoints");
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Active firmware version endpoints.");
        return -1;
    }

    const std::vector<std::string>* activeEndPoints =
        std::get_if<std::vector<std::string>>(&vActiveEndPoints);
    if ((activeEndPoints == nullptr))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Active firmware version endpoints.");
        return -1;
    }

    for (auto& activeEndPoint : *activeEndPoints)
    {
        GetObjectType objInfo = ctx->bus->yield_method_call<GetObjectType>(
            ctx->yield, ec, objMapperService, objMapperPath, objMapperIntf,
            "GetObject", activeEndPoint,
            std::array<const char*, 1>{softwareActivationIntf});
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to perform GetObject.",
                phosphor::logging::entry("OBJPATH=%s", activeEndPoint.c_str()));
            continue;
        }
        // There should be only single object with given path and interface.
        if (objInfo.size() != 1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Multiple objects found for end point.");
            continue;
        }

        PropertyMapType propMap = ctx->bus->yield_method_call<PropertyMapType>(
            ctx->yield, ec, objInfo[0].first, activeEndPoint, dbusPropIntf,
            "GetAll", softwareVerIntf);
        if (ec)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Failed to perform GetAll on Version interface.",
                phosphor::logging::entry("SERVICE=%s",
                                         objInfo[0].first.c_str()),
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
// 2.New solution  wht-0.2-3-gab3500-38384ac
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
    std::regex pattern2("(\\w+?)-(\\d+?).(\\d+?)-(\\d+?)-g(\\w+?)-(\\w+?)");
    if (std::regex_match(s, results, pattern2))
    {
        if (results.size() == matchedIntel)
        {
            rev.platform = results[1];
            rev.major = static_cast<uint8_t>(std::stoi(results[2]));
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
                devId.fwMinor =
                    revision.minor % 10 + (revision.minor / 10) * 16;
                try
                {
                    uint32_t hash = std::stoul(revision.metaHash, 0, 16);
                    hash = ((hash & 0xff000000) >> 24) |
                           ((hash & 0x00FF0000) >> 8) |
                           ((hash & 0x0000FF00) << 8) | ((hash & 0xFF) << 24);
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

    // Set availability to the actual current BMC state.
    // The availability may change in run time so don't cache.
    bool bmcDevBusy = isBMCBusy(ctx);

    return ipmi::responseSuccess(devId.id, devId.revision, devId.fwMajor,
                                 bmcDevBusy, devId.fwMinor, devId.ipmiVer,
                                 devId.addnDevSupport, devId.manufId,
                                 devId.prodId, devId.aux);
}

static void registerAPPFunctions(void)
{
    // <Get Device ID>
    registerHandler(prioOemBase, netFnApp, app::cmdGetDeviceId, Privilege::User,
                    ipmiAppGetDeviceId);
}

} // namespace ipmi
