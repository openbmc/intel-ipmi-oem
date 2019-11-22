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

#include <appcommands.hpp>
#include <fstream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/log.hpp>
#include <regex>
#include <xyz/openbmc_project/Software/Activation/server.hpp>
#include <xyz/openbmc_project/Software/Version/server.hpp>
#include <xyz/openbmc_project/State/BMC/server.hpp>

namespace ipmi
{

static void registerAPPFunctions() __attribute__((constructor));

namespace Log = phosphor::logging;
namespace Error = sdbusplus::xyz::openbmc_project::Common::Error;
using Version = sdbusplus::xyz::openbmc_project::Software::server::Version;
using Activation =
    sdbusplus::xyz::openbmc_project::Software::server::Activation;
using BMC = sdbusplus::xyz::openbmc_project::State::server::BMC;

constexpr auto bmc_state_interface = "xyz.openbmc_project.State.BMC";
constexpr auto bmc_state_property = "CurrentBMCState";

static constexpr auto redundancyIntf =
    "xyz.openbmc_project.Software.RedundancyPriority";
static constexpr auto versionIntf = "xyz.openbmc_project.Software.Version";
static constexpr auto activationIntf =
    "xyz.openbmc_project.Software.Activation";
static constexpr auto softwareRoot = "/xyz/openbmc_project/software";

bool getCurrentBmcState()
{
    sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};

    // Get the Inventory object implementing the BMC interface
    ipmi::DbusObjectInfo bmcObject =
        ipmi::getDbusObject(bus, bmc_state_interface);
    auto variant =
        ipmi::getDbusProperty(bus, bmcObject.second, bmcObject.first,
                              bmc_state_interface, bmc_state_property);

    return std::holds_alternative<std::string>(variant) &&
           BMC::convertBMCStateFromString(std::get<std::string>(variant)) ==
               BMC::BMCState::Ready;
}

bool getCurrentBmcStateWithFallback(const bool fallbackAvailability)
{
    try
    {
        return getCurrentBmcState();
    }
    catch (...)
    {
        // Nothing provided the BMC interface, therefore return whatever was
        // configured as the default.
        return fallbackAvailability;
    }
}

/**
 * @brief Returns the Version info from primary software object
 *
 * Get the Version info from the active s/w object which is having high
 * "Priority" value(a smaller number is a higher priority) and "Purpose"
 * is "BMC" from the list of all s/w objects those are implementing
 * RedundancyPriority interface from the given softwareRoot path.
 *
 * @return On success returns the Version info from primary software object.
 *
 */
std::string getActiveSoftwareVersionInfo()
{
    auto busp = getSdBus();

    std::string revision{};
    ipmi::ObjectTree objectTree;
    try
    {
        objectTree =
            ipmi::getAllDbusObjects(*busp, softwareRoot, redundancyIntf);
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        Log::log<Log::level::ERR>("Failed to fetch redundancy object from dbus",
                                  Log::entry("INTERFACE=%s", redundancyIntf),
                                  Log::entry("ERRMSG=%s", e.what()));
    }

    auto objectFound = false;
    for (auto& softObject : objectTree)
    {
        auto service =
            ipmi::getService(*busp, redundancyIntf, softObject.first);
        auto objValueTree =
            ipmi::getManagedObjects(*busp, service, softwareRoot);

        auto minPriority = 0xFF;
        for (const auto& objIter : objValueTree)
        {
            try
            {
                auto& intfMap = objIter.second;
                auto& redundancyPriorityProps = intfMap.at(redundancyIntf);
                auto& versionProps = intfMap.at(versionIntf);
                auto& activationProps = intfMap.at(activationIntf);
                auto priority =
                    std::get<uint8_t>(redundancyPriorityProps.at("Priority"));
                auto purpose =
                    std::get<std::string>(versionProps.at("Purpose"));
                auto activation =
                    std::get<std::string>(activationProps.at("Activation"));
                auto version =
                    std::get<std::string>(versionProps.at("Version"));
                if ((Version::convertVersionPurposeFromString(purpose) ==
                     Version::VersionPurpose::BMC) &&
                    (Activation::convertActivationsFromString(activation) ==
                     Activation::Activations::Active))
                {
                    if (priority < minPriority)
                    {
                        minPriority = priority;
                        objectFound = true;
                        revision = std::move(version);
                    }
                }
            }
            catch (const std::exception& e)
            {
                Log::log<Log::level::ERR>(e.what());
            }
        }
    }

    if (!objectFound)
    {
        Log::log<Log::level::ERR>("Could not find an BMC software object");
    }

    return revision;
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
            Log::log<Log::level::INFO>(
                "Get BMC version",
                Log::entry("VERSION=%s", versionString.c_str()));
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
            Log::log<Log::level::INFO>(
                "Get BMC version",
                Log::entry("VERSION=%s", versionString.c_str()));
            return rev;
        }
    }

    return std::nullopt;
}

RspType<uint8_t,  // Device ID
        uint8_t,  // Device Revision
        uint8_t,  // Firmware Revision Major
        uint8_t,  // Firmware Revision minor
        uint8_t,  // IPMI version
        uint8_t,  // Additional device support
        uint24_t, // MFG ID
        uint16_t, // Product ID
        uint32_t  // AUX info
        >
    ipmiAppGetDeviceId()
{
    static struct
    {
        uint8_t id;
        uint8_t revision;
        uint8_t fw[2];
        uint8_t ipmiVer;
        uint8_t addnDevSupport;
        uint24_t manufId;
        uint16_t prodId;
        uint32_t aux;
    } devId;
    static bool dev_id_initialized = false;
    static bool defaultActivationSetting = true;
    const char* filename = "/usr/share/ipmi-providers/dev_id.json";
    constexpr auto ipmiDevIdStateShift = 7;
    constexpr auto ipmiDevIdFw1Mask = ~(1 << ipmiDevIdStateShift);

    if (!dev_id_initialized)
    {
        std::optional<MetaRevision> rev;
        try
        {
            auto version = getActiveSoftwareVersionInfo();
            rev = convertIntelVersion(version);
        }
        catch (const std::exception& e)
        {
            Log::log<Log::level::ERR>("Failed to get active version info",
                                      Log::entry("ERROR=%s", e.what()));
        }

        if (rev.has_value())
        {
            // bit7 identifies if the device is available
            // 0=normal operation
            // 1=device firmware, SDR update,
            // or self-initialization in progress.
            // The availability may change in run time, so mask here
            // and initialize later.
            MetaRevision revision = rev.value();
            devId.fw[0] = revision.major & ipmiDevIdFw1Mask;

            revision.minor = (revision.minor > 99 ? 99 : revision.minor);
            devId.fw[1] = revision.minor % 10 + (revision.minor / 10) * 16;
            try
            {
                uint32_t hash = std::stoul(revision.metaHash, 0, 16);
                hash = ((hash & 0xff000000) >> 24) |
                       ((hash & 0x00FF0000) >> 8) | ((hash & 0x0000FF00) << 8) |
                       ((hash & 0xFF) << 24);
                devId.aux = (revision.buildNo & 0xFF) + (hash & 0xFFFFFF00);
            }
            catch (const std::exception& e)
            {
                Log::log<Log::level::ERR>("Failed to convert git hash",
                                          Log::entry("ERROR=%s", e.what()));
            }
        }

        // IPMI Spec version 2.0
        devId.ipmiVer = 2;

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
                dev_id_initialized = true;

                try
                {
                    auto busp = getSdBus();
                    const ipmi::DbusObjectInfo& object = ipmi::getDbusObject(
                        *busp, "xyz.openbmc_project.Inventory.Item.Board",
                        "/xyz/openbmc_project/inventory/system/board/",
                        "Baseboard");
                    const ipmi::Value& propValue = ipmi::getDbusProperty(
                        *busp, object.second, object.first,
                        "xyz.openbmc_project.Inventory.Item.Board",
                        "ProductId");
                    devId.prodId =
                        static_cast<uint8_t>(std::get<uint64_t>(propValue));
                }
                catch (std::exception& e)
                {
                    // For any exception send out platform id as 0,
                    // and make sure to re-query the device id.
                    dev_id_initialized = false;
                    devId.prodId = 0;
                }

                // Set the availablitity of the BMC.
                defaultActivationSetting = data.value("availability", true);
            }
            else
            {
                Log::log<Log::level::ERR>("Device ID JSON parser failure");
                return ipmi::responseUnspecifiedError();
            }
        }
        else
        {
            Log::log<Log::level::ERR>("Device ID file not found");
            return ipmi::responseUnspecifiedError();
        }
    }

    // Set availability to the actual current BMC state
    devId.fw[0] &= ipmiDevIdFw1Mask;
    if (!getCurrentBmcStateWithFallback(defaultActivationSetting))
    {
        devId.fw[0] |= (1 << ipmiDevIdStateShift);
    }

    return ipmi::responseSuccess(
        devId.id, devId.revision, devId.fw[0], devId.fw[1], devId.ipmiVer,
        devId.addnDevSupport, devId.manufId, devId.prodId, devId.aux);
}

static void registerAPPFunctions(void)
{
    Log::log<Log::level::INFO>("Registering App commands");
    // <Get Device ID>
    registerHandler(prioOemBase, netFnApp, app::cmdGetDeviceId, Privilege::User,
                    ipmiAppGetDeviceId);
}

} // namespace ipmi
