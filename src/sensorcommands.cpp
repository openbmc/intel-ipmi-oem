/*
// Copyright (c) 2017 2018 Intel Corporation
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

#include "ipmi_to_redfish_hooks.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/container/flat_map.hpp>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>

namespace ipmi
{
void registerSensorFunctions() __attribute__((constructor));

namespace meHealth
{
constexpr const char* busname = "xyz.openbmc_project.NodeManagerProxy";
constexpr const char* path = "/xyz/openbmc_project/status/me";
constexpr const char* interface = "xyz.openbmc_project.SetHealth";
constexpr const char* method = "SetHealth";
constexpr const char* critical = "critical";
constexpr const char* warning = "warning";
constexpr const char* ok = "ok";
} // namespace meHealth

static void setMeStatus(uint8_t eventData2, uint8_t eventData3, bool disable)
{
    constexpr const std::array<uint8_t, 10> critical = {
        0x1, 0x2, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xD, 0xE};
    constexpr const std::array<uint8_t, 5> warning = {0x3, 0xA, 0x13, 0x19,
                                                      0x1A};

    std::string state;
    if (std::find(critical.begin(), critical.end(), eventData2) !=
        critical.end())
    {
        state = meHealth::critical;
    }
    // special case 0x3 as we only care about a few states
    else if (eventData2 == 0x3)
    {
        if (eventData3 <= 0x2)
        {
            state = meHealth::warning;
        }
        else
        {
            return;
        }
    }
    else if (std::find(warning.begin(), warning.end(), eventData2) !=
             warning.end())
    {
        state = meHealth::warning;
    }
    else
    {
        return;
    }
    if (disable)
    {
        state = meHealth::ok;
    }

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto setHealth =
        dbus->new_method_call(meHealth::busname, meHealth::path,
                              meHealth::interface, meHealth::method);
    setHealth.append(std::to_string(static_cast<size_t>(eventData2)), state);
    try
    {
        dbus->call(setHealth);
    }
    catch (const sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set ME Health");
    }
}

ipmi::RspType<> ipmiSenPlatformEvent(ipmi::Context::ptr ctx,
                                     ipmi::message::Payload& p)
{
    constexpr const uint8_t meId = 0x2C;
    constexpr const uint8_t meSensorNum = 0x17;
    constexpr const uint8_t disabled = 0x80;

    uint8_t sysgeneratorID = 0;
    uint8_t evmRev = 0;
    uint8_t sensorType = 0;
    uint8_t sensorNum = 0;
    uint8_t eventType = 0;
    uint8_t eventData1 = 0;
    std::optional<uint8_t> eventData2 = 0;
    std::optional<uint8_t> eventData3 = 0;
    uint16_t generatorID = 0;
    ipmi::ChannelInfo chInfo;

    if (ipmi::getChannelInfo(ctx->channel, chInfo) != ipmi::ccSuccess)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get Channel Info",
            phosphor::logging::entry("CHANNEL=%d", ctx->channel));
        return ipmi::responseUnspecifiedError();
    }

    if (static_cast<ipmi::EChannelMediumType>(chInfo.mediumType) ==
        ipmi::EChannelMediumType::systemInterface)
    {
        p.unpack(sysgeneratorID, evmRev, sensorType, sensorNum, eventType,
                 eventData1, eventData2, eventData3);
        constexpr const uint8_t isSoftwareID = 0x01;
        if (!(sysgeneratorID & isSoftwareID))
        {
            return ipmi::responseInvalidFieldRequest();
        }
        // Refer to IPMI Spec Table 32: SEL Event Records
        generatorID = (ctx->channel << 12) // Channel
                      | (0x0 << 10)        // Reserved
                      | (0x0 << 8)         // 0x0 for sys-soft ID
                      | sysgeneratorID;
    }
    else
    {
        p.unpack(evmRev, sensorType, sensorNum, eventType, eventData1,
                 eventData2, eventData3);
        // Refer to IPMI Spec Table 32: SEL Event Records
        generatorID = (ctx->channel << 12)      // Channel
                      | (0x0 << 10)             // Reserved
                      | ((ctx->lun & 0x3) << 8) // Lun
                      | (ctx->rqSA << 1);
    }

    if (!p.fullyUnpacked())
    {
        return ipmi::responseReqDataLenInvalid();
    }

    // Check for valid evmRev and Sensor Type(per Table 42 of spec)
    if (evmRev != 0x04)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    if ((sensorType > 0x2C) && (sensorType < 0xC0))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    // Send this request to the Redfish hooks to log it as a Redfish message
    // instead.  There is no need to add it to the SEL, so just return success.
    intel_oem::ipmi::sel::checkRedfishHooks(
        generatorID, evmRev, sensorType, sensorNum, eventType, eventData1,
        eventData2.value_or(0xFF), eventData3.value_or(0xFF));

    if (static_cast<uint8_t>(generatorID) == meId && sensorNum == meSensorNum &&
        eventData2 && eventData3)
    {
        setMeStatus(*eventData2, *eventData3, (eventType & disabled));
    }

    return ipmi::responseSuccess();
}

void registerSensorFunctions()
{
    // <Platform Event>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnSensor,
                          ipmi::sensor_event::cmdPlatformEvent,
                          ipmi::Privilege::Operator, ipmiSenPlatformEvent);
}
} // namespace ipmi
