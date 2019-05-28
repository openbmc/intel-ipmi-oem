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

#include <fstream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <regex>
#include <sdbusplus/timer.hpp>

namespace ipmi
{
const static constexpr char *idButtonPath =
    "/xyz/openbmc_project/chassis/buttons/id";
const static constexpr char *idButtonInterface =
    "xyz.openbmc_project.Chassis.Buttons";
const static constexpr char *idButtonProp = "ButtonPressed";

const static constexpr char *ledService =
    "xyz.openbmc_project.LED.GroupManager";
const static constexpr char *ledIDOnObj =
    "/xyz/openbmc_project/led/groups/enclosure_identify";
const static constexpr char *ledIDBlinkObj =
    "/xyz/openbmc_project/led/groups/enclosure_identify_blink";
const static constexpr char *ledInterface = "xyz.openbmc_project.Led.Group";
const static constexpr char *ledProp = "Asserted";

constexpr size_t defaultIdentifyTimeOut = 15;

std::unique_ptr<phosphor::Timer> identifyTimer
    __attribute__((init_priority(101)));
std::unique_ptr<sdbusplus::bus::match_t> matchPtr
    __attribute__((init_priority(101)));

static void registerChassisFunctions() __attribute__((constructor));

static ipmi::ServiceCache LEDService(ledInterface, ledIDBlinkObj);

void enclosureIdentifyLed(const char *objName, bool flag)
{
    auto bus = getSdBus();

    try
    {
        std::string service = LEDService.getService(*bus);
        setDbusProperty(*bus, service, objName, ledInterface, ledProp, flag);
    }
    catch (const std::exception &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "enclosureIdentifyLed: can't set property",
            phosphor::logging::entry("ERR=%s", e.what()));
    }
}

bool getIDState(const char *objName, bool &state)
{
    auto bus = getSdBus();

    try
    {
        std::string service = LEDService.getService(*bus);
        ipmi::Value enabled =
            getDbusProperty(*bus, service, objName, ledInterface, ledProp);
        state = std::get<bool>(enabled);
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Fail to get property",
            phosphor::logging::entry("PATH=%s", objName),
            phosphor::logging::entry("ERROR=%s", e.what()));
        return false;
    }
    return true;
}

void enclosureIdentifyLedBlinkOff()
{
    enclosureIdentifyLed(ledIDBlinkObj, false);
}

void idButtonPropChanged(sdbusplus::message::message &msg)
{
    bool asserted = false;
    bool buttonPressed = false;
    std::string service = {};

    using DbusVariant =
        sdbusplus::message::variant<std::string, bool, uint8_t, uint16_t,
                                    int16_t, uint32_t, int32_t, uint64_t,
                                    int64_t, double>;

    std::map<std::string, DbusVariant> props;
    std::vector<std::string> inval;
    std::string iface;
    msg.read(iface, props, inval);

    for (const auto &t : props)
    {
        auto key = t.first;
        auto value = t.second;

        if (key == idButtonProp)
        {
            buttonPressed = std::get<bool>(value);
        }
        break;
    }

    if (buttonPressed)
    {
        if (identifyTimer->isRunning())
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "ID timer is running");
        }

        // make sure timer is stopped
        identifyTimer->stop();

        if (!getIDState(ledIDBlinkObj, asserted))
        {
            return;
        }

        if (asserted)
        {
            // LED is blinking, turn off the LED
            enclosureIdentifyLed(ledIDBlinkObj, false);
            enclosureIdentifyLed(ledIDOnObj, false);
        }
        else
        {
            // toggle the IED on/off
            if (!getIDState(ledIDOnObj, asserted))
            {
                return;
            }
            enclosureIdentifyLed(ledIDOnObj, !asserted);
        }
    }
}

void createIdentifyTimer()
{
    if (!identifyTimer)
    {
        identifyTimer =
            std::make_unique<phosphor::Timer>(enclosureIdentifyLedBlinkOff);
    }
}

ipmi::RspType<> ipmiChassisIdentify(std::optional<uint8_t> interval,
                                    std::optional<uint8_t> force)
{
    uint8_t identifyInterval = interval.value_or(defaultIdentifyTimeOut);
    bool forceIdentify = force.value_or(0) & 0x01;
    bool flag = false;

    enclosureIdentifyLed(ledIDOnObj, false);
    identifyTimer->stop();

    if (identifyInterval || forceIdentify)
    {
        enclosureIdentifyLed(ledIDBlinkObj, true);
        if (forceIdentify)
        {
            return ipmi::responseSuccess();
        }
        // start the timer
        auto time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds(identifyInterval));
        identifyTimer->start(time);
    }
    else
    {
        enclosureIdentifyLed(ledIDBlinkObj, false);
    }
    return ipmi::responseSuccess();
}

static void registerChassisFunctions(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering Chassis commands");

    createIdentifyTimer();

    if (matchPtr == nullptr)
    {
        using namespace sdbusplus::bus::match::rules;
        auto bus = getSdBus();

        matchPtr = std::make_unique<sdbusplus::bus::match_t>(
            *bus,
            sdbusplus::bus::match::rules::propertiesChanged(idButtonPath,
                                                            idButtonInterface),
            std::bind(idButtonPropChanged, std::placeholders::_1));
    }

    // <Chassis Identify>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdChassisIdentify,
                          ipmi::Privilege::Operator, ipmiChassisIdentify);
}

} // namespace ipmi
