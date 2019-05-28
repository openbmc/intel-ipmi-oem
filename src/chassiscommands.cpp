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
    "/xyz/openbmc_project/Chassis/Buttons/ID0";
const static constexpr char *idButtonInterface =
    "xyz.openbmc_project.Chassis.Buttons.ID";
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

void enclosureIdentifyLed(const char *objName, bool flag)
{
    auto bus = getSdBus();
    try
    {
        std::string service = getService(*bus, ledInterface, objName);
        setDbusProperty(*bus, service, objName, ledInterface, ledProp, flag);
    }
    catch (const std::exception &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "enclosureIdentifyLed: can't set property",
            phosphor::logging::entry("ERR=%s", e.what()));
    }
}

void enclosureIdentifyLedBlinkOff()
{
    try
    {
        enclosureIdentifyLed(ledIDBlinkObj, false);
    }
    catch (const sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure
               &e)
    {
        phosphor::logging::report<
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure>();
    }
}

void enclosureIdentifyLedOnOff()
{
    try
    {
        enclosureIdentifyLed(ledIDOnObj, false);
    }
    catch (const sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure
               &e)
    {
        phosphor::logging::report<
            sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure>();
    }
}

void idButtonPressed(sdbusplus::message::message &msg)
{
    auto bus = getSdBus();
    bool asserted = false;
    std::string service = {};

    if (identifyTimer->isRunning())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ID timer is running");

        // stop the timer
        identifyTimer->stop();
    }

    try
    {
        service = getService(*bus, ledInterface, ledIDBlinkObj);
        ipmi::Value enabled = getDbusProperty(*bus, service, ledIDBlinkObj,
                                              ledInterface, ledProp);
        asserted = std::get<bool>(enabled);
    }
    catch (sdbusplus::exception::SdBusError &e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Fail to get property",
            phosphor::logging::entry("PATH=%s", ledIDBlinkObj),
            phosphor::logging::entry("ERROR=%s", e.what()));
        return;
    }

    if (asserted)
    {
        // LED is blinking, turn off the LED
        enclosureIdentifyLedBlinkOff();
        enclosureIdentifyLedOnOff();
    }
    else
    {
        // toggle the IED on/off
        try
        {
            service = getService(*bus, ledInterface, ledIDOnObj);
            ipmi::Value enabled = getDbusProperty(*bus, service, ledIDOnObj,
                                                  ledInterface, ledProp);
            asserted = std::get<bool>(enabled);

            setDbusProperty(*bus, service, ledIDOnObj, ledInterface, ledProp,
                            !asserted);
        }
        catch (sdbusplus::exception::SdBusError &e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Fail to set property",
                phosphor::logging::entry("PATH=%s", ledIDOnObj),
                phosphor::logging::entry("ERROR=%s", e.what()));
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

    if (matchPtr == nullptr)
    {
        using namespace sdbusplus::bus::match::rules;
        sdbusplus::bus::bus bus{ipmid_get_sd_bus_connection()};
        matchPtr = std::make_unique<sdbusplus::bus::match_t>(
            bus,
            sdbusplus::bus::match::rules::type::signal() +
                sdbusplus::bus::match::rules::member("Pressed") +
                sdbusplus::bus::match::rules::path(idButtonPath) +
                sdbusplus::bus::match::rules::interface(idButtonInterface),
            std::bind(idButtonPressed, std::placeholders::_1));
    }
}

ipmi::RspType<> ipmiChassisIdentify(std::optional<uint8_t> interval,
                                    std::optional<uint8_t> force)
{
    uint8_t identifyInterval = interval.value_or(defaultIdentifyTimeOut);
    bool forceIdentify = force.value_or(0) & 0x01;
    bool flag = false;

    enclosureIdentifyLedOnOff();

    if (identifyInterval || forceIdentify)
    {
        // stop the timer if already started;
        // for force identify we should not turn off LED
        identifyTimer->stop();
        try
        {
            enclosureIdentifyLed(ledIDBlinkObj, true);
        }
        catch (const sdbusplus::xyz::openbmc_project::Common::Error::
                   InternalFailure &e)
        {
            phosphor::logging::report<sdbusplus::xyz::openbmc_project::Common::
                                          Error::InternalFailure>();
            return ipmi::responseResponseError();
        }

        if (forceIdentify)
        {
            return ipmi::responseSuccess();
        }
        // start the timer
        auto time = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::seconds(identifyInterval));
        identifyTimer->start(time);
    }
    else if (!identifyInterval)
    {
        identifyTimer->stop();
        enclosureIdentifyLedBlinkOff();
    }
    return ipmi::responseSuccess();
}

static void registerChassisFunctions(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering Chassis commands");

    createIdentifyTimer();

    // <Chassis Identify>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdChassisIdentify,
                          ipmi::Privilege::Operator, ipmiChassisIdentify);
    return;
}

} // namespace ipmi
