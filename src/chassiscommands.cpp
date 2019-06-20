/*
// Copyright (c) 2017-2019 Intel Corporation
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

#include <commandutils.hpp>
#include <iostream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <stdexcept>
#include <string_view>
#include <xyz/openbmc_project/Control/Power/RestorePolicy/server.hpp>

using namespace phosphor::logging;

namespace ipmi::chassis
{
void registerChassisFunctions() __attribute__((constructor));

static constexpr const char* buttonIntf = "xyz.openbmc_project.Chassis.Buttons";

static constexpr const char* powerButtonPath =
    "/xyz/openbmc_project/chassis/buttons/power";
static constexpr const char* resetButtonPath =
    "/xyz/openbmc_project/chassis/buttons/reset";
static constexpr const char* interruptButtonPath =
    "/xyz/openbmc_project/chassis/buttons/nmi";

namespace power_policy
{
/* helper function for Get Chassis Status Command
 */
std::optional<uint2_t> getPowerRestorePolicy()
{
    constexpr const char* powerRestorePath =
        "/xyz/openbmc_project/control/host0/power_restore_policy";
    constexpr const char* powerRestoreIntf =
        "xyz.openbmc_project.Control.Power.RestorePolicy";
    uint2_t restorePolicy = 0;
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();

    try
    {
        auto service =
            ipmi::getService(*busp, powerRestoreIntf, powerRestorePath);

        ipmi::Value result =
            ipmi::getDbusProperty(*busp, service, powerRestorePath,
                                  powerRestoreIntf, "PowerRestorePolicy");
        auto powerRestore = sdbusplus::xyz::openbmc_project::Control::Power::
            server::RestorePolicy::convertPolicyFromString(
                std::get<std::string>(result));

        using namespace sdbusplus::xyz::openbmc_project::Control::Power::server;
        switch (powerRestore)
        {
            case RestorePolicy::Policy::AlwaysOff:
                restorePolicy = 0x00;
                break;
            case RestorePolicy::Policy::Restore:
                restorePolicy = 0x01;
                break;
            case RestorePolicy::Policy::AlwaysOn:
                restorePolicy = 0x02;
                break;
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to fetch PowerRestorePolicy property",
                        entry("ERROR=%s", e.what()),
                        entry("PATH=%s", powerRestorePath),
                        entry("INTERFACE=%s", powerRestoreIntf));
        return std::nullopt;
    }
    return std::make_optional(restorePolicy);
}

/*
 * getPowerStatus
 * helper function for Get Chassis Status Command
 * return - optional value for pgood (no value on error)
 */
std::optional<bool> getPowerStatus()
{
    bool powerGood = false;
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        constexpr const char* chassisStatePath =
            "/xyz/openbmc_project/state/chassis0";
        constexpr const char* chassisStateIntf =
            "xyz.openbmc_project.State.Chassis";
        auto service =
            ipmi::getService(*busp, chassisStateIntf, chassisStatePath);

        ipmi::Value variant =
            ipmi::getDbusProperty(*busp, service, chassisStatePath,
                                  chassisStateIntf, "CurrentPowerState");
        std::string powerState = std::get<std::string>(variant);
        if (powerState == "xyz.openbmc_project.State.Chassis.PowerState.On")
        {
            powerGood = true;
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to fetch power state property",
                        entry("ERROR=%s", e.what()));
        return std::nullopt;
    }
    return std::make_optional(powerGood);
}

/*
 * getACFailStatus
 * helper function for Get Chassis Status Command
 * return - bool value for ACFail (false on error)
 */
bool getACFailStatus()
{
    constexpr const char* powerControlObj =
        "/xyz/openbmc_project/Chassis/Control/Power0";
    constexpr const char* powerControlIntf =
        "xyz.openbmc_project.Chassis.Control.Power";
    bool acFail = false;
    std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*bus, powerControlIntf, powerControlObj);

        ipmi::Value variant = ipmi::getDbusProperty(
            *bus, service, powerControlObj, powerControlIntf, "PFail");
        acFail = std::get<bool>(variant);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to fetch PFail property",
                        entry("ERROR=%s", e.what()),
                        entry("PATH=%s", powerControlObj),
                        entry("INTERFACE=%s", powerControlIntf));
    }
    return acFail;
}
} // namespace power_policy

static std::optional<bool> getButtonEnabled(const std::string& buttonPath)
{
    bool buttonDisabled = false;
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        auto service = ipmi::getService(*getSdBus(), buttonIntf, buttonPath);
        ipmi::Value disabled = ipmi::getDbusProperty(
            *busp, service, buttonPath, buttonIntf, "ButtonMasked");
        buttonDisabled = std::get<bool>(disabled);
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("Fail to get button disabled property",
                        entry("PATH=%s", buttonPath.c_str()),
                        entry("ERROR=%s", e.what()));
        return std::nullopt;
    }
    return std::make_optional(buttonDisabled);
}

static bool setButtonEnabled(const std::string& buttonPath, const bool disabled)
{
    try
    {
        auto service = ipmi::getService(*getSdBus(), buttonIntf, buttonPath);
        ipmi::setDbusProperty(*getSdBus(), service, buttonPath, buttonIntf,
                              "ButtonMasked", disabled);
    }
    catch (std::exception& e)
    {
        log<level::ERR>("Failed to set button disabled",
                        entry("EXCEPTION=%s, REQUEST=%x", e.what(), disabled));
        return -1;
    }

    return 0;
}

//----------------------------------------------------------------------
// Get Chassis Status commands
//----------------------------------------------------------------------
ipmi::RspType<bool,    // Power is on
              bool,    // Power overload
              bool,    // Interlock
              bool,    // power fault
              bool,    // power control fault
              uint2_t, // power restore policy
              bool,    // reserved

              bool, // AC failed
              bool, // last power down caused by a Power overload
              bool, // last power down caused by a power interlock
              bool, // last power down caused by power fault
              bool, // last ‘Power is on’ state was entered via IPMI command
              uint3_t, // reserved

              bool,    // Chassis intrusion active
              bool,    // Front Panel Lockout active
              bool,    // Drive Fault
              bool,    // Cooling/fan fault detected
              uint2_t, // Chassis Identify State
              bool,    // Chassis Identify command and state info supported
              bool,    // reserved

              bool, // Power off button disabled
              bool, // Reset button disabled
              bool, // Diagnostic Interrupt button disabled
              bool, // Standby (sleep) button disabled
              bool, // Power off button disable allowed
              bool, // Reset button disable allowed
              bool, // Diagnostic Interrupt button disable allowed
              bool  // Standby (sleep) button disable allowed
              >
    ipmiGetChassisStatus()
{
    std::optional<uint2_t> restorePolicy =
        power_policy::getPowerRestorePolicy();
    std::optional<bool> powerGood = power_policy::getPowerStatus();
    if (!restorePolicy || !powerGood)
    {
        return ipmi::responseUnspecifiedError();
    }

    //  Front Panel Button Capabilities and disable/enable status(Optional)
    std::optional<bool> powerButtonReading = getButtonEnabled(powerButtonPath);
    // allow disable if the interface is present
    bool powerButtonDisableAllow = static_cast<bool>(powerButtonReading);
    // default return the button is enabled (not disabled)
    bool powerButtonDisabled = false;
    if (powerButtonDisableAllow)
    {
        // return the real value of the button status, if present
        powerButtonDisabled = *powerButtonReading;
    }

    std::optional<bool> resetButtonReading = getButtonEnabled(resetButtonPath);
    // allow disable if the interface is present
    bool resetButtonDisableAllow = static_cast<bool>(resetButtonReading);
    // default return the button is enabled (not disabled)
    bool resetButtonDisabled = false;
    if (resetButtonDisableAllow)
    {
        // return the real value of the button status, if present
        resetButtonDisabled = *resetButtonReading;
    }

    std::optional<bool> interruptButtonReading =
        getButtonEnabled(interruptButtonPath);
    // allow disable if the interface is present
    bool interruptButtonDisableAllow =
        static_cast<bool>(interruptButtonReading);
    // default return the button is enabled (not disabled)
    bool interruptButtonDisabled = false;
    if (interruptButtonDisableAllow)
    {
        // return the real value of the button status, if present
        interruptButtonDisabled = *interruptButtonReading;
    }

    bool powerDownAcFailed = power_policy::getACFailStatus();

    // This response has a lot of hard-coded, unsupported fields
    // They are set to false or 0
    constexpr bool powerOverload = false;
    constexpr bool chassisInterlock = false;
    constexpr bool powerFault = false;
    constexpr bool powerControlFault = false;
    constexpr bool powerDownOverload = false;
    constexpr bool powerDownInterlock = false;
    constexpr bool powerDownPowerFault = false;
    constexpr bool powerStatusIPMI = false;
    constexpr bool chassisIntrusionActive = false;
    constexpr bool frontPanelLockoutActive = false;
    constexpr bool driveFault = false;
    constexpr bool coolingFanFault = false;
    // chassisIdentifySupport set because this command is implemented
    constexpr bool chassisIdentifySupport = true;
    uint2_t chassisIdentifyState = 0;
    constexpr bool sleepButtonDisabled = false;
    constexpr bool sleepButtonDisableAllow = false;

    return ipmi::responseSuccess(
        *powerGood, powerOverload, chassisInterlock, powerFault,
        powerControlFault, *restorePolicy,
        false, // reserved

        powerDownAcFailed, powerDownOverload, powerDownInterlock,
        powerDownPowerFault, powerStatusIPMI,
        uint3_t(0), // reserved

        chassisIntrusionActive, frontPanelLockoutActive, driveFault,
        coolingFanFault, chassisIdentifyState, chassisIdentifySupport,
        false, // reserved

        powerButtonDisabled, resetButtonDisabled, interruptButtonDisabled,
        sleepButtonDisabled, powerButtonDisableAllow, resetButtonDisableAllow,
        interruptButtonDisableAllow, sleepButtonDisableAllow);
}

static uint4_t getRestartCause(const std::string& cause)
{
    uint4_t restartCauseValue = 0;
    if (cause == "xyz.openbmc_project.State.Host.RestartCause.Unknown")
    {
        restartCauseValue = 0x0;
    }
    else if (cause == "xyz.openbmc_project.State.Host.RestartCause.IpmiCommand")
    {
        restartCauseValue = 0x1;
    }
    else if (cause == "xyz.openbmc_project.State.Host.RestartCause.ResetButton")
    {
        restartCauseValue = 0x2;
    }
    else if (cause == "xyz.openbmc_project.State.Host.RestartCause.PowerButton")
    {
        restartCauseValue = 0x3;
    }
    else if (cause ==
             "xyz.openbmc_project.State.Host.RestartCause.WatchdogTimer")
    {
        restartCauseValue = 0x4;
    }
    else if (cause == "xyz.openbmc_project.State.Host.RestartCause.OEM")
    {
        restartCauseValue = 0x5;
    }
    else if (cause ==
             "xyz.openbmc_project.State.Host.RestartCause.PowerPolicyAlwaysOn")
    {
        restartCauseValue = 0x6;
    }
    else if (cause == "xyz.openbmc_project.State.Host.RestartCause."
                      "PowerPolicyPreviousState")
    {
        restartCauseValue = 0x7;
    }
    else if (cause == "xyz.openbmc_project.State.Host.RestartCause.PEFReset")
    {
        restartCauseValue = 0x8;
    }
    else if (cause ==
             "xyz.openbmc_project.State.Host.RestartCause.PEFPowerCycle")
    {
        restartCauseValue = 0x9;
    }
    else if (cause == "xyz.openbmc_project.State.Host.RestartCause.SoftReset")
    {
        restartCauseValue = 0xa;
    }
    else if (cause == "xyz.openbmc_project.State.Host.RestartCause.RTCWakeup")
    {
        restartCauseValue = 0xb;
    }
    return restartCauseValue;
}

ipmi::RspType<uint4_t, // Restart Cause
              uint4_t, // reserved
              uint8_t  // channel number (not supported)
              >
    ipmiGetSystemRestartCause()
{
    constexpr const char* restartCausePath =
        "/xyz/openbmc_project/control/host0/restart_cause";
    constexpr const char* restartCauseIntf =
        "xyz.openbmc_project.Common.RestartCause";
    std::string restartCauseStr;
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();

    try
    {
        auto service =
            ipmi::getService(*busp, restartCauseIntf, restartCausePath);

        ipmi::Value result = ipmi::getDbusProperty(
            *busp, service, restartCausePath, restartCauseIntf, "RestartCause");
        restartCauseStr = std::get<std::string>(result);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to fetch RestartCause property",
                        entry("ERROR=%s", e.what()),
                        entry("PATH=%s", restartCausePath),
                        entry("INTERFACE=%s", restartCauseIntf));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(getRestartCause(restartCauseStr), 0, 0);
}

ipmi::RspType<> ipmiSetFrontPanelButtonEnables(bool disablePowerButton,
                                               bool disableResetButton,
                                               bool disableInterruptButton,
                                               bool disableSleepButton,
                                               uint4_t reserved)
{
    bool error = false;

    error |= setButtonEnabled(powerButtonPath, disablePowerButton);
    error |= setButtonEnabled(resetButtonPath, disableResetButton);
    error |= setButtonEnabled(interruptButtonPath, disableInterruptButton);

    if (error)
    {
        return ipmi::responseUnspecifiedError();
    }
    return ipmi::responseSuccess();
}

void registerChassisFunctions()
{
    // <Get Chassis Status>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdGetChassisStatus,
                          ipmi::Privilege::User, ipmiGetChassisStatus);
    // <Get System Restart Cause>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdGetSystemRestartCause,
                          ipmi::Privilege::User, ipmiGetSystemRestartCause);
    // <Set Front Panel Enables>
    ipmi::registerHandler(ipmi::prioOemBase, ipmi::netFnChassis,
                          ipmi::chassis::cmdSetFrontPanelButtonEnables,
                          ipmi::Privilege::User,
                          ipmiSetFrontPanelButtonEnables);
}
} // namespace ipmi::chassis
