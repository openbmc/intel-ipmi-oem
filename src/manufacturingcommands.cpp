/*
// Copyright (c) 2018 Intel Corporation
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

#include <boost/process/child.hpp>
#include <ipmid/api.hpp>
#include <manufacturingcommands.hpp>
#include <oemcommands.hpp>

namespace ipmi
{

Manufacturing mtm;

static auto revertTimeOut =
    std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::seconds(60)); // 1 minute timeout

static constexpr const char* idButtonPath =
    "/xyz/openbmc_project/Chassis/Buttons/ID0";
static constexpr const char* idButtonInterface =
    "xyz.openbmc_project.Chassis.Buttons.ID";
static constexpr const char* idButtonMemberPressed = "Pressed";

static constexpr const char* callbackMgrService =
    "xyz.openbmc_project.CallbackManager";
static constexpr const char* callbackMgrIntf =
    "xyz.openbmc_project.CallbackManager";
static constexpr const char* callbackMgrObjPath =
    "/xyz/openbmc_project/CallbackManager";
static constexpr const char* retriggerLedUpdate = "RetriggerLEDUpdate";

const static constexpr char* systemDService = "org.freedesktop.systemd1";
const static constexpr char* systemDObjPath = "/org/freedesktop/systemd1";
const static constexpr char* systemDMgrIntf =
    "org.freedesktop.systemd1.Manager";
const static constexpr char* pidControlService = "phosphor-pid-control.service";

// TODO: Temporary place to test the working code. Will be moved to
// gpio daemon
constexpr const char* passthroughPath = "/usr/bin/set-passthrough.sh";
void disablePassthrough(bool value)
{
    boost::process::child c(passthroughPath, value ? "0" : "1");
    c.wait();
}

ipmi_ret_t ledStoreAndSet(SmSignalSet signal, std::string setState)
{
    LedProperty* ledProp = mtm.findLedProperty(signal);
    if (ledProp == nullptr)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    std::string ledName = ledProp->getName();
    std::string ledService = ledServicePrefix + ledName;
    std::string ledPath = ledPathPrefix + ledName;
    ipmi::Value presentState;

    if (false == ledProp->getLock())
    {
        if (mtm.getProperty(ledService.c_str(), ledPath.c_str(), ledIntf,
                            "State", &presentState) != 0)
        {
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        ledProp->setPrevState(std::get<std::string>(presentState));
        ledProp->setLock(true);
        if (signal == SmSignalSet::smPowerFaultLed ||
            signal == SmSignalSet::smSystemReadyLed)
        {
            mtm.revertLedCallback = true;
        }
    }
    if (mtm.setProperty(ledService.c_str(), ledPath.c_str(), ledIntf, "State",
                        ledStateStr + setState) != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t ledRevert(SmSignalSet signal)
{
    LedProperty* ledProp = mtm.findLedProperty(signal);
    if (ledProp == nullptr)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (true == ledProp->getLock())
    {
        ledProp->setLock(false);
        if (signal == SmSignalSet::smPowerFaultLed ||
            signal == SmSignalSet::smSystemReadyLed)
        {
            try
            {
                ipmi::method_no_args::callDbusMethod(
                    *getSdBus(), callbackMgrService, callbackMgrObjPath,
                    callbackMgrIntf, retriggerLedUpdate);
            }
            catch (sdbusplus::exception_t& e)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            mtm.revertLedCallback = false;
        }
        else
        {
            std::string ledName = ledProp->getName();
            std::string ledService = ledServicePrefix + ledName;
            std::string ledPath = ledPathPrefix + ledName;
            if (mtm.setProperty(ledService.c_str(), ledPath.c_str(), ledIntf,
                                "State", ledProp->getPrevState()) != 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
        }
    }
    return IPMI_CC_OK;
}

void Manufacturing::initData()
{
    gpioPaths[(uint8_t)SmSignalGet::smPowerButton] = "Power_Button";
    gpioPaths[(uint8_t)SmSignalGet::smResetButton] = "Reset_Button";
    gpioPaths[(uint8_t)SmSignalGet::smIdentifyButton] = "ID_Button";
    gpioPaths[(uint8_t)SmSignalGet::smFpLcpEnterButton] = "Lcp_Enter_Button";
    gpioPaths[(uint8_t)SmSignalGet::smFpLcpLeftButton] = "Lcp_Left_Button";
    gpioPaths[(uint8_t)SmSignalGet::smFpLcpRightButton] = "Lcp_Right_Button";
    gpioPaths[(uint8_t)SmSignalGet::smNmiButton] = "Nmi_Button";

    ledPropertyList.push_back(
        LedProperty(SmSignalSet::smPowerFaultLed, "status_amber"));
    ledPropertyList.push_back(
        LedProperty(SmSignalSet::smSystemReadyLed, "status_green"));
    ledPropertyList.push_back(
        LedProperty(SmSignalSet::smIdentifyLed, "identify"));
}

void Manufacturing::revertTimerHandler()
{
    for (const auto& signal : revertSmSignalGetVector)
    {
        mtm.setProperty(gpioService,
                        mtm.getGpioPathForSmSignal((uint8_t)signal), gpioIntf,
                        "Ignore", false);
    }
    revertSmSignalGetVector.clear();
    disablePassthrough(false);
    if (revertFanPWM)
    {
        revertFanPWM = false;
        disablePidControlService(false);
    }

    for (const auto& ledProperty : ledPropertyList)
    {
        const std::string& ledName = ledProperty.getName();
        ledRevert(ledProperty.getSignal());
    }
}

Manufacturing::Manufacturing() :
    revertTimer([&](void) { revertTimerHandler(); })
{
    initData();
}

int8_t Manufacturing::getProperty(const char* service, std::string path,
                                  const char* interface,
                                  std::string propertyName, ipmi::Value* reply)
{
    try
    {
        *reply = ipmi::getDbusProperty(*getSdBus(), service, path.c_str(),
                                       interface, propertyName);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ERROR: getProperty");
        return -1;
    }

    return 0;
}

int8_t Manufacturing::setProperty(const char* service, std::string path,
                                  const char* interface,
                                  std::string propertyName, ipmi::Value value)
{
    try
    {
        ipmi::setDbusProperty(*getSdBus(), service, path.c_str(), interface,
                              propertyName, value);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ERROR: setProperty");
        return -1;
    }

    return 0;
}

int8_t Manufacturing::disablePidControlService(const bool disable)
{
    try
    {
        auto dbus = getSdBus();
        auto method = dbus->new_method_call(systemDService, systemDObjPath,
                                            systemDMgrIntf,
                                            disable ? "StopUnit" : "StartUnit");
        method.append(pidControlService, "replace");
        auto reply = dbus->call(method);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ERROR: phosphor-pid-control service start or stop failed");
        return -1;
    }
    return 0;
}

std::tuple<uint8_t, ipmi_ret_t, uint8_t>
    Manufacturing::proccessSignal(SmSignalGet signal, SmActionGet action)
{
    int8_t ret = 0;
    uint8_t retCode = 0;
    uint8_t dataLen = 0;
    uint8_t value = 0;
    ipmi::Value reply;

    switch (action)
    {
        case SmActionGet::sample:
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "case SmActionGet::sample");
            break;
        case SmActionGet::ignore:
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "case SmActionGet::ignore");
            if (std::find(revertSmSignalGetVector.begin(),
                          revertSmSignalGetVector.end(),
                          signal) == revertSmSignalGetVector.end())
            {
                // Todo: Needs to be replaced with pass-through of particular
                // pin
                disablePassthrough(true);
                ret = mtm.setProperty(
                    gpioService, mtm.getGpioPathForSmSignal((uint8_t)signal),
                    gpioIntf, "Ignore", true);
                if (ret < 0)
                {
                    dataLen = 0;
                    retCode = IPMI_CC_INVALID_FIELD_REQUEST;
                }
                revertSmSignalGetVector.push_back(signal);
                revertTimer.start(revertTimeOut);
            }
        }
        break;
        case SmActionGet::revert:
        {
            phosphor::logging::log<phosphor::logging::level::INFO>(
                "case SmActionGet::revert");
            auto iter = std::find(revertSmSignalGetVector.begin(),
                                  revertSmSignalGetVector.end(), signal);
            if (iter != revertSmSignalGetVector.end())
            {
                ret = mtm.setProperty(
                    gpioService, mtm.getGpioPathForSmSignal((uint8_t)signal),
                    gpioIntf, "Ignore", false);
                if (ret < 0)
                {
                    dataLen = 0;
                    retCode = IPMI_CC_INVALID_FIELD_REQUEST;
                }
                revertSmSignalGetVector.erase(iter);
                // Todo: Needs to be replaced with pass-through of particular
                // pin
                disablePassthrough(true);
                if (revertSmSignalGetVector.size() == 0)
                {
                    revertTimer.stop();
                }
            }
        }
        break;

        default:
            dataLen = 0;
            retCode = IPMI_CC_INVALID_FIELD_REQUEST;
            break;
    }

    if (ret == 0) // No error happend, cmd will return with gpio value
    {
        ret = mtm.getProperty(gpioService,
                              mtm.getGpioPathForSmSignal((uint8_t)signal),
                              gpioIntf, "SampledValue", &reply);
        if (ret < 0)
        {
            dataLen = 0;
            retCode = IPMI_CC_INVALID_FIELD_REQUEST;
        }
        else
        {
            dataLen = 1;
            value = std::get<bool>(reply);
        }
    }

    return std::make_tuple(dataLen, retCode, value);
}

/*
 *
 * @param SigVal - 8-bit Unsigned Integer for Signal Values
 * @param SigVal1 - 8-bit Unsigned Ineger for Signal Values1
 * @param SigVal2 - 8-bit Unsigned Integer for Signal Values2
 * @param myrsp_size - 8-bit Unsigned Integer for size of Response Structure
 * @param ret - 8-bit integer for Return value
 * @Response is of 3 Byte
 * @Request is of 3 Byte
 *
 * */

ipmi::RspType<uint8_t, uint8_t, uint8_t>
    ipmi_app_mtm_get_signal(SmSignalGet Signal, uint8_t Instance,
                            SmActionGet Action)
{
    uint8_t SigVal;
    uint8_t SigVal1;
    uint8_t SigVal2;

    uint8_t myrsp_size = 3;
    ipmi_ret_t retCode = IPMI_CC_OK;

    int8_t ret = 0;
    ipmi::Value reply;

    if (mtm.getAccessLvl() >= MtmLvl::mtmAvailable)
    {
        switch (Signal)
        {
            case SmSignalGet::smFanPwmGet:
            {

                std::string fullPath = fanPwmPath + std::to_string(Instance);
                ret = mtm.getProperty(fanService, fullPath, fanIntf, "Value",
                                      &reply);
                if (ret < 0)
                {
                    return ipmi::responseInvalidFieldRequest();
                    break;
                }
                SigVal = std::get<double>(reply);
            }
            break;
            case SmSignalGet::smFanTachometerGet:
            {
                // Full path calculation pattern:
                // Instance 1 path is
                // /xyz/openbmc_project/sensors/fan_tach/Fan_1a Instance 2 path
                // is /xyz/openbmc_project/sensors/fan_tach/Fan_1b Instance 3
                // path is /xyz/openbmc_project/sensors/fan_tach/Fan_2a
                // and so on...
                std::string fullPath = fanTachPathPrefix;
                std::string fanAb = (Instance % 2) == 0 ? "b" : "a";
                if (0 == Instance)
                {
                    return ipmi::responseInvalidFieldRequest();
                    break;
                }
                else if (0 == Instance / 2)
                {
                    fullPath += std::string("1") + fanAb;
                }
                else
                {
                    fullPath += std::to_string(Instance / 2) + fanAb;
                }

                ret = mtm.getProperty(fanService, fullPath, fanIntf, "Value",
                                      &reply);
                if (ret < 0)
                {
                    return ipmi::responseInvalidFieldRequest();
                    break;
                }

                uint16_t value = std::get<double>(reply);
                SigVal = FAN_PRESENT | FAN_SENSOR_PRESENT;
                SigVal1 = value & 0x00FF;
                SigVal2 = (value >> 8) & 0xFF;
            }
            break;

            case SmSignalGet::smResetButton:      // gpio32
            case SmSignalGet::smPowerButton:      // gpio34
            case SmSignalGet::smFpLcpEnterButton: // gpio51
            case SmSignalGet::smFpLcpLeftButton:  // gpio52
            case SmSignalGet::smFpLcpRightButton: // gpio53
            case SmSignalGet::smNmiButton:        // gpio217
            case SmSignalGet::smIdentifyButton:   // gpio218
                std::tie(myrsp_size, retCode, SigVal) =
                    mtm.proccessSignal(Signal, Action);
                break;

            default:
                return ipmi::responseInvalidFieldRequest();
                break;
        }
    }
    else
    {
        return ipmi::responseReqDataLenInvalid();
    }
    return ipmi::responseSuccess(SigVal, SigVal1, SigVal2);
}

/*
 *
 * @param Signal - 8-bit Unsigned integer for enum Signal code
 * @param Instance - 8-bit Unsigned Ineger for Instance
 * @param Action - 8-bit Unsigned Integer for enum  Action code
 * @param Value - 8-bit Unsigned Integer for Value
 * @param ret - 8-bit integer for Return value
 * @param retCode - 8-bit Return code for errors and Success
 * @Response is Completion Code
 * @Request is of 4 Byte
 *
 * */

ipmi::RspType<> ipmi_app_mtm_set_signal(SmSignalSet Signal, uint8_t Instance,
                                        SmActionSet Action, uint8_t Value)
{

    uint8_t ret = 0;
    ipmi_ret_t retCode = IPMI_CC_OK;
    std::string ledName;
    ///////////////////  Signal to led configuration ////////////////
    //        {SM_SYSTEM_READY_LED, STAT_GRN_LED},    GPIOS4  gpio148
    //        {SM_POWER_FAULT_LED, STAT_AMB_LED},     GPIOS5  gpio149
    //        {SM_IDENTIFY_LED, IDENTIFY_LED},        GPIOS6  gpio150
    //        {SM_SPEAKER, SPEAKER},                  GPIOAB0 gpio216
    /////////////////////////////////////////////////////////////////
    if (mtm.getAccessLvl() >= MtmLvl::mtmAvailable)
    {
        switch (Signal)
        {
            case SmSignalSet::smPowerFaultLed:
            case SmSignalSet::smSystemReadyLed:
            case SmSignalSet::smIdentifyLed:
                switch (Action)
                {
                    case SmActionSet::forceDeasserted:
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            "case SmActionSet::forceDeasserted");
                        retCode = ledStoreAndSet(Signal, std::string("Off"));
                        if (retCode != IPMI_CC_OK)
                        {
                            break;
                        }
                        mtm.revertTimer.start(revertTimeOut);
                    }
                    break;
                    case SmActionSet::forceAsserted:
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            "case SmActionSet::forceAsserted");

                        retCode = ledStoreAndSet(Signal, std::string("On"));
                        if (retCode != IPMI_CC_OK)
                        {
                            break;
                        }
                        mtm.revertTimer.start(revertTimeOut);
                        if (SmSignalSet::smPowerFaultLed == Signal)
                        {
                            // Deassert "system ready"
                            retCode =
                                ledStoreAndSet(SmSignalSet::smSystemReadyLed,
                                               std::string("Off"));
                            if (retCode != IPMI_CC_OK)
                            {
                                break;
                            }
                        }
                        else if (SmSignalSet::smSystemReadyLed == Signal)
                        {
                            // Deassert "fault led"
                            retCode =
                                ledStoreAndSet(SmSignalSet::smPowerFaultLed,
                                               std::string("Off"));
                            if (retCode != IPMI_CC_OK)
                            {
                                break;
                            }
                        }
                    }
                    break;
                    case SmActionSet::revert:
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            "case SmActionSet::revert");
                        retCode = ledRevert(Signal);
                        if (retCode != IPMI_CC_OK)
                        {
                            break;
                        }
                    }
                    break;
                    default:
                    {
                        return ipmi::responseInvalidFieldRequest();
                    }
                    break;
                }
                break;
            case SmSignalSet::smFanPowerSpeed:
            {
                if (((Action == SmActionSet::forceAsserted) && (Value > 100)) ||
                    Instance == 0)
                {
                    return ipmi::responseInvalidFieldRequest();
                    break;
                }
                uint8_t pwmValue = 0;
                switch (Action)
                {
                    case SmActionSet::revert:
                    {
                        if (mtm.revertFanPWM)
                        {
                            ret = mtm.disablePidControlService(false);
                            if (ret < 0)
                            {
                                return ipmi::response(ipmi::ccUnspecifiedError);
                                break;
                            }
                            mtm.revertFanPWM = false;
                        }
                    }
                    break;
                    case SmActionSet::forceAsserted:
                    {
                        pwmValue = Value;
                    } // fall-through
                    case SmActionSet::forceDeasserted:
                    {
                        if (!mtm.revertFanPWM)
                        {
                            ret = mtm.disablePidControlService(true);
                            if (ret < 0)
                            {
                                return ipmi::response(ipmi::ccUnspecifiedError);
                                break;
                            }
                            mtm.revertFanPWM = true;
                        }
                        mtm.revertTimer.start(revertTimeOut);
                        std::string fanPwmInstancePath =
                            fanPwmPath + std::to_string(Instance);

                        ret = mtm.setProperty(
                            fanService, fanPwmInstancePath.c_str(), fanIntf,
                            "Value", static_cast<double>(pwmValue));
                        if (ret < 0)
                        {
                            return ipmi::response(ipmi::ccUnspecifiedError);
                        }
                    }
                    break;
                    default:
                    {
                        return ipmi::responseInvalidFieldRequest();
                    }
                    break;
                }
            }
            break;
            default:
            {
                return ipmi::responseInvalidFieldRequest();
            }
            break;
        }
    }
    else
    {
        return ipmi::responseIllegalCommand();
        retCode = IPMI_CC_ILLEGAL_COMMAND;
    }
    return ipmi::responseSuccess();
}

} // namespace ipmi

void register_mtm_commands() __attribute__((constructor));
void register_mtm_commands()
{
    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(IPMINetFnIntelOemGeneralCmds::GetSmSignal),
        ipmi::Privilege::User, ipmi::ipmi_app_mtm_get_signal);
    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(IPMINetFnIntelOemGeneralCmds::SetSmSignal),
        ipmi::Privilege::User, ipmi::ipmi_app_mtm_set_signal);

    return;
}
