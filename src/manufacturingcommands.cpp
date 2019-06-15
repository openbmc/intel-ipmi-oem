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

#include <boost/container/flat_map.hpp>
#include <ipmid/api.hpp>
#include <manufacturingcommands.hpp>
#include <oemcommands.hpp>

namespace ipmi
{

Manufacturing mtm;

static auto revertTimeOut =
    std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::seconds(60)); // 1 minute timeout

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

static inline Cc resetMtmTimer(boost::asio::yield_context yield)
{
    auto sdbusp = getSdBus();
    boost::system::error_code ec;
    sdbusp->yield_method_call<>(yield, ec, specialModeService,
                                specialModeObjPath, specialModeIntf,
                                "ResetTimer");
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to reset the manufacturing mode timer");
        return ccUnspecifiedError;
    }
    return ccSuccess;
}

int getGpioPathForSmSignal(const SmSignalGet signal, std::string& path)
{
    switch (signal)
    {
        case SmSignalGet::smPowerButton:
            path = "/xyz/openbmc_project/chassis/buttons/power";
            break;
        case SmSignalGet::smResetButton:
            path = "/xyz/openbmc_project/chassis/buttons/reset";
            break;
        case SmSignalGet::smNMIButton:
            path = "/xyz/openbmc_project/chassis/buttons/nmi";
            break;
        case SmSignalGet::smIdentifyButton:
            path = "/xyz/openbmc_project/chassis/buttons/id";
            break;
        default:
            return -1;
            break;
    }
    return 0;
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
    if (mtm.setProperty(ledService, ledPath, ledIntf, "State",
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
            if (mtm.setProperty(ledService, ledPath, ledIntf, "State",
                                ledProp->getPrevState()) != 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
        }
    }
    return IPMI_CC_OK;
}

void Manufacturing::initData()
{
    ledPropertyList.push_back(
        LedProperty(SmSignalSet::smPowerFaultLed, "status_amber"));
    ledPropertyList.push_back(
        LedProperty(SmSignalSet::smSystemReadyLed, "status_green"));
    ledPropertyList.push_back(
        LedProperty(SmSignalSet::smIdentifyLed, "identify"));
}

void Manufacturing::revertTimerHandler()
{
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

int8_t Manufacturing::getProperty(const std::string& service,
                                  const std::string& path,
                                  const std::string& interface,
                                  const std::string& propertyName,
                                  ipmi::Value* reply)
{
    try
    {
        *reply = ipmi::getDbusProperty(*getSdBus(), service, path, interface,
                                       propertyName);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ERROR: getProperty");
        return -1;
    }

    return 0;
}

int8_t Manufacturing::setProperty(const std::string& service,
                                  const std::string& path,
                                  const std::string& interface,
                                  const std::string& propertyName,
                                  ipmi::Value value)
{
    try
    {
        ipmi::setDbusProperty(*getSdBus(), service, path, interface,
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

ipmi::RspType<uint8_t,                // Signal value
              std::optional<uint16_t> // Fan tach value
              >
    appMTMGetSignal(boost::asio::yield_context yield, uint8_t signalTypeByte,
                    uint8_t instance, uint8_t actionByte)
{
    if (mtm.getAccessLvl() < MtmLvl::mtmAvailable)
    {
        return ipmi::responseInvalidCommand();
    }

    SmSignalGet signalType = static_cast<SmSignalGet>(signalTypeByte);
    SmActionGet action = static_cast<SmActionGet>(actionByte);

    switch (signalType)
    {
        case SmSignalGet::smFanPwmGet:
        {
            ipmi::Value reply;
            std::string fullPath = fanPwmPath + std::to_string(instance + 1);
            if (mtm.getProperty(fanService, fullPath, fanIntf, "Value",
                                &reply) < 0)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            double* doubleVal = std::get_if<double>(&reply);
            if (doubleVal == nullptr)
            {
                return ipmi::responseUnspecifiedError();
            }
            uint8_t sensorVal = std::round(*doubleVal);
            return ipmi::responseSuccess(sensorVal, std::nullopt);
        }
        break;
        case SmSignalGet::smFanTachometerGet:
        {
            auto sdbusp = getSdBus();
            boost::system::error_code ec;
            using objFlatMap = boost::container::flat_map<
                std::string, boost::container::flat_map<
                                 std::string, std::vector<std::string>>>;

            auto flatMap = sdbusp->yield_method_call<objFlatMap>(
                yield, ec, "xyz.openbmc_project.ObjectMapper",
                "/xyz/openbmc_project/object_mapper",
                "xyz.openbmc_project.ObjectMapper", "GetSubTree",
                fanTachBasePath, 0, std::array<const char*, 1>{fanIntf});
            if (ec)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Failed to query fan tach sub tree objects");
                return ipmi::responseUnspecifiedError();
            }
            if (instance >= flatMap.size())
            {
                return ipmi::responseInvalidFieldRequest();
            }
            auto itr = flatMap.nth(instance);
            ipmi::Value reply;
            if (mtm.getProperty(fanService, itr->first, fanIntf, "Value",
                                &reply) < 0)
            {
                return ipmi::responseInvalidFieldRequest();
            }

            double* doubleVal = std::get_if<double>(&reply);
            if (doubleVal == nullptr)
            {
                return ipmi::responseUnspecifiedError();
            }
            uint8_t sensorVal = FAN_PRESENT | FAN_SENSOR_PRESENT;
            std::optional<uint16_t> fanTach = std::round(*doubleVal);

            return ipmi::responseSuccess(sensorVal, fanTach);
        }
        break;
        case SmSignalGet::smIdentifyButton:
        {
            if (action == SmActionGet::revert || action == SmActionGet::ignore)
            {
                // ButtonMasked property is not supported for ID button as it is
                // unnecessary. Hence if requested for revert / ignore, override
                // it to sample action to make tools happy.
                action = SmActionGet::sample;
            }
            // fall-through
        }
        case SmSignalGet::smResetButton:
        case SmSignalGet::smPowerButton:
        case SmSignalGet::smNMIButton:
        {
            std::string path;
            if (getGpioPathForSmSignal(signalType, path) < 0)
            {
                return ipmi::responseInvalidFieldRequest();
            }

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
                    if (mtm.setProperty(buttonService, path, buttonIntf,
                                        "ButtonMasked", true) < 0)
                    {
                        return ipmi::responseUnspecifiedError();
                    }
                }
                break;
                case SmActionGet::revert:
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "case SmActionGet::revert");
                    if (mtm.setProperty(buttonService, path, buttonIntf,
                                        "ButtonMasked", false) < 0)
                    {
                        return ipmi::responseUnspecifiedError();
                    }
                }
                break;

                default:
                    return ipmi::responseInvalidFieldRequest();
                    break;
            }

            ipmi::Value reply;
            if (mtm.getProperty(buttonService, path, buttonIntf,
                                "ButtonPressed", &reply) < 0)
            {
                return ipmi::responseUnspecifiedError();
            }
            bool* valPtr = std::get_if<bool>(&reply);
            if (valPtr == nullptr)
            {
                return ipmi::responseUnspecifiedError();
            }
            uint8_t sensorVal = *valPtr;
            return ipmi::responseSuccess(sensorVal, std::nullopt);
        }
        break;
        default:
            return ipmi::responseInvalidFieldRequest();
            break;
    }
}

ipmi_ret_t ipmi_app_mtm_set_signal(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    uint8_t ret = 0;
    ipmi_ret_t retCode = IPMI_CC_OK;
    SetSmSignalReq* pReq = static_cast<SetSmSignalReq*>(request);
    std::string ledName;
    ///////////////////  Signal to led configuration ////////////////
    //        {SM_SYSTEM_READY_LED, STAT_GRN_LED},    GPIOS4  gpio148
    //        {SM_POWER_FAULT_LED, STAT_AMB_LED},     GPIOS5  gpio149
    //        {SM_IDENTIFY_LED, IDENTIFY_LED},        GPIOS6  gpio150
    //        {SM_SPEAKER, SPEAKER},                  GPIOAB0 gpio216
    /////////////////////////////////////////////////////////////////
    if ((*data_len == sizeof(*pReq)) &&
        (mtm.getAccessLvl() >= MtmLvl::mtmAvailable))
    {
        switch (pReq->Signal)
        {
            case SmSignalSet::smPowerFaultLed:
            case SmSignalSet::smSystemReadyLed:
            case SmSignalSet::smIdentifyLed:
                switch (pReq->Action)
                {
                    case SmActionSet::forceDeasserted:
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            "case SmActionSet::forceDeasserted");

                        retCode =
                            ledStoreAndSet(pReq->Signal, std::string("Off"));
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

                        retCode =
                            ledStoreAndSet(pReq->Signal, std::string("On"));
                        if (retCode != IPMI_CC_OK)
                        {
                            break;
                        }
                        mtm.revertTimer.start(revertTimeOut);
                        if (SmSignalSet::smPowerFaultLed == pReq->Signal)
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
                        else if (SmSignalSet::smSystemReadyLed == pReq->Signal)
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
                        retCode = ledRevert(pReq->Signal);
                        if (retCode != IPMI_CC_OK)
                        {
                            break;
                        }
                    }
                    break;
                    default:
                    {
                        retCode = IPMI_CC_INVALID_FIELD_REQUEST;
                    }
                    break;
                }
                break;
            case SmSignalSet::smFanPowerSpeed:
            {
                if (((pReq->Action == SmActionSet::forceAsserted) &&
                     (*data_len != sizeof(*pReq)) && (pReq->Value > 100)) ||
                    pReq->Instance == 0)
                {
                    retCode = IPMI_CC_INVALID_FIELD_REQUEST;
                    break;
                }
                uint8_t pwmValue = 0;
                switch (pReq->Action)
                {
                    case SmActionSet::revert:
                    {
                        if (mtm.revertFanPWM)
                        {
                            ret = mtm.disablePidControlService(false);
                            if (ret < 0)
                            {
                                retCode = IPMI_CC_UNSPECIFIED_ERROR;
                                break;
                            }
                            mtm.revertFanPWM = false;
                        }
                    }
                    break;
                    case SmActionSet::forceAsserted:
                    {
                        pwmValue = pReq->Value;
                    } // fall-through
                    case SmActionSet::forceDeasserted:
                    {
                        if (!mtm.revertFanPWM)
                        {
                            ret = mtm.disablePidControlService(true);
                            if (ret < 0)
                            {
                                retCode = IPMI_CC_UNSPECIFIED_ERROR;
                                break;
                            }
                            mtm.revertFanPWM = true;
                        }
                        mtm.revertTimer.start(revertTimeOut);
                        std::string fanPwmInstancePath =
                            fanPwmPath + std::to_string(pReq->Instance);

                        ret = mtm.setProperty(fanService, fanPwmInstancePath,
                                              fanIntf, "Value",
                                              static_cast<double>(pwmValue));
                        if (ret < 0)
                        {
                            retCode = IPMI_CC_UNSPECIFIED_ERROR;
                        }
                    }
                    break;
                    default:
                    {
                        retCode = IPMI_CC_INVALID_FIELD_REQUEST;
                    }
                    break;
                }
            }
            break;
            default:
            {
                retCode = IPMI_CC_INVALID_FIELD_REQUEST;
            }
            break;
        }
    }
    else
    {
        retCode = IPMI_CC_INVALID;
    }

    *data_len = 0; // Only CC is return for SetSmSignal cmd
    return retCode;
}

ipmi::RspType<> mtmKeepAlive(boost::asio::yield_context yield, uint8_t reserved,
                             const std::array<char, 5>& intentionalSignature)
{
    // Allow MTM keep alive command only in manfacturing mode.
    if (mtm.getAccessLvl() != MtmLvl::mtmAvailable)
    {
        return ipmi::responseInvalidCommand();
    }
    constexpr std::array<char, 5> signatureOk = {'I', 'N', 'T', 'E', 'L'};
    if (intentionalSignature != signatureOk || reserved != 0)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    return ipmi::response(resetMtmTimer(yield));
}

} // namespace ipmi

void register_mtm_commands() __attribute__((constructor));
void register_mtm_commands()
{
    // <Get SM Signal>
    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::netFnOemOne,
        static_cast<ipmi::Cmd>(IPMINetFnIntelOemGeneralCmds::GetSmSignal),
        ipmi::Privilege::User, ipmi::appMTMGetSignal);

    ipmi_register_callback(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetFnIntelOemGeneralCmds::SetSmSignal),
        NULL, ipmi::ipmi_app_mtm_set_signal, PRIVILEGE_USER);

    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::netFnOemOne,
        static_cast<ipmi::Cmd>(IPMINetfnIntelOEMGeneralCmd::cmdMtmKeepAlive),
        ipmi::Privilege::Admin, ipmi::mtmKeepAlive);

    return;
}
