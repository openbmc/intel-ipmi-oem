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

#include "xyz/openbmc_project/Common/error.hpp"
#include "xyz/openbmc_project/Led/Physical/server.hpp"

#include <ipmid/api.h>

#include <array>
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>
#include <commandutils.hpp>
#include <iostream>
#include <oemcommands.hpp>
#include <phosphor-ipmi-host/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>
#include <string>
#include <user_channel/channel_layer.hpp>
#include <user_channel/user_layer.hpp>
#include <vector>

namespace ipmi
{
static void registerOEMFunctions() __attribute__((constructor));
sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection()); // from ipmid/api.h
static constexpr size_t maxFRUStringLength = 0x3F;

static constexpr auto ethernetIntf =
    "xyz.openbmc_project.Network.EthernetInterface";
static constexpr auto IPIntf = "xyz.openbmc_project.Network.IP";
static constexpr auto service = "xyz.openbmc_project.Network";

static constexpr auto networkRoot = "/xyz/openbmc_project/network";

// return code: 0 successful
int8_t getChassisSerialNumber(sdbusplus::bus::bus& bus, std::string& serial)
{
    std::string objpath = "/xyz/openbmc_project/FruDevice";
    std::string intf = "xyz.openbmc_project.FruDeviceManager";
    std::string service = getService(bus, intf, objpath);
    ObjectValueTree valueTree = getManagedObjects(bus, service, "/");
    if (valueTree.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No object implements interface",
            phosphor::logging::entry("INTF=%s", intf.c_str()));
        return -1;
    }

    for (const auto& item : valueTree)
    {
        auto interface = item.second.find("xyz.openbmc_project.FruDevice");
        if (interface == item.second.end())
        {
            continue;
        }

        auto property = interface->second.find("CHASSIS_SERIAL_NUMBER");
        if (property == interface->second.end())
        {
            continue;
        }

        try
        {
            Value variant = property->second;
            std::string& result =
                sdbusplus::message::variant_ns::get<std::string>(variant);
            if (result.size() > maxFRUStringLength)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "FRU serial number exceed maximum length");
                return -1;
            }
            serial = result;
            return 0;
        }
        catch (sdbusplus::message::variant_ns::bad_variant_access& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return -1;
        }
    }
    return -1;
}

ipmi_ret_t ipmiOEMWildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                           ipmi_request_t request, ipmi_response_t response,
                           ipmi_data_len_t dataLen, ipmi_context_t context)
{
    printCommand(+netfn, +cmd);
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *dataLen = 0;
    return rc;
}

// Returns the Chassis Identifier (serial #)
ipmi_ret_t ipmiOEMGetChassisIdentifier(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t dataLen,
                                       ipmi_context_t context)
{
    std::string serial;
    if (*dataLen != 0) // invalid request if there are extra parameters
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    if (getChassisSerialNumber(dbus, serial) == 0)
    {
        *dataLen = serial.size(); // length will never exceed response length
                                  // as it is checked in getChassisSerialNumber
        char* resp = static_cast<char*>(response);
        serial.copy(resp, *dataLen);
        return IPMI_CC_OK;
    }
    *dataLen = 0;
    return IPMI_CC_RESPONSE_ERROR;
}

ipmi_ret_t ipmiOEMSetSystemGUID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t dataLen, ipmi_context_t context)
{
    static constexpr size_t safeBufferLength = 50;
    char buf[safeBufferLength] = {0};
    GUIDData* Data = reinterpret_cast<GUIDData*>(request);

    if (*dataLen != sizeof(GUIDData)) // 16bytes
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 0;

    snprintf(
        buf, safeBufferLength,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        Data->timeLow4, Data->timeLow3, Data->timeLow2, Data->timeLow1,
        Data->timeMid2, Data->timeMid1, Data->timeHigh2, Data->timeHigh1,
        Data->clock2, Data->clock1, Data->node6, Data->node5, Data->node4,
        Data->node3, Data->node2, Data->node1);
    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    std::string guid = buf;

    std::string objpath = "/xyz/openbmc_project/control/host0/systemGUID";
    std::string intf = "xyz.openbmc_project.Common.UUID";
    std::string service = getService(dbus, intf, objpath);
    setDbusProperty(dbus, service, objpath, intf, "UUID", guid);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMSetBIOSID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t dataLen, ipmi_context_t context)
{
    DeviceInfo* data = reinterpret_cast<DeviceInfo*>(request);

    if ((*dataLen < 2) || (*dataLen != (1 + data->biosIDLength)))
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    std::string idString((char*)data->biosId, data->biosIDLength);

    std::string service = getService(dbus, biosIntf, biosObjPath);
    setDbusProperty(dbus, service, biosObjPath, biosIntf, biosProp, idString);
    uint8_t* bytesWritten = static_cast<uint8_t*>(response);
    *bytesWritten =
        data->biosIDLength; // how many bytes are written into storage
    *dataLen = 1;
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMGetDeviceInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t dataLen, ipmi_context_t context)
{
    GetOemDeviceInfoReq* req = reinterpret_cast<GetOemDeviceInfoReq*>(request);
    GetOemDeviceInfoRes* res = reinterpret_cast<GetOemDeviceInfoRes*>(response);

    if (*dataLen == 0)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    size_t reqDataLen = *dataLen;
    *dataLen = 0;
    if (req->entityType > static_cast<uint8_t>(OEMDevEntityType::sdrVer))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // handle OEM command items
    switch (OEMDevEntityType(req->entityType))
    {
        case OEMDevEntityType::biosId:
        {
            if (sizeof(GetOemDeviceInfoReq) != reqDataLen)
            {
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            std::string service = getService(dbus, biosIntf, biosObjPath);
            try
            {
                Value variant = getDbusProperty(dbus, service, biosObjPath,
                                                biosIntf, biosProp);
                std::string& idString =
                    sdbusplus::message::variant_ns::get<std::string>(variant);
                if (req->offset >= idString.size())
                {
                    return IPMI_CC_PARM_OUT_OF_RANGE;
                }
                size_t length = 0;
                if (req->countToRead > (idString.size() - req->offset))
                {
                    length = idString.size() - req->offset;
                }
                else
                {
                    length = req->countToRead;
                }
                std::copy(idString.begin() + req->offset, idString.end(),
                          res->data);
                res->resDatalen = length;
                *dataLen = res->resDatalen + 1;
            }
            catch (sdbusplus::message::variant_ns::bad_variant_access& e)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
        }
        break;

        case OEMDevEntityType::devVer:
        case OEMDevEntityType::sdrVer:
            // TODO:
            return IPMI_CC_ILLEGAL_COMMAND;
        default:
            return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMGetAICFRU(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t dataLen, ipmi_context_t context)
{
    if (*dataLen != 0)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 1;
    uint8_t* res = reinterpret_cast<uint8_t*>(response);
    // temporary fix. We don't support AIC FRU now. Just tell BIOS that no
    // AIC is available so that BIOS will not timeout repeatly which leads to
    // slow booting.
    *res = 0; // Byte1=Count of SlotPosition/FruID records.
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMGetPowerRestoreDelay(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t dataLen,
                                       ipmi_context_t context)
{
    GetPowerRestoreDelayRes* resp =
        reinterpret_cast<GetPowerRestoreDelayRes*>(response);

    if (*dataLen != 0)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::string service =
        getService(dbus, powerRestoreDelayIntf, powerRestoreDelayObjPath);
    Value variant =
        getDbusProperty(dbus, service, powerRestoreDelayObjPath,
                        powerRestoreDelayIntf, powerRestoreDelayProp);

    uint16_t delay = sdbusplus::message::variant_ns::get<uint16_t>(variant);
    resp->byteLSB = delay;
    resp->byteMSB = delay >> 8;

    *dataLen = sizeof(GetPowerRestoreDelayRes);

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMSetPowerRestoreDelay(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t dataLen,
                                       ipmi_context_t context)
{
    SetPowerRestoreDelayReq* data =
        reinterpret_cast<SetPowerRestoreDelayReq*>(request);
    uint16_t delay = 0;

    if (*dataLen != sizeof(SetPowerRestoreDelayReq))
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    delay = data->byteMSB;
    delay = (delay << 8) | data->byteLSB;
    std::string service =
        getService(dbus, powerRestoreDelayIntf, powerRestoreDelayObjPath);
    setDbusProperty(dbus, service, powerRestoreDelayObjPath,
                    powerRestoreDelayIntf, powerRestoreDelayProp, delay);
    *dataLen = 0;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMGetProcessorErrConfig(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t dataLen,
                                        ipmi_context_t context)
{
    GetProcessorErrConfigRes* resp =
        reinterpret_cast<GetProcessorErrConfigRes*>(response);

    if (*dataLen != 0)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::string service =
        getService(dbus, processorErrConfigIntf, processorErrConfigObjPath);
    Value variant = getDbusProperty(dbus, service, processorErrConfigObjPath,
                                    processorErrConfigIntf, "ResetCfg");
    resp->resetCfg = sdbusplus::message::variant_ns::get<uint8_t>(variant);

    std::vector<uint8_t> caterrStatus;
    sdbusplus::message::variant<std::vector<uint8_t>> message;

    auto method =
        dbus.new_method_call(service.c_str(), processorErrConfigObjPath,
                             "org.freedesktop.DBus.Properties", "Get");

    method.append(processorErrConfigIntf, "CATERRStatus");
    auto reply = dbus.call(method);

    try
    {
        reply.read(message);
        caterrStatus =
            sdbusplus::message::variant_ns::get<std::vector<uint8_t>>(message);
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetProcessorErrConfig: error on dbus",
            phosphor::logging::entry("PRORPERTY=CATERRStatus"),
            phosphor::logging::entry("PATH=%s", processorErrConfigObjPath),
            phosphor::logging::entry("INTERFACE=%s", processorErrConfigIntf));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    size_t len =
        maxCPUNum <= caterrStatus.size() ? maxCPUNum : caterrStatus.size();
    caterrStatus.resize(len);
    std::copy(caterrStatus.begin(), caterrStatus.end(), resp->caterrStatus);
    *dataLen = sizeof(GetProcessorErrConfigRes);

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMSetProcessorErrConfig(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t dataLen,
                                        ipmi_context_t context)
{
    SetProcessorErrConfigReq* req =
        reinterpret_cast<SetProcessorErrConfigReq*>(request);

    if (*dataLen != sizeof(SetProcessorErrConfigReq))
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    std::string service =
        getService(dbus, processorErrConfigIntf, processorErrConfigObjPath);
    setDbusProperty(dbus, service, processorErrConfigObjPath,
                    processorErrConfigIntf, "ResetCfg", req->resetCfg);

    setDbusProperty(dbus, service, processorErrConfigObjPath,
                    processorErrConfigIntf, "ResetErrorOccurrenceCounts",
                    req->resetErrorOccurrenceCounts);
    *dataLen = 0;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMGetShutdownPolicy(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen,
                                    ipmi_context_t context)
{
    GetOEMShutdownPolicyRes* resp =
        reinterpret_cast<GetOEMShutdownPolicyRes*>(response);

    if (*dataLen != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "oem_get_shutdown_policy: invalid input len!");
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 0;

    try
    {
        std::string service =
            getService(dbus, oemShutdownPolicyIntf, oemShutdownPolicyObjPath);
        Value variant = getDbusProperty(dbus, service, oemShutdownPolicyObjPath,
                                        oemShutdownPolicyIntf,
                                        oemShutdownPolicyObjPathProp);
        resp->policy = sdbusplus::message::variant_ns::get<uint8_t>(variant);
        // TODO needs to check if it is multi-node products,
        // policy is only supported on node 3/4
        resp->policySupport = shutdownPolicySupported;
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.description());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    *dataLen = sizeof(GetOEMShutdownPolicyRes);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMSetShutdownPolicy(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen,
                                    ipmi_context_t context)
{
    uint8_t* req = reinterpret_cast<uint8_t*>(request);

    // TODO needs to check if it is multi-node products,
    // policy is only supported on node 3/4
    if (*dataLen != 1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "oem_set_shutdown_policy: invalid input len!");
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 0;
    if ((*req != noShutdownOnOCOT) && (*req != shutdownOnOCOT))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "oem_set_shutdown_policy: invalid input!");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    try
    {
        std::string service =
            getService(dbus, oemShutdownPolicyIntf, oemShutdownPolicyObjPath);
        setDbusProperty(dbus, service, oemShutdownPolicyObjPath,
                        oemShutdownPolicyIntf, oemShutdownPolicyObjPathProp,
                        *req);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.description());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    return IPMI_CC_OK;
}
static bool isDHCPEnabled(uint8_t Channel)
{
    auto ethdevice = getChannelName(Channel);

    if (ethdevice.empty())
    {
        return 0;
    }
    auto ethIP = ethdevice + "/ipv4";

    auto ethernetObj = getDbusObject(dbus, IPIntf, networkRoot, ethIP);
    auto value =
        getDbusProperty(dbus, service, ethernetObj.first, IPIntf, "Origin");
    if (sdbusplus::message::variant_ns::get<std::string>(value) ==
        "xyz.openbmc_project.Network.IP.AddressOrigin.DHCP")
    {
        return true;
    }
    else
    {
        return false;
    }
}

static bool isDHCPIPv6Enabled(uint8_t Channel)
{
    auto ethdevice = getChannelName(Channel);

    if (ethdevice.empty())
    {
        return 0;
    }

    auto ethIP = ethdevice + "/ipv6";

    auto objectInfo = getDbusObject(dbus, IPIntf, networkRoot, ethIP);

    auto properties =
        getAllDbusProperties(dbus, objectInfo.second, objectInfo.first, IPIntf);

    std::string origin =
        sdbusplus::message::variant_ns::get<std::string>(properties["Origin"]);
    if (sdbusplus::message::variant_ns::get<std::string>(
            properties["Origin"]) ==
        "xyz.openbmc_project.Network.IP.AddressOrigin.DHCP")
    {
        return true;
    }
    else
    {
        return false;
    }
}
ipmi_ret_t ipmiOEMSetUser2Activation(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                     ipmi_request_t request,
                                     ipmi_response_t response,
                                     ipmi_data_len_t dataLen,
                                     ipmi_context_t context)
{
    bool userState = false;

    // TODO:command should be allowed only in system where there is no host
    // interface.

    if (getInterfaceIndex() == interfaceKCS)
    {

        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetUser2Activation:KCS not supported");
        *dataLen = 0;
        return IPMI_CC_INVALID;
    }
    if (*dataLen != sizeof(sSetOemUser2ActivationReq))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetUser2Activation: invalid input len!");
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    // Check the user 2 is enabled or not
    ipmiUserCheckEnabled(ipmiDefaultUserId, userState);

    if (userState == true)
    {
        *dataLen = 0;
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetUser2Activation: user 2 already enabled .");
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    for (uint8_t channel = 0; channel < maxIpmiChannels; channel++)
    {

        ChannelInfo chInfo;
        getChannelInfo(channel, chInfo);
        if (chInfo.mediumType ==
            static_cast<uint8_t>(EChannelMediumType::lan8032))
        {
            if (isDHCPIPv6Enabled(channel) || isDHCPEnabled(channel))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetUser2Activation: DHCP enabled .");
                *dataLen = 0;
                return IPMI_CC_INVALID_FIELD_REQUEST;
            }
        }
    }

    *dataLen = 0;
    sSetOemUser2ActivationReq* req =
        reinterpret_cast<sSetOemUser2ActivationReq*>(request);

#if BYTE_ORDER == LITTLE_ENDIAN
    PrivAccess privAccess = {PRIVILEGE_ADMIN, true, true, true, 0};
#endif
#if BYTE_ORDER == BIG_ENDIAN
    PrivAccess privAccess = {0, true, true, true, PRIVILEGE_ADMIN};
#endif

    if (IPMI_CC_OK ==
        ipmiUserSetUserName(ipmiDefaultUserId,
                            reinterpret_cast<const char*>(req->userName)))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetUser2Activation: username  passed .");
        if (IPMI_CC_OK == ipmiUserSetUserPassword(
                              ipmiDefaultUserId,
                              reinterpret_cast<const char*>(req->userPassword)))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetUser2Activation: password passed .");
            if (IPMI_CC_OK ==
                ipmiUserSetPrivilegeAccess(
                    ipmiDefaultUserId,
                    static_cast<uint8_t>(ipmi::EChannelID::chanLan1),
                    privAccess, true))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetUser2Activation: priv setting passed .");
                return IPMI_CC_OK;
            }
        }
        // we need to delete  the default user id which added in this command as
        // password / priv setting is failed.
        ipmiUserSetUserName(ipmiDefaultUserId, "");
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetUser2Activation: password / priv setting is failed.");
    }

    return IPMI_CC_UNSPECIFIED_ERROR;
}

namespace ledAction
{
using namespace sdbusplus::xyz::openbmc_project::Led::server;
std::map<Physical::Action, uint8_t> actionDbusToIpmi = {
    {Physical::Action::Off, 0x00},
    {Physical::Action::On, 0x10},
    {Physical::Action::Blink, 0x01}};

std::map<uint8_t, std::string> offsetObjPath = {
    {2, statusAmberObjPath}, {4, statusGreenObjPath}, {6, identifyLEDObjPath}};

} // namespace ledAction

int8_t getLEDState(sdbusplus::bus::bus& bus, const std::string& intf,
                   const std::string& objPath, uint8_t& state)
{
    try
    {
        std::string service = getService(bus, intf, objPath);
        Value stateValue =
            getDbusProperty(bus, service, objPath, intf, "State");
        std::string strState =
            sdbusplus::message::variant_ns::get<std::string>(stateValue);
        state = ledAction::actionDbusToIpmi.at(
            sdbusplus::xyz::openbmc_project::Led::server::Physical::
                convertActionFromString(strState));
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return -1;
    }
    return 0;
}

ipmi_ret_t ipmiOEMGetLEDStatus(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t dataLen, ipmi_context_t context)
{
    uint8_t* resp = reinterpret_cast<uint8_t*>(response);
    // LED Status
    //[1:0] = Reserved
    //[3:2] = Status(Amber)
    //[5:4] = Status(Green)
    //[7:6] = System Identify
    // Status definitions:
    // 00b = Off
    // 01b = Blink
    // 10b = On
    // 11b = invalid
    if (*dataLen != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "oem_get_led_status: invalid input len!");
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>("GET led status");
    *resp = 0;
    *dataLen = 0;
    for (auto it = ledAction::offsetObjPath.begin();
         it != ledAction::offsetObjPath.end(); ++it)
    {
        uint8_t state = 0;
        if (-1 == getLEDState(dbus, ledIntf, it->second, state))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "oem_get_led_status: fail to get ID LED status!");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        *resp |= state << it->first;
    }

    *dataLen = sizeof(*resp);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMCfgHostSerialPortSpeed(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                         ipmi_request_t request,
                                         ipmi_response_t response,
                                         ipmi_data_len_t dataLen,
                                         ipmi_context_t context)
{
    CfgHostSerialReq* req = reinterpret_cast<CfgHostSerialReq*>(request);
    uint8_t* resp = reinterpret_cast<uint8_t*>(response);

    if (*dataLen == 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "CfgHostSerial: invalid input len!",
            phosphor::logging::entry("LEN=%d", *dataLen));
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    switch (req->command)
    {
        case getHostSerialCfgCmd:
        {
            if (*dataLen != 1)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "CfgHostSerial: invalid input len!");
                *dataLen = 0;
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            *dataLen = 0;

            boost::process::ipstream is;
            std::vector<std::string> data;
            std::string line;
            boost::process::child c1(fwGetEnvCmd, "-n", fwHostSerailCfgEnvName,
                                     boost::process::std_out > is);

            while (c1.running() && std::getline(is, line) && !line.empty())
            {
                data.push_back(line);
            }

            c1.wait();
            if (c1.exit_code())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "CfgHostSerial:: error on execute",
                    phosphor::logging::entry("EXECUTE=%s", fwSetEnvCmd));
                // Using the default value
                *resp = 0;
            }
            else
            {
                if (data.size() != 1)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "CfgHostSerial:: error on read env");
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                try
                {
                    unsigned long tmp = std::stoul(data[0]);
                    if (tmp > std::numeric_limits<uint8_t>::max())
                    {
                        throw std::out_of_range("Out of range");
                    }
                    *resp = static_cast<uint8_t>(tmp);
                }
                catch (const std::invalid_argument& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "invalid config ",
                        phosphor::logging::entry("ERR=%s", e.what()));
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                catch (const std::out_of_range& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "out_of_range config ",
                        phosphor::logging::entry("ERR=%s", e.what()));
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
            }

            *dataLen = 1;
            break;
        }
        case setHostSerialCfgCmd:
        {
            if (*dataLen != sizeof(CfgHostSerialReq))
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "CfgHostSerial: invalid input len!");
                *dataLen = 0;
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            *dataLen = 0;

            if (req->parameter > HostSerialCfgParamMax)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "CfgHostSerial: invalid input!");
                return IPMI_CC_INVALID_FIELD_REQUEST;
            }

            boost::process::child c1(fwSetEnvCmd, fwHostSerailCfgEnvName,
                                     std::to_string(req->parameter));

            c1.wait();
            if (c1.exit_code())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "CfgHostSerial:: error on execute",
                    phosphor::logging::entry("EXECUTE=%s", fwGetEnvCmd));
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            break;
        }
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "CfgHostSerial: invalid input!");
            *dataLen = 0;
            return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    return IPMI_CC_OK;
}

static void registerOEMFunctions(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering OEM commands");
    ipmiPrintAndRegister(netfnIntcOEMGeneral, IPMI_CMD_WILDCARD, NULL,
                         ipmiOEMWildcard,
                         PRIVILEGE_USER); // wildcard default handler
    ipmiPrintAndRegister(netfunIntelAppOEM, IPMI_CMD_WILDCARD, NULL,
                         ipmiOEMWildcard,
                         PRIVILEGE_USER); // wildcard default handler
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMGeneralCmd::cmdGetChassisIdentifier),
        NULL, ipmiOEMGetChassisIdentifier,
        PRIVILEGE_USER); // get chassis identifier
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdSetSystemGUID),
        NULL, ipmiOEMSetSystemGUID,
        PRIVILEGE_ADMIN); // set system guid
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdSetBIOSID),
        NULL, ipmiOEMSetBIOSID, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(netfnIntcOEMGeneral,
                         static_cast<ipmi_cmd_t>(
                             IPMINetfnIntelOEMGeneralCmd::cmdGetOEMDeviceInfo),
                         NULL, ipmiOEMGetDeviceInfo, PRIVILEGE_USER);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMGeneralCmd::cmdGetAICSlotFRUIDSlotPosRecords),
        NULL, ipmiOEMGetAICFRU, PRIVILEGE_USER);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetPowerRestoreDelay),
        NULL, ipmiOEMSetPowerRestoreDelay, PRIVILEGE_OPERATOR);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMGeneralCmd::cmdGetPowerRestoreDelay),
        NULL, ipmiOEMGetPowerRestoreDelay, PRIVILEGE_USER);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetOEMUser2Activation),
        NULL, ipmiOEMSetUser2Activation, PRIVILEGE_CALLBACK);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMGeneralCmd::cmdGetProcessorErrConfig),
        NULL, ipmiOEMGetProcessorErrConfig, PRIVILEGE_USER);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetProcessorErrConfig),
        NULL, ipmiOEMSetProcessorErrConfig, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(netfnIntcOEMGeneral,
                         static_cast<ipmi_cmd_t>(
                             IPMINetfnIntelOEMGeneralCmd::cmdSetShutdownPolicy),
                         NULL, ipmiOEMSetShutdownPolicy, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(netfnIntcOEMGeneral,
                         static_cast<ipmi_cmd_t>(
                             IPMINetfnIntelOEMGeneralCmd::cmdGetShutdownPolicy),
                         NULL, ipmiOEMGetShutdownPolicy, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdGetLEDStatus),
        NULL, ipmiOEMGetLEDStatus, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(
        netfnIntcOEMPlatform,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMPlatformCmd::cmdCfgHostSerialPortSpeed),
        NULL, ipmiOEMCfgHostSerialPortSpeed, PRIVILEGE_ADMIN);
    return;
}

} // namespace ipmi
