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

#include <systemd/sd-journal.h>

#include <array>
#include <boost/container/flat_map.hpp>
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>
#include <com/intel/Control/OCOTShutdownPolicy/server.hpp>
#include <commandutils.hpp>
#include <iostream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <oemcommands.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>
#include <string>
#include <variant>
#include <vector>

namespace ipmi
{
static void registerOEMFunctions() __attribute__((constructor));
sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection()); // from ipmid/api.h
static constexpr size_t maxFRUStringLength = 0x3F;

static constexpr auto ethernetIntf =
    "xyz.openbmc_project.Network.EthernetInterface";
static constexpr auto networkIPIntf = "xyz.openbmc_project.Network.IP";
static constexpr auto networkService = "xyz.openbmc_project.Network";
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

static uint8_t bcdToDec(uint8_t val)
{
    return ((val / 16 * 10) + (val % 16));
}

// Allows an update utility or system BIOS to send the status of an embedded
// firmware update attempt to the BMC. After received, BMC will create a logging
// record.
ipmi::RspType<> ipmiOEMSendEmbeddedFwUpdStatus(uint8_t status, uint8_t target,
                                               uint8_t majorRevision,
                                               uint8_t minorRevision,
                                               uint32_t auxInfo)
{
    std::string firmware;
    int instance = (target & targetInstanceMask) >> targetInstanceShift;
    target = (target & selEvtTargetMask) >> selEvtTargetShift;

    /* make sure the status is 0, 1, or 2 as per the spec */
    if (status > 2)
    {
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }
    /* make sure the target is 0, 1, 2, or 4 as per the spec */
    if (target > 4 || target == 3)
    {
        return ipmi::response(ipmi::ccInvalidFieldRequest);
    }
    /*orignal OEM command is to record OEM SEL.
    But openbmc does not support OEM SEL, so we redirect it to redfish event
    logging. */
    std::string buildInfo;
    std::string action;
    switch (FWUpdateTarget(target))
    {
        case FWUpdateTarget::targetBMC:
            firmware = "BMC";
            buildInfo = "major: " + std::to_string(majorRevision) + " minor: " +
                        std::to_string(bcdToDec(minorRevision)) + // BCD encoded
                        " BuildID: " + std::to_string(auxInfo);
            buildInfo += std::to_string(auxInfo);
            break;
        case FWUpdateTarget::targetBIOS:
            firmware = "BIOS";
            buildInfo =
                "major: " +
                std::to_string(bcdToDec(majorRevision)) + // BCD encoded
                " minor: " +
                std::to_string(bcdToDec(minorRevision)) + // BCD encoded
                " ReleaseNumber: " +                      // ASCII encoded
                std::to_string(static_cast<uint8_t>(auxInfo >> 0) - '0') +
                std::to_string(static_cast<uint8_t>(auxInfo >> 8) - '0') +
                std::to_string(static_cast<uint8_t>(auxInfo >> 16) - '0') +
                std::to_string(static_cast<uint8_t>(auxInfo >> 24) - '0');
            break;
        case FWUpdateTarget::targetME:
            firmware = "ME";
            buildInfo =
                "major: " + std::to_string(majorRevision) + " minor1: " +
                std::to_string(bcdToDec(minorRevision)) + // BCD encoded
                " minor2: " +
                std::to_string(bcdToDec(static_cast<uint8_t>(auxInfo >> 0))) +
                " build1: " +
                std::to_string(bcdToDec(static_cast<uint8_t>(auxInfo >> 8))) +
                " build2: " +
                std::to_string(bcdToDec(static_cast<uint8_t>(auxInfo >> 16)));
            break;
        case FWUpdateTarget::targetOEMEWS:
            firmware = "EWS";
            buildInfo = "major: " + std::to_string(majorRevision) + " minor: " +
                        std::to_string(bcdToDec(minorRevision)) + // BCD encoded
                        " BuildID: " + std::to_string(auxInfo);
            break;
    }

    static const std::string openBMCMessageRegistryVersion("0.1");
    std::string redfishMsgID = "OpenBMC." + openBMCMessageRegistryVersion;

    switch (status)
    {
        case 0x0:
            action = "update started";
            redfishMsgID += ".FirmwareUpdateStarted";
            break;
        case 0x1:
            action = "update completed successfully";
            redfishMsgID += ".FirmwareUpdateCompleted";
            break;
        case 0x2:
            action = "update failure";
            redfishMsgID += ".FirmwareUpdateFailed";
            break;
        default:
            action = "unknown";
            break;
    }

    std::string firmwareInstanceStr =
        firmware + " instance: " + std::to_string(instance);
    std::string message("[firmware update] " + firmwareInstanceStr +
                        " status: <" + action + "> " + buildInfo);

    sd_journal_send("MESSAGE=%s", message.c_str(), "PRIORITY=%i", LOG_INFO,
                    "REDFISH_MESSAGE_ID=%s", redfishMsgID.c_str(),
                    "REDFISH_MESSAGE_ARGS=%s,%s", firmwareInstanceStr.c_str(),
                    buildInfo.c_str(), NULL);
    return ipmi::responseSuccess();
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

        if (sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::
                convertPolicyFromString(std::get<std::string>(variant)) ==
            sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::Policy::
                NoShutdownOnOCOT)
        {
            resp->policy = 0;
        }
        else if (sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::
                     convertPolicyFromString(std::get<std::string>(variant)) ==
                 sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::
                     Policy::ShutdownOnOCOT)
        {
            resp->policy = 1;
        }
        else
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "oem_set_shutdown_policy: invalid property!",
                phosphor::logging::entry(
                    "PROP=%s", std::get<std::string>(variant).c_str()));
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
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
    sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::Policy policy =
        sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::Policy::
            NoShutdownOnOCOT;

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

    if (*req == noShutdownOnOCOT)
    {
        policy = sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::
            Policy::NoShutdownOnOCOT;
    }
    else
    {
        policy = sdbusplus::com::intel::Control::server::OCOTShutdownPolicy::
            Policy::ShutdownOnOCOT;
    }

    try
    {
        std::string service =
            getService(dbus, oemShutdownPolicyIntf, oemShutdownPolicyObjPath);
        setDbusProperty(
            dbus, service, oemShutdownPolicyObjPath, oemShutdownPolicyIntf,
            oemShutdownPolicyObjPathProp,
            sdbusplus::com::intel::Control::server::convertForMessage(policy));
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.description());
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    return IPMI_CC_OK;
}

/** @brief implementation for check the DHCP or not in IPv4
 *  @param[in] Channel - Channel number
 *  @returns true or false.
 */
static bool isDHCPEnabled(uint8_t Channel)
{
    try
    {
        auto ethdevice = getChannelName(Channel);
        if (ethdevice.empty())
        {
            return false;
        }
        auto ethIP = ethdevice + "/ipv4";
        auto ethernetObj =
            getDbusObject(dbus, networkIPIntf, networkRoot, ethIP);
        auto value = getDbusProperty(dbus, networkService, ethernetObj.first,
                                     networkIPIntf, "Origin");
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
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.description());
        return true;
    }
}

/** @brief implementes for check the DHCP or not in IPv6
 *  @param[in] Channel - Channel number
 *  @returns true or false.
 */
static bool isDHCPIPv6Enabled(uint8_t Channel)
{

    try
    {
        auto ethdevice = getChannelName(Channel);
        if (ethdevice.empty())
        {
            return false;
        }
        auto ethIP = ethdevice + "/ipv6";
        auto objectInfo =
            getDbusObject(dbus, networkIPIntf, networkRoot, ethIP);
        auto properties = getAllDbusProperties(dbus, objectInfo.second,
                                               objectInfo.first, networkIPIntf);
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
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.description());
        return true;
    }
}

/** @brief implementes the creating of default new user
 *  @param[in] userName - new username in 16 bytes.
 *  @param[in] userPassword - new password in 20 bytes
 *  @returns ipmi completion code.
 */
ipmi::RspType<> ipmiOEMSetUser2Activation(
    std::array<uint8_t, ipmi::ipmiMaxUserName>& userName,
    std::array<uint8_t, ipmi::maxIpmi20PasswordSize>& userPassword)
{
    bool userState = false;
    // Check for System Interface not exist and LAN should be static
    for (uint8_t channel = 0; channel < maxIpmiChannels; channel++)
    {
        ChannelInfo chInfo;
        try
        {
            getChannelInfo(channel, chInfo);
        }
        catch (sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetUser2Activation: Failed to get Channel Info",
                phosphor::logging::entry("MSG: %s", e.description()));
            return ipmi::response(ipmi::ccUnspecifiedError);
        }
        if (chInfo.mediumType ==
            static_cast<uint8_t>(EChannelMediumType::systemInterface))
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetUser2Activation: system interface  exist .");
            return ipmi::response(ipmi::ccCommandNotAvailable);
        }
        else
        {

            if (chInfo.mediumType ==
                static_cast<uint8_t>(EChannelMediumType::lan8032))
            {
                if (isDHCPIPv6Enabled(channel) || isDHCPEnabled(channel))
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "ipmiOEMSetUser2Activation: DHCP enabled .");
                    return ipmi::response(ipmi::ccCommandNotAvailable);
                }
            }
        }
    }
    uint8_t maxChUsers = 0, enabledUsers = 0, fixedUsers = 0;
    if (ipmi::ccSuccess ==
        ipmiUserGetAllCounts(maxChUsers, enabledUsers, fixedUsers))
    {
        if (enabledUsers > 1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetUser2Activation: more than one user is enabled.");
            return ipmi::response(ipmi::ccCommandNotAvailable);
        }
        // Check the user 2 is enabled or not
        ipmiUserCheckEnabled(ipmiDefaultUserId, userState);
        if (userState == true)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetUser2Activation: user 2 already enabled .");
            return ipmi::response(ipmi::ccCommandNotAvailable);
        }
    }
    else
    {
        return ipmi::response(ipmi::ccUnspecifiedError);
    }

#if BYTE_ORDER == LITTLE_ENDIAN
    PrivAccess privAccess = {PRIVILEGE_ADMIN, true, true, true, 0};
#endif
#if BYTE_ORDER == BIG_ENDIAN
    PrivAccess privAccess = {0, true, true, true, PRIVILEGE_ADMIN};
#endif

    if (ipmi::ccSuccess ==
        ipmiUserSetUserName(ipmiDefaultUserId,
                            reinterpret_cast<const char*>(userName.data())))
    {
        if (ipmi::ccSuccess ==
            ipmiUserSetUserPassword(
                ipmiDefaultUserId,
                reinterpret_cast<const char*>(userPassword.data())))
        {
            if (ipmi::ccSuccess ==
                ipmiUserSetPrivilegeAccess(
                    ipmiDefaultUserId,
                    static_cast<uint8_t>(ipmi::EChannelID::chanLan1),
                    privAccess, true))
            {
                phosphor::logging::log<phosphor::logging::level::INFO>(
                    "ipmiOEMSetUser2Activation: user created successfully ");
                return ipmi::responseSuccess();
            }
        }
        // we need to delete  the default user id which added in this command as
        // password / priv setting is failed.
        ipmiUserSetUserName(ipmiDefaultUserId, "");
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetUser2Activation: password / priv setting is failed.");
    }
    else
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetUser2Activation: Setting username failed.");
    }

    return ipmi::response(ipmi::ccCommandNotAvailable);
}

/** @brief implementes setting password for special user
 *  @param[in] specialUserIndex
 *  @param[in] userPassword - new password in 20 bytes
 *  @returns ipmi completion code.
 */
ipmi::RspType<> ipmiOEMSetSpecialUserPassword(ipmi::Context::ptr ctx,
                                              uint8_t specialUserIndex,
                                              std::vector<uint8_t> userPassword)
{
    ChannelInfo chInfo;
    try
    {
        getChannelInfo(ctx->channel, chInfo);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetSpecialUserPassword: Failed to get Channel Info",
            phosphor::logging::entry("MSG: %s", e.description()));
        return ipmi::responseUnspecifiedError();
    }
    if (chInfo.mediumType !=
        static_cast<uint8_t>(EChannelMediumType::systemInterface))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetSpecialUserPassword: Error - supported only in KCS "
            "interface");
        return ipmi::responseCommandNotAvailable();
    }
    if (specialUserIndex != 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetSpecialUserPassword: Invalid user account");
        return ipmi::responseParmOutOfRange();
    }
    constexpr uint8_t minPasswordSizeRequired = 6;
    if (userPassword.size() < minPasswordSizeRequired ||
        userPassword.size() > ipmi::maxIpmi20PasswordSize)
    {
        return ipmi::responseReqDataLenInvalid();
    }
    std::string passwd;
    passwd.assign(reinterpret_cast<const char*>(userPassword.data()),
                  userPassword.size());
    return ipmi::response(ipmiSetSpecialUserPassword("root", passwd));
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
/*@ param ledstate - 8-bit unsigned integer to be used with iterator
 *@ param state - 8-bit unsigned integer to know the led state
 *@ returns completion code with 1 byte led status
 */

ipmi::RspType<uint8_t> ipmiOEMGetLEDStatus()
{
    uint8_t ledstate = 0;
    uint8_t state = 0;
    phosphor::logging::log<phosphor::logging::level::DEBUG>("GET led status");
    for (auto it = ledAction::offsetObjPath.begin();
         it != ledAction::offsetObjPath.end(); ++it)
    {
        state = 0;
        if (getLEDState(dbus, ledIntf, it->second, state) == -1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "oem_get_led_status: fail to get ID LED status!");
            return ipmi::response(ipmi::ccUnspecifiedError);
        }
        ledstate |= state << it->first;
    }
    return ipmi::responseSuccess(state);
}

/*
 *@ param command - 8-bit unsigned integer to be used with serial port config
 *command
 *@ param parameter - 8-bit unsigned integer to know the parameter passed as
 *request
 *@ param myrsp - 8-bit unsigned integer to send the response of serial config
 *command
 *@ Using ipmi APIs and Error codes
 *@ returns completion code of 1 byte
 *
 */

ipmi::RspType<uint8_t> ipmiOEMCfgHostSerialPortSpeed(uint8_t command,
                                                     uint8_t parameter)
{
    phosphor::logging::log<phosphor::logging::level::ERR>("Nitin");
    uint8_t myrsp = 0x00;

    switch (command)
    {
        case getHostSerialCfgCmd:
        {
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
                myrsp = 0x00;
                // Using the default value
            }
            else
            {
                if (data.size() != 1)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "CfgHostSerial:: error on read env");
                    return ipmi::response(ipmi::ccUnspecifiedError);
                }
                try
                {
                    unsigned long tmp = std::stoul(data[0]);
                    if (tmp > std::numeric_limits<uint8_t>::max())
                    {
                        throw std::out_of_range("Out of range");
                    }
                    myrsp = static_cast<uint8_t>(tmp);
                }
                catch (const std::invalid_argument& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "invalid config ",
                        phosphor::logging::entry("ERR=%s", e.what()));
                    return ipmi::response(ipmi::ccUnspecifiedError);
                }
                catch (const std::out_of_range& e)
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "out_of_range config ",
                        phosphor::logging::entry("ERR=%s", e.what()));
                    return ipmi::response(ipmi::ccUnspecifiedError);
                }
            }
            break;
        }
        case setHostSerialCfgCmd:
        {
            if (parameter > HostSerialCfgParamMax)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "CfgHostSerial: invalid input!");

                return ipmi::responseInvalidFieldRequest();
            }

            boost::process::child c1(fwSetEnvCmd, fwHostSerailCfgEnvName,
                                     std::to_string(parameter));
            c1.wait();
            if (c1.exit_code())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "CfgHostSerial:: error on execute",
                    phosphor::logging::entry("EXECUTE=%s", fwGetEnvCmd));
                return ipmi::response(ipmi::ccUnspecifiedError);
            }
            break;
        }
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "CfgHostSerial: invalid input!");
            return ipmi::responseInvalidFieldRequest();
    }
    return ipmi::responseSuccess(myrsp);
}

constexpr const char* thermalModeInterface =
    "xyz.openbmc_project.Control.ThermalMode";
constexpr const char* thermalModePath =
    "/xyz/openbmc_project/control/thermal_mode";

bool getFanProfileInterface(
    sdbusplus::bus::bus& bus,
    boost::container::flat_map<
        std::string, std::variant<std::vector<std::string>, std::string>>& resp)
{
    auto call = bus.new_method_call(settingsBusName, thermalModePath, PROP_INTF,
                                    "GetAll");
    call.append(thermalModeInterface);
    try
    {
        auto data = bus.call(call);
        data.read(resp);
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getFanProfileInterface: can't get thermal mode!",
            phosphor::logging::entry("ERR=%s", e.what()));
        return false;
    }
    return true;
}

ipmi_ret_t ipmiOEMSetFanConfig(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t dataLen, ipmi_context_t context)
{

    if (*dataLen < 2 || *dataLen > 7)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetFanConfig: invalid input len!");
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    // todo: tell bios to only send first 2 bytes

    SetFanConfigReq* req = reinterpret_cast<SetFanConfigReq*>(request);
    boost::container::flat_map<
        std::string, std::variant<std::vector<std::string>, std::string>>
        profileData;
    if (!getFanProfileInterface(dbus, profileData))
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    std::vector<std::string>* supported =
        std::get_if<std::vector<std::string>>(&profileData["Supported"]);
    if (supported == nullptr)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    std::string mode;
    if (req->flags &
        (1 << static_cast<uint8_t>(setFanProfileFlags::setPerfAcousMode)))
    {
        bool performanceMode =
            (req->flags & (1 << static_cast<uint8_t>(
                               setFanProfileFlags::performAcousSelect))) > 0;

        if (performanceMode)
        {

            if (std::find(supported->begin(), supported->end(),
                          "Performance") != supported->end())
            {
                mode = "Performance";
            }
        }
        else
        {

            if (std::find(supported->begin(), supported->end(), "Acoustic") !=
                supported->end())
            {
                mode = "Acoustic";
            }
        }
        if (mode.empty())
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        setDbusProperty(dbus, settingsBusName, thermalModePath,
                        thermalModeInterface, "Current", mode);
    }

    return IPMI_CC_OK;
}

ipmi_ret_t ipmiOEMGetFanConfig(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                               ipmi_request_t request, ipmi_response_t response,
                               ipmi_data_len_t dataLen, ipmi_context_t context)
{

    if (*dataLen > 1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetFanConfig: invalid input len!");
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    // todo: talk to bios about needing less information

    GetFanConfigResp* resp = reinterpret_cast<GetFanConfigResp*>(response);
    *dataLen = sizeof(GetFanConfigResp);

    boost::container::flat_map<
        std::string, std::variant<std::vector<std::string>, std::string>>
        profileData;

    if (!getFanProfileInterface(dbus, profileData))
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    std::string* current = std::get_if<std::string>(&profileData["Current"]);

    if (current == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetFanConfig: can't get current mode!");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    bool performance = (*current == "Performance");

    if (performance)
    {
        resp->flags |= 1 << 2;
    }

    return IPMI_CC_OK;
}

constexpr const char* cfmLimitSettingPath =
    "/xyz/openbmc_project/control/cfm_limit";
constexpr const char* cfmLimitIface = "xyz.openbmc_project.Control.CFMLimit";
constexpr const size_t legacyExitAirSensorNumber = 0x2e;
constexpr const char* pidConfigurationIface =
    "xyz.openbmc_project.Configuration.Pid";

static std::string getExitAirConfigPath()
{

    auto method =
        dbus.new_method_call("xyz.openbmc_project.ObjectMapper",
                             "/xyz/openbmc_project/object_mapper",
                             "xyz.openbmc_project.ObjectMapper", "GetSubTree");

    method.append("/", 0, std::array<const char*, 1>{pidConfigurationIface});
    std::string path;
    GetSubTreeType resp;
    try
    {
        auto reply = dbus.call(method);
        reply.read(resp);
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetFscParameter: mapper error");
    };
    auto config = std::find_if(resp.begin(), resp.end(), [](const auto& pair) {
        return pair.first.find("Exit_Air") != std::string::npos;
    });
    if (config != resp.end())
    {
        path = std::move(config->first);
    }
    return path;
}

// flat map to make alphabetical
static boost::container::flat_map<std::string, PropertyMap> getPidConfigs()
{
    boost::container::flat_map<std::string, PropertyMap> ret;
    auto method =
        dbus.new_method_call("xyz.openbmc_project.ObjectMapper",
                             "/xyz/openbmc_project/object_mapper",
                             "xyz.openbmc_project.ObjectMapper", "GetSubTree");

    method.append("/", 0, std::array<const char*, 1>{pidConfigurationIface});
    GetSubTreeType resp;

    try
    {
        auto reply = dbus.call(method);
        reply.read(resp);
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "getFanConfigPaths: mapper error");
    };
    for (const auto& [path, objects] : resp)
    {
        if (objects.empty())
        {
            continue; // should be impossible
        }

        try
        {
            ret.emplace(path, getAllDbusProperties(dbus, objects[0].first, path,
                                                   pidConfigurationIface));
        }
        catch (sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "getPidConfigs: can't get DbusProperties!",
                phosphor::logging::entry("ERR=%s", e.what()));
        }
    }
    return ret;
}

ipmi::RspType<uint8_t> ipmiOEMGetFanSpeedOffset(void)
{
    boost::container::flat_map<std::string, PropertyMap> data = getPidConfigs();
    if (data.empty())
    {
        return ipmi::responseResponseError();
    }
    uint8_t minOffset = std::numeric_limits<uint8_t>::max();
    for (const auto& [_, pid] : data)
    {
        auto findClass = pid.find("Class");
        if (findClass == pid.end())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetFscParameter: found illegal pid "
                "configurations");
            return ipmi::responseResponseError();
        }
        std::string type = std::get<std::string>(findClass->second);
        if (type == "fan")
        {
            auto findOutLimit = pid.find("OutLimitMin");
            if (findOutLimit == pid.end())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMGetFscParameter: found illegal pid "
                    "configurations");
                return ipmi::responseResponseError();
            }
            // get the min out of all the offsets
            minOffset = std::min(
                minOffset,
                static_cast<uint8_t>(std::get<double>(findOutLimit->second)));
        }
    }
    if (minOffset == std::numeric_limits<uint8_t>::max())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetFscParameter: found no fan configurations!");
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(minOffset);
}

ipmi::RspType<> ipmiOEMSetFanSpeedOffset(uint8_t offset)
{
    boost::container::flat_map<std::string, PropertyMap> data = getPidConfigs();
    if (data.empty())
    {

        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetFanSpeedOffset: found no pid configurations!");
        return ipmi::responseResponseError();
    }

    bool found = false;
    for (const auto& [path, pid] : data)
    {
        auto findClass = pid.find("Class");
        if (findClass == pid.end())
        {

            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetFanSpeedOffset: found illegal pid "
                "configurations");
            return ipmi::responseResponseError();
        }
        std::string type = std::get<std::string>(findClass->second);
        if (type == "fan")
        {
            auto findOutLimit = pid.find("OutLimitMin");
            if (findOutLimit == pid.end())
            {

                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetFanSpeedOffset: found illegal pid "
                    "configurations");
                return ipmi::responseResponseError();
            }
            ipmi::setDbusProperty(dbus, "xyz.openbmc_project.EntityManager",
                                  path, pidConfigurationIface, "OutLimitMin",
                                  static_cast<double>(offset));
            found = true;
        }
    }
    if (!found)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetFanSpeedOffset: set no fan offsets");
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<> ipmiOEMSetFscParameter(uint8_t command, uint8_t param1,
                                       uint8_t param2)
{
    constexpr const size_t disableLimiting = 0x0;

    if (command == static_cast<uint8_t>(setFscParamFlags::tcontrol))
    {
        if (param1 == legacyExitAirSensorNumber)
        {
            std::string path = getExitAirConfigPath();
            ipmi::setDbusProperty(dbus, "xyz.openbmc_project.EntityManager",
                                  path, pidConfigurationIface, "SetPoint",
                                  static_cast<double>(param2));
            return ipmi::responseSuccess();
        }
        else
        {
            return ipmi::responseParmOutOfRange();
        }
    }
    else if (command == static_cast<uint8_t>(setFscParamFlags::cfm))
    {
        uint16_t cfm = param1 | (static_cast<uint16_t>(param2) << 8);

        // must be greater than 50 based on eps
        if (cfm < 50 && cfm != disableLimiting)
        {
            return ipmi::responseParmOutOfRange();
        }

        try
        {
            ipmi::setDbusProperty(dbus, settingsBusName, cfmLimitSettingPath,
                                  cfmLimitIface, "Limit",
                                  static_cast<double>(cfm));
        }
        catch (sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetFscParameter: can't set cfm setting!",
                phosphor::logging::entry("ERR=%s", e.what()));
            return ipmi::responseResponseError();
        }
        return ipmi::responseSuccess();
    }
    else if (command == static_cast<uint8_t>(setFscParamFlags::maxPwm))
    {
        constexpr const size_t maxDomainCount = 8;
        uint8_t requestedDomainMask = param1;
        boost::container::flat_map data = getPidConfigs();
        if (data.empty())
        {

            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetFscParameter: found no pid configurations!");
            return ipmi::responseResponseError();
        }
        size_t count = 0;
        for (const auto& [path, pid] : data)
        {
            auto findClass = pid.find("Class");
            if (findClass == pid.end())
            {

                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMSetFscParameter: found illegal pid "
                    "configurations");
                return ipmi::responseResponseError();
            }
            std::string type = std::get<std::string>(findClass->second);
            if (type == "fan")
            {
                if (requestedDomainMask & (1 << count))
                {
                    ipmi::setDbusProperty(
                        dbus, "xyz.openbmc_project.EntityManager", path,
                        pidConfigurationIface, "OutLimitMax",
                        static_cast<double>(param2));
                }
                count++;
            }
        }
        return ipmi::responseSuccess();
    }
    else
    {
        // todo other command parts possibly
        // tcontrol is handled in peci now
        // fan speed offset not implemented yet
        // domain pwm limit not implemented
        return ipmi::responseParmOutOfRange();
    }
}

ipmi::RspType<
    std::variant<uint8_t, std::array<uint8_t, 2>, std::array<uint16_t, 2>>>
    ipmiOEMGetFscParameter(uint8_t command, std::optional<uint8_t> param)
{
    constexpr uint8_t legacyDefaultExitAirLimit = -128;

    if (command == static_cast<uint8_t>(setFscParamFlags::tcontrol))
    {
        if (!param)
        {
            return ipmi::responseReqDataLenInvalid();
        }

        if (*param != legacyExitAirSensorNumber)
        {
            return ipmi::responseParmOutOfRange();
        }
        uint8_t setpoint = legacyDefaultExitAirLimit;
        std::string path = getExitAirConfigPath();
        if (path.size())
        {
            Value val =
                ipmi::getDbusProperty(dbus, "xyz.openbmc_project.EntityManager",
                                      path, pidConfigurationIface, "SetPoint");
            setpoint = std::floor(std::get<double>(val) + 0.5);
        }

        // old implementation used to return the "default" and current, we
        // don't make the default readily available so just make both the
        // same

        return ipmi::responseSuccess(
            std::array<uint8_t, 2>{setpoint, setpoint});
    }
    else if (command == static_cast<uint8_t>(setFscParamFlags::maxPwm))
    {
        constexpr const size_t maxDomainCount = 8;

        if (!param)
        {
            return ipmi::responseReqDataLenInvalid();
        }
        uint8_t requestedDomain = *param;
        if (requestedDomain >= maxDomainCount)
        {
            return ipmi::responseInvalidFieldRequest();
        }

        boost::container::flat_map data = getPidConfigs();
        if (data.empty())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetFscParameter: found no pid configurations!");
            return ipmi::responseResponseError();
        }
        size_t count = 0;
        for (const auto& [_, pid] : data)
        {
            auto findClass = pid.find("Class");
            if (findClass == pid.end())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "ipmiOEMGetFscParameter: found illegal pid "
                    "configurations");
                return ipmi::responseResponseError();
            }
            std::string type = std::get<std::string>(findClass->second);
            if (type == "fan")
            {
                if (requestedDomain == count)
                {
                    auto findOutLimit = pid.find("OutLimitMax");
                    if (findOutLimit == pid.end())
                    {
                        phosphor::logging::log<phosphor::logging::level::ERR>(
                            "ipmiOEMGetFscParameter: found illegal pid "
                            "configurations");
                        return ipmi::responseResponseError();
                    }

                    return ipmi::responseSuccess(
                        static_cast<uint8_t>(std::floor(
                            std::get<double>(findOutLimit->second) + 0.5)));
                }
                else
                {
                    count++;
                }
            }
        }

        return ipmi::responseInvalidFieldRequest();
    }
    else if (command == static_cast<uint8_t>(setFscParamFlags::cfm))
    {

        /*
        DataLen should be 1, but host is sending us an extra bit. As the
        previous behavior didn't seem to prevent this, ignore the check for
        now.

        if (param)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetFscParameter: invalid input len!");
            return IPMI_CC_REQ_DATA_LEN_INVALID;
        }
        */
        Value cfmLimit;
        Value cfmMaximum;
        try
        {
            cfmLimit = ipmi::getDbusProperty(dbus, settingsBusName,
                                             cfmLimitSettingPath, cfmLimitIface,
                                             "Limit");
            cfmMaximum = ipmi::getDbusProperty(
                dbus, "xyz.openbmc_project.ExitAirTempSensor",
                "/xyz/openbmc_project/control/MaxCFM", cfmLimitIface, "Limit");
        }
        catch (sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetFscParameter: can't get cfm setting!",
                phosphor::logging::entry("ERR=%s", e.what()));
            return ipmi::responseResponseError();
        }

        double cfmMax = std::get<double>(cfmMaximum);
        double cfmLim = std::get<double>(cfmLimit);

        cfmLim = std::floor(cfmLim + 0.5);
        cfmMax = std::floor(cfmMax + 0.5);
        uint16_t cfmLimResp = static_cast<uint16_t>(cfmLim);
        uint16_t cfmMaxResp = static_cast<uint16_t>(cfmMax);

        return ipmi::responseSuccess(
            std::array<uint16_t, 2>{cfmLimResp, cfmMaxResp});
    }

    else
    {
        // todo other command parts possibly
        // domain pwm limit not implemented
        return ipmi::responseParmOutOfRange();
    }
}

ipmi::RspType<> ipmiOEMSetFaultIndication(uint8_t sourceId, uint8_t faultType,
                                          uint8_t faultState,
                                          uint8_t faultGroup,
                                          std::array<uint8_t, 8>& ledStateData)
{
    static constexpr const char* objpath = "/xyz/openbmc_project/EntityManager";
    static constexpr const char* intf = "xyz.openbmc_project.EntityManager";
    constexpr auto maxFaultType = static_cast<size_t>(RemoteFaultType::max);
    static const std::array<std::string, maxFaultType> faultNames = {
        "faultFan",       "faultTemp",     "faultPower",
        "faultDriveSlot", "faultSoftware", "faultMemory"};
    static constexpr const char* sysGpioPath = "/sys/class/gpio/gpio";
    static constexpr const char* postfixValue = "/value";

    constexpr uint8_t maxFaultSource = 0x4;
    constexpr uint8_t skipLEDs = 0xFF;
    constexpr uint8_t pinSize = 64;
    constexpr uint8_t groupSize = 16;

    std::vector<uint16_t> ledFaultPins(pinSize, 0xFFFF);
    uint64_t resFIndex = 0;
    std::string resFType;
    std::string service;
    ObjectValueTree valueTree;

    // Validate the source, fault type
    if ((sourceId >= maxFaultSource) ||
        (faultType >= static_cast<int8_t>(RemoteFaultType::max)) ||
        (faultState >= static_cast<int8_t>(RemoteFaultState::maxFaultState)) ||
        (faultGroup >= static_cast<int8_t>(DimmFaultType::maxFaultGroup)))
    {
        return ipmi::responseParmOutOfRange();
    }

    try
    {
        service = getService(dbus, intf, objpath);
        valueTree = getManagedObjects(dbus, service, "/");
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No object implements interface",
            phosphor::logging::entry("SERVICE=%s", service.c_str()),
            phosphor::logging::entry("INTF=%s", intf));
        return ipmi::responseResponseError();
    }

    if (valueTree.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No object implements interface",
            phosphor::logging::entry("INTF=%s", intf));
        return ipmi::responseResponseError();
    }

    for (const auto& item : valueTree)
    {
        // find LedFault configuration
        auto interface =
            item.second.find("xyz.openbmc_project.Configuration.LedFault");
        if (interface == item.second.end())
        {
            continue;
        }

        // find matched fault type: faultMemmory / faultFan
        // find LedGpioPins/FaultIndex configuration
        auto propertyFaultType = interface->second.find("FaultType");
        auto propertyFIndex = interface->second.find("FaultIndex");
        auto ledIndex = interface->second.find("LedGpioPins");

        if (propertyFaultType == interface->second.end() ||
            propertyFIndex == interface->second.end() ||
            ledIndex == interface->second.end())
        {
            continue;
        }

        try
        {
            Value valIndex = propertyFIndex->second;
            resFIndex = std::get<uint64_t>(valIndex);

            Value valFType = propertyFaultType->second;
            resFType = std::get<std::string>(valFType);
        }
        catch (const std::bad_variant_access& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return ipmi::responseResponseError();
        }
        // find the matched requested fault type: faultMemmory or faultFan
        if (resFType != faultNames[faultType])
        {
            continue;
        }

        // read LedGpioPins data
        std::vector<uint64_t> ledgpios;
        std::variant<std::vector<uint64_t>> message;

        auto method = dbus.new_method_call(
            service.c_str(), (std::string(item.first)).c_str(),
            "org.freedesktop.DBus.Properties", "Get");

        method.append("xyz.openbmc_project.Configuration.LedFault",
                      "LedGpioPins");

        try
        {
            auto reply = dbus.call(method);
            reply.read(message);
            ledgpios = std::get<std::vector<uint64_t>>(message);
        }
        catch (std::exception& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            return ipmi::responseResponseError();
        }

        // Check the size to be sure it will never overflow on groupSize
        if (ledgpios.size() > groupSize)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Fault gpio Pins out of range!");
            return ipmi::responseParmOutOfRange();
        }
        // Store data, according to command data bit index order
        for (int i = 0; i < ledgpios.size(); i++)
        {
            ledFaultPins[i + groupSize * resFIndex] = ledgpios[i];
        }
    }

    switch (RemoteFaultType(faultType))
    {
        case (RemoteFaultType::fan):
        case (RemoteFaultType::memory):
        {
            if (faultGroup == skipLEDs)
            {
                return ipmi::responseSuccess();
            }

            uint64_t ledState = 0;
            // calculate led state bit filed count, each byte has 8bits
            // the maximum bits will be 8 * 8 bits
            constexpr uint8_t size = sizeof(ledStateData) * 8;
            for (int i = 0; i < sizeof(ledStateData); i++)
            {
                ledState = (uint64_t)(ledState << 8);
                ledState = (uint64_t)(ledState | (uint64_t)ledStateData[i]);
            }

            std::bitset<size> ledStateBits(ledState);
            std::string gpioValue;
            for (int i = 0; i < size; i++)
            { // skip invalid value
                if (ledFaultPins[i] == 0xFFFF)
                {
                    continue;
                }

                std::string device = sysGpioPath +
                                     std::to_string(ledFaultPins[i]) +
                                     postfixValue;
                std::fstream gpioFile;

                gpioFile.open(device, std::ios::out);

                if (!gpioFile.good())
                {
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Not Find Led Gpio Device!",
                        phosphor::logging::entry("DEVICE=%s", device.c_str()));
                    return ipmi::responseResponseError();
                }
                gpioFile << std::to_string(
                    static_cast<uint8_t>(ledStateBits[i]));
                gpioFile.close();
            }
            break;
        }
        default:
        {
            // now only support two fault types
            return ipmi::responseParmOutOfRange();
        }
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOEMReadBoardProductId()
{
    uint8_t prodId = 0;
    try
    {
        const DbusObjectInfo& object = getDbusObject(
            dbus, "xyz.openbmc_project.Inventory.Item.Board",
            "/xyz/openbmc_project/inventory/system/board/", "Baseboard");
        const Value& propValue = getDbusProperty(
            dbus, object.second, object.first,
            "xyz.openbmc_project.Inventory.Item.Board", "ProductId");
        prodId = static_cast<uint8_t>(std::get<uint64_t>(propValue));
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMReadBoardProductId: Product ID read failed!",
            phosphor::logging::entry("ERR=%s", e.what()));
    }
    return ipmi::responseSuccess(prodId);
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

    ipmi::registerHandler(
        ipmi::prioOpenBmcBase, ipmi::netFnOemOne,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdSendEmbeddedFWUpdStatus),
        ipmi::Privilege::Operator, ipmiOEMSendEmbeddedFwUpdStatus);

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

    ipmi::registerHandler(
        ipmi::prioOpenBmcBase, ipmi::netFnOemOne,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetOEMUser2Activation),
        ipmi::Privilege::Callback, ipmiOEMSetUser2Activation);

    ipmi::registerHandler(
        ipmi::prioOpenBmcBase, ipmi::netFnOemOne,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetSpecialUserPassword),
        ipmi::Privilege::Callback, ipmiOEMSetSpecialUserPassword);

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
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdSetFanConfig),
        NULL, ipmiOEMSetFanConfig, PRIVILEGE_USER);

    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdGetFanConfig),
        NULL, ipmiOEMGetFanConfig, PRIVILEGE_USER);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdGetFanSpeedOffset),
        ipmi::Privilege::User, ipmiOEMGetFanSpeedOffset);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetFanSpeedOffset),
        ipmi::Privilege::User, ipmiOEMSetFanSpeedOffset);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(IPMINetfnIntelOEMGeneralCmd::cmdSetFscParameter),
        ipmi::Privilege::User, ipmiOEMSetFscParameter);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(IPMINetfnIntelOEMGeneralCmd::cmdGetFscParameter),
        ipmi::Privilege::User, ipmiOEMGetFscParameter);

    ipmi::registerHandler(
        ipmi::prioOpenBmcBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdReadBaseBoardProductId),
        ipmi::Privilege::Admin, ipmiOEMReadBoardProductId);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(IPMINetfnIntelOEMGeneralCmd::cmdGetLEDStatus),
        ipmi::Privilege::Admin, ipmiOEMGetLEDStatus);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMPlatform,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMPlatformCmd::cmdCfgHostSerialPortSpeed),
        ipmi::Privilege::Admin, ipmiOEMCfgHostSerialPortSpeed);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetFaultIndication),
        ipmi::Privilege::Operator, ipmiOEMSetFaultIndication);
    return;
}

} // namespace ipmi
