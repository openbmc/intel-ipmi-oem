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
    target = (target & selEvtTargetMask) >> selEvtTargetShift;

    /* make sure the status is 0, 1, or 2 as per the spec */
    if (status > 2)
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
            buildInfo = " major: " + std::to_string(majorRevision) +
                        " minor: " +
                        std::to_string(bcdToDec(minorRevision)) + // BCD encoded
                        " BuildID: " + std::to_string(auxInfo);
            buildInfo += std::to_string(auxInfo);
            break;
        case FWUpdateTarget::targetBIOS:
            firmware = "BIOS";
            buildInfo =
                " major: " +
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
                " major: " + std::to_string(majorRevision) + " minor1: " +
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
            buildInfo = " major: " + std::to_string(majorRevision) +
                        " minor: " +
                        std::to_string(bcdToDec(minorRevision)) + // BCD encoded
                        " BuildID: " + std::to_string(auxInfo);
            break;
    }

    switch (status)
    {
        case 0x0:
            action = "update started";
            break;
        case 0x1:
            action = "update completed successfully";
            break;
        case 0x2:
            action = "update failure";
            break;
        default:
            action = "unknown";
            break;
    }

    std::string message(
        "[firmware update] " + firmware + " instance: " +
        std::to_string((target & targetInstanceMask) >> targetInstanceShift) +
        " status: <" + action + ">" + buildInfo);
    static constexpr const char* redfishMsgId = "FirmwareUpdate";

    sd_journal_send("MESSAGE=%s", message.c_str(), "PRIORITY=%i", LOG_INFO,
                    "REDFISH_MESSAGE_ID=%s", redfishMsgId, NULL);
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

static std::string getExitAirConfigPath()
{

    auto method =
        dbus.new_method_call("xyz.openbmc_project.ObjectMapper",
                             "/xyz/openbmc_project/object_mapper",
                             "xyz.openbmc_project.ObjectMapper", "GetSubTree");

    method.append(
        "/", 0,
        std::array<const char*, 1>{"xyz.openbmc_project.Configuration.Pid"});
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

ipmi_ret_t ipmiOEMSetFscParameter(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t dataLen,
                                  ipmi_context_t context)
{
    constexpr const size_t disableLimiting = 0x0;

    if (*dataLen < 2)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMSetFscParameter: invalid input len!");
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t* req = static_cast<uint8_t*>(request);

    if (*req == static_cast<uint8_t>(setFscParamFlags::tcontrol))
    {
        if (*dataLen == 3 && req[1] == legacyExitAirSensorNumber)
        {
            *dataLen = 0;
            std::string path = getExitAirConfigPath();
            ipmi::setDbusProperty(dbus, "xyz.openbmc_project.EntityManager",
                                  path, "xyz.openbmc_project.Configuration.Pid",
                                  "SetPoint", static_cast<double>(req[2]));
            return IPMI_CC_OK;
        }
        else if (*dataLen == 3)
        {
            *dataLen = 0;
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
        else
        {
            *dataLen = 0;
            return IPMI_CC_REQ_DATA_LEN_INVALID;
        }
    }
    else if (*req == static_cast<uint8_t>(setFscParamFlags::cfm))
    {
        if (*dataLen != 3)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetFscParameter: invalid input len!");
            *dataLen = 0;
            return IPMI_CC_REQ_DATA_LEN_INVALID;
        }
        *dataLen = 0;

        uint16_t cfm = req[1] | (static_cast<uint16_t>(req[2]) << 8);

        // must be greater than 50 based on eps
        if (cfm < 50 && cfm != disableLimiting)
        {
            return IPMI_CC_PARM_OUT_OF_RANGE;
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
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        return IPMI_CC_OK;
    }
    else
    {
        // todo other command parts possibly
        // tcontrol is handled in peci now
        // fan speed offset not implemented yet
        // domain pwm limit not implemented
        *dataLen = 0;
        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
}

ipmi_ret_t ipmiOEMGetFscParameter(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t dataLen,
                                  ipmi_context_t context)
{
    constexpr uint8_t legacyDefaultExitAirLimit = -128;

    if (*dataLen < 1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetFscParameter: invalid input len!");
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t* req = static_cast<uint8_t*>(request);

    if (*req == static_cast<uint8_t>(setFscParamFlags::tcontrol))
    {
        if (*dataLen != 2)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetFscParameter: invalid input len!");
            *dataLen = 0;
            return IPMI_CC_REQ_DATA_LEN_INVALID;
        }

        if (req[1] != legacyExitAirSensorNumber)
        {
            return IPMI_CC_PARM_OUT_OF_RANGE;
        }
        uint8_t setpoint = legacyDefaultExitAirLimit;
        std::string path = getExitAirConfigPath();
        if (path.size())
        {
            Value val = ipmi::getDbusProperty(
                dbus, "xyz.openbmc_project.EntityManager", path,
                "xyz.openbmc_project.Configuration.Pid", "SetPoint");
            setpoint = std::floor(std::get<double>(val) + 0.5);
        }

        // old implementation used to return the "default" and current, we
        // don't make the default readily available so just make both the
        // same
        auto resp = static_cast<uint8_t*>(response);
        resp[0] = setpoint;
        resp[1] = setpoint;

        *dataLen = 2;
        return IPMI_CC_OK;
    }
    else if (*req == static_cast<uint8_t>(setFscParamFlags::cfm))
    {

        /*
        DataLen should be 1, but host is sending us an extra bit. As the
        previous behavior didn't seem to prevent this, ignore the check for now.

        if (*dataLen != 1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMGetFscParameter: invalid input len!");
            *dataLen = 0;
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
                "ipmiOEMSetFscParameter: can't get cfm setting!",
                phosphor::logging::entry("ERR=%s", e.what()));
            *dataLen = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }

        auto cfmLim = std::get_if<double>(&cfmLimit);
        if (cfmLim == nullptr ||
            *cfmLim > std::numeric_limits<uint16_t>::max() || *cfmLim < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetFscParameter: cfm limit out of range!");
            *dataLen = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }

        auto cfmMax = std::get_if<double>(&cfmMaximum);
        if (cfmMax == nullptr ||
            *cfmMax > std::numeric_limits<uint16_t>::max() || *cfmMax < 0)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetFscParameter: cfm max out of range!");
            *dataLen = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        *cfmLim = std::floor(*cfmLim + 0.5);
        *cfmMax = std::floor(*cfmMax + 0.5);
        uint16_t resp = static_cast<uint16_t>(*cfmLim);
        uint16_t* ptr = static_cast<uint16_t*>(response);
        ptr[0] = resp;
        resp = static_cast<uint16_t>(*cfmMax);
        ptr[1] = resp;

        *dataLen = 4;

        return IPMI_CC_OK;
    }
    else
    {
        // todo other command parts possibly
        // fan speed offset not implemented yet
        // domain pwm limit not implemented
        *dataLen = 0;

        return IPMI_CC_PARM_OUT_OF_RANGE;
    }
}

ipmi_ret_t ipmiOEMSetFaultIndication(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                     ipmi_request_t request,
                                     ipmi_response_t response,
                                     ipmi_data_len_t dataLen,
                                     ipmi_context_t context)
{
    std::string objpath = "/xyz/openbmc_project/EntityManager";
    std::string intf = "xyz.openbmc_project.EntityManager";
    std::string fType[6] = {"faultFan",       "faultTemp",     "faultPower",
                            "faultDriveSlot", "faultSoftware", "faultMemory"};
    static constexpr const char* sysGpioPath = "/sys/class/gpio/gpio";
    static constexpr const char* postfixValue = "/value";
    static uint8_t maxFaultSource = 0x4;
    static uint8_t skipLEDs = 0xFF;
    std::vector<uint16_t> ledFaultPins(64, 0xFFFF);
    uint64_t resFIndex = 0;

    SetFaultReq* sfReq = reinterpret_cast<SetFaultReq*>(request);

    if (*dataLen != sizeof(SetFaultReq))
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    // Validate the source, fault type, and criticality (state)
    if ((sfReq->source >= maxFaultSource) ||
        (sfReq->eFaultType >=
         static_cast<int8_t>(ERemoteFaultType::maxFaultTypes)) ||
        (sfReq->eState >=
         static_cast<int8_t>(ERemoteFaultState::maxFaultState)) ||
        (sfReq->faultLEDGroup >=
         static_cast<int8_t>(EDimmFaultType::maxFaultGroup)))
    {
        *dataLen = 0;
        return IPMI_CC_ILLEGAL_COMMAND;
    }

    std::string service = getService(dbus, intf, objpath);
    ObjectValueTree valueTree = getManagedObjects(dbus, service, "/");

    if (valueTree.empty())
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "No object implements interface",
            phosphor::logging::entry("INTF=%s", intf.c_str()));
        *dataLen = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
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
        auto propertyFaultType = interface->second.find("FaultType");
        if (propertyFaultType == interface->second.end())
        {
            continue;
        }
        Value valFType = propertyFaultType->second;
        std::string& resFType =
            sdbusplus::message::variant_ns::get<std::string>(valFType);

        if (resFType != fType[sfReq->eFaultType])
        {
            continue;
        }

        // find LedIndexs configuration
        auto ledIndex = interface->second.find("LedGpioPins");
        if (ledIndex == interface->second.end())
        {
            continue;
        }

        // read LedIndexs data
        std::vector<uint64_t> ledgpios(16, 0xFFFF);
        sdbusplus::message::variant<std::vector<uint64_t>> message;

        auto method = dbus.new_method_call(
            service.c_str(), (std::string(item.first)).c_str(),
            "org.freedesktop.DBus.Properties", "Get");

        method.append("xyz.openbmc_project.Configuration.LedFault",
                      "LedGpioPins");
        auto reply = dbus.call(method);

        try
        {
            reply.read(message);
            ledgpios =
                sdbusplus::message::variant_ns::get<std::vector<uint64_t>>(
                    message);
        }
        catch (sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                e.description());
            *dataLen = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }

        auto propertyFIndex = interface->second.find("FaultIndex");
        if (propertyFIndex == interface->second.end())
        {
            continue;
        }

        try
        {
            Value valIndex = propertyFIndex->second;
            resFIndex = sdbusplus::message::variant_ns::get<uint64_t>(valIndex);
        }
        catch (sdbusplus::message::variant_ns::bad_variant_access& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
            *dataLen = 0;
            return IPMI_CC_UNSPECIFIED_ERROR;
        }

        // Store data, according to command data bit index order
        for (int i = 0; i < ledgpios.capacity(); i++)
        {
            ledFaultPins[i + 16 * resFIndex] = ledgpios[i];
        }
        ledgpios.clear();
    }

    switch (ERemoteFaultType(sfReq->eFaultType))
    {
        case (ERemoteFaultType::faultFan):
        case (ERemoteFaultType::faultMemory):
        {
            if (sfReq->faultLEDGroup == skipLEDs)
            {
                *dataLen = 0;
                ledFaultPins.clear();
                return IPMI_CC_OK;
            }

            uint64_t ledState = 0;
            // caculate led state bit filed count, each byte has 8bits
            const uint8_t size = sizeof(sfReq->LEDState) * 8;

            for (int i = 0; i < sizeof(sfReq->LEDState); i++)
            {
                ledState = (uint64_t)(ledState << 8);
                ledState = (uint64_t)(ledState | (uint64_t)sfReq->LEDState[i]);
            }

            std::bitset<size> bitvec5(ledState);
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
                    std::cerr << "Not find device: " << device << "\n";
                    *dataLen = 0;
                    ledFaultPins.clear();
                    return IPMI_CC_UNSPECIFIED_ERROR;
                }
                gpioFile << std::to_string((uint8_t)(bitvec5[i]));
                gpioFile.close();
            }
            ledFaultPins.clear();
            break;
        }
        default:
            break;
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

    ipmiPrintAndRegister(netfnIntcOEMGeneral,
                         static_cast<ipmi_cmd_t>(
                             IPMINetfnIntelOEMGeneralCmd::cmdSetFscParameter),
                         NULL, ipmiOEMSetFscParameter, PRIVILEGE_USER);

    ipmiPrintAndRegister(netfnIntcOEMGeneral,
                         static_cast<ipmi_cmd_t>(
                             IPMINetfnIntelOEMGeneralCmd::cmdGetFscParameter),
                         NULL, ipmiOEMGetFscParameter, PRIVILEGE_USER);

    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdGetLEDStatus),
        NULL, ipmiOEMGetLEDStatus, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(
        netfnIntcOEMPlatform,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMPlatformCmd::cmdCfgHostSerialPortSpeed),
        NULL, ipmiOEMCfgHostSerialPortSpeed, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetFaultIndication),
        NULL, ipmiOEMSetFaultIndication, PRIVILEGE_OPERATOR);
    return;
}

} // namespace ipmi
