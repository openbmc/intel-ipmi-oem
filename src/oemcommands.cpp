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

#include <host-ipmid/ipmid-api.h>

#include <array>
#include <commandutils.hpp>
#include <iostream>
#include <oemcommands.hpp>
#include <phosphor-ipmi-host/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <string>
#include <vector>

namespace ipmi
{
static void RegisterNetfnFirmwareFunctions() __attribute__((constructor));
sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection()); // from ipmid-api.h
static constexpr size_t maxFRUStringLength = 0x3F;

// return code: 0 successful
int8_t getChassisSerialNumber(sdbusplus::bus::bus& bus, std::string& serial)
{
    std::string objpath = "/xyz/openbmc_project/FruDevice";
    std::string intf = "xyz.openbmc_project.FruDeviceManager";
    std::string service = getService(bus, intf, objpath);
    ObjectValueTree valueTree = getManagedObjects(bus, service, "/");
    if (valueTree.empty())
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "No object implements interface",
            phosphor::logging::entry("INTERFACE=%s", intf.c_str()));
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
            std::string& result = variant.get<std::string>();
            if (result.size() > maxFRUStringLength)
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    "FRU serial number exceed maximum length");
                return -1;
            }
            else
            {
                serial = result;
            }
            return 0;
        }
        catch (mapbox::util::bad_variant_access& e)
        {
            phosphor::logging::log<phosphor::logging::level::DEBUG>(e.what());
            return -1;
        }
    }
    return -1;
}
ipmi_ret_t IPMIOEMWildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                           ipmi_request_t request, ipmi_response_t response,
                           ipmi_data_len_t dataLen, ipmi_context_t context)
{
    PrintCommand(+netfn, +cmd);
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *dataLen = 0;
    return rc;
}

// Returns the Chassis Identifier (serial #)
ipmi_ret_t IPMIOEMGetChassisIdentifier(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t dataLen,
                                       ipmi_context_t context)
{
    std::string serial;
    if (*dataLen != 0) // invalid request if there are extra parameters
    {
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
    else
    {
        *dataLen = 0;
        return IPMI_CC_RESPONSE_ERROR;
    }
}

ipmi_ret_t IPMIOEMSetSystemGUID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t dataLen, ipmi_context_t context)
{
    static constexpr size_t safeBufLen = 50;
    char buf[safeBufLen] = {0};
    GUIDData* Data = reinterpret_cast<GUIDData*>(request);

    if (*dataLen != sizeof(GUIDData)) // 16bytes
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *dataLen = 0;

    snprintf(
        buf, safeBufLen,
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

ipmi_ret_t IPMIOEMSetBIOSID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
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

ipmi_ret_t IPMIOEMGetDeviceInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t dataLen, ipmi_context_t context)
{
    GetOemDeviceInfoReq* req = reinterpret_cast<GetOemDeviceInfoReq*>(request);
    GetOemDeviceInfoRes* res = reinterpret_cast<GetOemDeviceInfoRes*>(response);

    if (*dataLen == 0)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint32_t reqDataLen = *dataLen;
    *dataLen = 0;
    if (req->entityType > OEMDevEntityType::sdrVer)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    // handle OEM command items
    switch (req->entityType)
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
                std::string& idString = variant.get<std::string>();
                if (req->offset >= idString.size())
                {
                    return IPMI_CC_PARM_OUT_OF_RANGE;
                }
                else
                {
                    uint8_t length = 0;
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
            }
            catch (mapbox::util::bad_variant_access& e)
            {
                phosphor::logging::log<phosphor::logging::level::DEBUG>(
                    e.what());
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

ipmi_ret_t IPMIOEMGetAICFRU(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                            ipmi_request_t request, ipmi_response_t response,
                            ipmi_data_len_t dataLen, ipmi_context_t context)
{
    if (*dataLen != 0)
    {
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

ipmi_ret_t IPMIOEMGetPowerRestoreDelay(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t dataLen,
                                       ipmi_context_t context)
{
    GetPowerRestoreDelayRes* resp =
        reinterpret_cast<GetPowerRestoreDelayRes*>(response);

    if (*dataLen != 0)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::string service =
        getService(dbus, powerRestoreDelayIntf, powerRestoreDelayObjPath);
    Value variant =
        getDbusProperty(dbus, service, powerRestoreDelayObjPath,
                        powerRestoreDelayIntf, powerRestoreDelayProp);

    uint16_t delay = variant.get<uint16_t>();
    resp->byteLSB = delay;
    resp->byteMSB = delay >> 8;

    *dataLen = 2;

    return IPMI_CC_OK;
}

ipmi_ret_t IPMIOEMSetPowerRestoreDelay(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t dataLen,
                                       ipmi_context_t context)
{
    SetPowerRestoreDelayReq* data =
        reinterpret_cast<SetPowerRestoreDelayReq*>(request);
    uint16_t delay = 0;

    if (*dataLen != 2)
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

ipmi_ret_t IPMIOEMGetProcessorErrConfig(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t dataLen,
                                        ipmi_context_t context)
{
    GetProcessorErrConfigRes* resp =
        reinterpret_cast<GetProcessorErrConfigRes*>(response);

    if (*dataLen != 0)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::string service =
        getService(dbus, processorErrConfigIntf, processorErrConfigObjPath);
    Value variant = getDbusProperty(dbus, service, processorErrConfigObjPath,
                                    processorErrConfigIntf, "ResetCfg");
    resp->resetCfg = variant.get<uint8_t>();

    std::vector<uint8_t> caterrStatus;

    auto method =
        dbus.new_method_call(service.c_str(), processorErrConfigObjPath,
                             "org.freedesktop.DBus.Properties", "Get");

    method.append(processorErrConfigIntf, "CATERRStatus");

    try
    {
        auto reply = dbus.call(method);
        reply.read(caterrStatus);
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::DEBUG>(
            "IPMIOEMGetProcessorErrConfig: error on dbus",
            phosphor::logging::entry("PRORPERTY=CATERRStatus"),
            phosphor::logging::entry("PATH=%s", processorErrConfigObjPath),
            phosphor::logging::entry("INTERFACE=%s", processorErrConfigIntf));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    unsigned char len =
        maxCPUNum <= caterrStatus.size() ? maxCPUNum : caterrStatus.size();
    caterrStatus.resize(len);
    std::copy(caterrStatus.begin(), caterrStatus.end(), resp->caterrStatus);
    *dataLen = sizeof(GetProcessorErrConfigRes);

    return IPMI_CC_OK;
}

ipmi_ret_t IPMIOEMSetProcessorErrConfig(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t dataLen,
                                        ipmi_context_t context)
{
    SetProcessorErrConfigReq* req =
        reinterpret_cast<SetProcessorErrConfigReq*>(request);

    if (*dataLen != 3)
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

void IPMIRegister(ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_context_t context,
                  ipmid_callback_t handler, ipmi_cmd_privilege_t priv)
{
    PrintRegistration(netfn, cmd);
    ipmi_register_callback(netfn, cmd, context, handler, priv);
}

static void RegisterNetfnFirmwareFunctions(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering OEM commands");
    IPMIRegister(netfnIntcOEMGeneral, IPMI_CMD_WILDCARD, NULL, IPMIOEMWildcard,
                 PRIVILEGE_USER); // wildcard default handler
    IPMIRegister(netfnIntcOEMGeneral, CmdGetChassisIdentifier, NULL,
                 IPMIOEMGetChassisIdentifier,
                 PRIVILEGE_USER); // get chassis identifier
    IPMIRegister(netfnIntcOEMGeneral, CmdSetSystemGUID, NULL,
                 IPMIOEMSetSystemGUID,
                 PRIVILEGE_ADMIN); // set system guid
    IPMIRegister(netfnIntcOEMGeneral, CmdSetBIOSID, NULL, IPMIOEMSetBIOSID,
                 PRIVILEGE_ADMIN);
    IPMIRegister(netfnIntcOEMGeneral, CmdGetOEMDeviceInfo, NULL,
                 IPMIOEMGetDeviceInfo, PRIVILEGE_USER);
    IPMIRegister(netfnIntcOEMGeneral, CmdGetAICSlotFRUIDSlotPosRecords, NULL,
                 IPMIOEMGetAICFRU, PRIVILEGE_USER);
    IPMIRegister(netfnIntcOEMGeneral, CmdSetPowerRestoreDelay, NULL,
                 IPMIOEMSetPowerRestoreDelay, PRIVILEGE_OPERATOR);
    IPMIRegister(netfnIntcOEMGeneral, CmdGetPowerRestoreDelay, NULL,
                 IPMIOEMGetPowerRestoreDelay, PRIVILEGE_USER);
    IPMIRegister(netfnIntcOEMGeneral, CmdGetProcessorErrConfig, NULL,
                 IPMIOEMGetProcessorErrConfig, PRIVILEGE_USER);
    IPMIRegister(netfnIntcOEMGeneral, CmdSetProcessorErrConfig, NULL,
                 IPMIOEMSetProcessorErrConfig, PRIVILEGE_ADMIN);
    return;
}

} // namespace ipmi
