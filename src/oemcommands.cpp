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
static void register_netfn_firmware_functions() __attribute__((constructor));
sdbusplus::bus::bus _dbus(ipmid_get_sd_bus_connection()); // from ipmid-api.h
static constexpr size_t MAX_FRU_STRING_LENGTH = 0x3F;

// return code: 0 successful
int8_t getChassisSerialNumber(sdbusplus::bus::bus& bus, std::string& serial)
{
    std::string objpath = "/xyz/openbmc_project/FruDevice";
    std::string intf = "xyz.openbmc_project.FruDeviceManager";
    std::string service = getService(bus, intf, objpath);
    if (DEBUG)
        std::cerr << "service : " << service << '\n';
    ObjectValueTree valueTree = getManagedObjects(bus, service, "/");
    if (valueTree.empty())
    {
        std::cerr << "No object implements " << intf << std::endl;
        return -1;
    }

    if (DEBUG)
    {
        std::cerr << "Tree.size() is " << valueTree.size() << '\n';
    }
    for (auto& item : valueTree)
    {
        if (DEBUG)
            std::cerr << "objpath : " << std::string(item.first) << '\n';
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
            if (result.size() > MAX_FRU_STRING_LENGTH)
            {
                std::cerr << "FRU serial number exceed maximum length"
                          << std::endl;
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
            std::cerr << e.what() << std::endl;
            return -1;
        }
    }
    return -1;
}
ipmi_ret_t ipmi_oem_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    std::cerr << "Handling OEM WILDCARD "
              << "Netfn:" << std::hex << +netfn << " Cmd:" << +cmd << std::endl;
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *data_len = 0;
    return rc;
}

// Returns the Chassis Identifier (serial #)
ipmi_ret_t ipmi_oem_get_chassis_identifier(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                           ipmi_request_t request,
                                           ipmi_response_t response,
                                           ipmi_data_len_t data_len,
                                           ipmi_context_t context)
{
    std::string serial;
    if (*data_len != 0) // invalid request if there are extra parameters
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    if (getChassisSerialNumber(_dbus, serial) == 0)
    {
        *data_len = serial.size(); // length will never exceed response length
                                   // as it is checked in getChassisSerialNumber
        char* resp = static_cast<char*>(response);
        serial.copy(resp, *data_len);
        return IPMI_CC_OK;
    }
    else
    {
        *data_len = 0;
        return IPMI_CC_RESPONSE_ERROR;
    }
}

ipmi_ret_t ipmi_oem_set_system_guid(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    static constexpr size_t SAFE_BUF_LEN = 50;
    char buf[SAFE_BUF_LEN] = {0};
    sGuidData* Data = reinterpret_cast<sGuidData*>(request);

    if (*data_len != sizeof(sGuidData)) // 16bytes
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    snprintf(
        buf, SAFE_BUF_LEN,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        Data->timeLow4, Data->timeLow3, Data->timeLow2, Data->timeLow1,
        Data->timeMid2, Data->timeMid1, Data->timeHigh2, Data->timeHigh1,
        Data->clock2, Data->clock1, Data->node6, Data->node5, Data->node4,
        Data->node3, Data->node2, Data->node1);
    // UUID is in RFC4122 format. Ex: 61a39523-78f2-11e5-9862-e6402cfc3223
    std::string guid = buf;
    if (DEBUG)
    {
        std::cerr << "GUID:" << guid << '\n';
    }

    std::string objpath = "/xyz/openbmc_project/control/host0/systemGUID";
    std::string intf = "xyz.openbmc_project.Common.UUID";
    std::string service = getService(_dbus, intf, objpath);
    setDbusProperty(_dbus, service, objpath, intf, "UUID", guid);
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_oem_set_bios_id(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t dataLen, ipmi_context_t context)
{
    sDeviceInfo* data = reinterpret_cast<sDeviceInfo*>(request);

    if ((*dataLen < 2) || (*dataLen != (1 + data->biosIdLength)))
    {
        std::cerr << "len: " << *dataLen
                  << "BIOSID len: " << +data->biosIdLength << std::endl;
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    std::string idString((char*)data->biosId, data->biosIdLength);
    if (DEBUG)
    {
        std::cerr << "len:" << (int)(data->biosIdLength) << '\n';
        std::cerr << "idString:" << idString << '\n';
    }

    std::string service = getService(_dbus, biosIntf, biosObjPath);
    setDbusProperty(_dbus, service, biosObjPath, biosIntf, biosProp, idString);
    uint8_t* bytesWritten = static_cast<uint8_t*>(response);
    *bytesWritten =
        data->biosIdLength; // how many bytes are written into storage
    *dataLen = 1;
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_oem_get_device_info(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen,
                                    ipmi_context_t context)
{
    sGetOemDeviceInfoReq* req =
        reinterpret_cast<sGetOemDeviceInfoReq*>(request);
    sGetOemDeviceInfoRes* res =
        reinterpret_cast<sGetOemDeviceInfoRes*>(response);

    if (*dataLen == 0)
    {
        std::cerr << "Paramter length should be at least one byte" << std::endl;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint32_t reqDataLen = *dataLen;
    *dataLen = 0;
    if (req->entityType > eOemDevEntityType::sdrVer)
    {
        std::cerr << req->entityType << " out of range " << std::endl;
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    if (DEBUG)
    {
        std::cerr << "Reqtype:" << (int)(req->entityType) << '\n';
        std::cerr << "Cnt:" << (int)(req->countToRead) << '\n';
        std::cerr << "Offset:" << (int)(req->offset) << '\n';
    }

    // handle OEM command items
    switch (req->entityType)
    {
        case eOemDevEntityType::biosId:
        {
            if (sizeof(sGetOemDeviceInfoReq) != reqDataLen)
            {
                std::cerr << "dataLen " << reqDataLen << " does not match "
                          << sizeof(sGetOemDeviceInfoReq) << std::endl;
                return IPMI_CC_REQ_DATA_LEN_INVALID;
            }

            std::string service = getService(_dbus, biosIntf, biosObjPath);
            try
            {
                Value variant = getDbusProperty(_dbus, service, biosObjPath,
                                                biosIntf, biosProp);
                std::string& idString = variant.get<std::string>();
                if (req->offset >= idString.size())
                {
                    std::cerr << "offset " << +req->offset << " exceed "
                              << idString.size() << std::endl;
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
                std::cerr << e.what() << std::endl;
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
        }
        break;

        case eOemDevEntityType::devVer:
        case eOemDevEntityType::sdrVer:
            // TODO:
            return IPMI_CC_ILLEGAL_COMMAND;
        default:
            return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_oem_get_aic_fru(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t dataLen, ipmi_context_t context)
{
    if (*dataLen != 0)
    {
        std::cerr << "this command should not have any paramter" << std::endl;
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

ipmi_ret_t ipmi_oem_get_power_restore_delay(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                            ipmi_request_t request,
                                            ipmi_response_t response,
                                            ipmi_data_len_t dataLen,
                                            ipmi_context_t context)
{
    sGetPowerRestoreDelayRes* resp =
        reinterpret_cast<sGetPowerRestoreDelayRes*>(response);

    if (*dataLen != 0)
    {
        std::cerr << "this command should not have any parameter" << std::endl;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::string service =
        getService(_dbus, powerRestoreDelayIntf, powerRestoreDelayObjPath);
    Value variant =
        getDbusProperty(_dbus, service, powerRestoreDelayObjPath,
                        powerRestoreDelayIntf, powerRestoreDelayProp);

    uint16_t delay = variant.get<uint16_t>();
    resp->byteLSB = delay;
    resp->byteMSB = delay >> 8;

    *dataLen = 2;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_oem_set_power_restore_delay(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                            ipmi_request_t request,
                                            ipmi_response_t response,
                                            ipmi_data_len_t dataLen,
                                            ipmi_context_t context)
{
    sSetPowerRestoreDelayReq* data =
        reinterpret_cast<sSetPowerRestoreDelayReq*>(request);
    uint16_t delay = 0;

    if (*dataLen != 2)
    {
        std::cerr << "len: " << *dataLen << std::endl;
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    delay = data->byteMSB;
    delay = (delay << 8) | data->byteLSB;
    std::string service =
        getService(_dbus, powerRestoreDelayIntf, powerRestoreDelayObjPath);
    setDbusProperty(_dbus, service, powerRestoreDelayObjPath,
                    powerRestoreDelayIntf, powerRestoreDelayProp, delay);
    *dataLen = 0;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_oem_get_processor_err_config(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                             ipmi_request_t request,
                                             ipmi_response_t response,
                                             ipmi_data_len_t dataLen,
                                             ipmi_context_t context)
{
    sGetProcessorErrConfigRes* resp =
        reinterpret_cast<sGetProcessorErrConfigRes*>(response);

    if (*dataLen != 0)
    {
        std::cerr << "this command should not have any parameter" << std::endl;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    std::string service =
        getService(_dbus, processorErrConfigIntf, processorErrConfigObjPath);
    Value variant = getDbusProperty(_dbus, service, processorErrConfigObjPath,
                                    processorErrConfigIntf, "ResetCfg");
    resp->u8ResetCfg = variant.get<uint8_t>();

    std::vector<uint8_t> vCATERRStatus;

    auto method =
        _dbus.new_method_call(service.c_str(), processorErrConfigObjPath,
                              "org.freedesktop.DBus.Properties", "Get");

    method.append(processorErrConfigIntf, "CATERRStatus");

    auto reply = _dbus.call(method);

    if (reply.is_method_error())
    {
        std::cerr << "PROPERTY:CATERRStatus" << '\n';
        std::cerr << "PATH:" << processorErrConfigObjPath << '\n';
        std::cerr << "INTERFACE:" << processorErrConfigIntf << std::endl;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    reply.read(vCATERRStatus);

    unsigned char len =
        maxCPUNum <= vCATERRStatus.size() ? maxCPUNum : vCATERRStatus.size();
    vCATERRStatus.resize(len);
    std::copy(vCATERRStatus.begin(), vCATERRStatus.end(), resp->u8CATERRStatus);
    *dataLen = sizeof(sGetProcessorErrConfigRes);

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_oem_set_processor_err_config(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                             ipmi_request_t request,
                                             ipmi_response_t response,
                                             ipmi_data_len_t dataLen,
                                             ipmi_context_t context)
{
    sSetProcessorErrConfigReq* req =
        reinterpret_cast<sSetProcessorErrConfigReq*>(request);

    if (*dataLen != 3)
    {
        std::cerr << "len: " << *dataLen << std::endl;
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    std::string service =
        getService(_dbus, processorErrConfigIntf, processorErrConfigObjPath);
    setDbusProperty(_dbus, service, processorErrConfigObjPath,
                    processorErrConfigIntf, "ResetCfg", req->u8ResetCfg);

    setDbusProperty(_dbus, service, processorErrConfigObjPath,
                    processorErrConfigIntf, "ResetErrorOccurrenceCounts",
                    req->resetErrorOccurrenceCounts);
    *dataLen = 0;

    return IPMI_CC_OK;
}

void ipmi_register(ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_context_t context,
                   ipmid_callback_t handler, ipmi_cmd_privilege_t priv)
{
    print_registration(netfn, cmd);
    ipmi_register_callback(netfn, cmd, context, handler, priv);
}

static void register_netfn_firmware_functions(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering OEM commands");
    ipmi_register(NETFUN_INTC_OEM_GENERAL, IPMI_CMD_WILDCARD, NULL,
                  ipmi_oem_wildcard,
                  PRIVILEGE_USER); // wildcard default handler
    ipmi_register(NETFUN_INTC_OEM_GENERAL, CMD_GET_CHASSIS_IDENTIFIER, NULL,
                  ipmi_oem_get_chassis_identifier,
                  PRIVILEGE_USER); // get chassis identifier
    ipmi_register(NETFUN_INTC_OEM_GENERAL, CMD_SET_SYSTEM_GUID, NULL,
                  ipmi_oem_set_system_guid,
                  PRIVILEGE_ADMIN); // set system guid
    ipmi_register(NETFUN_INTC_OEM_GENERAL, CMD_SET_BIOS_ID, NULL,
                  ipmi_oem_set_bios_id, PRIVILEGE_ADMIN);
    ipmi_register(NETFUN_INTC_OEM_GENERAL, CMD_GET_OEM_DEVICE_INFO, NULL,
                  ipmi_oem_get_device_info, PRIVILEGE_USER);
    ipmi_register(NETFUN_INTC_OEM_GENERAL,
                  CMD_GET_AIC_SLOT_FRUID_SLOTPOS_RECORDS, NULL,
                  ipmi_oem_get_aic_fru, PRIVILEGE_USER);
    ipmi_register(NETFUN_INTC_OEM_GENERAL, CMD_SET_POWER_RESTORE_DELAY, NULL,
                  ipmi_oem_set_power_restore_delay, PRIVILEGE_OPERATOR);
    ipmi_register(NETFUN_INTC_OEM_GENERAL, CMD_GET_POWER_RESTORE_DELAY, NULL,
                  ipmi_oem_get_power_restore_delay, PRIVILEGE_USER);
    ipmi_register(NETFUN_INTC_OEM_GENERAL, CMD_GET_PROCESSOR_ERR_CONFIG, NULL,
                  ipmi_oem_get_processor_err_config, PRIVILEGE_USER);
    ipmi_register(NETFUN_INTC_OEM_GENERAL, CMD_SET_PROCESSOR_ERR_CONFIG, NULL,
                  ipmi_oem_set_processor_err_config, PRIVILEGE_ADMIN);
    return;
}

} // namespace ipmi
