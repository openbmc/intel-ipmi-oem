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

#include <host-ipmid/ipmid-api.h>

#include <array>
#include <commandutils.hpp>
#include <host-ipmid/utils.hpp>
#include <iostream>
#include <oemcommands.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <string>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>

namespace ipmi
{
static void register_netfn_firmware_functions() __attribute__((constructor));
sdbusplus::bus::bus _dbus(ipmid_get_sd_bus_connection()); // from ipmid-api.h
static constexpr size_t maxFruStringLength = 0x3F;

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
            if (result.size() > maxFruStringLength)
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
ipmi_ret_t ipmiOEMWildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t data_len, ipmi_context_t context)
{
    std::cerr << "Handling OEM WILDCARD "
              << "Netfn:" << netfn << "Cmd:" << cmd << std::endl;
    // Status code.
    ipmi_ret_t rc = IPMI_CC_INVALID;
    *data_len = 0;
    return rc;
}

// Returns the Chassis Identifier (serial #)
ipmi_ret_t ipmiOEMGetChassisIdentifier(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
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

ipmi_ret_t ipmiOEMSetSystemGUID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t data_len,
                                    ipmi_context_t context)
{
    static constexpr size_t safeBufferLength = 50;
    char buf[safeBufferLength] = {0};
    GUIDData* Data = reinterpret_cast<GUIDData*>(request);

    if (*data_len != sizeof(GUIDData)) // 16bytes
    {
        *data_len = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    *data_len = 0;

    snprintf(
        buf, safeBufferLength,
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

ipmi_ret_t ipmiOEMSetBIOSID(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t dataLen, ipmi_context_t context)
{
    DeviceInfo* data = reinterpret_cast<DeviceInfo*>(request);

    if ((*dataLen < 2) || (*dataLen != (1 + data->biosIdLength)))
    {
        std::cerr << "len: " << *dataLen << "BIOSID len: " << data->biosIdLength
                  << std::endl;
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

ipmi_ret_t ipmiOEMGetDeviceInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen,
                                    ipmi_context_t context)
{
    GetOemDeviceInfoReq* req =
        reinterpret_cast<GetOemDeviceInfoReq*>(request);
    GetOemDeviceInfoRes* res =
        reinterpret_cast<GetOemDeviceInfoRes*>(response);

    if (*dataLen == 0)
    {
        std::cerr << "Paramter length should be at least one byte" << std::endl;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    size_t reqDataLen = *dataLen;
    *dataLen = 0;
    if (req->entityType > OEMDevEntityType::sdrVer)
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
        case OEMDevEntityType::biosId:
        {
            if (sizeof(GetOemDeviceInfoReq) != reqDataLen)
            {
                std::cerr << "dataLen " << reqDataLen << " does not match "
                          << sizeof(GetOemDeviceInfoReq) << std::endl;
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
                    std::cerr << "offset " << req->offset << " exceed "
                              << idString.size() << std::endl;
                    return IPMI_CC_PARM_OUT_OF_RANGE;
                }
                else
                {
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
            }
            catch (mapbox::util::bad_variant_access& e)
            {
                std::cerr << e.what() << std::endl;
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
    ipmi_register(netfunIntcOEMGeneral, IPMI_CMD_WILDCARD, NULL,
                  ipmiOEMWildcard,
                  PRIVILEGE_USER); // wildcard default handler
    ipmi_register(netfunIntcOEMGeneral, cmdGetChassisIdentifier, NULL,
                  ipmiOEMGetChassisIdentifier,
                  PRIVILEGE_USER); // get chassis identifier
    ipmi_register(netfunIntcOEMGeneral, cmdSetSystemGUID, NULL,
                  ipmiOEMSetSystemGUID,
                  PRIVILEGE_ADMIN); // set system guid
    ipmi_register(netfunIntcOEMGeneral, cmdSetBIOSID, NULL,
                  ipmiOEMSetBIOSID, PRIVILEGE_ADMIN);
    ipmi_register(netfunIntcOEMGeneral, cmdGetOEMDeviceInfo, NULL,
                  ipmiOEMGetDeviceInfo, PRIVILEGE_USER);
    ipmi_register(netfunIntcOEMGeneral,
                  cmdGetAICSlotFRUIDRecords, NULL,
                  ipmiOEMGetAICFRU, PRIVILEGE_USER);
    return;
}

} // namespace ipmi
