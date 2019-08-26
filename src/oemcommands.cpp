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
#include <com/intel/Control/NMISource/server.hpp>
#include <com/intel/Control/OCOTShutdownPolicy/server.hpp>
#include <commandutils.hpp>
#include <filesystem>
#include <iostream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <nlohmann/json.hpp>
#include <oemcommands.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>
#include <string>
#include <variant>
#include <vector>
#include <xyz/openbmc_project/Control/PowerSupplyRedundancy/server.hpp>

namespace ipmi
{
static void registerOEMFunctions() __attribute__((constructor));

namespace netfn::intel
{
constexpr NetFn oemGeneral = netFnOemOne;
constexpr Cmd cmdRestoreConfiguration = 0x02;
} // namespace netfn::intel

static constexpr size_t maxFRUStringLength = 0x3F;

static constexpr auto ethernetIntf =
    "xyz.openbmc_project.Network.EthernetInterface";
static constexpr auto networkIPIntf = "xyz.openbmc_project.Network.IP";
static constexpr auto networkService = "xyz.openbmc_project.Network";
static constexpr auto networkRoot = "/xyz/openbmc_project/network";

static constexpr const char* oemNmiSourceIntf = "com.intel.Control.NMISource";
static constexpr const char* oemNmiSourceObjPath =
    "/com/intel/control/NMISource";
static constexpr const char* oemNmiBmcSourceObjPathProp = "BMCSource";
static constexpr const char* oemNmiEnabledObjPathProp = "Enabled";

static constexpr const char* dimmOffsetFile = "/var/lib/ipmi/ipmi_dimms.json";

enum class NmiSource : uint8_t
{
    none = 0,
    fpBtn = 1,
    wdPreTimeout = 2,
    pefMatch = 3,
    chassisCmd = 4,
    memoryError = 5,
    pciSerrPerr = 6,
    southbridgeNmi = 7,
    chipsetNmi = 8,
};

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
            std::string& result = std::get<std::string>(variant);
            if (result.size() > maxFRUStringLength)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "FRU serial number exceed maximum length");
                return -1;
            }
            serial = result;
            return 0;
        }
        catch (std::bad_variant_access& e)
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
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    if (getChassisSerialNumber(*dbus, serial) == 0)
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
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service = getService(*dbus, intf, objpath);
    setDbusProperty(*dbus, service, objpath, intf, "UUID", guid);
    return IPMI_CC_OK;
}

ipmi::RspType<> ipmiOEMDisableBMCSystemReset(bool disableResetOnSMI,
                                             uint7_t reserved1)
{
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();

    try
    {
        auto service =
            ipmi::getService(*busp, bmcResetDisablesIntf, bmcResetDisablesPath);
        ipmi::setDbusProperty(*busp, service, bmcResetDisablesPath,
                              bmcResetDisablesIntf, "ResetOnSMI",
                              !disableResetOnSMI);
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set BMC reset disables",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<bool,   // disableResetOnSMI
              uint7_t // reserved
              >
    ipmiOEMGetBMCResetDisables()
{
    bool disableResetOnSMI = true;

    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*busp, bmcResetDisablesIntf, bmcResetDisablesPath);
        Value variant =
            ipmi::getDbusProperty(*busp, service, bmcResetDisablesPath,
                                  bmcResetDisablesIntf, "ResetOnSMI");
        disableResetOnSMI = !std::get<bool>(variant);
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get BMC reset disables",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(disableResetOnSMI, 0);
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

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service = getService(*dbus, biosIntf, biosObjPath);
    setDbusProperty(*dbus, service, biosObjPath, biosIntf, biosProp, idString);
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

            std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
            std::string service = getService(*dbus, biosIntf, biosObjPath);
            try
            {
                Value variant = getDbusProperty(*dbus, service, biosObjPath,
                                                biosIntf, biosProp);
                std::string& idString = std::get<std::string>(variant);
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
            catch (std::bad_variant_access& e)
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

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, powerRestoreDelayIntf, powerRestoreDelayObjPath);
    Value variant =
        getDbusProperty(*dbus, service, powerRestoreDelayObjPath,
                        powerRestoreDelayIntf, powerRestoreDelayProp);

    uint16_t delay = std::get<uint16_t>(variant);
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
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    std::string service =
        getService(*dbus, powerRestoreDelayIntf, powerRestoreDelayObjPath);
    setDbusProperty(*dbus, service, powerRestoreDelayObjPath,
                    powerRestoreDelayIntf, powerRestoreDelayProp, delay);
    *dataLen = 0;

    return IPMI_CC_OK;
}

static bool cpuPresent(const std::string& cpuName)
{
    static constexpr const char* cpuPresencePathPrefix =
        "/xyz/openbmc_project/inventory/system/chassis/motherboard/";
    static constexpr const char* cpuPresenceIntf =
        "xyz.openbmc_project.Inventory.Item";
    std::string cpuPresencePath = cpuPresencePathPrefix + cpuName;
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        auto service =
            ipmi::getService(*busp, cpuPresenceIntf, cpuPresencePath);

        ipmi::Value result = ipmi::getDbusProperty(
            *busp, service, cpuPresencePath, cpuPresenceIntf, "Present");
        return std::get<bool>(result);
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Cannot find processor presence",
            phosphor::logging::entry("NAME=%s", cpuName.c_str()));
        return false;
    }
}

ipmi::RspType<bool,    // CATERR Reset Enabled
              bool,    // ERR2 Reset Enabled
              uint6_t, // reserved
              uint8_t, // reserved, returns 0x3F
              uint6_t, // CPU1 CATERR Count
              uint2_t, // CPU1 Status
              uint6_t, // CPU2 CATERR Count
              uint2_t, // CPU2 Status
              uint6_t, // CPU3 CATERR Count
              uint2_t, // CPU3 Status
              uint6_t, // CPU4 CATERR Count
              uint2_t, // CPU4 Status
              uint8_t  // Crashdump Count
              >
    ipmiOEMGetProcessorErrConfig()
{
    bool resetOnCATERR = false;
    bool resetOnERR2 = false;
    uint6_t cpu1CATERRCount = 0;
    uint6_t cpu2CATERRCount = 0;
    uint6_t cpu3CATERRCount = 0;
    uint6_t cpu4CATERRCount = 0;
    uint8_t crashdumpCount = 0;
    uint2_t cpu1Status =
        cpuPresent("CPU_1") ? CPUStatus::enabled : CPUStatus::notPresent;
    uint2_t cpu2Status =
        cpuPresent("CPU_2") ? CPUStatus::enabled : CPUStatus::notPresent;
    uint2_t cpu3Status =
        cpuPresent("CPU_3") ? CPUStatus::enabled : CPUStatus::notPresent;
    uint2_t cpu4Status =
        cpuPresent("CPU_4") ? CPUStatus::enabled : CPUStatus::notPresent;

    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();
    try
    {
        auto service = ipmi::getService(*busp, processorErrConfigIntf,
                                        processorErrConfigObjPath);

        ipmi::PropertyMap result = ipmi::getAllDbusProperties(
            *busp, service, processorErrConfigObjPath, processorErrConfigIntf);
        resetOnCATERR = std::get<bool>(result.at("ResetOnCATERR"));
        resetOnERR2 = std::get<bool>(result.at("ResetOnERR2"));
        cpu1CATERRCount = std::get<uint8_t>(result.at("ErrorCountCPU1"));
        cpu2CATERRCount = std::get<uint8_t>(result.at("ErrorCountCPU2"));
        cpu3CATERRCount = std::get<uint8_t>(result.at("ErrorCountCPU3"));
        cpu4CATERRCount = std::get<uint8_t>(result.at("ErrorCountCPU4"));
        crashdumpCount = std::get<uint8_t>(result.at("CrashdumpCount"));
    }
    catch (const std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to fetch processor error config",
            phosphor::logging::entry("ERROR=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess(resetOnCATERR, resetOnERR2, 0, 0x3F,
                                 cpu1CATERRCount, cpu1Status, cpu2CATERRCount,
                                 cpu2Status, cpu3CATERRCount, cpu3Status,
                                 cpu4CATERRCount, cpu4Status, crashdumpCount);
}

ipmi::RspType<> ipmiOEMSetProcessorErrConfig(
    bool resetOnCATERR, bool resetOnERR2, uint6_t reserved1, uint8_t reserved2,
    std::optional<bool> clearCPUErrorCount,
    std::optional<bool> clearCrashdumpCount, std::optional<uint6_t> reserved3)
{
    std::shared_ptr<sdbusplus::asio::connection> busp = getSdBus();

    try
    {
        auto service = ipmi::getService(*busp, processorErrConfigIntf,
                                        processorErrConfigObjPath);
        ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                              processorErrConfigIntf, "ResetOnCATERR",
                              resetOnCATERR);
        ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                              processorErrConfigIntf, "ResetOnERR2",
                              resetOnERR2);
        if (clearCPUErrorCount.value_or(false))
        {
            ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                                  processorErrConfigIntf, "ErrorCountCPU1",
                                  static_cast<uint8_t>(0));
            ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                                  processorErrConfigIntf, "ErrorCountCPU2",
                                  static_cast<uint8_t>(0));
            ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                                  processorErrConfigIntf, "ErrorCountCPU3",
                                  static_cast<uint8_t>(0));
            ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                                  processorErrConfigIntf, "ErrorCountCPU4",
                                  static_cast<uint8_t>(0));
        }
        if (clearCrashdumpCount.value_or(false))
        {
            ipmi::setDbusProperty(*busp, service, processorErrConfigObjPath,
                                  processorErrConfigIntf, "CrashdumpCount",
                                  static_cast<uint8_t>(0));
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set processor error config",
            phosphor::logging::entry("EXCEPTION=%s", e.what()));
        return ipmi::responseUnspecifiedError();
    }

    return ipmi::responseSuccess();
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
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, oemShutdownPolicyIntf, oemShutdownPolicyObjPath);
        Value variant = getDbusProperty(
            *dbus, service, oemShutdownPolicyObjPath, oemShutdownPolicyIntf,
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
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, oemShutdownPolicyIntf, oemShutdownPolicyObjPath);
        setDbusProperty(
            *dbus, service, oemShutdownPolicyObjPath, oemShutdownPolicyIntf,
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
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        auto ethernetObj =
            getDbusObject(*dbus, networkIPIntf, networkRoot, ethIP);
        auto value = getDbusProperty(*dbus, networkService, ethernetObj.first,
                                     networkIPIntf, "Origin");
        if (std::get<std::string>(value) ==
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
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        auto objectInfo =
            getDbusObject(*dbus, networkIPIntf, networkRoot, ethIP);
        auto properties = getAllDbusProperties(*dbus, objectInfo.second,
                                               objectInfo.first, networkIPIntf);
        if (std::get<std::string>(properties["Origin"]) ==
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
        std::string strState = std::get<std::string>(stateValue);
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
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    for (auto it = ledAction::offsetObjPath.begin();
         it != ledAction::offsetObjPath.end(); ++it)
    {
        uint8_t state = 0;
        if (-1 == getLEDState(*dbus, ledIntf, it->second, state))
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
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    if (!getFanProfileInterface(*dbus, profileData))
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
        setDbusProperty(*dbus, settingsBusName, thermalModePath,
                        thermalModeInterface, "Current", mode);
    }

    return IPMI_CC_OK;
}

ipmi::RspType<uint8_t, // profile support map
              uint8_t, // fan control profile enable
              uint8_t, // flags
              uint32_t // dimm presence bit map
              >
    ipmiOEMGetFanConfig(uint8_t dimmGroupId)
{
    boost::container::flat_map<
        std::string, std::variant<std::vector<std::string>, std::string>>
        profileData;

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    if (!getFanProfileInterface(*dbus, profileData))
    {
        return ipmi::responseResponseError();
    }

    std::string* current = std::get_if<std::string>(&profileData["Current"]);

    if (current == nullptr)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetFanConfig: can't get current mode!");
        return ipmi::responseResponseError();
    }
    bool performance = (*current == "Performance");

    uint8_t flags = 0;
    if (performance)
    {
        flags |= 1 << 2;
    }

    return ipmi::responseSuccess(0, 0, flags, 0);
}
constexpr const char* cfmLimitSettingPath =
    "/xyz/openbmc_project/control/cfm_limit";
constexpr const char* cfmLimitIface = "xyz.openbmc_project.Control.CFMLimit";
constexpr const size_t legacyExitAirSensorNumber = 0x2e;
constexpr const size_t legacyPCHSensorNumber = 0x22;
constexpr const char* exitAirPathName = "Exit_Air";
constexpr const char* pchPathName = "SSB_Temp";
constexpr const char* pidConfigurationIface =
    "xyz.openbmc_project.Configuration.Pid";

static std::string getConfigPath(const std::string& name)
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto method =
        dbus->new_method_call("xyz.openbmc_project.ObjectMapper",
                              "/xyz/openbmc_project/object_mapper",
                              "xyz.openbmc_project.ObjectMapper", "GetSubTree");

    method.append("/", 0, std::array<const char*, 1>{pidConfigurationIface});
    std::string path;
    GetSubTreeType resp;
    try
    {
        auto reply = dbus->call(method);
        reply.read(resp);
    }
    catch (sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "ipmiOEMGetFscParameter: mapper error");
    };
    auto config =
        std::find_if(resp.begin(), resp.end(), [&name](const auto& pair) {
            return pair.first.find(name) != std::string::npos;
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
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    auto method =
        dbus->new_method_call("xyz.openbmc_project.ObjectMapper",
                              "/xyz/openbmc_project/object_mapper",
                              "xyz.openbmc_project.ObjectMapper", "GetSubTree");

    method.append("/", 0, std::array<const char*, 1>{pidConfigurationIface});
    GetSubTreeType resp;

    try
    {
        auto reply = dbus->call(method);
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
            ret.emplace(path,
                        getAllDbusProperties(*dbus, objects[0].first, path,
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

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
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
            ipmi::setDbusProperty(*dbus, "xyz.openbmc_project.EntityManager",
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

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    if (command == static_cast<uint8_t>(setFscParamFlags::tcontrol))
    {
        std::string pathName;
        if (param1 == legacyExitAirSensorNumber)
        {
            pathName = exitAirPathName;
        }
        else if (param1 == legacyPCHSensorNumber)
        {
            pathName = pchPathName;
        }
        else
        {
            return ipmi::responseParmOutOfRange();
        }
        std::string path = getConfigPath(pathName);
        ipmi::setDbusProperty(*dbus, "xyz.openbmc_project.EntityManager", path,
                              pidConfigurationIface, "SetPoint",
                              static_cast<double>(param2));
        return ipmi::responseSuccess();
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
            ipmi::setDbusProperty(*dbus, settingsBusName, cfmLimitSettingPath,
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
                        *dbus, "xyz.openbmc_project.EntityManager", path,
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
    constexpr uint8_t legacyDefaultSetpoint = -128;

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    if (command == static_cast<uint8_t>(setFscParamFlags::tcontrol))
    {
        if (!param)
        {
            return ipmi::responseReqDataLenInvalid();
        }

        std::string pathName;

        if (*param == legacyExitAirSensorNumber)
        {
            pathName = exitAirPathName;
        }
        else if (*param == legacyPCHSensorNumber)
        {
            pathName = pchPathName;
        }
        else
        {
            return ipmi::responseParmOutOfRange();
        }

        uint8_t setpoint = legacyDefaultSetpoint;
        std::string path = getConfigPath(pathName);
        if (path.size())
        {
            Value val = ipmi::getDbusProperty(
                *dbus, "xyz.openbmc_project.EntityManager", path,
                pidConfigurationIface, "SetPoint");
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
            cfmLimit = ipmi::getDbusProperty(*dbus, settingsBusName,
                                             cfmLimitSettingPath, cfmLimitIface,
                                             "Limit");
            cfmMaximum = ipmi::getDbusProperty(
                *dbus, "xyz.openbmc_project.ExitAirTempSensor",
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

using crConfigVariant =
    std::variant<bool, uint8_t, uint32_t, std::vector<uint8_t>, std::string>;

int setCRConfig(ipmi::Context::ptr ctx, const std::string& property,
                const crConfigVariant& value,
                std::chrono::microseconds timeout = ipmi::IPMI_DBUS_TIMEOUT)
{
    boost::system::error_code ec;
    ctx->bus->yield_method_call<void>(
        *(ctx->yield), ec, "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/power_supply_redundancy",
        "org.freedesktop.DBus.Properties", "Set",
        "xyz.openbmc_project.Control.PowerSupplyRedundancy", property, value);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to set dbus property to cold redundancy");
        return -1;
    }

    return 0;
}

int getCRConfig(ipmi::Context::ptr ctx, const std::string& property,
                crConfigVariant& value,
                std::chrono::microseconds timeout = ipmi::IPMI_DBUS_TIMEOUT)
{
    boost::system::error_code ec;
    value = ctx->bus->yield_method_call<crConfigVariant>(
        *(ctx->yield), ec, "xyz.openbmc_project.Settings",
        "/xyz/openbmc_project/control/power_supply_redundancy",
        "org.freedesktop.DBus.Properties", "Get",
        "xyz.openbmc_project.Control.PowerSupplyRedundancy", property);
    if (ec)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get dbus property to cold redundancy");
        return -1;
    }
    return 0;
}

uint8_t getPSUCount(void)
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    ipmi::Value num;
    try
    {
        num = ipmi::getDbusProperty(
            *dbus, "xyz.openbmc_project.PSURedundancy",
            "/xyz/openbmc_project/control/power_supply_redundancy",
            "xyz.openbmc_project.Control.PowerSupplyRedundancy", "PSUNumber");
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to get PSUNumber property from dbus interface");
        return 0;
    }
    uint8_t* pNum = std::get_if<uint8_t>(&num);
    if (!pNum)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error to get PSU Number");
        return 0;
    }
    return *pNum;
}

bool validateCRAlgo(std::vector<uint8_t>& conf, uint8_t num)
{
    if (conf.size() < num)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Invalid PSU Ranking");
        return false;
    }
    std::set<uint8_t> confSet;
    for (uint8_t i = 0; i < num; i++)
    {
        if (conf[i] > num)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "PSU Ranking is larger than current PSU number");
            return false;
        }
        confSet.emplace(conf[i]);
    }

    if (confSet.size() != num)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "duplicate PSU Ranking");
        return false;
    }
    return true;
}

enum class crParameter
{
    crStatus = 0,
    crFeature = 1,
    rotationFeature = 2,
    rotationAlgo = 3,
    rotationPeriod = 4,
    numOfPSU = 5
};

constexpr ipmi::Cc ccParameterNotSupported = 0x80;
static const constexpr uint32_t oneDay = 0x15180;
static const constexpr uint32_t oneMonth = 0xf53700;
static const constexpr uint8_t userSpecific = 0x01;
static const constexpr uint8_t crSetCompleted = 0;
ipmi::RspType<uint8_t> ipmiOEMSetCRConfig(ipmi::Context::ptr ctx,
                                          uint8_t parameter,
                                          ipmi::message::Payload& payload)
{
    switch (static_cast<crParameter>(parameter))
    {
        case crParameter::crFeature:
        {
            uint8_t param1;
            if (payload.unpack(param1) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            // ColdRedundancy Enable can only be true or flase
            if (param1 > 1)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (setCRConfig(ctx, "ColdRedundancyEnabled",
                            static_cast<bool>(param1)))
            {
                return ipmi::responseResponseError();
            }
            break;
        }
        case crParameter::rotationFeature:
        {
            uint8_t param1;
            if (payload.unpack(param1) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            // Rotation Enable can only be true or false
            if (param1 > 1)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (setCRConfig(ctx, "RotationEnabled", static_cast<bool>(param1)))
            {
                return ipmi::responseResponseError();
            }
            break;
        }
        case crParameter::rotationAlgo:
        {
            // Rotation Algorithm can only be 0-BMC Specific or 1-User Specific
            std::string algoName;
            uint8_t param1;
            if (payload.unpack(param1))
            {
                return ipmi::responseReqDataLenInvalid();
            }
            switch (param1)
            {
                case 0:
                    algoName = "xyz.openbmc_project.Control."
                               "PowerSupplyRedundancy.Algo.bmcSpecific";
                    break;
                case 1:
                    algoName = "xyz.openbmc_project.Control."
                               "PowerSupplyRedundancy.Algo.userSpecific";
                    break;
                default:
                    return ipmi::responseInvalidFieldRequest();
            }
            if (setCRConfig(ctx, "RotationAlgorithm", algoName))
            {
                return ipmi::responseResponseError();
            }

            uint8_t numberOfPSU = getPSUCount();
            if (!numberOfPSU)
            {
                return ipmi::responseResponseError();
            }
            std::vector<uint8_t> rankOrder;

            if (param1 == userSpecific)
            {
                if (payload.unpack(rankOrder) || !payload.fullyUnpacked())
                {
                    ipmi::responseReqDataLenInvalid();
                }
                if (rankOrder.size() < numberOfPSU)
                {
                    return ipmi::responseReqDataLenInvalid();
                }

                if (!validateCRAlgo(rankOrder, numberOfPSU))
                {
                    return ipmi::responseInvalidFieldRequest();
                }
            }
            else
            {
                if (rankOrder.size() > 0)
                {
                    return ipmi::responseReqDataLenInvalid();
                }
                for (uint8_t i = 1; i <= numberOfPSU; i++)
                {
                    rankOrder.emplace_back(i);
                }
            }
            if (setCRConfig(ctx, "RotationRankOrder", rankOrder))
            {
                return ipmi::responseResponseError();
            }
            break;
        }
        case crParameter::rotationPeriod:
        {
            // Minimum Rotation period is  One day (86400 seconds) and Max
            // Rotation Period is 6 month (0xf53700 seconds)
            uint32_t period;
            if (payload.unpack(period) || !payload.fullyUnpacked())
            {
                return ipmi::responseReqDataLenInvalid();
            }
            if ((period < oneDay) || (period > oneMonth))
            {
                return ipmi::responseInvalidFieldRequest();
            }
            if (setCRConfig(ctx, "PeriodOfRotation", period))
            {
                return ipmi::responseResponseError();
            }
            break;
        }
        default:
        {
            return ipmi::response(ccParameterNotSupported);
        }
    }

    // TODO Halfwidth needs to set SetInProgress
    if (setCRConfig(ctx, "ColdRedundancyStatus",
                    std::string("xyz.openbmc_project.Control."
                                "PowerSupplyRedundancy.Status.completed")))
    {
        return ipmi::responseResponseError();
    }
    return ipmi::responseSuccess(crSetCompleted);
}

ipmi::RspType<std::variant<uint8_t, uint32_t, std::array<uint8_t, 5>>>
    ipmiOEMGetCRConfig(ipmi::Context::ptr ctx, uint8_t parameter)
{
    crConfigVariant value;
    switch (static_cast<crParameter>(parameter))
    {
        case crParameter::crStatus:
        {
            if (getCRConfig(ctx, "ColdRedundancyStatus", value))
            {
                return ipmi::responseResponseError();
            }
            std::string* pStatus = std::get_if<std::string>(&value);
            if (!pStatus)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get ColdRedundancyStatus property");
                return ipmi::responseResponseError();
            }
            namespace server = sdbusplus::xyz::openbmc_project::Control::server;
            auto status =
                server::PowerSupplyRedundancy::convertStatusFromString(
                    *pStatus);
            switch (status)
            {
                case server::PowerSupplyRedundancy::Status::inProgress:
                    return ipmi::responseSuccess(static_cast<uint8_t>(0));

                case server::PowerSupplyRedundancy::Status::completed:
                    return ipmi::responseSuccess(static_cast<uint8_t>(1));
                default:
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Error to get valid status");
                    return ipmi::responseResponseError();
            }
        }
        case crParameter::crFeature:
        {
            if (getCRConfig(ctx, "ColdRedundancyEnabled", value))
            {
                return ipmi::responseResponseError();
            }
            bool* pResponse = std::get_if<bool>(&value);
            if (!pResponse)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get ColdRedundancyEnable property");
                return ipmi::responseResponseError();
            }

            return ipmi::responseSuccess(static_cast<uint8_t>(*pResponse));
        }
        case crParameter::rotationFeature:
        {
            if (getCRConfig(ctx, "RotationEnabled", value))
            {
                return ipmi::responseResponseError();
            }
            bool* pResponse = std::get_if<bool>(&value);
            if (!pResponse)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get RotationEnabled property");
                return ipmi::responseResponseError();
            }
            return ipmi::responseSuccess(static_cast<uint8_t>(*pResponse));
        }
        case crParameter::rotationAlgo:
        {
            if (getCRConfig(ctx, "RotationAlgorithm", value))
            {
                return ipmi::responseResponseError();
            }

            std::string* pAlgo = std::get_if<std::string>(&value);
            if (!pAlgo)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get RotationAlgorithm property");
                return ipmi::responseResponseError();
            }
            std::array<uint8_t, 5> response = {0, 0, 0, 0, 0};
            namespace server = sdbusplus::xyz::openbmc_project::Control::server;
            auto algo =
                server::PowerSupplyRedundancy::convertAlgoFromString(*pAlgo);
            switch (algo)
            {
                case server::PowerSupplyRedundancy::Algo::bmcSpecific:
                    response[0] = 0;
                    break;
                case server::PowerSupplyRedundancy::Algo::userSpecific:
                    response[0] = 1;
                    break;
                default:
                    phosphor::logging::log<phosphor::logging::level::ERR>(
                        "Error to get valid algo");
                    return ipmi::responseResponseError();
            }

            if (getCRConfig(ctx, "RotationRankOrder", value))
            {
                return ipmi::responseResponseError();
            }
            std::vector<uint8_t>* pResponse =
                std::get_if<std::vector<uint8_t>>(&value);
            if (!pResponse)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get RotationRankOrder property");
                return ipmi::responseResponseError();
            }
            if (pResponse->size() + 1 > response.size())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Incorrect size of RotationAlgorithm property");
                return ipmi::responseResponseError();
            }
            std::copy(pResponse->begin(), pResponse->end(),
                      response.begin() + 1);
            return ipmi::responseSuccess(response);
        }
        case crParameter::rotationPeriod:
        {
            if (getCRConfig(ctx, "PeriodOfRotation", value))
            {
                return ipmi::responseResponseError();
            }
            uint32_t* pResponse = std::get_if<uint32_t>(&value);
            if (!pResponse)
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Error to get RotationAlgorithm property");
                return ipmi::responseResponseError();
            }
            return ipmi::responseSuccess(*pResponse);
        }
        case crParameter::numOfPSU:
        {
            uint8_t numberOfPSU = getPSUCount();
            if (!numberOfPSU)
            {
                return ipmi::responseResponseError();
            }
            return ipmi::responseSuccess(numberOfPSU);
        }
        default:
        {
            return ipmi::response(ccParameterNotSupported);
        }
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

    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    try
    {
        service = getService(*dbus, intf, objpath);
        valueTree = getManagedObjects(*dbus, service, "/");
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

        auto method = dbus->new_method_call(
            service.c_str(), (std::string(item.first)).c_str(),
            "org.freedesktop.DBus.Properties", "Get");

        method.append("xyz.openbmc_project.Configuration.LedFault",
                      "LedGpioPins");

        try
        {
            auto reply = dbus->call(method);
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
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        const DbusObjectInfo& object = getDbusObject(
            *dbus, "xyz.openbmc_project.Inventory.Item.Board",
            "/xyz/openbmc_project/inventory/system/board/", "Baseboard");
        const Value& propValue = getDbusProperty(
            *dbus, object.second, object.first,
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

ipmi::RspType<uint8_t /* restore status */>
    ipmiRestoreConfiguration(const std::array<uint8_t, 3>& clr, uint8_t cmd)
{
    static constexpr std::array<uint8_t, 3> expClr = {'C', 'L', 'R'};

    if (clr != expClr)
    {
        return ipmi::responseInvalidFieldRequest();
    }
    constexpr uint8_t cmdStatus = 0;
    constexpr uint8_t cmdDefaultRestore = 0xaa;
    constexpr uint8_t cmdFullRestore = 0xbb;
    constexpr uint8_t cmdFormat = 0xcc;

    constexpr const char* restoreOpFname = "/tmp/.rwfs/.restore_op";

    switch (cmd)
    {
        case cmdStatus:
            break;
        case cmdDefaultRestore:
        case cmdFullRestore:
        case cmdFormat:
        {
            // write file to rwfs root
            int value = (cmd - 1) & 0x03; // map aa, bb, cc => 1, 2, 3
            std::ofstream restoreFile(restoreOpFname);
            if (!restoreFile)
            {
                return ipmi::responseUnspecifiedError();
            }
            restoreFile << value << "\n";
            break;
        }
        default:
            return ipmi::responseInvalidFieldRequest();
    }

    constexpr uint8_t restorePending = 0;
    constexpr uint8_t restoreComplete = 1;

    uint8_t restoreStatus = std::filesystem::exists(restoreOpFname)
                                ? restorePending
                                : restoreComplete;
    return ipmi::responseSuccess(restoreStatus);
}

ipmi::RspType<uint8_t> ipmiOEMGetNmiSource(void)
{
    uint8_t bmcSource;
    namespace nmi = sdbusplus::com::intel::Control::server;

    try
    {
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, oemNmiSourceIntf, oemNmiSourceObjPath);
        Value variant =
            getDbusProperty(*dbus, service, oemNmiSourceObjPath,
                            oemNmiSourceIntf, oemNmiBmcSourceObjPathProp);

        switch (nmi::NMISource::convertBMCSourceSignalFromString(
            std::get<std::string>(variant)))
        {
            case nmi::NMISource::BMCSourceSignal::None:
                bmcSource = static_cast<uint8_t>(NmiSource::none);
                break;
            case nmi::NMISource::BMCSourceSignal::FpBtn:
                bmcSource = static_cast<uint8_t>(NmiSource::fpBtn);
                break;
            case nmi::NMISource::BMCSourceSignal::WdPreTimeout:
                bmcSource = static_cast<uint8_t>(NmiSource::wdPreTimeout);
                break;
            case nmi::NMISource::BMCSourceSignal::PefMatch:
                bmcSource = static_cast<uint8_t>(NmiSource::pefMatch);
                break;
            case nmi::NMISource::BMCSourceSignal::ChassisCmd:
                bmcSource = static_cast<uint8_t>(NmiSource::chassisCmd);
                break;
            case nmi::NMISource::BMCSourceSignal::MemoryError:
                bmcSource = static_cast<uint8_t>(NmiSource::memoryError);
                break;
            case nmi::NMISource::BMCSourceSignal::PciSerrPerr:
                bmcSource = static_cast<uint8_t>(NmiSource::pciSerrPerr);
                break;
            case nmi::NMISource::BMCSourceSignal::SouthbridgeNmi:
                bmcSource = static_cast<uint8_t>(NmiSource::southbridgeNmi);
                break;
            case nmi::NMISource::BMCSourceSignal::ChipsetNmi:
                bmcSource = static_cast<uint8_t>(NmiSource::chipsetNmi);
                break;
            default:
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "NMI source: invalid property!",
                    phosphor::logging::entry(
                        "PROP=%s", std::get<std::string>(variant).c_str()));
                return ipmi::responseResponseError();
        }
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess(bmcSource);
}

ipmi::RspType<> ipmiOEMSetNmiSource(uint8_t sourceId)
{
    namespace nmi = sdbusplus::com::intel::Control::server;

    nmi::NMISource::BMCSourceSignal bmcSourceSignal =
        nmi::NMISource::BMCSourceSignal::None;

    switch (NmiSource(sourceId))
    {
        case NmiSource::none:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::None;
            break;
        case NmiSource::fpBtn:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::FpBtn;
            break;
        case NmiSource::wdPreTimeout:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::WdPreTimeout;
            break;
        case NmiSource::pefMatch:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::PefMatch;
            break;
        case NmiSource::chassisCmd:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::ChassisCmd;
            break;
        case NmiSource::memoryError:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::MemoryError;
            break;
        case NmiSource::pciSerrPerr:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::PciSerrPerr;
            break;
        case NmiSource::southbridgeNmi:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::SouthbridgeNmi;
            break;
        case NmiSource::chipsetNmi:
            bmcSourceSignal = nmi::NMISource::BMCSourceSignal::ChipsetNmi;
            break;
        default:
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "NMI source: invalid property!");
            return ipmi::responseResponseError();
    }

    try
    {
        // keep NMI signal source
        std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
        std::string service =
            getService(*dbus, oemNmiSourceIntf, oemNmiSourceObjPath);
        setDbusProperty(
            *dbus, service, oemNmiSourceObjPath, oemNmiSourceIntf,
            oemNmiBmcSourceObjPathProp,
            sdbusplus::com::intel::Control::server::convertForMessage(
                bmcSourceSignal));
        // set Enabled property to inform NMI source handling
        // to trigger a NMI_OUT BSOD.
        // if it's triggered by NMI source property changed,
        // NMI_OUT BSOD could be missed if the same source occurs twice in a row
        if (bmcSourceSignal != nmi::NMISource::BMCSourceSignal::None)
        {
            setDbusProperty(*dbus, service, oemNmiSourceObjPath,
                            oemNmiSourceIntf, oemNmiEnabledObjPathProp,
                            static_cast<bool>(true));
        }
    }
    catch (sdbusplus::exception_t& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return ipmi::responseResponseError();
    }

    return ipmi::responseSuccess();
}

namespace dimmOffset
{
constexpr const char* dimmPower = "DimmPower";
constexpr const char* staticCltt = "StaticCltt";
constexpr const char* offsetPath = "/xyz/openbmc_project/Inventory/Item/Dimm";
constexpr const char* offsetInterface =
    "xyz.openbmc_project.Inventory.Item.Dimm.Offset";
constexpr const char* property = "DimmOffset";

}; // namespace dimmOffset

ipmi::RspType<>
    ipmiOEMSetDimmOffset(uint8_t type,
                         const std::vector<std::tuple<uint8_t, uint8_t>>& data)
{
    if (type != static_cast<uint8_t>(dimmOffsetTypes::dimmPower) &&
        type != static_cast<uint8_t>(dimmOffsetTypes::staticCltt))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (data.empty())
    {
        return ipmi::responseInvalidFieldRequest();
    }
    nlohmann::json json;

    std::ifstream jsonStream(dimmOffsetFile);
    if (jsonStream.good())
    {
        json = nlohmann::json::parse(jsonStream, nullptr, false);
        if (json.is_discarded())
        {
            json = nlohmann::json();
        }
        jsonStream.close();
    }

    std::string typeName;
    if (type == static_cast<uint8_t>(dimmOffsetTypes::dimmPower))
    {
        typeName = dimmOffset::dimmPower;
    }
    else
    {
        typeName = dimmOffset::staticCltt;
    }

    nlohmann::json& field = json[typeName];

    for (const auto& [index, value] : data)
    {
        field[index] = value;
    }

    for (nlohmann::json& val : field)
    {
        if (val == nullptr)
        {
            val = static_cast<uint8_t>(0);
        }
    }

    std::ofstream output(dimmOffsetFile);
    if (!output.good())
    {
        std::cerr << "Error writing json file\n";
        return ipmi::responseResponseError();
    }

    output << json.dump(4);

    if (type == static_cast<uint8_t>(dimmOffsetTypes::staticCltt))
    {
        std::shared_ptr<sdbusplus::asio::connection> bus = getSdBus();

        std::variant<std::vector<uint8_t>> offsets =
            field.get<std::vector<uint8_t>>();
        auto call = bus->new_method_call(
            settingsBusName, dimmOffset::offsetPath, PROP_INTF, "Set");
        call.append(dimmOffset::offsetInterface, dimmOffset::property, offsets);
        try
        {
            bus->call(call);
        }
        catch (sdbusplus::exception_t& e)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "ipmiOEMSetDimmOffset: can't set dimm offsets!",
                phosphor::logging::entry("ERR=%s", e.what()));
            return ipmi::responseResponseError();
        }
    }

    return ipmi::responseSuccess();
}

ipmi::RspType<uint8_t> ipmiOEMGetDimmOffset(uint8_t type, uint8_t index)
{

    if (type != static_cast<uint8_t>(dimmOffsetTypes::dimmPower) &&
        type != static_cast<uint8_t>(dimmOffsetTypes::staticCltt))
    {
        return ipmi::responseInvalidFieldRequest();
    }

    std::ifstream jsonStream(dimmOffsetFile);

    auto json = nlohmann::json::parse(jsonStream, nullptr, false);
    if (json.is_discarded())
    {
        std::cerr << "File error in " << dimmOffsetFile << "\n";
        return ipmi::responseResponseError();
    }

    std::string typeName;
    if (type == static_cast<uint8_t>(dimmOffsetTypes::dimmPower))
    {
        typeName = dimmOffset::dimmPower;
    }
    else
    {
        typeName = dimmOffset::staticCltt;
    }

    auto it = json.find(typeName);
    if (it == json.end())
    {
        return ipmi::responseInvalidFieldRequest();
    }

    if (it->size() <= index)
    {
        return ipmi::responseInvalidFieldRequest();
    }

    uint8_t resp = it->at(index).get<uint8_t>();
    return ipmi::responseSuccess(resp);
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

    // <Disable BMC System Reset Action>
    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdDisableBMCSystemReset),
        ipmi::Privilege::Admin, ipmiOEMDisableBMCSystemReset);
    // <Get BMC Reset Disables>
    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdGetBMCResetDisables),
        ipmi::Privilege::Admin, ipmiOEMGetBMCResetDisables);

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

    // <Get Processor Error Config>
    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdGetProcessorErrConfig),
        ipmi::Privilege::User, ipmiOEMGetProcessorErrConfig);
    // <Set Processor Error Config>
    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetProcessorErrConfig),
        ipmi::Privilege::Admin, ipmiOEMSetProcessorErrConfig);

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

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(IPMINetfnIntelOEMGeneralCmd::cmdGetFanConfig),
        ipmi::Privilege::User, ipmiOEMGetFanConfig);

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
        static_cast<ipmi::Cmd>(IPMINetfnIntelOEMGeneralCmd::cmdGetNmiStatus),
        ipmi::Privilege::User, ipmiOEMGetNmiSource);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(IPMINetfnIntelOEMGeneralCmd::cmdSetNmiStatus),
        ipmi::Privilege::Operator, ipmiOEMSetNmiSource);

    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdGetLEDStatus),
        NULL, ipmiOEMGetLEDStatus, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(
        netfnIntcOEMPlatform,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMPlatformCmd::cmdCfgHostSerialPortSpeed),
        NULL, ipmiOEMCfgHostSerialPortSpeed, PRIVILEGE_ADMIN);
    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetFaultIndication),
        ipmi::Privilege::Operator, ipmiOEMSetFaultIndication);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetColdRedundancyConfig),
        ipmi::Privilege::User, ipmiOEMSetCRConfig);
    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(
            IPMINetfnIntelOEMGeneralCmd::cmdGetColdRedundancyConfig),
        ipmi::Privilege::User, ipmiOEMGetCRConfig);

    registerHandler(prioOemBase, netfn::intel::oemGeneral,
                    netfn::intel::cmdRestoreConfiguration, Privilege::Admin,
                    ipmiRestoreConfiguration);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(IPMINetfnIntelOEMGeneralCmd::cmdSetDimmOffset),
        ipmi::Privilege::Operator, ipmiOEMSetDimmOffset);

    ipmi::registerHandler(
        ipmi::prioOemBase, netfnIntcOEMGeneral,
        static_cast<ipmi::Cmd>(IPMINetfnIntelOEMGeneralCmd::cmdGetDimmOffset),
        ipmi::Privilege::Operator, ipmiOEMGetDimmOffset);
}

} // namespace ipmi
