/*
// Copyright (c) 2019 Intel Corporation
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

#include <array>
#include <boost/container/flat_map.hpp>
#include <boost/process/child.hpp>
#include <boost/process/io.hpp>
#include <commandutils.hpp>
#include <iostream>
#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <multinodecommands.hpp>
#include <oemcommands.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/types.hpp>
#include <string>
#include <variant>
#include <vector>

namespace ipmi
{
void registerMultiNodeFunctions() __attribute__((constructor));
static sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());

int8_t getMultiNodeInfo(std::string name, uint8_t& value)
{
    try
    {
        std::string service = getService(dbus, multiNodeIntf, multiNodeObjPath);
        Value dbusValue = getDbusProperty(dbus, service, multiNodeObjPath,
                                          multiNodeIntf, name);
        value = sdbusplus::message::variant_ns::get<uint8_t>(dbusValue);
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return -1;
    }
    return 0;
}

int8_t getMultiNodeRole(uint8_t& value)
{
    try
    {
        std::string service = getService(dbus, multiNodeIntf, multiNodeObjPath);
        Value dbusValue = getDbusProperty(dbus, service, multiNodeObjPath,
                                          multiNodeIntf, "NodeRole");
        std::string valueStr =
            sdbusplus::message::variant_ns::get<std::string>(dbusValue);
        if (valueStr == "single")
            value = static_cast<uint8_t>(NodeRole::single);
        else if (valueStr == "master")
            value = static_cast<uint8_t>(NodeRole::master);
        else if (valueStr == "slave")
            value = static_cast<uint8_t>(NodeRole::slave);
        else if (valueStr == "arbitrating")
            value = static_cast<uint8_t>(NodeRole::arbitrating);
    }
    catch (sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(e.what());
        return -1;
    }
    return 0;
}

ipmi_ret_t ipmiGetMultiNodePresence(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                    ipmi_request_t request,
                                    ipmi_response_t response,
                                    ipmi_data_len_t dataLen,
                                    ipmi_context_t context)
{
    if (*dataLen != 0)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t value = 0;
    if (getMultiNodeInfo("NodePresence", value) == -1)
    {
        *dataLen = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    uint8_t* resp = reinterpret_cast<uint8_t*>(response);
    *resp = value;
    *dataLen = 1;
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiGetMultiNodeId(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t dataLen, ipmi_context_t context)
{
    if (*dataLen != 0)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t value = 0;
    if (getMultiNodeInfo("NodeId", value) == -1)
    {
        *dataLen = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    uint8_t* resp = reinterpret_cast<uint8_t*>(response);
    *resp = value;
    *dataLen = 1;
    return IPMI_CC_OK;
}

ipmi_ret_t ipmiGetMultiNodeRole(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t dataLen, ipmi_context_t context)
{
    if (*dataLen != 0)
    {
        *dataLen = 0;
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t value = 0;
    if (getMultiNodeRole(value) == -1)
    {
        *dataLen = 0;
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    uint8_t* resp = reinterpret_cast<uint8_t*>(response);
    *resp = value;
    *dataLen = 1;
    return IPMI_CC_OK;
}

void registerMultiNodeFunctions(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "Registering MultiNode commands");

    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnMultiNodeCmd::cmdGetMultiNodePresence),
        NULL, ipmiGetMultiNodePresence, PRIVILEGE_USER);

    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnMultiNodeCmd::cmdGetMultiNodeId), NULL,
        ipmiGetMultiNodeId, PRIVILEGE_USER);

    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnMultiNodeCmd::cmdGetMultiNodeRole),
        NULL, ipmiGetMultiNodeRole, PRIVILEGE_USER);
    return;
}

} // namespace ipmi
