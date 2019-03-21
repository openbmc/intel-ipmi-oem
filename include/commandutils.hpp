/*
// Copyright (c) 2017 2018 Intel Corporation
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

#pragma once
#include <iostream>
#include <sdbusplus/bus.hpp>

static constexpr bool debug = false;

inline static void printRegistration(unsigned int netfn, unsigned int cmd)
{
    if constexpr (debug)
    {
        std::cout << "Registering NetFn:[0x" << std::hex << std::uppercase
                  << netfn << "], Cmd:[0x" << cmd << "]\n";
    }
}

inline static void ipmiPrintAndRegister(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_context_t context,
                                        ipmid_callback_t handler,
                                        ipmi_cmd_privilege_t priv)
{
    printRegistration(netfn, cmd);
    ipmi_register_callback(netfn, cmd, context, handler, priv);
}

inline static void printCommand(unsigned int netfn, unsigned int cmd)
{
    if constexpr (debug)
    {
        std::cout << "Executing NetFn:[0x" << std::hex << std::uppercase
                  << netfn << "], Cmd:[0x" << cmd << "]\n";
    }
}

namespace ipmi
{
using DbusVariant =
    sdbusplus::message::variant<std::string, bool, uint8_t, uint16_t, int16_t,
                                uint32_t, int32_t, uint64_t, int64_t, double>;
using GetSubTreeType = std::vector<
    std::pair<std::string,
              std::vector<std::pair<std::string, std::vector<std::string>>>>>;
} // namespace ipmi
