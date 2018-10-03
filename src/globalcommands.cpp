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

#include <commandutils.hpp>
#include <globalcommands.hpp>
#include <iostream>
#include <sdbusplus/bus.hpp>
#include <string>

namespace ipmi
{

void register_netfn_firmware_functions() __attribute__((constructor));

ipmi_ret_t ipmi_global_wildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                ipmi_request_t request,
                                ipmi_response_t response,
                                ipmi_data_len_t data_len,
                                ipmi_context_t context)
{
    if (DEBUG)
        std::cout << "Handling Global WILDCARD NetFn:[0x" << std::hex
                  << std::uppercase << (unsigned int)netfn << "], Cmd:[0x"
                  << (unsigned int)cmd << "]\n";

    *data_len = 0;

    return IPMI_CC_INVALID;
}

ipmi_ret_t ipmi_global_get_self_test_results(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                             ipmi_request_t request,
                                             ipmi_response_t response,
                                             ipmi_data_len_t data_len,
                                             ipmi_context_t context)
{
    if (*data_len)
        return IPMI_CC_REQ_DATA_LEN_INVALID;

    // 1st Byte    2nd Byte     Description
    // 55h         00h          No error detected
    // 56h         00h          Self test function not implemented
    // 57h         01h          BMC operational code corrupted
    // 57h         02h          BMC boot/firmware update code corrupted
    // 57h         08h          SDR repository empty
    // 57h         10h          IPMB signal error
    // 57h         20h          BMC FRU device inaccessible
    // 57h         40h          BMC SDR repository inaccessible
    // 57h         80h          BMC SEL device inaccessible

    auto msg_reply = static_cast<getselftestresultresp_t *>(response);
    *data_len = sizeof(getselftestresultresp_t);

    // TO DO Later: reply with self-Test result reflect boot POST code,
    // response with self-Test function not implemented for now.
    msg_reply->selfTestCode_class = 0x56;
    msg_reply->selfTestCode_type = 0;

    return IPMI_CC_OK;
}

void register_netfn_firmware_functions()
{
    // Handling wildcard
    print_registration(NETFUN_APP, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WILDCARD, NULL,
                           ipmi_global_wildcard, PRIVILEGE_OPERATOR);

    // Get Self Test Results
    print_registration(NETFUN_APP, IPMI_CMD_GLOBAL_SELFTEST);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_GLOBAL_SELFTEST, NULL,
                           ipmi_global_get_self_test_results,
                           PRIVILEGE_OPERATOR);

    return;
}
} // namespace ipmi
