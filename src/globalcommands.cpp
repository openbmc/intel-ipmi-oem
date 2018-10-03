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

void RegisterNetfnFirmwareFunctions() __attribute__((constructor));

ipmi_ret_t IPMIGlobalWildcard(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                              ipmi_request_t request, ipmi_response_t response,
                              ipmi_data_len_t dataLen, ipmi_context_t context)
{
    PrintCommand(+netfn, +cmd);
    *dataLen = 0;

    return IPMI_CC_INVALID;
}

ipmi_ret_t IPMIGlobalGetSelfTestResults(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                        ipmi_request_t request,
                                        ipmi_response_t response,
                                        ipmi_data_len_t dataLen,
                                        ipmi_context_t context)
{
    if (*dataLen)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

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

    auto msgReply = static_cast<GetSelfTestResultResp *>(response);
    *dataLen = sizeof(GetSelfTestResultResp);

    // TO DO Later: reply with self-Test result reflect boot POST code,
    // response with self-Test function not implemented for now.
    msgReply->selfTestCodeClass = 0x56;
    msgReply->selfTestCodeType = 0;

    return IPMI_CC_OK;
}

void RegisterNetfnFirmwareFunctions()
{
    // Handling wildcard
    PrintRegistration(NETFUN_APP, IPMI_CMD_WILDCARD);
    ipmi_register_callback(NETFUN_APP, IPMI_CMD_WILDCARD, NULL,
                           IPMIGlobalWildcard, PRIVILEGE_OPERATOR);

    // Get Self Test Results
    PrintRegistration(NETFUN_APP, ipmiCmdGlobalSelfTest);
    ipmi_register_callback(NETFUN_APP, ipmiCmdGlobalSelfTest, NULL,
                           IPMIGlobalGetSelfTestResults, PRIVILEGE_OPERATOR);

    return;
}
} // namespace ipmi
