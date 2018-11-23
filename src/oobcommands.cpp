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
#include <oobcommands.hpp>

namespace ipmi
{
static void initOOB() __attribute__((constructor));
sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection()); // from ipmid-api.h

static constexpr uint8_t imageTypes = 5; //0-XML type 0 / 1- xml type 1 / 2-bios image / 3- ME image / 4 -allinone (BIOS and ME) image

std::vector<DataTransfer> gPayload;

ipmi_ret_t ipmiOOBSetPayload(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request,
                             ipmi_response_t response,
                             ipmi_data_len_t dataLen,
                             ipmi_context_t context)
{
    SetPayloadReq*  pPayloadReq  = reinterpret_cast<SetPayloadReq*>(request);
    SetPayloadResp* pPayloadResp = reinterpret_cast<SetPayloadResp*>(response);
    uint32_t u32Crc;
    size_t   returnSize=0;
    OOBImageType currentPayloadType = pPayloadReq->payloadType;
    ipmi_ret_t rc=IPMI_CC_OK;

    //This is a must step as CurrentPayloadType == INVALID_IMG_TYPE after module init or each transfer complete.
    if (currentPayloadType >= OOBImageType::invalidType) {
        phosphor::logging::log<phosphor::logging::level::ERR>("invalid image type");
        *dataLen = 0;
        return OOBCompleteCode::compcodePayloadTypeNotSupported;
    }
    
    phosphor::logging::log<phosphor::logging::level::DEBUG>("PARASEL", phosphor::logging::entry("PARASEL=%x", pPayloadReq->paraSel));

    switch(pPayloadReq->paraSel) {
        case TransferState::PasswdAuth:
            break;
        case TransferState::StartTransfer:
            break;
        case TransferState::InProgress:
            break;
        case TransferState::EndOfTransfer:
            break;
        case TransferState::UserAbort:
            break;
        default:
            *dataLen = 0;
            rc = IPMI_CC_INVALID_FIELD_REQUEST;           
    }
    gPayload[1].status = pPayloadReq->paraSel;
    
    return rc;
}

static void initOOB(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "OOB module initialization");

    gPayload.reserve(imageTypes);

    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetPayload),
        NULL, ipmiOOBSetPayload, PRIVILEGE_ADMIN);
    
    return;
}

}

