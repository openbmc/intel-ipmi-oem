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

// #include <host-ipmid/ipmid-api.h>

// #include <boost/container/flat_map.hpp>
// #include <commandutils.hpp>
// #include <iostream>
// #include <phosphor-ipmi-host/selutility.hpp>
#include <phosphor-logging/log.hpp>
// #include <sdbusplus/message/types.hpp>
// #include <sdbusplus/timer.hpp>
// #include <sdrutils.hpp>
// #include <stdexcept>
#include <ipmi_to_redfish_hooks.hpp>
#include <storagecommands.hpp>
// #include <string_view>

namespace intel_oem::ipmi::sel
{
namespace redfish_hooks
{
bool biosMessageHook(AddSELRequest* selRequest)
{
    // First check that this is a system event record type since that
    // determines the definition of the rest of the data
    if (selRequest->recordType != intel_oem::ipmi::sel::systemEvent)
    {
        // OEM record type, so let it go to the SEL
        return false;
    }

    // Check if this message is from the BIOS Generator ID
    constexpr uint8_t biosID = 0x01;
    if (selRequest->record.system.generatorID != biosID)
    {
        // Not a BIOS message, so let it go to the SEL
        return false;
    }

    // This is a BIOS message, so record it as a Redfish message instead
    // of a SEL record

    // Walk through the SEL request record to build the appropriate Redfish
    // message

    return true;
}

bool biosSMIMessageHook(AddSELRequest* selRequest)
{
    // First check that this is a system event record type since that
    // determines the definition of the rest of the data
    if (selRequest->recordType != intel_oem::ipmi::sel::systemEvent)
    {
        // OEM record type, so let it go to the SEL
        return false;
    }

    // Check if this message is from the BIOS SMI Generator ID
    constexpr uint8_t biosSMIID = 0x33;
    if (selRequest->record.system.generatorID != biosSMIID)
    {
        // Not a BIOS SMI message, so let it go to the SEL
        return false;
    }

    // This is a BIOS SMI message, so record it as a Redfish message instead
    // of a SEL record

    // Walk through the SEL request record to build the appropriate Redfish
    // message
    std::string redfishMessage;
    std::string redfishMessageID;
    switch (selRequest->record.system.sensorNum)
    {
        case 0x01:
            redfishMessageID = "MirroringRedundancy";
            redfishMessage += "Mirroring redundancy state ";
            switch (selRequest->record.system.eventType)
            {
                case 0x0B:
                {
                    // Get the offset from eventData1 bits [3:0]
                    int offset = selRequest->record.system.eventData[0] & 0x0F;
                    switch (offset)
                    {
                        case 0x00:
                            redfishMessage += "fully redundant. ";
                            break;
                        case 0x02:
                            redfishMessage += "degraded. ";
                            break;
                        default:
                            redfishMessage +=
                                "unknown offset: " + std::to_string(offset);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // pair = eventData2 bits [7:4]
                    int pair =
                        selRequest->record.system.eventData[1] >> 4 & 0x0F;
                    // rank = eventData2 bits [1:0]
                    int rank = selRequest->record.system.eventData[1] & 0x03;

                    // Socket ID = eventData3 bits [7:5]
                    int socket =
                        selRequest->record.system.eventData[2] >> 5 & 0x07;
                    // Channel = eventData3 bits [4:2]
                    int channel =
                        selRequest->record.system.eventData[2] >> 2 & 0x07;
                    char channelLetter[4] = {'A'};
                    channelLetter[0] += channel;
                    // std::string channelLetter('A' + channel);
                    // DIMM = eventData3 bits [1:0]
                    int dimm = selRequest->record.system.eventData[2] & 0x03;

                    redfishMessage += "Socket=" + std::to_string(socket + 1) +
                                      " Channel=" + std::string(channelLetter) +
                                      " DIMM=" + std::to_string(dimm + 1) +
                                      " Pair=" + std::to_string(pair) +
                                      " Rank=" + std::to_string(rank) + ".";

                    break;
                }
                default:
                    redfishMessage +=
                        "unknown event type: " +
                        std::to_string(selRequest->record.system.eventType);
                    break;
            }
            break;
        default:
            redfishMessage +=
                "Unknown BIOS sensor number: " +
                std::to_string(selRequest->record.system.sensorNum);
            break;
    }

    // Log the Redfish message to the journal with the appropriate metadata
    phosphor::logging::log<phosphor::logging::level::INFO>(
        redfishMessage.c_str(),
        phosphor::logging::entry("REDFISH_MESSAGE_ID=%s",
                                 redfishMessageID.c_str()));
    // (journalMsg, std::string(msg.get_path()), eventData,
    //                    assert, selBMCGenID, "REDFISH_MESSAGE_ID=%.*s",
    //                    redfishMessageID.length(), redfishMessageID.data(),
    //                    "REDFISH_MESSAGE_ARG_1=%.*s", sensorName.length(),
    //                    sensorName.data(), "REDFISH_MESSAGE_ARG_2=%f",
    //                    sensorVal, "REDFISH_MESSAGE_ARG_3=%f", thresholdVal);

    return true;
}

bool meMessageHook(AddSELRequest* selRequest)
{
    // First check that this is a system event record type since that
    // determines the definition of the rest of the data
    if (selRequest->recordType != intel_oem::ipmi::sel::systemEvent)
    {
        // OEM record type, so let it go to the SEL
        return false;
    }

    // Check if this message is from the ME Generator ID
    constexpr uint8_t meID = 0x2C;
    if (selRequest->record.system.generatorID != meID)
    {
        // Not an ME message, so let it go to the SEL
        return false;
    }

    // This is an ME message, so record it as a Redfish message instead
    // of a SEL record

    return true;
}
} // namespace redfish_hooks

bool checkRedfishHooks(AddSELRequest* selRequest)
{
    // Check if the BIOS hook will handle this request
    if (redfish_hooks::biosMessageHook(selRequest))
    {
        return true;
    }

    // Check if the BIOS SMI hook will handle this request
    if (redfish_hooks::biosSMIMessageHook(selRequest))
    {
        return true;
    }

    // Check if the ME hook will handle this request
    if (redfish_hooks::meMessageHook(selRequest))
    {
        return true;
    }

    // No hooks handled the request, so let it go to the SEL
    return false;
}

} // namespace intel_oem::ipmi::sel
