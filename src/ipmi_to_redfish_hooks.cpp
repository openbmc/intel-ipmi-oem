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

#include <boost/algorithm/string/join.hpp>
#include <boost/beast/core/span.hpp>
#include <iomanip>
#include <ipmi_to_redfish_hooks.hpp>
#include <phosphor-logging/log.hpp>
#include <sstream>
#include <storagecommands.hpp>

namespace intel_oem::ipmi::sel
{

namespace redfish_hooks
{
static std::string ipmiRaw;

static void toHexStr(const boost::beast::span<uint8_t> bytes,
                     std::string& hexStr)
{
    std::stringstream stream;
    stream << std::hex << std::uppercase << std::setfill('0');
    for (const uint8_t& byte : bytes)
    {
        stream << std::setw(2) << static_cast<int>(byte);
    }
    hexStr = stream.str();
}

// Record a BIOS message as a Redfish message instead of a SEL record
bool biosMessageHook(SELData& selData)
{
    // This is a BIOS message, so record it as a Redfish message instead
    // of a SEL record

    // Walk through the SEL request record to build the appropriate Redfish
    // message
    static const std::string oemIntelBIOSMessageRegistryVersion("0.1");
    std::string messageID = "IntelBIOS." + oemIntelBIOSMessageRegistryVersion;
    std::vector<std::string> messageArgs;
    switch (selData.sensorNum)
    {
        case 0x02: // Sensor Number
            switch (selData.eventType)
            {
                case 0x09: // Discrete Redundancy State
                {
                    switch (selData.offset)
                    {
                        case 0x00:
                            messageID += ".MemoryRASConfigurationDisabled";
                            break;
                        case 0x01:
                            messageID += ".MemoryRASConfigurationEnabled";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // error = eventData2 bits [3:0]
                    int error = selData.eventData2 & 0x0F;

                    // mode = eventData3 bits [3:0]
                    int mode = selData.eventData3 & 0x0F;

                    // Save the messageArgs
                    switch (error)
                    {
                        case 0x00:
                            messageArgs.push_back("None");
                            break;
                        case 0x03:
                            messageArgs.push_back("Invalid DIMM Config");
                            break;
                        default:
                            messageArgs.push_back(std::to_string(error));
                            break;
                    }
                    switch (mode)
                    {
                        case 0x00:
                            messageArgs.push_back("None");
                            break;
                        case 0x01:
                            messageArgs.push_back("Mirroring");
                            break;
                        case 0x02:
                            messageArgs.push_back("Lockstep");
                            break;
                        case 0x04:
                            messageArgs.push_back("Rank Sparing");
                            break;
                        default:
                            messageArgs.push_back(std::to_string(mode));
                            break;
                    }

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x06: // Sensor Number
            switch (selData.eventType)
            {
                case 0x6F: // Sensor Specific Offset
                {
                    switch (selData.offset)
                    {
                        case 0x00:
                            messageID += ".BIOSPOSTError";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    std::array<uint8_t, 2> post;
                    // post LSB = eventData2 bits [7:0]
                    post[1] = selData.eventData2;
                    // post MSB = eventData3 bits [7:0]
                    post[0] = selData.eventData3;

                    // Save the messageArgs
                    messageArgs.emplace_back();
                    std::string& postStr = messageArgs.back();
                    toHexStr(boost::beast::span<uint8_t>(post), postStr);

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x09: // Sensor Number
            switch (selData.eventType)
            {
                case 0x77: // OEM Discrete
                {
                    switch (selData.offset)
                    {
                        case 0x01:
                            messageID += ".IntelUPILinkWidthReducedToHalf";
                            break;
                        case 0x02:
                            messageID += ".IntelUPILinkWidthReducedToQuarter";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2

                    // Node ID = eventData2 bits [7:0]
                    int node = selData.eventData2;

                    // Save the messageArgs
                    messageArgs.push_back(std::to_string(node + 1));

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x12: // Sensor Number
            switch (selData.eventType)
            {
                case 0x09: // OEM Discrete
                {
                    switch (selData.offset)
                    {
                        case 0x00:
                            messageID += ".MemoryRASModeDisabled";
                            break;
                        case 0x01:
                            messageID += ".MemoryRASModeEnabled";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // prior mode = eventData2 bits [3:0]
                    int priorMode = selData.eventData2 & 0x0F;

                    // selected mode = eventData3 bits [3:0]
                    int selectedMode = selData.eventData3 & 0x0F;

                    // Save the messageArgs
                    switch (priorMode)
                    {
                        case 0x00:
                            messageArgs.push_back("None");
                            break;
                        case 0x01:
                            messageArgs.push_back("Mirroring");
                            break;
                        case 0x02:
                            messageArgs.push_back("Lockstep");
                            break;
                        case 0x04:
                            messageArgs.push_back("Rank Sparing");
                            break;
                        default:
                            messageArgs.push_back(std::to_string(priorMode));
                            break;
                    }
                    switch (selectedMode)
                    {
                        case 0x00:
                            messageArgs.push_back("None");
                            break;
                        case 0x01:
                            messageArgs.push_back("Mirroring");
                            break;
                        case 0x02:
                            messageArgs.push_back("Lockstep");
                            break;
                        case 0x04:
                            messageArgs.push_back("Rank Sparing");
                            break;
                        default:
                            messageArgs.push_back(std::to_string(selectedMode));
                            break;
                    }

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x83: // Sensor Number
            switch (selData.eventType)
            {
                case 0x6F: // Sensor Specific Offset
                {
                    switch (selData.offset)
                    {
                        case 0x01:
                            messageID += ".BIOSBoot";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        default:
            messageID += ".Unknown";
            messageArgs.push_back(ipmiRaw);
            break;
    }

    // Log the Redfish message to the journal with the appropriate metadata
    std::string journalMsg = "BIOS POST IPMI event: " + ipmiRaw;
    if (messageArgs.empty())
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            journalMsg.c_str(),
            phosphor::logging::entry("REDFISH_MESSAGE_ID=%s",
                                     messageID.c_str()));
    }
    else
    {
        std::string messageArgsString =
            boost::algorithm::join(messageArgs, ",");
        phosphor::logging::log<phosphor::logging::level::INFO>(
            journalMsg.c_str(),
            phosphor::logging::entry("REDFISH_MESSAGE_ID=%s",
                                     messageID.c_str()),
            phosphor::logging::entry("REDFISH_MESSAGE_ARGS=%s",
                                     messageArgsString.c_str()));
    }

    return true;
}

// Record a BIOS SMI message as a Redfish message instead of a SEL record
bool biosSMIMessageHook(SELData& selData)
{
    // This is a BIOS SMI message, so record it as a Redfish message instead
    // of a SEL record

    // Walk through the SEL request record to build the appropriate Redfish
    // message
    static const std::string oemIntelBIOSMessageRegistryVersion("0.1");
    std::string messageID = "IntelBIOS." + oemIntelBIOSMessageRegistryVersion;
    std::vector<std::string> messageArgs;
    switch (selData.sensorNum)
    {
        case 0x01: // Sensor Number
            switch (selData.eventType)
            {
                case 0x0B: // Discrete Redundancy State
                {
                    switch (selData.offset)
                    {
                        case 0x00:
                            messageID += ".MirroringRedundancyFull";
                            break;
                        case 0x02:
                            messageID += ".MirroringRedundancyDegraded";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // pair = eventData2 bits [7:4]
                    int pair = selData.eventData2 >> 4 & 0x0F;
                    // rank = eventData2 bits [1:0]
                    int rank = selData.eventData2 & 0x03;

                    // Socket ID = eventData3 bits [7:5]
                    int socket = selData.eventData3 >> 5 & 0x07;
                    // Channel = eventData3 bits [4:2]
                    int channel = selData.eventData3 >> 2 & 0x07;
                    char channelLetter[4] = {'A'};
                    channelLetter[0] += channel;
                    // DIMM = eventData3 bits [1:0]
                    int dimm = selData.eventData3 & 0x03;

                    // Save the messageArgs
                    messageArgs.push_back(std::to_string(socket + 1));
                    messageArgs.push_back(std::string(channelLetter));
                    messageArgs.push_back(std::to_string(dimm + 1));
                    messageArgs.push_back(std::to_string(pair));
                    messageArgs.push_back(std::to_string(rank));

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x02: // Sensor Number
            switch (selData.eventType)
            {
                case 0x6F: // Sensor Specific Offset
                {
                    switch (selData.offset)
                    {
                        case 0x00:
                            messageID += ".MemoryECCCorrectable";
                            break;
                        case 0x01:
                            messageID += ".MemoryECCUncorrectable";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // dimm = eventData2 bits [7:4]
                    int dimm = selData.eventData2 >> 4 & 0x0F;
                    // rank = eventData2 bits [3:0]
                    int rank = selData.eventData2 & 0x0F;

                    // Socket ID = eventData3 bits [7:4]
                    int socket = selData.eventData3 >> 4 & 0x0F;
                    // Channel = eventData3 bits [3:0]
                    int channel = selData.eventData3 & 0x0F;
                    char channelLetter[4] = {'A'};
                    channelLetter[0] += channel;

                    // Save the messageArgs
                    messageArgs.push_back(std::to_string(socket + 1));
                    messageArgs.push_back(std::string(channelLetter));
                    messageArgs.push_back(std::to_string(dimm));
                    messageArgs.push_back(std::to_string(rank));

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x03: // Sensor Number
            switch (selData.eventType)
            {
                case 0x6F: // Sensor Specific Offset
                {
                    switch (selData.offset)
                    {
                        case 0x04:
                            messageID += ".LegacyPCIPERR";
                            break;
                        case 0x05:
                            messageID += ".LegacyPCISERR";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // Bus = eventData2 bits [7:0]
                    int bus = selData.eventData2;
                    // Device = eventData3 bits [7:3]
                    int device = selData.eventData3 >> 3 & 0x1F;
                    // Function = eventData3 bits [2:0]
                    int function = selData.eventData3 >> 0x07;

                    // Save the messageArgs
                    messageArgs.push_back(std::to_string(bus));
                    messageArgs.push_back(std::to_string(device));
                    messageArgs.push_back(std::to_string(function));

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x04: // Sensor Number
            switch (selData.eventType)
            {
                case 0x70: // OEM Discrete
                {
                    switch (selData.offset)
                    {
                        case 0x00:
                            messageID += ".PCIeFatalDataLinkLayerProtocol";
                            break;
                        case 0x01:
                            messageID += ".PCIeFatalSurpriseLinkDown";
                            break;
                        case 0x02:
                            messageID += ".PCIeFatalCompleterAbort";
                            break;
                        case 0x03:
                            messageID += ".PCIeFatalUnsupportedRequest";
                            break;
                        case 0x04:
                            messageID += ".PCIeFatalPoisonedTLP";
                            break;
                        case 0x05:
                            messageID += ".PCIeFatalFlowControlProtocol";
                            break;
                        case 0x06:
                            messageID += ".PCIeFatalCompletionTimeout";
                            break;
                        case 0x07:
                            messageID += ".PCIeFatalReceiverBufferOverflow";
                            break;
                        case 0x08:
                            messageID += ".PCIeFatalACSViolation";
                            break;
                        case 0x09:
                            messageID += ".PCIeFatalMalformedTLP";
                            break;
                        case 0x0a:
                            messageID += ".PCIeFatalECRCError";
                            break;
                        case 0x0b:
                            messageID +=
                                ".PCIeFatalReceivedFatalMessageFromDownstream";
                            break;
                        case 0x0c:
                            messageID += ".PCIeFatalUnexpectedCompletion";
                            break;
                        case 0x0d:
                            messageID +=
                                ".PCIeFatalReceivedERR_NONFATALMessage";
                            break;
                        case 0x0e:
                            messageID += ".PCIeFatalUncorrectableInternal";
                            break;
                        case 0x0f:
                            messageID += ".PCIeFatalMCBlockedTLP";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // Bus = eventData2 bits [7:0]
                    int bus = selData.eventData2;
                    // Device = eventData3 bits [7:3]
                    int device = selData.eventData3 >> 3 & 0x1F;
                    // Function = eventData3 bits [2:0]
                    int function = selData.eventData3 >> 0x07;

                    // Save the messageArgs
                    messageArgs.push_back(std::to_string(bus));
                    messageArgs.push_back(std::to_string(device));
                    messageArgs.push_back(std::to_string(function));

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x05: // Sensor Number
            switch (selData.eventType)
            {
                case 0x71: // OEM Discrete
                {
                    switch (selData.offset)
                    {
                        case 0x00:
                            messageID += ".PCIeCorrectableReceiverError";
                            break;
                        case 0x01:
                            messageID += ".PCIeCorrectableBadDLLP";
                            break;
                        case 0x02:
                            messageID += ".PCIeCorrectableBadTLP";
                            break;
                        case 0x03:
                            messageID += ".PCIeCorrectableReplayNumRollover";
                            break;
                        case 0x04:
                            messageID += ".PCIeCorrectableReplayTimerTimeout";
                            break;
                        case 0x05:
                            messageID += ".PCIeCorrectableAdvisoryNonFatal";
                            break;
                        case 0x06:
                            messageID += ".PCIeCorrectableLinkBWChanged";
                            break;
                        case 0x07:
                            messageID += ".PCIeCorrectableInternal";
                            break;
                        case 0x08:
                            messageID += ".PCIeCorrectableHeaderLogOverflow";
                            break;
                        case 0x0f:
                            messageID += ".PCIeCorrectableUnspecifiedAERError";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // Bus = eventData2 bits [7:0]
                    int bus = selData.eventData2;
                    // Device = eventData3 bits [7:3]
                    int device = selData.eventData3 >> 3 & 0x1F;
                    // Function = eventData3 bits [2:0]
                    int function = selData.eventData3 >> 0x07;

                    // Save the messageArgs
                    messageArgs.push_back(std::to_string(bus));
                    messageArgs.push_back(std::to_string(device));
                    messageArgs.push_back(std::to_string(function));

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x11: // Sensor Number
            switch (selData.eventType)
            {
                case 0x0B: // Discrete Redundancy State
                {
                    switch (selData.offset)
                    {
                        case 0x00:
                            messageID += ".SparingRedundancyFull";
                            break;
                        case 0x02:
                            messageID += ".SparingRedundancyDegraded";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // domain = eventData2 bits [7:4]
                    int domain = selData.eventData2 >> 4 & 0x0F;
                    char domainLetter[4] = {'A'};
                    domainLetter[0] += domain;
                    // rank = eventData2 bits [1:0]
                    int rank = selData.eventData2 & 0x03;

                    // Socket ID = eventData3 bits [7:5]
                    int socket = selData.eventData3 >> 5 & 0x07;
                    // Channel = eventData3 bits [4:2]
                    int channel = selData.eventData3 >> 2 & 0x07;
                    char channelLetter[4] = {'A'};
                    channelLetter[0] += channel;
                    // DIMM = eventData3 bits [1:0]
                    int dimm = selData.eventData3 & 0x03;

                    // Save the messageArgs
                    messageArgs.push_back(std::to_string(socket + 1));
                    messageArgs.push_back(std::string(channelLetter));
                    messageArgs.push_back(std::to_string(dimm + 1));
                    messageArgs.push_back(std::string(domainLetter));
                    messageArgs.push_back(std::to_string(rank));

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x13: // Sensor Number
            switch (selData.eventType)
            {
                case 0x6f: // Sensor Specific Offset
                {
                    switch (selData.offset)
                    {
                        case 0x03:
                        {
                            // type = eventData2 bits [2:0]
                            int type = selData.eventData2 & 0x07;
                            switch (type)
                            {
                                case 0x00:
                                    messageID += ".MemoryParityNotKnown";
                                    break;
                                case 0x03:
                                    messageID +=
                                        ".MemoryParityCommandAndAddress";
                                    break;
                                default:
                                    messageID += ".Unknown";
                                    messageArgs.push_back(ipmiRaw);
                                    break;
                            }
                            break;
                        }
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // channelValid = eventData2 bit [4]
                    int channelValid = selData.eventData2 >> 4 & 0x01;
                    // dimmValid = eventData2 bit [3]
                    int dimmValid = selData.eventData2 >> 3 & 0x01;

                    // Socket ID = eventData3 bits [7:5]
                    int socket = selData.eventData3 >> 5 & 0x07;
                    // Channel = eventData3 bits [4:2]
                    int channel = selData.eventData3 >> 2 & 0x07;
                    char channelLetter[4] = {'A'};
                    channelLetter[0] += channel;
                    // DIMM = eventData3 bits [1:0]
                    int dimm = selData.eventData3 & 0x03;

                    // Save the messageArgs
                    messageArgs.push_back(std::to_string(socket + 1));
                    messageArgs.push_back(std::string(channelLetter));
                    messageArgs.push_back(std::to_string(dimm + 1));
                    messageArgs.push_back(std::to_string(channelValid));
                    messageArgs.push_back(std::to_string(dimmValid));

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x14: // Sensor Number
            switch (selData.eventType)
            {
                case 0x76: // OEM Discrete
                {
                    switch (selData.offset)
                    {
                        case 0x00:
                            messageID += ".PCIeFatalAtomicEgressBlocked";
                            break;
                        case 0x01:
                            messageID += ".PCIeFatalTLPPrefixBlocked";
                            break;
                        case 0x0f:
                            messageID +=
                                ".PCIeFatalUnspecifiedNonAERFatalError";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    // Get the message data from eventData2 and eventData3

                    // Bus = eventData2 bits [7:0]
                    int bus = selData.eventData2;
                    // Device = eventData3 bits [7:3]
                    int device = selData.eventData3 >> 3 & 0x1F;
                    // Function = eventData3 bits [2:0]
                    int function = selData.eventData3 >> 0x07;

                    // Save the messageArgs
                    messageArgs.push_back(std::to_string(bus));
                    messageArgs.push_back(std::to_string(device));
                    messageArgs.push_back(std::to_string(function));

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x15: // Sensor Number
            switch (selData.eventType)
            {
                case 0x70: // OEM Discrete
                {
                    switch (selData.offset)
                    {
                        case 0x01:
                            messageID += ".BIOSRecoveryStart";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    break;
                }
                case 0xf0: // OEM Discrete
                {
                    switch (selData.offset)
                    {
                        case 0x01:
                            messageID += ".BIOSRecoveryComplete";
                            break;
                        default:
                            messageID += ".Unknown";
                            messageArgs.push_back(ipmiRaw);
                            break;
                    }
                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        case 0x20: // Sensor Number
            switch (selData.eventType)
            {
                case 0xA0: // Correctable Error
                {
                    messageID += ".ADDDCCorrectable";

                    // Get the message data from eventData2 and eventData3

                    // dimm = eventData2 bits [7:4]
                    int dimm = selData.eventData2 >> 4 & 0x0F;
                    // rank = eventData2 bits [3:0]
                    int rank = selData.eventData2 & 0x0F;

                    // Socket ID = eventData3 bits [7:4]
                    int socket = selData.eventData3 >> 4 & 0x0F;
                    // Channel = eventData3 bits [3:0]
                    int channel = selData.eventData3 & 0x0F;
                    char channelLetter[4] = {'A'};
                    channelLetter[0] += channel;

                    // Save the messageArgs
                    messageArgs.push_back(std::to_string(socket + 1));
                    messageArgs.push_back(std::string(channelLetter));
                    messageArgs.push_back(std::to_string(dimm));
                    messageArgs.push_back(std::to_string(rank));

                    break;
                }
                default:
                    messageID += ".Unknown";
                    messageArgs.push_back(ipmiRaw);
                    break;
            }
            break;
        default:
            messageID += ".Unknown";
            messageArgs.push_back(ipmiRaw);
            break;
    }

    // Log the Redfish message to the journal with the appropriate metadata
    std::string journalMsg = "BIOS SMI IPMI event: " + ipmiRaw;
    std::string messageArgsString = boost::algorithm::join(messageArgs, ",");
    phosphor::logging::log<phosphor::logging::level::INFO>(
        journalMsg.c_str(),
        phosphor::logging::entry("REDFISH_MESSAGE_ID=%s", messageID.c_str()),
        phosphor::logging::entry("REDFISH_MESSAGE_ARGS=%s",
                                 messageArgsString.c_str()));

    return true;
}

bool startRedfishHook(SELData& selData)
{
    switch (selData.generatorID)
    {
        case 0x01: // Check if this message is from the BIOS Generator ID
            // Let the BIOS hook handle this request
            return biosMessageHook(selData);
            break;

        case 0x33: // Check if this message is from the BIOS SMI Generator ID
            // Let the BIOS SMI hook handle this request
            return biosSMIMessageHook(selData);
            break;
    }

    // No hooks handled the request, so let it go to the SEL
    return false;
}
} // namespace redfish_hooks

bool checkRedfishHooks(AddSELRequest* selRequest)
{
    // First check that this is a system event record type since that
    // determines the definition of the rest of the data
    if (selRequest->recordType != ipmi::sel::systemEvent)
    {
        // OEM record type, so let it go to the SEL
        return false;
    }

    // Save the raw IPMI string of the request
    const boost::beast::span<uint8_t> selBytes(
        reinterpret_cast<uint8_t*>(selRequest), sizeof(AddSELRequest));
    redfish_hooks::toHexStr(selBytes, redfish_hooks::ipmiRaw);

    // Extract the SEL data for the hook
    redfish_hooks::SELData selData = {
        .generatorID = selRequest->record.system.generatorID,
        .sensorNum = selRequest->record.system.sensorNum,
        .eventType = selRequest->record.system.eventType,
        .offset = selRequest->record.system.eventData[0] & 0x0F,
        .eventData2 = selRequest->record.system.eventData[1],
        .eventData3 = selRequest->record.system.eventData[2]};

    return redfish_hooks::startRedfishHook(selData);
}

bool checkRedfishHooks(uint8_t generatorID, uint8_t evmRev, uint8_t sensorType,
                       uint8_t sensorNum, uint8_t eventType, uint8_t eventData1,
                       uint8_t eventData2, uint8_t eventData3)
{
    // Save the raw IPMI string of the selData
    std::array selBytes = {generatorID, evmRev,     sensorType, sensorNum,
                           eventType,   eventData1, eventData2, eventData3};
    redfish_hooks::toHexStr(boost::beast::span<uint8_t>(selBytes),
                            redfish_hooks::ipmiRaw);

    // Extract the SEL data for the hook
    redfish_hooks::SELData selData = {.generatorID = generatorID,
                                      .sensorNum = sensorNum,
                                      .eventType = eventType,
                                      .offset = eventData1 & 0x0F,
                                      .eventData2 = eventData2,
                                      .eventData3 = eventData3};

    return redfish_hooks::startRedfishHook(selData);
}

} // namespace intel_oem::ipmi::sel
