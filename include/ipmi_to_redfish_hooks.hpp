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

#pragma once
#include <storagecommands.hpp>

namespace intel_oem::ipmi::sel
{
bool checkRedfishHooks(AddSELRequest* selRequest);
bool checkRedfishHooks(uint8_t generatorID, uint8_t evmRev, uint8_t sensorType,
                       uint8_t sensorNum, uint8_t eventType, uint8_t eventData1,
                       uint8_t eventData2, uint8_t eventData3);
namespace redfish_hooks
{
struct SELData
{
    int generatorID;
    int sensorNum;
    int eventType;
    int offset;
    int eventData2;
    int eventData3;
};

enum class BIOSSensors
{
    memoryRASConfigStatus = 0x02,
    biosPOSTError = 0x06,
    intelUPILinkWidthReduced = 0x09,
    memoryRASModeSelect = 0x12,
    bootEvent = 0x83,
};

enum class BIOSSMISensors
{
    mirroringRedundancyState = 0x01,
    memoryECCError = 0x02,
    legacyPCIError = 0x03,
    pcieFatalError = 0x04,
    pcieCorrectableError = 0x05,
    sparingRedundancyState = 0x11,
    memoryParityError = 0x13,
    pcieFatalError2 = 0x14,
    biosRecovery = 0x15,
    adddcError = 0x20,
};

enum class BIOSEventTypes
{
    digitalDiscrete = 0x09,
    discreteRedundancyStates = 0x0b,
    sensorSpecificOffset = 0x6f,
    oemDiscrete0 = 0x70,
    oemDiscrete1 = 0x71,
    oemDiscrete6 = 0x76,
    oemDiscrete7 = 0x77,
    reservedA0 = 0xa0,
    reservedF0 = 0xf0,
};
} // namespace redfish_hooks
} // namespace intel_oem::ipmi::sel
