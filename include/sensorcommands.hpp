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
#include <cstdint>

#pragma pack(push, 1)
struct SensorReadingResp
{
    uint8_t value;
    uint8_t operation;
    uint8_t indication[2];
};

struct SensorThresholdResp
{
    uint8_t readable;
    uint8_t lowernc;
    uint8_t lowercritical;
    uint8_t lowernonrecoverable;
    uint8_t uppernc;
    uint8_t uppercritical;
    uint8_t uppernonrecoverable;
};

struct SensorThresholdReq
{
    uint8_t sensorNum;
    uint8_t mask;
    uint8_t lowerNonCritical;
    uint8_t lowerCritical;
    uint8_t lowerNonRecoverable;
    uint8_t upperNonCritical;
    uint8_t upperCritical;
    uint8_t upperNonRecoverable;
};
#pragma pack(pop)

enum class SensorThresholdReqEnable : uint8_t
{
    setLowerNonCritical = 0x1,
    setLowerCritical = 0x2,
    setLowerNonRecoverable = 0x4,
    setUpperNonCritical = 0x8,
    setUpperCritical = 0x10,
    setUpperNonRecoverable = 0x20
};

#pragma pack(push, 1)
struct SensorEventEnableResp
{
    uint8_t enabled;
    uint8_t assertionEnabledLSB;
    uint8_t assertionEnabledMSB;
    uint8_t deassertionEnabledLSB;
    uint8_t deassertionEnabledMSB;
};

struct SensorEventStatusResp
{
    uint8_t enabled;
    uint8_t assertionsLSB;
    uint8_t assertionsMSB;
    uint8_t deassertionsLSB;
    uint8_t deassertionsMSB;
};
#pragma pack(pop)

enum class IPMIhresholdRespBits
{
    lowerNonCritical,
    lowerCritical,
    lowerNonRecoverable,
    upperNonCritical,
    upperCritical,
    upperNonRecoverable
};

enum class IPMISensorReadingByte2 : uint8_t
{
    eventMessagesEnable = (1 << 7),
    sensorScanningEnable = (1 << 6),
    readingStateUnavailable = (1 << 5),
};

enum class IPMISensorEventEnableByte2 : uint8_t
{
    eventMessagesEnable = (1 << 7),
    sensorScanningEnable = (1 << 6),
};

enum class IPMISensorEventEnableThresholds : uint8_t
{
    upperNonRecoverableGoingHigh = (1 << 3),
    upperNonRecoverableGoingLow = (1 << 2),
    upperCriticalGoingHigh = (1 << 1),
    upperCriticalGoingLow = (1 << 0),
    upperNonCriticalGoingHigh = (1 << 7),
    upperNonCriticalGoingLow = (1 << 6),
    lowerNonRecoverableGoingHigh = (1 << 5),
    lowerNonRecoverableGoingLow = (1 << 4),
    lowerCriticalGoingHigh = (1 << 3),
    lowerCriticalGoingLow = (1 << 2),
    lowerNonCriticalGoingHigh = (1 << 1),
    lowerNonCriticalGoingLow = (1 << 0),
};

enum class IPMINetfnSensorCmds : ipmi_cmd_t
{
    ipmiCmdGetDeviceSDRInfo = 0x20,
    ipmiCmdGetDeviceSDR = 0x21,
    ipmiCmdReserveDeviceSDRRepo = 0x22,
    ipmiCmdSetSensorThreshold = 0x26,
    ipmiCmdGetSensorThreshold = 0x27,
    ipmiCmdGetSensorEventEnable = 0x29,
    ipmiCmdGetSensorEventStatus = 0x2B,
    ipmiCmdGetSensorReading = 0x2D,
    ipmiCmdGetSensorType = 0x2F,
    ipmiCmdSetSensorReadingAndEventStatus = 0x30,
};

namespace ipmi
{
extern SensorSubTree sensorTree;
static ipmi_ret_t getSensorConnection(uint8_t sensnum, std::string &connection,
                                      std::string &path)
{
    if (sensorTree.empty() && !getSensorSubtree(sensorTree))
    {
        return IPMI_CC_RESPONSE_ERROR;
    }

    if (sensorTree.size() < (sensnum + 1))
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    uint8_t sensorIndex = sensnum;
    for (const auto &sensor : sensorTree)
    {
        if (sensorIndex-- == 0)
        {
            if (!sensor.second.size())
            {
                return IPMI_CC_RESPONSE_ERROR;
            }
            connection = sensor.second.begin()->first;
            path = sensor.first;
            break;
        }
    }

    return 0;
}
} // namespace ipmi
