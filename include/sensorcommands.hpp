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

struct SensorReadingResp
{
    uint8_t value;
    uint8_t operation;
    uint8_t indication[2];
} __attribute__((packed));

struct SensorThresholdResp
{
    uint8_t readable;
    uint8_t lowernc;
    uint8_t lowercritical;
    uint8_t lowernonrecoverable;
    uint8_t uppernc;
    uint8_t uppercritical;
    uint8_t uppernonrecoverable;
} __attribute__((packed));

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
} __attribute__((packed));

enum class SensorThresholdReqEnable : uint8_t
{
    setLowerNonCritical = 0x1,
    setLowerCritical = 0x2,
    setLowerNonRecoverable = 0x4,
    setUpperNonCritical = 0x8,
    setUpperCritical = 0x10,
    setUpperNonRecoverable = 0x20
};

struct SensorEventEnableResp
{
    uint8_t enabled;
    uint8_t assertionEnabledLSB;
    uint8_t assertionEnabledMSB;
    uint8_t deassertionEnabledLSB;
    uint8_t deassertionEnabledMSB;
} __attribute__((packed));

struct SensorEventStatusResp
{
    uint8_t enabled;
    uint8_t assertionsLSB;
    uint8_t assertionsMSB;
    // deassertion events currently not supported
    // uint8_t deassertionsLSB;
    // uint8_t deassertionsMSB;
} __attribute__((packed));

enum IpmiThresholdRespBits
{
    lowerNonCritical,
    lowerCritical,
    lowerNonRecoverable,
    upperNonCritical,
    upperCritical,
    upperNonRecoverable
};

enum IPMINetfnSensorCmds
{
    IPMICmdGetDeviceSDRInfo = 0x20,
    IPMICmdGetDeviceSDR = 0x21,
    IPMICmdReserveDeviceSDRRepo = 0x22,
    IPMICmdGetSensorThreshold = 0x27,
    IPMICmdSetSensorThreshold = 0x28,
    IPMICmdGetSensorEventEnable = 0x29,
    IPMICmdGetSensorEventStatus = 0x2B,
    IPMICmdGetSensorReading = 0x2D,
    IPMICmdGetSensorType = 0x2F,
    IPMICmdSetSensorReadingAndEventStatus = 0x30,
};
