/*
// Copyright (c) 2020 Intel Corporation
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

#include <array>
#include <fstream>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

constexpr uint8_t maxPayloadSupported = 0x6;
constexpr uint8_t maxHashSize = 64;
constexpr uint8_t maxSeedSize = 32;
constexpr uint8_t maxPasswordSize = 64;

#pragma pack(push, 1)
struct PayloadStartTransfer
{
    uint16_t payloadVersion;
    uint32_t payloadTotalSize;
    uint32_t payloadTotalChecksum;
    uint8_t payloadFlag;
};
#pragma pack(pop)

struct PayloadInProgress
{
    uint32_t payloadReservationID;
    uint32_t payloadOffset;
    uint32_t payloadCurrentSize;
    uint32_t payloadCurrentChecksum;
};

struct PayloadEndTransfer
{
    uint32_t payloadReservationID;
};

struct SetPayloadRetValue
{
    uint32_t reservationToken;
    uint32_t actualPayloadWritten;
    uint32_t actualTotalPayloadWritten;
};

struct setBIOSCapabilitiesReq
{
    uint8_t OOBCapability;
    uint8_t reserved1;
    uint8_t reserved2;
    uint8_t reserved3;
};

struct PayloadInfo
{
    uint32_t payloadReservationID;
    uint8_t payloadType;
    uint16_t payloadVersion;
    uint32_t payloadTotalSize;
    uint32_t payloadTotalChecksum;
    uint8_t payloadStatus;
    uint8_t payloadflag;
    uint32_t payloadTimeStamp;
    uint32_t payloadCurrentSize;
    uint32_t payloadCurrentChecksum;
    uint32_t actualTotalPayloadWritten;
};

struct NVOOBdata
{
    setBIOSCapabilitiesReq mBIOSCapabilities;
    uint8_t mIsBIOSCapInitDone;
    PayloadInfo payloadInfo[maxPayloadSupported];
};
