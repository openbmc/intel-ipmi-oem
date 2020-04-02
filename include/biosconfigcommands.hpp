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

#pragma pack(push, 1)

struct PayloadStartTransfer
{
    uint8_t payloadType;
    uint16_t payloadVersion;
    uint32_t payloadTotalSize;
    uint32_t payloadTotalChecksum;
    uint32_t payloadFlag;
};
struct PayloadInProgress
{
    uint8_t payloadType;
    uint32_t payloadReservationID;
    uint32_t payloadCurrentSize;
    uint32_t payloadCurrentChecksum;
};

struct PayloadEndTransfer
{
    uint8_t payloadType;
    uint32_t payloadReservationID;
};

struct SetPayloadRetValue
{
    uint32_t reservationToken;
    uint32_t actualPayloadWritten;
    uint32_t actualTotalPayloadWritten;
};
struct PayloadInfo
{
    uint32_t payloadReservationID;
    uint16_t payloadVersion;
    uint32_t payloadCurrentSize;
    uint32_t payloadCurrentChecksum;
    uint32_t payloadTotalSize;
    uint32_t payloadTotalChecksum;
    uint32_t actualTotalPayloadWritten;
};

#pragma pack(pop)
