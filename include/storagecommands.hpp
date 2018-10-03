/*
// Copyright (c) 2017 Intel Corporation
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
#include <phosphor-ipmi-host/sensorhandler.hpp>
#include <cstdint>

static constexpr uint8_t IPMI_SDR_VERSION = 0x51;

struct getsdrinforesp_t
{
    uint8_t sdr_version;
    uint8_t record_count_ls;
    uint8_t record_count_ms;
    uint8_t free_space[2];
    uint8_t most_recent_addition[4];
    uint8_t most_recent_erase[4];
    uint8_t operation_support;
} __attribute__((packed));

enum class SdrRepositoryInfoOps : uint8_t
{
    AllocCommandSupported = 0x1,
    ReserveSDRRepositoryCommandSupported = 0x2,
    PartialAddSdrSupported = 0x4,
    DeleteSdrSupported = 0x8,
    Reserved = 0x10,
    ModalLsb = 0x20,
    ModalMsb = 0x40,
    Overflow = 0x80
};

struct getallocinforesp_t
{
    uint8_t alloc_units_lsb;
    uint8_t alloc_units_msb;
    uint8_t alloc_unit_size_lsb;
    uint8_t alloc_unit_size_msb;
    uint8_t alloc_unit_free_lsb;
    uint8_t alloc_unit_free_msb;
    uint8_t alloc_unit_largest_free_lsb;
    uint8_t alloc_unit_largest_free_msb;
    uint8_t max_record_size;
} __attribute__((packed));

enum sensor_type_codes : uint8_t
{
    RESERVED = 0x0,
    TEMPERATURE = 0x1,
    VOLTAGE = 0x2,
    CURRENT = 0x3,
    FAN = 0x4,
    OTHER = 0xB,
};

enum sensor_units : uint8_t
{
    UNSPECIFIED = 0x0,
    DEGREES_C = 0x1,
    // DEGREEES_F
    // DEGREES_K
    VOLTS = 0x4,
    AMPS = 0x5,
    WATTS = 0x6,
    RPM = 0x12,
};

enum ipmi_netfn_storage_cmds
{
    IPMI_CMD_GET_FRU_INV_AREA_INFO = 0x10,
    IPMI_CMD_READ_FRU_DATA = 0x11,
    IPMI_CMD_WRITE_FRU_DATA = 0x12,
    IPMI_CMD_GET_REPOSITORY_INFO = 0x20,
    IPMI_CMD_GET_SDR_ALLOCATION_INFO = 0x21,
    IPMI_CMD_RESERVE_SDR = 0x22,
    IPMI_CMD_GET_SDR = 0x23,
    IPMI_CMD_GET_SEL_INFO = 0x40,
    IPMI_CMD_RESERVE_SEL = 0x42,
    IPMI_CMD_GET_SEL_ENTRY = 0x43,
    IPMI_CMD_ADD_SEL = 0x44,
    IPMI_CMD_DELETE_SEL = 0x46,
    IPMI_CMD_CLEAR_SEL = 0x47,
    IPMI_CMD_GET_SEL_TIME = 0x48,
    IPMI_CMD_SET_SEL_TIME = 0x49,
};

namespace ipmi
{
namespace storage
{
ipmi_ret_t getFruSdrs(size_t index, get_sdr::SensorDataFruRecord& resp);

ipmi_ret_t getFruSdrCount(size_t& count);
} // namespace storage
} // namespace ipmi