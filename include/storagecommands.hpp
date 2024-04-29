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
#include <ipmid/api-types.hpp>
#include <ipmid/api.hpp>

#include <cstdint>

static constexpr uint8_t ipmiSdrVersion = 0x51;

namespace intel_oem::ipmi::sel
{
static constexpr uint8_t selOperationSupport = 0x02;
static constexpr uint8_t systemEvent = 0x02;
static constexpr size_t systemEventSize = 3;
static constexpr uint8_t oemTsEventFirst = 0xC0;
static constexpr uint8_t oemTsEventLast = 0xDF;
static constexpr size_t oemTsEventSize = 9;
static constexpr uint8_t oemEventFirst = 0xE0;
static constexpr uint8_t oemEventLast = 0xFF;
static constexpr size_t oemEventSize = 13;
static constexpr uint8_t eventMsgRev = 0x04;
} // namespace intel_oem::ipmi::sel

//////////////////////////////////////////////////////////////////////////////
//
// blurbs from ipmi-host/sensorhandler.hpp
//
//////////////////////////////////////////////////////////////////////////////
static constexpr int FULL_RECORD_ID_STR_MAX_LENGTH = 16;
namespace get_sdr
{
// Record header
struct SensorDataRecordHeader
{
    uint8_t record_id_lsb;
    uint8_t record_id_msb;
    uint8_t sdr_version;
    uint8_t record_type;
    uint8_t record_length; // Length not counting the header
} __attribute__((packed));

namespace header
{

inline void set_record_id(int id, SensorDataRecordHeader* hdr)
{
    hdr->record_id_lsb = (id & 0xFF);
    hdr->record_id_msb = (id >> 8) & 0xFF;
};

} // namespace header

/** @struct SensorDataFruRecordKey
 *
 *  FRU Device Locator Record(key) - SDR Type 11
 */
struct SensorDataFruRecordKey
{
    uint8_t deviceAddress;
    uint8_t fruID;
    uint8_t accessLun;
    uint8_t channelNumber;
} __attribute__((packed));

static constexpr int FRU_RECORD_DEVICE_ID_MAX_LENGTH = 16;

/** @struct SensorDataFruRecordBody
 *
 *  FRU Device Locator Record(body) - SDR Type 11
 */
struct SensorDataFruRecordBody
{
    uint8_t reserved;
    uint8_t deviceType;
    uint8_t deviceTypeModifier;
    uint8_t entityID;
    uint8_t entityInstance;
    uint8_t oem;
    uint8_t deviceIDLen;
    char deviceID[FRU_RECORD_DEVICE_ID_MAX_LENGTH];
} __attribute__((packed));

/** @struct SensorDataFruRecord
 *
 *  FRU Device Locator Record - SDR Type 11
 */
struct SensorDataFruRecord
{
    SensorDataRecordHeader header;
    SensorDataFruRecordKey key;
    SensorDataFruRecordBody body;
} __attribute__((packed));

enum SensorDataRecordType
{
    SENSOR_DATA_FULL_RECORD = 0x1,
    SENSOR_DATA_EVENT_RECORD = 0x3,
    SENSOR_DATA_FRU_RECORD = 0x11,
    SENSOR_DATA_ENTITY_RECORD = 0x8,
};

// Record key
struct SensorDataRecordKey
{
    uint8_t owner_id;
    uint8_t owner_lun;
    uint8_t sensor_number;
} __attribute__((packed));

struct SensorDataFullRecordBody
{
    uint8_t entity_id;
    uint8_t entity_instance;
    uint8_t sensor_initialization;
    uint8_t sensor_capabilities; // no macro support
    uint8_t sensor_type;
    uint8_t event_reading_type;
    uint8_t supported_assertions[2];          // no macro support
    uint8_t supported_deassertions[2];        // no macro support
    uint8_t discrete_reading_setting_mask[2]; // no macro support
    uint8_t sensor_units_1;
    uint8_t sensor_units_2_base;
    uint8_t sensor_units_3_modifier;
    uint8_t linearization;
    uint8_t m_lsb;
    uint8_t m_msb_and_tolerance;
    uint8_t b_lsb;
    uint8_t b_msb_and_accuracy_lsb;
    uint8_t accuracy_and_sensor_direction;
    uint8_t r_b_exponents;
    uint8_t analog_characteristic_flags; // no macro support
    uint8_t nominal_reading;
    uint8_t normal_max;
    uint8_t normal_min;
    uint8_t sensor_max;
    uint8_t sensor_min;
    uint8_t upper_nonrecoverable_threshold;
    uint8_t upper_critical_threshold;
    uint8_t upper_noncritical_threshold;
    uint8_t lower_nonrecoverable_threshold;
    uint8_t lower_critical_threshold;
    uint8_t lower_noncritical_threshold;
    uint8_t positive_threshold_hysteresis;
    uint8_t negative_threshold_hysteresis;
    uint16_t reserved;
    uint8_t oem_reserved;
    uint8_t id_string_info;
    char id_string[FULL_RECORD_ID_STR_MAX_LENGTH];
} __attribute__((packed));

struct SensorDataFullRecord
{
    SensorDataRecordHeader header;
    SensorDataRecordKey key;
    SensorDataFullRecordBody body;
} __attribute__((packed));

namespace body
{
inline void set_id_strlen(uint8_t len, SensorDataFullRecordBody* body)
{
    body->id_string_info &= ~(0x1f);
    body->id_string_info |= len & 0x1f;
};
inline void set_id_type(uint8_t type, SensorDataFullRecordBody* body)
{
    body->id_string_info &= ~(3 << 6);
    body->id_string_info |= (type & 0x3) << 6;
};
} // namespace body
} // namespace get_sdr
//////////////////////////////////////////////////////////////////////////////
//
// <end> blurbs from ipmi-host/sensorhandler.hpp
//
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////
//
// blurbs from ipmi-host/selutility.hpp
//
//////////////////////////////////////////////////////////////////////////////
namespace ipmi::sel
{
static constexpr auto firstEntry = 0x0000;
static constexpr auto lastEntry = 0xFFFF;
static constexpr auto entireRecord = 0xFF;
static constexpr auto selVersion = 0x51;
static constexpr auto invalidTimeStamp = 0xFFFFFFFF;
static constexpr auto getEraseStatus = 0x00;
static constexpr auto eraseComplete = 0x01;
static constexpr auto initiateErase = 0xAA;

} // namespace ipmi::sel
//////////////////////////////////////////////////////////////////////////////
//
// <end> blurbs from ipmi-host/selutility.hpp
//
//////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)
struct GetSDRReq
{
    uint16_t reservationID;
    uint16_t recordID;
    uint8_t offset;
    uint8_t bytesToRead;
};
#pragma pack(pop)

enum class SdrRepositoryInfoOps : uint8_t
{
    allocCommandSupported = 0x1,
    reserveSDRRepositoryCommandSupported = 0x2,
    partialAddSDRSupported = 0x4,
    deleteSDRSupported = 0x8,
    reserved = 0x10,
    modalLSB = 0x20,
    modalMSB = 0x40,
    overflow = 0x80
};

enum class GetFRUAreaAccessType : uint8_t
{
    byte = 0x0,
    words = 0x1
};

enum class SensorUnits : uint8_t
{
    unspecified = 0x0,
    degreesC = 0x1,
    volts = 0x4,
    amps = 0x5,
    watts = 0x6,
    rpm = 0x12,
};

#pragma pack(push, 1)
struct Type12Record
{
    get_sdr::SensorDataRecordHeader header;
    uint8_t targetAddress;
    uint8_t channelNumber;
    uint8_t powerStateNotification;
    uint8_t deviceCapabilities;
    // define reserved bytes explicitly. The uint24_t is silently expanded to
    // uint32_t, which ruins the byte alignment required by this structure.
    uint8_t reserved[3];
    uint8_t entityID;
    uint8_t entityInstance;
    uint8_t oem;
    uint8_t typeLengthCode;
    char name[16];

    Type12Record(uint16_t recordID, uint8_t address, uint8_t chNumber,
                 uint8_t pwrStateNotification, uint8_t capabilities,
                 uint8_t eid, uint8_t entityInst, uint8_t mfrDefined,
                 const std::string& sensorname) :
        targetAddress(address), channelNumber(chNumber),
        powerStateNotification(pwrStateNotification),
        deviceCapabilities(capabilities), reserved{}, entityID(eid),
        entityInstance(entityInst), oem(mfrDefined)
    {
        get_sdr::header::set_record_id(recordID, &header);
        header.sdr_version = ipmiSdrVersion;
        header.record_type = 0x12;
        size_t nameLen = std::min(sensorname.size(), sizeof(name));
        header.record_length = sizeof(Type12Record) -
                               sizeof(get_sdr::SensorDataRecordHeader) -
                               sizeof(name) + nameLen;
        typeLengthCode = 0xc0 | nameLen;
        std::copy(sensorname.begin(), sensorname.begin() + nameLen, name);
    }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct NMDiscoveryRecord
{
    get_sdr::SensorDataRecordHeader header;
    uint8_t oemID0;
    uint8_t oemID1;
    uint8_t oemID2;
    uint8_t subType;
    uint8_t version;
    uint8_t targetAddress;
    uint8_t channelNumber;
    uint8_t healthEventSensor;
    uint8_t exceptionEventSensor;
    uint8_t operationalCapSensor;
    uint8_t thresholdExceededSensor;
};
#pragma pack(pop)

namespace ipmi
{
namespace storage
{

constexpr const size_t nmDiscoverySDRCount = 1;
constexpr const size_t type12Count = 2;
ipmi::Cc getFruSdrs(ipmi::Context::ptr& ctx, size_t index,
                    get_sdr::SensorDataFruRecord& resp);

ipmi::Cc getFruSdrCount(ipmi::Context::ptr& ctx, size_t& count);

std::vector<uint8_t> getType12SDRs(uint16_t index, uint16_t recordId);
std::vector<uint8_t> getNMDiscoverySDR(uint16_t index, uint16_t recordId);
} // namespace storage
} // namespace ipmi
