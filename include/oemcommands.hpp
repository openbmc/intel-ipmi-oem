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

#pragma once

enum IPMI_NETFN_INTEL_OEM_GENERAL_CMD
{
    CMD_SET_BIOS_ID = 0x26,
    CMD_GET_OEM_DEVICE_INFO = 0x27,
    CMD_GET_AIC_SLOT_FRUID_SLOTPOS_RECORDS = 0x31,
    CMD_SET_SYSTEM_GUID = 0x41,
    CMD_GET_CHASSIS_IDENTIFIER = 0x92,
};

enum IPMI_INTEL_OEM_RETURN_CODES
{
    IPMI_CC_OEM_PAYLOAD_ACTIVE = 0x80,
    IPMI_CC_OEM_INVALID_PCIE_SLOTID = 0x80,
    IPMI_CC_OEM_PARAMETER_NOT_SUPPORTED = 0x80,
    IPMI_CC_OEM_PAYLOAD_ALREADY_DEACTIVATED = 0x80,
    IPMI_CC_OEM_SET_IN_PROCESS = 0x81,
    IPMI_CC_OEM_PAYLOAD_DISABLE = 0x81,
    IPMI_CC_OEM_LOST_ARBITRATION = 0x81,
    IPMI_CC_OEM_INVALID_CABLE_PORT_INDEX = 0x81,
    IPMI_CC_OEM_HEALTH_STATUS_NOT_AVAILABLE = 0x81,
    IPMI_CC_OEM_BUS_ERROR = 0x82,
    IPMI_CC_OEM_READ_ONLY = 0x82,
    IPMI_CC_OEM_WRITE_ONLY = 0x82,
    IPMI_CC_OEM_NO_CABLE_PRESENT = 0x82,
    IPMI_CC_OEM_DATA_COLLECTION_IN_PROGRESS = 0x82,
    IPMI_CC_OEM_PAYLOAD_ACTIVATION_LIMIT_REACH = 0x82,
    IPMI_CC_OEM_NACK_ON_WRITE = 0x83,
    IPMI_CC_OEM_DATA_COLLECTION_FAILED = 0x83,
    IPMI_CC_OEM_CAN_NOT_ACTIVATE_WITH_ENCRYPTION = 0x83,
    IPMI_CC_OEM_CAN_NOT_ACTIVATE_WITHOUT_ENCRYPTION = 0x84,
    IPMI_CC_OEM_INVALID_CHECKSUM = 0x85,
    IPMI_CC_OEM_NO_CABLED_PCIE_PORTS_AVAILABLE = 0xC2,
};

enum IPMI_RETURN_CODE_EXT
{
    IPMI_CC_INVALID_LUN = 0xC2,
    IPMI_CC_TIMEOUT = 0xC3,
    IPMI_CC_STORGE_LEAK = 0xC4,
    IPMI_CC_REQUEST_DATA_TRUNCATED = 0xC6,
    IPMI_CC_REQUEST_DATA_FIELD_LENGTH_LIMIT_EXCEEDED = 0xC8,
    IPMI_CC_CANNOT_RETURN_NUMBER_OF_REQUESTED_DATA_BYTES = 0xCA,
    IPMI_CC_REQUEST_SENSOR_DATA_RECORD_NOT_FOUND = 0xCB,
    IPMI_CC_DESTINATION_UNAVAILABLE = 0xD3,
    IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE = 0xD5,
};

constexpr unsigned char NETFUN_INTEL_APP_OEM = 0x3E;
static constexpr ipmi_netfn_t NETFUN_INTC_OEM_GENERAL =
    NETFUN_NONE; // Netfun_none. In our platform, we use it as "intel oem
                 // general". The code is 0x30
static constexpr unsigned char maxBiosIdLength = 0xFF;
static constexpr char* biosObjPath = (char *)"/xyz/openbmc_project/bios";
static constexpr char* biosIntf = (char *)"xyz.openbmc_project.Inventory.Item.Bios";
static constexpr char* biosProp = (char *)"BiosId";

enum IPMI_NETFN_INTEL_OEM_APP_CMD
{
    MDR_STATUS = 0x20,
    MDR_COMPLETE = 0x21,
    MDR_EVENT = 0x22,
    MDR_READ = 0x23,
    MDR_WRITE = 0x24,
    MDR_LOCK = 0x25,
    MDRII_AGENT_STATUS = 0x30,
    MDRII_GET_DIR = 0x31,
    MDRII_GET_DATA_INFO = 0x32,
    MDRII_LOCK_DATA = 0x33,
    MDRII_UNLOCK_DATA = 0x34,
    MDRII_GET_DATA_BLOCK = 0x35,
    MDRII_SEND_DIR = 0x38,
    MDRII_SEND_DATA_INFO_OFFER = 0x39,
    MDRII_SEND_DATA_INFO = 0x3a,
    MDRII_DATA_START = 0x3b,
    MDRII_DATA_DONE = 0x3c,
    MDRII_SEND_DATA_BLOCK = 0x3d,
};

typedef enum {
    biosId,
    devVer,
    sdrVer,
} eOemDevEntityType;

typedef union
{
    typedef struct
    {
        uint8_t bBrdSlotNum : 3;   //Bits 2:0
        uint8_t riserSlotNum : 3;  //Bits 5:3
        uint8_t protocol : 1;      //Bit 6, FRU type
        uint8_t reserved : 1;      //Bit 7
    } bits;
    uint8_t byte;
} __attribute__((packed)) AICFruRec;

typedef struct
{
    AICFruRec u8SlotPosition;
    uint8_t u8FruID;
} __attribute__((packed))sFruSlotPosRecord;

typedef struct
{
    uint8_t node1;
    uint8_t node2;
    uint8_t node3;
    uint8_t node4;
    uint8_t node5;
    uint8_t node6;
    uint8_t clock1;
    uint8_t clock2;
    uint8_t timeHigh1;
    uint8_t timeHigh2;
    uint8_t timeMid1;
    uint8_t timeMid2;
    uint8_t timeLow1;
    uint8_t timeLow2;
    uint8_t timeLow3;
    uint8_t timeLow4;
} __attribute__((packed)) sGuidData;

typedef struct
{
    uint8_t biosIdLength;
    uint8_t biosId[maxBiosIdLength];
} __attribute__((packed)) sDeviceInfo;

typedef struct
{
    uint8_t entityType;
    uint8_t countToRead;
    uint8_t offset;
} __attribute__((packed)) sGetOemDeviceInfoReq;

typedef struct
{
    uint8_t resDatalen;
    uint8_t data[maxBiosIdLength];
} __attribute__((packed)) sGetOemDeviceInfoRes;
