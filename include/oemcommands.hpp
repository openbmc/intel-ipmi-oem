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
    CMD_SET_POWER_RESTORE_DELAY = 0x54,
    CMD_GET_POWER_RESTORE_DELAY = 0x55,
    CMD_GET_CHASSIS_IDENTIFIER = 0x92,
    CMD_GET_PROCESSOR_ERR_CONFIG = 0x9A,
    CMD_SET_PROCESSOR_ERR_CONFIG = 0x9B,
};

static constexpr ipmi_netfn_t NETFUN_INTC_OEM_GENERAL =
    NETFUN_NONE; // Netfun_none. In our platform, we use it as "intel oem
                 // general". The code is 0x30
static constexpr unsigned char maxBiosIdLength = 0xFF;
static constexpr unsigned char maxCPUNum = 4;
static constexpr const char* biosObjPath = "/xyz/openbmc_project/bios";
static constexpr const char* biosIntf =
    "xyz.openbmc_project.Inventory.Item.Bios";
static constexpr const char* biosProp = "BiosId";

static constexpr const char* powerRestoreDelayObjPath =
    "/xyz/openbmc_project/control/power_restore_delay";
static constexpr const char* powerRestoreDelayIntf =
    "xyz.openbmc_project.Control.Power.RestoreDelay";
static constexpr const char* powerRestoreDelayProp = "PowerRestoreDelay";
static constexpr const char* processorErrConfigObjPath =
    "/xyz/openbmc_project/control/processor_error_config";
static constexpr const char* processorErrConfigIntf =
    "xyz.openbmc_project.Control.Processor.ErrConfig";

typedef enum
{
    biosId,
    devVer,
    sdrVer,
} eOemDevEntityType;

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
    uint8_t byteMSB;
    uint8_t byteLSB;
} __attribute__((packed)) sSetPowerRestoreDelayReq;

typedef struct
{
    uint8_t byteMSB;
    uint8_t byteLSB;
} __attribute__((packed)) sGetPowerRestoreDelayRes;

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

typedef struct
{
    uint8_t u8ResetCfg; // Reset Configuration
                        //   [0]:   CATERR Reset Enabled
                        //               0b: Disabled
                        //               1b: Enabled
                        //   [1]:   ERR2 Reset Enabled
                        //               0b: Disabled
                        //               1b: Enabled
                        //   [7:2]: Reserved
    uint8_t reserved;   // Reserved
    uint8_t
        resetErrorOccurrenceCounts; // Reset Error Occurrence Counts
                                    //[0]: Reset CPU Error Counts
                                    //    0b: Keep CPU Error Counts
                                    //    1b: Reset all CPU Error Counts to zero
                                    //[7:1]: Reserved
} __attribute__((packed)) sSetProcessorErrConfigReq;

typedef struct
{
    uint8_t u8ResetCfg;             // Reset Configuration
                                    //   [0]:   CATERR Reset Enabled
                                    //               0b: Disabled
                                    //               1b: Enabled
                                    //   [1]:   ERR2 Reset Enabled
                                    //               0b: Disabled
                                    //               1b: Enabled
                                    //   [7:2]: Reserved
    uint8_t reserved;               // Reserved
    char u8CATERRStatus[maxCPUNum]; // for all CPUs including the non-legacy
                                    // socket CPU CPU CATERR (Core Error)
                                    // occurrence
                                    //     [5:0]: Error Occurrence Count
                                    //     [7:6]: CPU Status
                                    //                 00b: Disabled
                                    //                 01b: Enabled
                                    //                 11b: Not Present
} __attribute__((packed)) sGetProcessorErrConfigRes;
