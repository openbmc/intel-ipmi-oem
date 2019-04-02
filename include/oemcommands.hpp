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

enum class IPMINetfnIntelOEMGeneralCmd
{
    cmdSetBIOSID = 0x26,
    cmdGetOEMDeviceInfo = 0x27,
    cmdGetAICSlotFRUIDSlotPosRecords = 0x31,
    cmdSetSystemGUID = 0x41,
    cmdSetPowerRestoreDelay = 0x54,
    cmdGetPowerRestoreDelay = 0x55,
    cmdSetShutdownPolicy = 0x60,
    cmdGetShutdownPolicy = 0x62,
    cmdSetFanConfig = 0x89,
    cmdGetFanConfig = 0x8a,
    cmdSetFanSpeedOffset = 0x8c,
    cmdGetFanSpeedOffset = 0x8d,
    cmdSetFscParameter = 0x90,
    cmdGetFscParameter = 0x91,
    cmdGetChassisIdentifier = 0x92,
    cmdGetProcessorErrConfig = 0x9A,
    cmdSetProcessorErrConfig = 0x9B,
    cmdGetLEDStatus = 0xB0,
};

enum class IPMINetfnIntelOEMPlatformCmd
{
    cmdCfgHostSerialPortSpeed = 0x90,
};

enum class IPMIIntelOEMReturnCodes
{
    ipmiCCPayloadActive = 0x80,
    ipmiCCInvalidPCIESlotID = 0x80,
    ipmiCCParameterNotSupported = 0x80,
    ipmiCCPayloadAlreadyDeactivated = 0x80,
    ipmiCCSetInProcess = 0x81,
    ipmiCCPayloadDisable = 0x81,
    ipmiCCLostArbitration = 0x81,
    ipmiCCInvalidCablePortIndex = 0x81,
    ipmiCCHealthStatusNotAvailable = 0x81,
    ipmiCCBusError = 0x82,
    ipmiCCReadOnly = 0x82,
    ipmiCCWriteOnly = 0x82,
    ipmiCCNoCablePresent = 0x82,
    ipmiCCDataCollectionInProgress = 0x82,
    ipmiCCPayloadActivationLimitReached = 0x82,
    ipmiCCNACKOnWrite = 0x83,
    ipmiCCDataCollectionFailed = 0x83,
    ipmiCCCanNotActivateWithEncrption = 0x83,
    ipmiCCCanNotActivateWithoutEncryption = 0x84,
    ipmiCCInvalidChecksum = 0x85,
    ipmiCCNoCabledPCIEPortsAvailable = 0xC2,

};

enum class IPMIReturnCodeExt
{
    ipmiCCInvalidLUN = 0xC2,
    ipmiCCTimeout = 0xC3,
    ipmiCCStorageLeak = 0xC4,
    ipmiCCRequestDataTruncated = 0xC6,
    ipmiCCRequestDataFieldLengthLimitExceeded = 0xC8,
    ipmiCCCanNotReturnNumberOfRequestedDataBytes = 0xCA,
    ipmiCCRequestSensorDataRecordNotFound = 0xCB,
    ipmiCCDestinationUnavailable = 0xD3,
    ipmiCCParamterNotSupportInPresentState = 0xD5,
};

constexpr const uint8_t netfunIntelAppOEM = 0x3E;
static constexpr ipmi_netfn_t netfnIntcOEMGeneral =
    NETFUN_NONE; // Netfun_none. In our platform, we use it as "intel oem
                 // general". The code is 0x30

// Intel OEM Platform code is 0x32
static constexpr ipmi_netfn_t netfnIntcOEMPlatform = NETFUN_OEM;
static constexpr const uint8_t maxBIOSIDLength = 0xFF;
static constexpr const uint8_t maxCPUNum = 4;
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

static constexpr const char* postCodesObjPath =
    "/xyz/openbmc_project/State/Boot/PostCode";
static constexpr const char* postCodesIntf =
    "xyz.openbmc_project.State.Boot.PostCode";

static constexpr const char* identifyLEDObjPath =
    "/xyz/openbmc_project/led/physical/identify";
static constexpr const char* ledIntf = "xyz.openbmc_project.Led.Physical";
static constexpr const char* statusAmberObjPath =
    "/xyz/openbmc_project/led/physical/status_amber";
static constexpr const char* statusGreenObjPath =
    "/xyz/openbmc_project/led/physical/status_green";

static constexpr const uint8_t noShutdownOnOCOT = 0;
static constexpr const uint8_t shutdownOnOCOT = 1;
static constexpr const uint8_t noShutdownPolicySupported = 0;
static constexpr const uint8_t shutdownPolicySupported = 1;
static constexpr const char* oemShutdownPolicyIntf =
    "xyz.openbmc_project.Control.ShutdownPolicy";
static constexpr const char* oemShutdownPolicyObjPath =
    "/xyz/openbmc_project/control/shutdown_policy_config";
static constexpr const char* oemShutdownPolicyObjPathProp = "Policy";

static constexpr const char* fwGetEnvCmd = "/sbin/fw_printenv";
static constexpr const char* fwSetEnvCmd = "/sbin/fw_setenv";
static constexpr const char* fwHostSerailCfgEnvName = "hostserialcfg";

constexpr const char* settingsBusName = "xyz.openbmc_project.Settings";

static constexpr const uint8_t getHostSerialCfgCmd = 0;
static constexpr const uint8_t setHostSerialCfgCmd = 1;

// parameters:
// 0: host serial port 1 and 2 normal speed
// 1: host serial port 1 high spend, port 2 normal speed
// 2: host serial port 1 normal spend, port 2 high speed
// 3: host serial port 1 and 2 high speed
static constexpr const uint8_t HostSerialCfgParamMax = 3;

enum class IPMINetfnIntelOEMAppCmd
{
    mdrStatus = 0x20,
    mdrComplete = 0x21,
    mdrEvent = 0x22,
    mdrRead = 0x23,
    mdrWrite = 0x24,
    mdrLock = 0x25,
    mdr2AgentStatus = 0x30,
    mdr2GetDir = 0x31,
    mdr2GetDataInfo = 0x32,
    mdr2LockData = 0x33,
    mdr2UnlockData = 0x34,
    mdr2GetDataBlock = 0x35,
    mdr2SendDir = 0x38,
    mdr2SendDataInfoOffer = 0x39,
    mdr2SendDataInfo = 0x3a,
    mdr2DataStart = 0x3b,
    mdr2DataDone = 0x3c,
    mdr2SendDataBlock = 0x3d,
};

enum class OEMDevEntityType
{
    biosId,
    devVer,
    sdrVer,
};

#pragma pack(push, 1)
struct GUIDData
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
};

struct DeviceInfo
{
    uint8_t biosIDLength;
    uint8_t biosId[maxBIOSIDLength];
};

struct SetPowerRestoreDelayReq
{
    uint8_t byteMSB;
    uint8_t byteLSB;
};

struct GetPowerRestoreDelayRes
{
    uint8_t byteMSB;
    uint8_t byteLSB;
};

struct GetOemDeviceInfoReq
{
    uint8_t entityType;
    uint8_t countToRead;
    uint8_t offset;
};

struct GetOemDeviceInfoRes
{
    uint8_t resDatalen;
    uint8_t data[maxBIOSIDLength];
};

struct SetProcessorErrConfigReq
{
    uint8_t resetCfg; // Reset Configuration
                      //   [0]:   CATERR Reset Enabled
                      //               0b: Disabled
                      //               1b: Enabled
                      //   [1]:   ERR2 Reset Enabled
                      //               0b: Disabled
                      //               1b: Enabled
                      //   [7:2]: Reserved
    uint8_t reserved; // Reserved
    uint8_t
        resetErrorOccurrenceCounts; // Reset Error Occurrence Counts
                                    //[0]: Reset CPU Error Counts
                                    //    0b: Keep CPU Error Counts
                                    //    1b: Reset all CPU Error Counts to zero
                                    //[7:1]: Reserved
};

struct GetProcessorErrConfigRes
{
    uint8_t resetCfg;             // Reset Configuration
                                  //   [0]:   CATERR Reset Enabled
                                  //               0b: Disabled
                                  //               1b: Enabled
                                  //   [1]:   ERR2 Reset Enabled
                                  //               0b: Disabled
                                  //               1b: Enabled
                                  //   [7:2]: Reserved
    uint8_t reserved;             // Reserved
    char caterrStatus[maxCPUNum]; // for all CPUs including the non-legacy
                                  // socket CPU CPU CATERR (Core Error)
                                  // occurrence
                                  //     [5:0]: Error Occurrence Count
                                  //     [7:6]: CPU Status
                                  //                 00b: Disabled
                                  //                 01b: Enabled
                                  //                 11b: Not Present
};

struct GetOEMShutdownPolicyRes
{
    uint8_t policy;
    uint8_t policySupport;
};

struct SetFanConfigReq
{
    uint8_t selectedProfile;
    uint8_t flags;
    // other parameters from previous generation are not supported
};

struct GetFanConfigResp
{
    uint8_t supportMask;
    uint8_t profileSupport;
    uint8_t fanControlProfileEnable;
    uint8_t flags;
    uint8_t dimmPresenceMap[4];
};

struct CfgHostSerialReq
{
    uint8_t command;
    uint8_t parameter;
};
#pragma pack(pop)

enum class setFanProfileFlags : uint8_t
{
    setFanProfile = 7,
    setPerfAcousMode = 6,
    // reserved [5:3]
    performAcousSelect = 2
    // reserved [1:0]
};

enum class setFscParamFlags : uint8_t
{
    tcontrol = 0x1,
    pwmOffset = 0x2,
    maxPwm = 0x3,
    cfm = 0x4
};