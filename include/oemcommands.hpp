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

#include <user_channel/user_layer.hpp>
enum class IPMINetfnIntelOEMGeneralCmd
{
    cmdSetBIOSID = 0x26,
    cmdGetOEMDeviceInfo = 0x27,
    cmdSetColdRedundancyConfig = 0x2d,
    cmdGetColdRedundancyConfig = 0x2e,
    cmdGetAICSlotFRUIDSlotPosRecords = 0x31,
    cmdSetSystemGUID = 0x41,
    cmdDisableBMCSystemReset = 0x42,
    cmdGetBMCResetDisables = 0x43,
    cmdSendEmbeddedFWUpdStatus = 0x44,
    cmdSetPowerRestoreDelay = 0x54,
    cmdGetPowerRestoreDelay = 0x55,
    cmdSetFaultIndication = 0x57,
    cmdSetOEMUser2Activation = 0x5A,
    cmdSetSpecialUserPassword = 0x5F,
    cmdSetShutdownPolicy = 0x60,
    cmdGetShutdownPolicy = 0x62,
    cmdSetFanConfig = 0x89,
    cmdGetFanConfig = 0x8a,
    cmdSetFanSpeedOffset = 0x8c,
    cmdGetFanSpeedOffset = 0x8d,
    cmdSetDimmOffset = 0x8e,
    cmdGetDimmOffset = 0x8f,
    cmdSetFscParameter = 0x90,
    cmdGetFscParameter = 0x91,
    cmdGetChassisIdentifier = 0x92,
    cmdReadBaseBoardProductId = 0x93,
    cmdGetProcessorErrConfig = 0x9A,
    cmdSetProcessorErrConfig = 0x9B,
    cmdSetManufacturingData = 0xA1,
    cmdGetManufacturingData = 0xA2,
    cmdGetLEDStatus = 0xB0,
    cmdMtmKeepAlive = 0xB5,
    cmdGetNmiStatus = 0xE5,
    cmdSetNmiStatus = 0xED,
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
static constexpr const char* bmcResetDisablesPath =
    "/xyz/openbmc_project/control/bmc_reset_disables";
static constexpr const char* bmcResetDisablesIntf =
    "xyz.openbmc_project.Control.ResetDisables";

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
    "com.intel.Control.OCOTShutdownPolicy";
static constexpr const char* oemShutdownPolicyObjPath =
    "/com/intel/control/ocotshutdown_policy_config";
static constexpr const char* oemShutdownPolicyObjPathProp = "OCOTPolicy";

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
static constexpr uint8_t ipmiDefaultUserId = 2;

static constexpr const uint8_t selEvtTargetMask = 0xF0;
static constexpr const uint8_t selEvtTargetShift = 4;

static constexpr const uint8_t targetInstanceMask = 0x0E;
static constexpr const uint8_t targetInstanceShift = 1;

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

enum class FWUpdateTarget : uint8_t
{
    targetBMC = 0x0,
    targetBIOS = 0x1,
    targetME = 0x2,
    targetOEMEWS = 0x4,
};

enum class CPUStatus
{
    disabled = 0x0,
    enabled = 0x1,
    notPresent = 0x3,
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
struct CfgHostSerialReq
{
    uint8_t command;
    uint8_t parameter;
};
#pragma pack(pop)

//
// Fault type enumeration
//
enum class RemoteFaultType
{
    fan,         // 0
    temperature, // 1
    power,       // 2
    driveslot,   // 3
    software,    // 4
    memory,      // 5
    max = 6      // 6
};

// Enumeration for remote fault states as required by the HSC
//
enum class RemoteFaultState
{
    // fault indicators
    fanLEDs,
    cpu1DimmLeds,
    cpu2DimmLeds,
    cpu3DimmLeds,
    cpu4DimmLeds,
    maxFaultState,
};

enum class DimmFaultType
{
    cpu1cpu2Dimm,
    cpu3cpu4Dimm,
    maxFaultGroup,
};

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

enum class dimmOffsetTypes : uint8_t
{
    staticCltt = 0x0,
    dimmPower = 0x2
};

// FIXME: this stuff needs to be rewritten
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
    IPMI_CC_STORGE_LEAK = 0xC4,
    IPMI_CC_REQUEST_DATA_TRUNCATED = 0xC6,
    IPMI_CC_REQUEST_DATA_FIELD_LENGTH_LIMIT_EXCEEDED = 0xC8,
    IPMI_CC_CANNOT_RETURN_NUMBER_OF_REQUESTED_DATA_BYTES = 0xCA,
    IPMI_CC_REQUEST_SENSOR_DATA_RECORD_NOT_FOUND = 0xCB,
    IPMI_CC_DESTINATION_UNAVAILABLE = 0xD3,
    IPMI_CC_PARAMETER_NOT_SUPPORT_IN_PRESENT_STATE = 0xD5,
};

constexpr unsigned char NETFUN_INTEL_APP_OEM = 0x3E;

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

enum class IPMINetFnIntelOemGeneralCmds
{
    GetSmSignal = 0x14,
    SetSmSignal = 0x15,
    controlBmcServices = 0xB1,
    getBmcServiceStatus = 0xB2,
    SetSensorOverride = 0xEE,
};
