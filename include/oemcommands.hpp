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

enum IPMINetfnIntelOEMGeneralCmd
{
    cmdSetBIOSID = 0x26,
    cmdGetOEMDeviceInfo = 0x27,
    cmdGetAICSlotFRUIDRecords = 0x31,
    cmdSetSystemGUID = 0x41,
    cmdGetChassisIdentifier = 0x92,
};

enum IPMIIntelOEMReturnCodes
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
    ipmiCCWriteOnly= 0x82,
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

enum IPMIReturnCodeExt
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

constexpr unsigned char netfunIntelAppOEM = 0x3E;
static constexpr ipmi_netfn_t netfunIntcOEMGeneral =
    NETFUN_NONE; // Netfun_none. In our platform, we use it as "intel oem
                 // general". The code is 0x30
static constexpr unsigned char maxBiosIdLength = 0xFF;
static constexpr char* biosObjPath = (char*)"/xyz/openbmc_project/bios";
static constexpr char* biosIntf =
    (char*)"xyz.openbmc_project.Inventory.Item.Bios";
static constexpr char* biosProp = (char*)"BiosId";

enum IPMINetfnIntelOEMAppCmd
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

typedef enum
{
    biosId,
    devVer,
    sdrVer,
} OEMDevEntityType;

typedef union
{
    typedef struct
    {
        uint8_t bBrdSlotNum : 3;  // Bits 2:0
        uint8_t riserSlotNum : 3; // Bits 5:3
        uint8_t protocol : 1;     // Bit 6, FRU type
        uint8_t reserved : 1;     // Bit 7
    } bits;
    uint8_t byte;
} __attribute__((packed)) AICFruRec;

typedef struct
{
    AICFruRec u8SlotPosition;
    uint8_t u8FruID;
} __attribute__((packed)) FRUSlotPosRecord;

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
} __attribute__((packed)) GUIDData;

typedef struct
{
    uint8_t biosIdLength;
    uint8_t biosId[maxBiosIdLength];
} __attribute__((packed)) DeviceInfo;

typedef struct
{
    uint8_t entityType;
    uint8_t countToRead;
    uint8_t offset;
} __attribute__((packed)) GetOemDeviceInfoReq;

typedef struct
{
    uint8_t resDatalen;
    uint8_t data[maxBiosIdLength];
} __attribute__((packed)) GetOemDeviceInfoRes;
