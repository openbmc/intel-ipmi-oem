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

#include "xyz/openbmc_project/Common/error.hpp"
#include <host-ipmid/ipmid-api.h>
#include <ImageUpdate.hpp>
#include <array>
#include <commandutils.hpp>
#include <iostream>
#include <oemcommands.hpp>
#include <oobcommands.hpp>
#include <phosphor-ipmi-host/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <openssl/sha.h>


namespace ipmi
{
static void initOOB() __attribute__((constructor));
sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection()); // from ipmid-api.h


nvOOBdata  gNVOOBdata;

uint8_t calcUserActualPwdlength(uint8_t *pwd,uint16_t *unicodePwd)
{
    uint8_t i=0,len=0;
    for(i=0; i<maxPasswordSize; i++) {
         unicodePwd[i]=pwd[i];
        if(pwd[i] ==0)
            return len*sizeof(uint16_t);
        else
            len++;
    }
    return len*sizeof(uint16_t);
}


uint8_t flushNVOOBdata()
{
FILE *fptr;
uint16_t  size;
   // open file for writing
    fptr = fopen ("/tmp/oobconf/nvoobdata.dat", "w");
    if (fptr == NULL)
    {
        return -1;
    }
    size= fwrite(&gNVOOBdata, sizeof(struct nvOOBdata), 1, fptr);
    if(size != sizeof(struct nvOOBdata))
    {
        fclose(fptr);
        return -1;
    }
    // close file
    fclose (fptr);
    return 0;
}

uint8_t getNVOOBdata()
{
FILE *fptr;
uint16_t  size;

   // open file for writing
    fptr = fopen ("/tmp/oobconf/nvoobdata.dat", "r");
    if (fptr == NULL)
    {
        return -1;
    }
    size= fread(&gNVOOBdata, sizeof(struct nvOOBdata), 1, fptr);
    if(size != sizeof(struct nvOOBdata))
    {
        fclose(fptr);
        return -1;
    }
    // close file
    fclose (fptr);
    return 0;
}

uint8_t computeHash(uint8_t *userBIOSPwd, uint8_t *BIOSPwdSeed,uint8_t *userBIOSHash,uint8_t algo)
{
    uint8_t data[64];
    uint8_t userpwdlength=0;
    uint16_t unicodePwd[maxPasswordSize]={0};
    std::copy(&data[0],&data[0]+maxSeedSize,BIOSPwdSeed);
    userpwdlength= calcUserActualPwdlength(userBIOSPwd,unicodePwd);
    std::copy(&data[0],&data[0]+userpwdlength+2,unicodePwd);
    switch(algo) {
    case HashAlg::HashSha256:
        SHA256( data, maxSeedSize+userpwdlength+2, gNVOOBdata.mUserPwdHash);
        break;
    default:
        return -1;
    }
    return 0;
}

uint8_t validateBIOSPwd(uint8_t *userpwd) {
    uint8_t Status;
    uint8_t cmp = 0;

    Status = computeHash(userpwd,gNVOOBdata.mBIOSHashInfo.BIOSPwdSeed,gNVOOBdata.mUserPwdHash, gNVOOBdata.mBIOSHashInfo.hashAlgo);
    if(Status == 0) {
        if((cmp =memcmp(gNVOOBdata.mUserPwdHash,gNVOOBdata.mBIOSHashInfo.BIOSPwdHash,maxHashSize)) == 0) {
           if(cmp == 0) {
             gNVOOBdata.mIsUserPwdInitDone = true;
             return 0;
           }
        }
    }
    return -1;
}



ipmi_ret_t ipmiOOBSetBIOSCap(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t dataLen, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    *dataLen = 0;
    setBIOSCapabilitiesReq *setBIOSCap =
        reinterpret_cast<setBIOSCapabilitiesReq *>(request);
    if (setBIOSCap->reserved1 != 0 || setBIOSCap->reserved2 != 0 ||
        setBIOSCap->reserved3 != 0)
    {
        rc = IPMI_CC_INVALID_FIELD_REQUEST;
        return rc;
    }
    gNVOOBdata.mBIOSCapabilities.OOBCapability = setBIOSCap->OOBCapability;
    gNVOOBdata.mIsBIOSCapInitDone = true;
    flushNVOOBdata();

    return rc;
}

ipmi_ret_t ipmiOOBGetBIOSCap(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t dataLen, ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    getBIOSCapabilitiesResp *getBIOSCapabilties =
        reinterpret_cast<getBIOSCapabilitiesResp *>(request);
    getNVOOBdata();
    if (gNVOOBdata.mIsBIOSCapInitDone)
    {
        getBIOSCapabilties->reserved1 = 0;
        getBIOSCapabilties->reserved2 = 0;
        getBIOSCapabilties->reserved3 = 0;
        getBIOSCapabilties->OOBCapability = gNVOOBdata.mBIOSCapabilities.OOBCapability;
        *dataLen = sizeof(getBIOSCapabilitiesResp);
        return rc;
    }
    else
    {
        *dataLen = 0;
        return OOBCompleteCode::compcodePayloadLengthIllegal;
    }
}

ipmi_ret_t ipmiOOBSetPayload(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t dataLen, ipmi_context_t context)
{
    SetPayloadReq *pPayloadReq = reinterpret_cast<SetPayloadReq *>(request);
    SetPayloadResp *pPayloadResp = reinterpret_cast<SetPayloadResp *>(response);
    uint32_t u32Crc;
    size_t returnSize = 0;
    OOBImageType currentPayloadType = pPayloadReq->payloadType;
    ipmi_ret_t rc = IPMI_CC_OK;

    // This is a must step as CurrentPayloadType == INVALID_IMG_TYPE after
    // module init or each transfer complete.
    if (currentPayloadType >= OOBImageType::invalidType)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "invalid image type");
        *dataLen = 0;
        return OOBCompleteCode::compcodePayloadTypeNotSupported;
    }
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "PARASEL",
        phosphor::logging::entry("PARASEL=%x", pPayloadReq->paraSel));

    switch (pPayloadReq->paraSel)
    {
        case TransferState::PasswdAuth:
            if(0 != validateBIOSPwd(pPayloadReq->Input.Para0.BIOSPassword)){
                rc = compcodePwdVerficationFailed;
                *dataLen = 0;
                return rc;
            }
            std::copy(gNVOOBdata.payloadInfo[currentPayloadType].ExData.BIOSPassword,
            gNVOOBdata.payloadInfo[currentPayloadType].ExData.BIOSPassword+ maxPasswordSize,
            pPayloadReq->Input.Para0.BIOSPassword);
            returnSize = 1;
           break;
        case TransferState::StartTransfer:
            break;
        case TransferState::InProgress:
            break;
        case TransferState::EndOfTransfer:
            break;
        case TransferState::UserAbort:
            break;
        default:
            *dataLen = 0;
            rc = IPMI_CC_INVALID_FIELD_REQUEST;
    }
    gNVOOBdata.payloadInfo[1].status = pPayloadReq->paraSel;

    return rc;
}

ipmi_ret_t ipmiOOBGetPayload(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                             ipmi_request_t request, ipmi_response_t response,
                             ipmi_data_len_t dataLen, ipmi_context_t context)
{
    GetPayloadReq *pPayloadReq = reinterpret_cast<GetPayloadReq *>(request);
    GetPayloadResp *pPayloadResp = reinterpret_cast<GetPayloadResp *>(response);
    uint32_t u32Crc;
    uint8_t *Imgbuffer;
    size_t returnSize = 0;
    OOBImageType currentPayloadType =
        static_cast<OOBImageType>(pPayloadReq->Input.Para0.payloadType);
    ipmi_ret_t rc = IPMI_CC_OK;
    getNVOOBdata();

    // This is a must step as CurrentPayloadType == INVALID_IMG_TYPE after
    // module init or each transfer complete.
    if (currentPayloadType >= OOBImageType::invalidType)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "invalid image type");
        *dataLen = 0;
        return OOBCompleteCode::compcodePayloadTypeNotSupported;
    }

    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "ipmiOOBGetPayload",
        phosphor::logging::entry("ipmiOOBGetPayload Param=%x",
                                 pPayloadReq->paraSel));

    switch (pPayloadReq->paraSel)
    {
        case GetPayloadParameter::PayloadInfo:
            returnSize = 0;
            pPayloadResp->Output.Para0.payloadType =
                pPayloadReq->Input.Para0.payloadType;
            pPayloadResp->Output.Para0.payloadVersion =
                gNVOOBdata.payloadInfo[pPayloadReq->Input.Para0.payloadType].payloadVersion;
            pPayloadResp->Output.Para0.totalPayloadlength =
                gNVOOBdata.payloadInfo[pPayloadReq->Input.Para0.payloadType].givenPayloadSize;
            pPayloadResp->Output.Para0.totalPayloadchecksum =
                gNVOOBdata.payloadInfo[pPayloadReq->Input.Para0.payloadType]
                    .givenPayloadChecksum;
            pPayloadResp->Output.Para0.payloadCurrentStatus =
                gNVOOBdata.payloadInfo[pPayloadReq->Input.Para0.payloadType].status;
            pPayloadResp->Output.Para0.timeStamp =
                gNVOOBdata.payloadInfo[pPayloadReq->Input.Para0.payloadType].uploadTimeStamp;
            pPayloadResp->Output.Para0.payloadFlag =
                gNVOOBdata.payloadInfo[pPayloadReq->Input.Para0.payloadType].payloadFlag;
            rc = IPMI_CC_OK;
            rc = sizeof(pPayloadResp->Output.Para0);

            break;
        case GetPayloadParameter::PayloadData:
            if (pPayloadReq->Input.Para1.payloadLength == 0)
            {
                rc = IPMI_CC_INVALID_FIELD_REQUEST;
                *dataLen = 0;
                break;
            }
            Imgbuffer = new uint8_t(pPayloadReq->Input.Para1.payloadLength);
            if (Imgbuffer != NULL)
            {
                pPayloadResp->Output.Para1.actualPayloadlength =
                    imgReadFromFile(
                        pPayloadReq->Input.Para1.payloadType, Imgbuffer,
                        pPayloadReq->Input.Para1.payloadOffset,
                        pPayloadReq->Input.Para1.payloadLength,
                        &pPayloadResp->Output.Para1.actualPayloadChecksum);
                rc = IPMI_CC_OK;
                std::copy(pPayloadResp->Output.Para1.payloadData,
                          pPayloadResp->Output.Para1.payloadData +
                              pPayloadResp->Output.Para1.actualPayloadlength,
                          Imgbuffer);
                *dataLen =
                    pPayloadResp->Output.Para1.actualPayloadlength +
                    sizeof(pPayloadResp->Output.Para1.actualPayloadlength) +
                    sizeof(pPayloadResp->Output.Para1.actualPayloadChecksum) +
                    sizeof(pPayloadResp->Output.Para1.payloadType);
                delete Imgbuffer;
            }
            else
            {
                rc = OOBCompleteCode::compcodePayloadTypeNotSupported;
                *dataLen = 0;
            }

            break;
        case GetPayloadParameter::PayloadStatus:
            pPayloadResp->Output.Para2.status =
                gNVOOBdata.payloadInfo[pPayloadReq->Input.Para0.payloadType].status;
            rc = IPMI_CC_OK;
            *dataLen = sizeof(pPayloadResp->Output.Para2.status);
            break;

        default:
            *dataLen = 0;
            rc = IPMI_CC_INVALID_FIELD_REQUEST;
    }

    return rc;
}

ipmi_ret_t ipmiOOBSetBIOSPwdHashInfo(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                     ipmi_request_t request,
                                     ipmi_response_t response,
                                     ipmi_data_len_t dataLen,
                                     ipmi_context_t context)
{
    setBIOSHashInfoReq *pBIOSHashinfo =
        reinterpret_cast<setBIOSHashInfoReq *>(request);
    ipmi_ret_t rc = IPMI_CC_OK;
    *dataLen = 0;
    if (pBIOSHashinfo->hashAlgo != 0)
    { // Atpresent, we are supporting only SHA 256 - HASH algo in BIOS side
        rc = IPMI_CC_INVALID_FIELD_REQUEST;
        return rc;
    }
    std::copy(gNVOOBdata.mBIOSHashInfo.BIOSPwdHash,
              gNVOOBdata.mBIOSHashInfo.BIOSPwdHash + maxHashSize,
              pBIOSHashinfo->BIOSPwdHash);
    std::copy(gNVOOBdata.mBIOSHashInfo.BIOSPwdHash,
              gNVOOBdata.mBIOSHashInfo.BIOSPwdHash + maxSeedSize,
              pBIOSHashinfo->BIOSPwdSeed);
    gNVOOBdata.mBIOSHashInfo.hashAlgo = pBIOSHashinfo->hashAlgo;
    flushNVOOBdata();

    return rc;
}

ipmi_ret_t ipmiOOBGetBIOSPwdHash(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                 ipmi_request_t request,
                                 ipmi_response_t response,
                                 ipmi_data_len_t dataLen,
                                 ipmi_context_t context)
{
    getUserBIOSHashResp *getUserBIOSHash =
        reinterpret_cast<getUserBIOSHashResp *>(response);
    ipmi_ret_t rc = IPMI_CC_OK;
    getNVOOBdata();
    if (gNVOOBdata.mIsUserPwdInitDone)
    {
        std::copy(getUserBIOSHash->userPwdHash,
                  getUserBIOSHash->userPwdHash + maxHashSize, gNVOOBdata.mUserPwdHash);
        *dataLen = sizeof(getUserBIOSHashResp);
    }
    else
    {
        *dataLen = 0;
        rc = OOBCompleteCode::compcodePayloadTypeNotSupported;
    }
    return rc;
}

ipmi_ret_t ipmiOOBUpdateOOBStatus(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                  ipmi_request_t request,
                                  ipmi_response_t response,
                                  ipmi_data_len_t dataLen,
                                  ipmi_context_t context)
{
    ipmi_ret_t rc = IPMI_CC_OK;
    setUpdateStatusReq  *pPayloadReq  = (setUpdateStatusReq *) request;

    OOBImageType currentPayloadType =
        static_cast<OOBImageType>(pPayloadReq->payloadType);

    if (currentPayloadType >= OOBImageType::invalidType) {
        *dataLen = 0;
        rc = OOBCompleteCode::compcodePayloadTypeNotSupported;
        return rc;
    }

    gNVOOBdata.payloadInfo[currentPayloadType].payloadVersion        = 0;
    gNVOOBdata.payloadInfo[currentPayloadType].givenPayloadSize      = pPayloadReq->payloadSize;
    gNVOOBdata.payloadInfo[currentPayloadType].givenPayloadChecksum  = pPayloadReq->payloadChecksum;
    gNVOOBdata.payloadInfo[currentPayloadType].actualPayloadSize     = pPayloadReq->payloadSize;
    gNVOOBdata.payloadInfo[currentPayloadType].actualPayloadChecksum = pPayloadReq->payloadChecksum;
    gNVOOBdata.payloadInfo[currentPayloadType].reservationToken      = rand();
    gNVOOBdata.payloadInfo[currentPayloadType].uploadTimeStamp       = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();;//static_cast<uint32_t>(std::chrono::steady_clock::now());
    gNVOOBdata.payloadInfo[currentPayloadType].status                = TransferState::EndOfTransfer;
    gNVOOBdata.payloadInfo[currentPayloadType].imageType             = currentPayloadType;
    flushNVOOBdata();

    return rc;
}

static void initOOB(void)
{
    phosphor::logging::log<phosphor::logging::level::INFO>(
        "OOB module initialization");

    getNVOOBdata();
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdSetBIOSCap),
        NULL, ipmiOOBSetBIOSCap, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdGetBIOSCap),
        NULL, ipmiOOBGetBIOSCap, PRIVILEGE_USER);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdSetPayload),
        NULL, ipmiOOBSetPayload, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdGetPayload),
        NULL, ipmiOOBGetPayload, PRIVILEGE_USER);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(
            IPMINetfnIntelOEMGeneralCmd::cmdSetBIOSPwdHashInfo),
        NULL, ipmiOOBSetBIOSPwdHashInfo, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMGeneralCmd::cmdGetBIOSPwdHash),
        NULL, ipmiOOBGetBIOSPwdHash, PRIVILEGE_ADMIN);
    ipmiPrintAndRegister(netfnIntcOEMGeneral,
                         static_cast<ipmi_cmd_t>(
                             IPMINetfnIntelOEMGeneralCmd::cmdUpdateOOBStatus),
                         NULL, ipmiOOBUpdateOOBStatus, PRIVILEGE_ADMIN);
    return;
}

} // namespace ipmi
