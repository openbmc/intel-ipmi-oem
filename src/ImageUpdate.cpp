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

#include <array>
#include <boost/crc.hpp>
#include <boost/integer.hpp>
#include <commandutils.hpp>
#include <fstream>
#include <iostream>
#include <oemcommands.hpp>
#include <oobcommands.hpp>
#include <phosphor-ipmi-host/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>

namespace ipmi
{

struct ImageFileTable
{
    std::string file;
    std::string tempFile;
};

extern nvOOBdata  gNVOOBdata;


static constexpr const char* XMLType0Tmp = "/tmp/tmp-XMLTyp0.7z";
static constexpr const char* XMLType1Tmp = "/tmp/tmp-XMLTyp1.conf";
static constexpr const char* BIOSImageTmp = "/tmp/tmp-BIOS.cap";
static constexpr const char* MEImageTmp = "/tmp/tmp-ME.cap";
static constexpr const char* FDImageTmp = "/tmp/tmp-FD.cap";

static constexpr const char* XMLType0File = "/tmp/XMLTyp0.7z";
static constexpr const char* XMLType1File = "/tmp/XMLTyp1.conf";
static constexpr const char* BIOSImageFile = "/tmp/BIOS.cap";
static constexpr const char* MEImageFile = "/tmp/ME.cap";
static constexpr const char* FDImageFile = "/tmp/FD.cap";

static ImageFileTable file_table[OOBImageType::invalidType] = {
    {XMLType0File, XMLType0Tmp},   {XMLType1File, XMLType1Tmp},
    {BIOSImageFile, BIOSImageTmp}, {MEImageFile, MEImageTmp},
    {FDImageFile, FDImageTmp},
};

// return actual read size. return 0 means something wrong
uint32_t imgReadFromFile(uint8_t payloadType, uint8_t* data, uint32_t offset,
                         uint32_t length, uint32_t* actualChksum)
{

    uint32_t u32Crc = 0;
    ssize_t size = 0;
    std::fstream fp;
    boost::crc_32_type result;

    if (payloadType >= OOBImageType::invalidType)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "imgReadFromFile:invalid image type");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    if (gNVOOBdata.payloadInfo[payloadType].status != TransferState::EndOfTransfer)
    {
        fp.open(file_table[payloadType].tempFile,
                std::ios::binary | std::ios::in);
    }
    else
    {
        fp.open(file_table[payloadType].file, std::ios::binary | std::ios::in);
    }

    if (!fp)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "imgReadFromFile:Fail to open file");
        return IPMI_CC_UNSPECIFIED_ERROR;
    }

    fp.seekg(offset, std::ios::beg);

    fp.read((char*)data, length);
    if (fp.gcount() == -1)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "imgReadFromFile:Fail to read from file");
        fp.close();
        return 0;
    }

    result.process_bytes(data, length);
    u32Crc = result.checksum();

    *actualChksum = u32Crc;

    // close fs handler
    fp.close();
    phosphor::logging::log<phosphor::logging::level::DEBUG>(
        "imgReadFromFile:",
        phosphor::logging::entry(" Read Size : %x and Length requested %x",
                                 fp.gcount(), (unsigned int)length));
    return size;
}

} // namespace ipmi
