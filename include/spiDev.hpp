/*
// Copyright (c) 2019 Intel Corporation
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

#include <stdio.h>

#include <experimental/filesystem>

/** @class SPIDev
 *  @brief Responsible for handling file pointer
 */
class SPIDev
{
  private:
    /** @brief handler for operating on file */
    int fd;

  public:
    SPIDev() = delete;
    SPIDev(const SPIDev&) = delete;
    SPIDev& operator=(const SPIDev&) = delete;
    SPIDev(SPIDev&&) = delete;
    SPIDev& operator=(SPIDev&&) = delete;

    /** @brief Opens spi(mtd) device file
     *
     *  @param[in] devNo       - MTD device number
     */
    SPIDev(const uint8_t& devNo)
    {
        std::string spiDev = "/dev/mtd" + std::to_string(devNo);

        fd = open(spiDev.c_str(), O_RDWR | O_CLOEXEC);
        if (fd < 0)
        {
            throw std::runtime_error("Unable to open mtd device.");
        }
    }

    /** @brief Reads the byte data from SPI(MTD) device
     *
     *  @param[in] startAddr    - start address
     *  @param[in] dataLen      - No of byte to read
     *  @param[out] dataRes     - Out data pointer
     */
    void spiReadData(const uint32_t& startAddr, const uint32_t& dataLen,
                     void* dataRes)
    {
        if (lseek(fd, startAddr, SEEK_SET) < 0)
        {
            throw std::runtime_error("Failed to do lseek on mtd device.");
        }

        if (read(fd, dataRes, dataLen) != dataLen)
        {
            throw std::runtime_error("Failed to read on mtd device.");
        }

        return;
    }

    ~SPIDev()
    {
        if (!(fd < 0))
        {
            close(fd);
        }
    }

    auto operator()()
    {
        return fd;
    }
};
