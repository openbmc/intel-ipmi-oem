/*
// Copyright (c) 2017-2019 Intel Corporation
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

#include "fruutils.hpp"

#include <vector>

#pragma pack(push, 1)
struct FRUHeader
{
    uint8_t commonHeaderFormat;
    uint8_t internalOffset;
    uint8_t chassisOffset;
    uint8_t boardOffset;
    uint8_t productOffset;
    uint8_t multiRecordOffset;
    uint8_t pad;
    uint8_t checksum;
};
#pragma pack(pop)

// Validate the vector holds a complete FRU's contents.
bool ValidateContainsFru(const std::vector<uint8_t>& fru, size_t lastWriteAddr)
{
    bool atEnd = false;

    if (fru.size() >= sizeof(FRUHeader))
    {
        const FRUHeader* header =
            reinterpret_cast<const FRUHeader*>(fru.data());

        int areaLength = 0;
        size_t lastRecordStart = std::max(
            {header->internalOffset, header->chassisOffset, header->boardOffset,
             header->productOffset, header->multiRecordOffset});
        lastRecordStart *= 8; // header starts in are multiples of 8 bytes

        if (header->multiRecordOffset)
        {
            // This FRU has a MultiRecord Area
            uint8_t endOfList = 0;
            // Walk the MultiRecord headers until the last record
            while (!endOfList)
            {
                // The MSB in the second byte of the MultiRecord header signals
                // "End of list"
                endOfList = fru[lastRecordStart + 1] & 0x80;
                // Third byte in the MultiRecord header is the length
                areaLength = fru[lastRecordStart + 2];
                // This length is in bytes (not 8 bytes like other headers)
                areaLength += 5; // The length omits the 5 byte header
                if (!endOfList)
                {
                    // Next MultiRecord header
                    lastRecordStart += areaLength;
                }
            }
        }
        else
        {
            // This FRU does not have a MultiRecord Area
            // Get the length of the area in multiples of 8 bytes
            if (lastWriteAddr > (lastRecordStart + 1))
            {
                // second byte in record area is the length
                areaLength = fru[lastRecordStart + 1];
                areaLength *= 8; // it is in multiples of 8 bytes
            }
        }
        if (lastWriteAddr >= (areaLength + lastRecordStart))
        {
            atEnd = true;
        }
    }

    return atEnd;
}
