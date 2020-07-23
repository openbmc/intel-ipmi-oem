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

#include "fruutils.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

// Validate the vector holds a complete FRU's contents.
bool ValidateContainsFru(const std::vector<uint8_t>& fru, int lastWriteAddr)
{
    if (fru.size() < sizeof(FRUHeader))
    {
        return false;
    }

    bool atEnd = false;
    bool earlyBail = false;
    const FRUHeader* header = reinterpret_cast<const FRUHeader*>(fru.data());

    int areaLength = 0;
    int lastRecordStart = std::max(
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
            // Check before accessing cache.
            if ((lastRecordStart + 1) >= fru.size())
            {
                earlyBail = true;
                break;
            }

            // The MSB in the second byte of the MultiRecord header signals
            // "End of list"
            endOfList = fru[lastRecordStart + 1] & 0x80;
            if (endOfList)
            {
                break;
            }

            // Check before accessing cache.
            if ((lastRecordStart + 2) >= fru.size())
            {
                // Leave loop atEnd should stay false.
                earlyBail = true;
                break;
            }

            // Third byte in the MultiRecord header is the length
            areaLength = fru[lastRecordStart + 2];
            // This length is in bytes (not 8 bytes like other headers)
            areaLength += 5; // The length omits the 5 byte header
            // Next MultiRecord header
            lastRecordStart += areaLength;
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

    // Only check if we have the whole record if we didn't bail early.
    if (earlyBail)
    {
        return false;
    }

    if (lastWriteAddr >= (areaLength + lastRecordStart))
    {
        atEnd = true;
    }

    return atEnd;
}
