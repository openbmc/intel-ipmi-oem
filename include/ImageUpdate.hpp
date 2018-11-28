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
#pragma pack(push, 1)

// return actual read size. return 0 means something wrong
uint32_t imgReadFromFile(uint8_t payloadType, uint8_t *data, uint32_t offset,
                         uint32_t length, uint32_t *actualChksum);

#pragma pack(pop)
