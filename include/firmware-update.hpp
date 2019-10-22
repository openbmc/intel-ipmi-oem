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

static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_FW_VERSION_INFO = 0x20;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_FW_SEC_VERSION_INFO = 0x21;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_FW_UPD_CHAN_INFO = 0x22;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_BMC_EXEC_CTX = 0x23;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_ROOT_CERT_INFO = 0x24;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_ROOT_CERT_DATA = 0x25;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_FW_UPDATE_RAND_NUM = 0x26;
static constexpr ipmi_cmd_t IPMI_CMD_FW_SET_FW_UPDATE_MODE = 0x27;
static constexpr ipmi_cmd_t IPMI_CMD_FW_EXIT_FW_UPDATE_MODE = 0x28;
static constexpr ipmi_cmd_t IPMI_CMD_FW_UPDATE_CONTROL = 0x29;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_STATUS = 0x2a;
static constexpr ipmi_cmd_t IPMI_CMD_FW_SET_FW_UPDATE_OPTIONS = 0x2b;
static constexpr ipmi_cmd_t IPMI_CMD_FW_IMAGE_WRITE = 0x2c;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_TIMESTAMP = 0x2d;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_UPDATE_ERR_MSG = 0xe0;
static constexpr ipmi_cmd_t IPMI_CMD_FW_GET_REMOTE_FW_INFO = 0xf0;

static constexpr ipmi_netfn_t NETFUN_INTC_APP = 0x30;
static constexpr ipmi_cmd_t IPMI_CMD_INTC_GET_BUFFER_SIZE = 0x66;
