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

#include "oemcommands.hpp"

#include <openssl/hmac.h>

#include <ipmid/api.hpp>
#include <ipmid/utils.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>

void register_netfn_bmc_control_functions() __attribute__((constructor));

enum ipmi_bmc_control_services_return_codes
{
    ipmiCCBmcControlInvalidBitMask = 0xCC,
    ipmiCCBmcControlPasswdInvalid = 0xCD,
    ipmiCCBmcControlInvalidChannel = 0xD4,
};

// TODO: Add other services, once they are supported
static const std::unordered_map<uint8_t, std::string> bmcServices = {
    {3, "netipmid"},
    {5, "web"},
    {6, "ssh"},
};

static constexpr const char* objectManagerIntf =
    "org.freedesktop.DBus.ObjectManager";
static constexpr const char* serviceConfigBasePath =
    "/xyz/openbmc_project/control/service";
static constexpr const char* serviceConfigAttrIntf =
    "xyz.openbmc_project.Control.Service.Attributes";
static constexpr const char* serviceStateProperty = "State";
static std::string disableServiceValue = "disabled";

static ipmi_ret_t disableBmcServices(const std::string& objName)
{
    std::shared_ptr<sdbusplus::asio::connection> dbus = getSdBus();
    static std::string serviceCfgMgr{};
    if (serviceCfgMgr.empty())
    {
        try
        {
            serviceCfgMgr = ipmi::getService(*dbus, objectManagerIntf,
                                             serviceConfigBasePath);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            serviceCfgMgr.clear();
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Error: In fetching disabling service manager name");
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
    }
    auto path = std::string(serviceConfigBasePath) + "/" + objName;
    try
    {
        ipmi::setDbusProperty(*dbus, serviceCfgMgr, path, serviceConfigAttrIntf,
                              serviceStateProperty,
                              ipmi::Value(disableServiceValue));
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "Disabling service",
            phosphor::logging::entry("PATH=%s", path.c_str()),
            phosphor::logging::entry("MGR_NAME=%s", serviceCfgMgr.c_str()));
        return IPMI_CC_OK;
    }
    catch (const sdbusplus::exception_t&)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Error: Disabling service",
            phosphor::logging::entry("PATH=%s", path.c_str()),
            phosphor::logging::entry("MGR_NAME=%s", serviceCfgMgr.c_str()));
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
}

static constexpr size_t controlPasswdSize = 32;

ipmi::RspType<> bmcIntelControlServices(
    ipmi::Context::ptr ctx,
    const std::array<uint8_t, controlPasswdSize>& passwd, uint8_t stdServices,
    uint8_t oemServices)
{
    // Execute this command only in KCS interface
    if (ctx->channel != interfaceKCS)
    {
        return ipmi::response(ipmiCCBmcControlInvalidChannel);
    }

    static std::string hashData("Intel 0penBMC");
    static std::vector<uint8_t> hashedValue = {
        0x89, 0x6A, 0xAB, 0x7D, 0xB0, 0x5A, 0x2D, 0x92, 0x41, 0xAD, 0x92,
        0xEE, 0xD4, 0x82, 0xDE, 0x62, 0x66, 0x16, 0xC1, 0x08, 0xFD, 0x23,
        0xC6, 0xD8, 0x75, 0xB3, 0x52, 0x53, 0x31, 0x3C, 0x7F, 0x69};
    std::vector<uint8_t> hashedOutput(EVP_MAX_MD_SIZE, 0);
    unsigned int outputLen = 0;
    HMAC(EVP_sha256(), passwd.data(), passwd.size(),
         reinterpret_cast<const uint8_t*>(hashData.c_str()), hashData.length(),
         &hashedOutput[0], &outputLen);
    hashedOutput.resize(outputLen);

    if (hashedOutput != hashedValue)
    {
        return ipmi::response(ipmiCCBmcControlPasswdInvalid);
    }

    if (stdServices == 0 && oemServices == 0)
    {
        return ipmi::response(ipmiCCBmcControlInvalidBitMask);
    }

    ipmi_ret_t retVal = IPMI_CC_OK;
    for (size_t bitIndex = 0; bitIndex < 8; ++bitIndex)
    {
        if (stdServices & (1 << bitIndex))
        {
            auto it = bmcServices.find(bitIndex);
            if (it == bmcServices.end())
            {
                return ipmi::response(ipmiCCBmcControlInvalidBitMask);
            }
            retVal = disableBmcServices(it->second);
            if (retVal != IPMI_CC_OK)
            {
                return ipmi::response(retVal);
            }
        }
    }
    return ipmi::responseSuccess();
}

void register_netfn_bmc_control_functions()
{
    ipmi::registerHandler(ipmi::prioOpenBmcBase, netfnIntcOEMGeneral,
                          static_cast<ipmi_cmd_t>(
                              IPMINetFnIntelOemGeneralCmds::BmcControlServices),
                          ipmi::Privilege::User, bmcIntelControlServices);
}
