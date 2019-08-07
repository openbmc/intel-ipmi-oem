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
#include <linux/i2c-dev.h>
#include <linux/i2c.h>

#include <filesystem>
#include <fstream>
#include <ipmid/api.hpp>
#include <manufacturingcommands.hpp>
#include <nlohmann/json.hpp>
#include <oemcommands.hpp>

namespace ipmi
{

Manufacturing mtm;

typedef struct
{
    uint8_t busId;
    uint8_t slaveAddr;
    uint8_t slaveAddrMask;
    std::vector<uint8_t> data;
    std::vector<uint8_t> dataMask;
} i2cMasterWRWhitelist;

static std::vector<i2cMasterWRWhitelist>& getWRWhitelist()
{
    static std::vector<i2cMasterWRWhitelist> wrWhitelist;
    return wrWhitelist;
}

static constexpr const char* i2cMasterWRWhitelistFile =
    "/usr/share/ipmi-providers/master_write_read_white_list.json";

static constexpr uint8_t slotAddressTypeBus = 0;
static constexpr uint8_t slotAddressTypeUniqueid = 1;
static constexpr uint8_t slotI2CMaxRead = 35;
static constexpr uint8_t slotBBNumMask = 0x7;
static constexpr uint8_t slotRiserSlotNumMask = 0x38;
static constexpr int base_16 = 16;
static constexpr const char* filtersStr = "filters";
static constexpr const char* busIdStr = "busId";
static constexpr const char* slaveAddrStr = "slaveAddr";
static constexpr const char* slaveAddrMaskStr = "slaveAddrMask";
static constexpr const char* cmdStr = "command";
static constexpr const char* cmdMaskStr = "commandMask";

static auto revertTimeOut =
    std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::seconds(60)); // 1 minute timeout

static constexpr const char* callbackMgrService =
    "xyz.openbmc_project.CallbackManager";
static constexpr const char* callbackMgrIntf =
    "xyz.openbmc_project.CallbackManager";
static constexpr const char* callbackMgrObjPath =
    "/xyz/openbmc_project/CallbackManager";
static constexpr const char* retriggerLedUpdate = "RetriggerLEDUpdate";

const static constexpr char* systemDService = "org.freedesktop.systemd1";
const static constexpr char* systemDObjPath = "/org/freedesktop/systemd1";
const static constexpr char* systemDMgrIntf =
    "org.freedesktop.systemd1.Manager";
const static constexpr char* pidControlService = "phosphor-pid-control.service";

int getGpioPathForSmSignal(const SmSignalGet signal, std::string& path)
{
    switch (signal)
    {
        case SmSignalGet::smPowerButton:
            path = "/xyz/openbmc_project/chassis/buttons/power";
            break;
        case SmSignalGet::smResetButton:
            path = "/xyz/openbmc_project/chassis/buttons/reset";
            break;
        case SmSignalGet::smNMIButton:
            path = "/xyz/openbmc_project/chassis/buttons/nmi";
            break;
        default:
            return -1;
            break;
    }
    return 0;
}

ipmi_ret_t ledStoreAndSet(SmSignalSet signal, std::string setState)
{
    LedProperty* ledProp = mtm.findLedProperty(signal);
    if (ledProp == nullptr)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    std::string ledName = ledProp->getName();
    std::string ledService = ledServicePrefix + ledName;
    std::string ledPath = ledPathPrefix + ledName;
    ipmi::Value presentState;

    if (false == ledProp->getLock())
    {
        if (mtm.getProperty(ledService.c_str(), ledPath.c_str(), ledIntf,
                            "State", &presentState) != 0)
        {
            return IPMI_CC_UNSPECIFIED_ERROR;
        }
        ledProp->setPrevState(std::get<std::string>(presentState));
        ledProp->setLock(true);
        if (signal == SmSignalSet::smPowerFaultLed ||
            signal == SmSignalSet::smSystemReadyLed)
        {
            mtm.revertLedCallback = true;
        }
    }
    if (mtm.setProperty(ledService, ledPath, ledIntf, "State",
                        ledStateStr + setState) != 0)
    {
        return IPMI_CC_UNSPECIFIED_ERROR;
    }
    return IPMI_CC_OK;
}

ipmi_ret_t ledRevert(SmSignalSet signal)
{
    LedProperty* ledProp = mtm.findLedProperty(signal);
    if (ledProp == nullptr)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    if (true == ledProp->getLock())
    {
        ledProp->setLock(false);
        if (signal == SmSignalSet::smPowerFaultLed ||
            signal == SmSignalSet::smSystemReadyLed)
        {
            try
            {
                ipmi::method_no_args::callDbusMethod(
                    *getSdBus(), callbackMgrService, callbackMgrObjPath,
                    callbackMgrIntf, retriggerLedUpdate);
            }
            catch (sdbusplus::exception_t& e)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
            mtm.revertLedCallback = false;
        }
        else
        {
            std::string ledName = ledProp->getName();
            std::string ledService = ledServicePrefix + ledName;
            std::string ledPath = ledPathPrefix + ledName;
            if (mtm.setProperty(ledService, ledPath, ledIntf, "State",
                                ledProp->getPrevState()) != 0)
            {
                return IPMI_CC_UNSPECIFIED_ERROR;
            }
        }
    }
    return IPMI_CC_OK;
}

void Manufacturing::initData()
{
    ledPropertyList.push_back(
        LedProperty(SmSignalSet::smPowerFaultLed, "status_amber"));
    ledPropertyList.push_back(
        LedProperty(SmSignalSet::smSystemReadyLed, "status_green"));
    ledPropertyList.push_back(
        LedProperty(SmSignalSet::smIdentifyLed, "identify"));
}

void Manufacturing::revertTimerHandler()
{
    if (revertFanPWM)
    {
        revertFanPWM = false;
        disablePidControlService(false);
    }

    for (const auto& ledProperty : ledPropertyList)
    {
        const std::string& ledName = ledProperty.getName();
        ledRevert(ledProperty.getSignal());
    }
}

Manufacturing::Manufacturing() :
    revertTimer([&](void) { revertTimerHandler(); })
{
    initData();
}

int8_t Manufacturing::getProperty(const std::string& service,
                                  const std::string& path,
                                  const std::string& interface,
                                  const std::string& propertyName,
                                  ipmi::Value* reply)
{
    try
    {
        *reply = ipmi::getDbusProperty(*getSdBus(), service, path, interface,
                                       propertyName);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ERROR: getProperty");
        return -1;
    }

    return 0;
}

int8_t Manufacturing::setProperty(const std::string& service,
                                  const std::string& path,
                                  const std::string& interface,
                                  const std::string& propertyName,
                                  ipmi::Value value)
{
    try
    {
        ipmi::setDbusProperty(*getSdBus(), service, path, interface,
                              propertyName, value);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ERROR: setProperty");
        return -1;
    }

    return 0;
}

int8_t Manufacturing::disablePidControlService(const bool disable)
{
    try
    {
        auto dbus = getSdBus();
        auto method = dbus->new_method_call(systemDService, systemDObjPath,
                                            systemDMgrIntf,
                                            disable ? "StopUnit" : "StartUnit");
        method.append(pidControlService, "replace");
        auto reply = dbus->call(method);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        phosphor::logging::log<phosphor::logging::level::INFO>(
            "ERROR: phosphor-pid-control service start or stop failed");
        return -1;
    }
    return 0;
}

inline std::vector<uint8_t> convertStringToData(const std::string& command)
{
    std::istringstream iss(command);
    std::string token;
    std::vector<uint8_t> dataValue;
    while (std::getline(iss, token, ' '))
    {
        dataValue.emplace_back(
            static_cast<uint8_t>(std::stoul(token, nullptr, base_16)));
    }
    return dataValue;
}

static bool populateI2CMasterWRWhitelist()
{
    nlohmann::json data = nullptr;
    std::ifstream jsonFile(i2cMasterWRWhitelistFile);

    if (!jsonFile.good())
    {
        phosphor::logging::log<phosphor::logging::level::WARNING>(
            "i2c white list file not found!",
            phosphor::logging::entry("FILE_NAME=%s", i2cMasterWRWhitelistFile));
        return false;
    }

    try
    {
        data = nlohmann::json::parse(jsonFile, nullptr, false);
    }
    catch (nlohmann::json::parse_error& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Corrupted i2c white list config file",
            phosphor::logging::entry("FILE_NAME=%s", i2cMasterWRWhitelistFile),
            phosphor::logging::entry("MSG=%s", e.what()));
        return false;
    }

    try
    {
        // Example JSON Structure format
        // "filters": [
        //    {
        //      "Description": "Allow full read - ignore first byte write value
        //      for 0x40 to 0x4F",
        //      "busId": "0x01",
        //      "slaveAddr": "0x40",
        //      "slaveAddrMask": "0x0F",
        //      "command": "0x00",
        //      "commandMask": "0xFF"
        //    },
        //    {
        //      "Description": "Allow full read - first byte match 0x05 and
        //      ignore second byte",
        //      "busId": "0x01",
        //      "slaveAddr": "0x57",
        //      "slaveAddrMask": "0x00",
        //      "command": "0x05 0x00",
        //      "commandMask": "0x00 0xFF"
        //    },]

        nlohmann::json filters = data[filtersStr].get<nlohmann::json>();
        std::vector<i2cMasterWRWhitelist>& whitelist = getWRWhitelist();
        for (const auto& it : filters.items())
        {
            nlohmann::json filter = it.value();
            if (filter.is_null())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "Corrupted I2C master write read whitelist config file",
                    phosphor::logging::entry("FILE_NAME=%s",
                                             i2cMasterWRWhitelistFile));
                return false;
            }
            const std::vector<uint8_t>& writeData =
                convertStringToData(filter[cmdStr].get<std::string>());
            const std::vector<uint8_t>& writeDataMask =
                convertStringToData(filter[cmdMaskStr].get<std::string>());
            if (writeDataMask.size() != writeData.size())
            {
                phosphor::logging::log<phosphor::logging::level::ERR>(
                    "I2C master write read whitelist filter "
                    "mismatch for command & mask size");
                return false;
            }
            whitelist.push_back(
                {static_cast<uint8_t>(std::stoul(
                     filter[busIdStr].get<std::string>(), nullptr, base_16)),
                 static_cast<uint8_t>(
                     std::stoul(filter[slaveAddrStr].get<std::string>(),
                                nullptr, base_16)),
                 static_cast<uint8_t>(
                     std::stoul(filter[slaveAddrMaskStr].get<std::string>(),
                                nullptr, base_16)),
                 writeData, writeDataMask});
        }
        if (whitelist.size() != filters.size())
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "I2C master write read whitelist filter size mismatch");
            return false;
        }
    }
    catch (std::exception& e)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "I2C master write read whitelist unexpected exception",
            phosphor::logging::entry("ERROR=%s", e.what()));
        return false;
    }
    return true;
}

static inline bool isWriteDataWhitelisted(const std::vector<uint8_t>& data,
                                          const std::vector<uint8_t>& dataMask,
                                          const std::vector<uint8_t>& writeData)
{
    std::vector<uint8_t> processedDataBuf(data.size());
    std::vector<uint8_t> processedReqBuf(dataMask.size());
    std::transform(writeData.begin(), writeData.end(), dataMask.begin(),
                   processedReqBuf.begin(), std::bit_or<uint8_t>());
    std::transform(data.begin(), data.end(), dataMask.begin(),
                   processedDataBuf.begin(), std::bit_or<uint8_t>());

    return (processedDataBuf == processedReqBuf);
}

static bool isCmdWhitelisted(uint8_t busId, uint8_t slaveAddr,
                             std::vector<uint8_t>& writeData)
{
    std::vector<i2cMasterWRWhitelist>& whiteList = getWRWhitelist();

    for (const auto& wlEntry : whiteList)
    {
        if ((busId == wlEntry.busId) &&
            ((slaveAddr | wlEntry.slaveAddrMask) ==
             (wlEntry.slaveAddr | wlEntry.slaveAddrMask)))
        {
            const std::vector<uint8_t>& dataMask = wlEntry.dataMask;
            // Skip as no-match, if requested write data is more than the
            // write data mask size
            if (writeData.size() > dataMask.size())
            {
                continue;
            }
            if (isWriteDataWhitelisted(wlEntry.data, dataMask, writeData))
            {
                return true;
            }
        }
    }
    return false;
}

static int getBusNum(const uint8_t& riserNum, const uint8_t& slotNum,
                     uint8_t& busNum)
{

    std::string path = "/dev/i2c-mux/Riser_" + std::to_string(riserNum) +
                       "_Mux/Pcie_Slot_" + std::to_string(slotNum);

    if (std::filesystem::exists(path) && std::filesystem::is_symlink(path))
    {
        std::string link = std::filesystem::read_symlink(path).filename();
        size_t findDash = link.find("-");
        if (findDash == std::string::npos || link.size() <= findDash + 1)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Master write read command: Error finding device from symlink");
            return -1;
        }

        size_t bus = 0;
        bus = std::stoi(link.substr(findDash + 1));
        busNum = bus;
    }
    else
    {
        return -1;
    }

    return 0;
}

/** @brief implements slot master write read IPMI command which can be used for
 * low-level I2C/SMBus write, read or write-read access for PCIE slots
 *  @param busNum - bus number
 *  @param reserved - skip 2 bit
 *  @param addressType - address type
 *  @param slotNum - slot number
 *  @param slaveAddr - slave address
 *  @param readCount - number of bytes to be read
 *  @param writeData - data to be written
 *
 *  @returns IPMI completion code plus response data
 */
ipmi::RspType<std::vector<uint8_t>>
    appSlotI2C(uint4_t busNum, uint2_t reserved, uint2_t addressType,
               uint8_t slotNum, uint8_t slaveAddr, uint8_t readCount,
               std::vector<uint8_t> writeData)
{
    i2c_rdwr_ioctl_data msgReadWrite = {0};
    i2c_msg i2cmsg[2] = {0};
    uint8_t busId = 0;
    int ret = 0;

    if (addressType == slotAddressTypeBus)
    {
        ret = getBusNum((slotNum & slotBBNumMask),
                        ((slotNum & slotRiserSlotNumMask) >> 3), busId);
        if (ret)
        {
            phosphor::logging::log<phosphor::logging::level::ERR>(
                "Master write read command: Cannot get BusID");
            return ipmi::responseInvalidFieldRequest();
        }
    }
    else if (addressType == slotAddressTypeUniqueid)
    {
        if (mtm.getAccessLvl() < MtmLvl::mtmAvailable)
        {
            return ipmi::responseInsufficientPrivilege();
        }
        busId = slotNum;
    }

    if (readCount > slotI2CMaxRead)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Master write read command: Read count exceeds limit");
        return ipmi::responseParmOutOfRange();
    }

    const size_t writeCount = writeData.size();
    if (!readCount && !writeCount)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Master write read command: Read & write count are 0");
        return ipmi::responseInvalidFieldRequest();
    }

    if (!isCmdWhitelisted(static_cast<uint8_t>(busId),
                          static_cast<uint8_t>(slaveAddr), writeData))
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Master write read request blocked!",
            phosphor::logging::entry("BUS=%d", static_cast<uint8_t>(busId)),
            phosphor::logging::entry("ADDR=0x%x",
                                     static_cast<uint8_t>(slaveAddr)));
        return ipmi::responseInvalidFieldRequest();
    }

    std::vector<uint8_t> readBuf(readCount);
    std::string i2cBus =
        "/dev/i2c-" + std::to_string(static_cast<uint8_t>(busId));

    int i2cDev = ::open(i2cBus.c_str(), O_RDWR | O_CLOEXEC);
    if (i2cDev < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Failed to open i2c bus",
            phosphor::logging::entry("BUS=%s", i2cBus.c_str()));
        return ipmi::responseInvalidFieldRequest();
    }

    int msgCount = 0;
    if (writeCount)
    {
        i2cmsg[msgCount].addr = static_cast<uint8_t>(slaveAddr);
        i2cmsg[msgCount].flags = 0x00;
        i2cmsg[msgCount].len = writeCount;
        i2cmsg[msgCount].buf = writeData.data();
        msgCount++;
    }
    if (readCount)
    {
        i2cmsg[msgCount].addr = static_cast<uint8_t>(slaveAddr);
        i2cmsg[msgCount].flags = I2C_M_RD;
        i2cmsg[msgCount].len = readCount;
        i2cmsg[msgCount].buf = readBuf.data();
        msgCount++;
    }

    msgReadWrite.msgs = i2cmsg;
    msgReadWrite.nmsgs = msgCount;

    ret = ::ioctl(i2cDev, I2C_RDWR, &msgReadWrite);
    ::close(i2cDev);

    if (ret < 0)
    {
        phosphor::logging::log<phosphor::logging::level::ERR>(
            "Master write read: Failed",
            phosphor::logging::entry("RET=%d", ret));
        return ipmi::responseUnspecifiedError();
    }
    if (readCount)
    {
        readBuf.resize(msgReadWrite.msgs[msgCount - 1].len);
    }
    return ipmi::responseSuccess(readBuf);
}

ipmi::RspType<uint8_t,                // Signal value
              std::optional<uint16_t> // Fan tach value
              >
    appMTMGetSignal(uint8_t signalTypeByte, uint8_t instance,
                    uint8_t actionByte)
{
    if (mtm.getAccessLvl() < MtmLvl::mtmAvailable)
    {
        return ipmi::responseInsufficientPrivilege();
    }

    SmSignalGet signalType = static_cast<SmSignalGet>(signalTypeByte);
    SmActionGet action = static_cast<SmActionGet>(actionByte);

    switch (signalType)
    {
        case SmSignalGet::smFanPwmGet:
        {
            ipmi::Value reply;
            std::string fullPath = fanPwmPath + std::to_string(instance);
            if (mtm.getProperty(fanService, fullPath, fanIntf, "Value",
                                &reply) < 0)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            double* doubleVal = std::get_if<double>(&reply);
            if (doubleVal == nullptr)
            {
                return ipmi::responseUnspecifiedError();
            }
            uint8_t sensorVal = std::round(*doubleVal);
            return ipmi::responseSuccess(sensorVal, std::nullopt);
        }
        break;
        case SmSignalGet::smFanTachometerGet:

        {
            // Full path calculation pattern:
            // Instance 1 path is
            // /xyz/openbmc_project/sensors/fan_tach/Fan_1a Instance 2 path
            // is /xyz/openbmc_project/sensors/fan_tach/Fan_1b Instance 3
            // path is /xyz/openbmc_project/sensors/fan_tach/Fan_2a
            // and so on...
            std::string fullPath = fanTachPathPrefix;
            std::string fanAb = (instance % 2) == 0 ? "b" : "a";
            if (0 == instance)
            {
                return ipmi::responseInvalidFieldRequest();
            }
            else if (0 == instance / 2)
            {
                fullPath += std::string("1") + fanAb;
            }
            else
            {
                fullPath += std::to_string(instance / 2) + fanAb;
            }

            ipmi::Value reply;
            if (mtm.getProperty(fanService, fullPath, fanIntf, "Value",
                                &reply) < 0)
            {
                return ipmi::responseInvalidFieldRequest();
            }

            double* doubleVal = std::get_if<double>(&reply);
            if (doubleVal == nullptr)
            {
                return ipmi::responseUnspecifiedError();
            }
            uint8_t sensorVal = FAN_PRESENT | FAN_SENSOR_PRESENT;
            std::optional<uint16_t> fanTach = std::round(*doubleVal);

            return ipmi::responseSuccess(sensorVal, fanTach);
        }
        break;
        case SmSignalGet::smResetButton:
        case SmSignalGet::smPowerButton:
        case SmSignalGet::smNMIButton:
        case SmSignalGet::smIdentifyButton:
        {
            std::string path;
            if (getGpioPathForSmSignal(signalType, path) < 0)
            {
                return ipmi::responseInvalidFieldRequest();
            }

            switch (action)
            {
                case SmActionGet::sample:
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "case SmActionGet::sample");
                    break;
                case SmActionGet::ignore:
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "case SmActionGet::ignore");
                    if (mtm.setProperty(buttonService, path, buttonIntf,
                                        "ButtonMasked", true) < 0)
                    {
                        return ipmi::responseUnspecifiedError();
                    }
                }
                break;
                case SmActionGet::revert:
                {
                    phosphor::logging::log<phosphor::logging::level::INFO>(
                        "case SmActionGet::revert");
                    if (mtm.setProperty(buttonService, path, buttonIntf,
                                        "ButtonMasked", false) < 0)
                    {
                        return ipmi::responseUnspecifiedError();
                    }
                }
                break;

                default:
                    return ipmi::responseInvalidFieldRequest();
                    break;
            }

            ipmi::Value reply;
            if (mtm.getProperty(buttonService, path, buttonIntf,
                                "ButtonPressed", &reply) < 0)
            {
                return ipmi::responseUnspecifiedError();
            }
            bool* valPtr = std::get_if<bool>(&reply);
            if (valPtr == nullptr)
            {
                return ipmi::responseUnspecifiedError();
            }
            uint8_t sensorVal = *valPtr;
            return ipmi::responseSuccess(sensorVal, std::nullopt);
        }
        break;
        default:
            return ipmi::responseInvalidFieldRequest();
            break;
    }
}

ipmi_ret_t ipmi_app_mtm_set_signal(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                   ipmi_request_t request,
                                   ipmi_response_t response,
                                   ipmi_data_len_t data_len,
                                   ipmi_context_t context)
{
    uint8_t ret = 0;
    ipmi_ret_t retCode = IPMI_CC_OK;
    SetSmSignalReq* pReq = static_cast<SetSmSignalReq*>(request);
    std::string ledName;
    ///////////////////  Signal to led configuration ////////////////
    //        {SM_SYSTEM_READY_LED, STAT_GRN_LED},    GPIOS4  gpio148
    //        {SM_POWER_FAULT_LED, STAT_AMB_LED},     GPIOS5  gpio149
    //        {SM_IDENTIFY_LED, IDENTIFY_LED},        GPIOS6  gpio150
    //        {SM_SPEAKER, SPEAKER},                  GPIOAB0 gpio216
    /////////////////////////////////////////////////////////////////
    if ((*data_len == sizeof(*pReq)) &&
        (mtm.getAccessLvl() >= MtmLvl::mtmAvailable))
    {
        switch (pReq->Signal)
        {
            case SmSignalSet::smPowerFaultLed:
            case SmSignalSet::smSystemReadyLed:
            case SmSignalSet::smIdentifyLed:
                switch (pReq->Action)
                {
                    case SmActionSet::forceDeasserted:
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            "case SmActionSet::forceDeasserted");

                        retCode =
                            ledStoreAndSet(pReq->Signal, std::string("Off"));
                        if (retCode != IPMI_CC_OK)
                        {
                            break;
                        }
                        mtm.revertTimer.start(revertTimeOut);
                    }
                    break;
                    case SmActionSet::forceAsserted:
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            "case SmActionSet::forceAsserted");

                        retCode =
                            ledStoreAndSet(pReq->Signal, std::string("On"));
                        if (retCode != IPMI_CC_OK)
                        {
                            break;
                        }
                        mtm.revertTimer.start(revertTimeOut);
                        if (SmSignalSet::smPowerFaultLed == pReq->Signal)
                        {
                            // Deassert "system ready"
                            retCode =
                                ledStoreAndSet(SmSignalSet::smSystemReadyLed,
                                               std::string("Off"));
                            if (retCode != IPMI_CC_OK)
                            {
                                break;
                            }
                        }
                        else if (SmSignalSet::smSystemReadyLed == pReq->Signal)
                        {
                            // Deassert "fault led"
                            retCode =
                                ledStoreAndSet(SmSignalSet::smPowerFaultLed,
                                               std::string("Off"));
                            if (retCode != IPMI_CC_OK)
                            {
                                break;
                            }
                        }
                    }
                    break;
                    case SmActionSet::revert:
                    {
                        phosphor::logging::log<phosphor::logging::level::INFO>(
                            "case SmActionSet::revert");
                        retCode = ledRevert(pReq->Signal);
                        if (retCode != IPMI_CC_OK)
                        {
                            break;
                        }
                    }
                    break;
                    default:
                    {
                        retCode = IPMI_CC_INVALID_FIELD_REQUEST;
                    }
                    break;
                }
                break;
            case SmSignalSet::smFanPowerSpeed:
            {
                if (((pReq->Action == SmActionSet::forceAsserted) &&
                     (*data_len != sizeof(*pReq)) && (pReq->Value > 100)) ||
                    pReq->Instance == 0)
                {
                    retCode = IPMI_CC_INVALID_FIELD_REQUEST;
                    break;
                }
                uint8_t pwmValue = 0;
                switch (pReq->Action)
                {
                    case SmActionSet::revert:
                    {
                        if (mtm.revertFanPWM)
                        {
                            ret = mtm.disablePidControlService(false);
                            if (ret < 0)
                            {
                                retCode = IPMI_CC_UNSPECIFIED_ERROR;
                                break;
                            }
                            mtm.revertFanPWM = false;
                        }
                    }
                    break;
                    case SmActionSet::forceAsserted:
                    {
                        pwmValue = pReq->Value;
                    } // fall-through
                    case SmActionSet::forceDeasserted:
                    {
                        if (!mtm.revertFanPWM)
                        {
                            ret = mtm.disablePidControlService(true);
                            if (ret < 0)
                            {
                                retCode = IPMI_CC_UNSPECIFIED_ERROR;
                                break;
                            }
                            mtm.revertFanPWM = true;
                        }
                        mtm.revertTimer.start(revertTimeOut);
                        std::string fanPwmInstancePath =
                            fanPwmPath + std::to_string(pReq->Instance);

                        ret = mtm.setProperty(fanService, fanPwmInstancePath,
                                              fanIntf, "Value",
                                              static_cast<double>(pwmValue));
                        if (ret < 0)
                        {
                            retCode = IPMI_CC_UNSPECIFIED_ERROR;
                        }
                    }
                    break;
                    default:
                    {
                        retCode = IPMI_CC_INVALID_FIELD_REQUEST;
                    }
                    break;
                }
            }
            break;
            default:
            {
                retCode = IPMI_CC_INVALID_FIELD_REQUEST;
            }
            break;
        }
    }
    else
    {
        retCode = IPMI_CC_INVALID;
    }

    *data_len = 0; // Only CC is return for SetSmSignal cmd
    return retCode;
}

} // namespace ipmi

void register_mtm_commands() __attribute__((constructor));
void register_mtm_commands()
{
    // <Get SM Signal>
    ipmi::registerHandler(
        ipmi::prioOemBase, ipmi::netFnOemOne,
        static_cast<ipmi::Cmd>(IPMINetFnIntelOemGeneralCmds::GetSmSignal),
        ipmi::Privilege::User, ipmi::appMTMGetSignal);

    // Note: For security reason, this command will be registered only when
    // there are proper I2C Master write read whitelist
    if (ipmi::populateI2CMasterWRWhitelist())
    {
        ipmi::registerHandler(
            ipmi::prioOemBase, ipmi::netFnOemEight,
            static_cast<ipmi_cmd_t>(IPMINetfnIntelOEMAppCmd::slotI2C),
            ipmi::Privilege::User, ipmi::appSlotI2C);
    }

    ipmi_register_callback(
        netfnIntcOEMGeneral,
        static_cast<ipmi_cmd_t>(IPMINetFnIntelOemGeneralCmds::SetSmSignal),
        NULL, ipmi::ipmi_app_mtm_set_signal, PRIVILEGE_USER);
    return;
}
