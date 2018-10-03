/*
// Copyright (c) 2017 2018 Intel Corporation
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

#include <host-ipmid/ipmid-api.h>

#include <boost/container/flat_map.hpp>
#include <commandutils.hpp>
#include <iostream>
#include <phosphor-ipmi-host/timer.hpp>
#include <sdbusplus/message/types.hpp>
#include <storagecommands.hpp>
#include <variantvisitors.hpp>

namespace ipmi
{

namespace storage
{

constexpr size_t MAX_MESSAGE_SIZE = 64;
constexpr size_t maxFruSdrNameSize = 16;
using ManagedObjectType = boost::container::flat_map<
    sdbusplus::message::object_path,
    boost::container::flat_map<
        std::string, boost::container::flat_map<std::string, DbusVariant>>>;
using ManagedEntry = std::pair<
    sdbusplus::message::object_path,
    boost::container::flat_map<
        std::string, boost::container::flat_map<std::string, DbusVariant>>>;

constexpr const char* FRU_DEVICE_SERVICE_NAME = "com.intel.FruDevice";
constexpr size_t CACHE_TIMEOUT_SECONDS = 10;

static std::vector<uint8_t> fruCache;
static uint8_t cacheBus = 0xFF;
static uint8_t cacheAddr = 0XFF;

std::unique_ptr<phosphor::ipmi::Timer> cacheTimer = nullptr;

// we unfortunately have to build a map of hashes in case there is a
// collision to verify our dev-id
boost::container::flat_map<uint8_t, std::pair<uint8_t, uint8_t>> deviceHashes;

void register_netfn_storage_functions() __attribute__((constructor));
sdbusplus::bus::bus dbus(ipmid_get_sd_bus_connection());

bool writeFru()
{
    sdbusplus::message::message writeFru = dbus.new_method_call(
        FRU_DEVICE_SERVICE_NAME, "/xyz/openbmc_project/FruDevice",
        "xyz.openbmc_project.FruDeviceManager", "WriteFru");
    writeFru.append(cacheBus, cacheAddr, fruCache);
    sdbusplus::message::message writeFruResp = dbus.call(writeFru);
    if (writeFruResp.is_method_error())
    {
        // todo: log sel?
        std::cerr << "error writing fru\n";
        return false;
    }
    return true;
}

void createTimer()
{
    if (cacheTimer == nullptr)
    {
        cacheTimer = std::make_unique<phosphor::ipmi::Timer>(
            ipmid_get_sd_event_connection(), writeFru);
    }
}

ipmi_return_codes replaceCacheFru(uint8_t devId)
{
    static uint8_t lastDevId = 0xFF;

    bool timerRunning = (cacheTimer != nullptr) && !cacheTimer->isExpired();
    if (lastDevId == devId && timerRunning)
    {
        return IPMI_CC_OK; // cache already up to date
    }
    // if timer is running, stop it and writeFru manually
    else if (timerRunning)
    {
        cacheTimer->setTimer(SD_EVENT_OFF);
        writeFru();
    }

    sdbusplus::message::message getObjects = dbus.new_method_call(
        FRU_DEVICE_SERVICE_NAME, "/", "org.freedesktop.DBus.ObjectManager",
        "GetManagedObjects");
    sdbusplus::message::message resp = dbus.call(getObjects);
    if (resp.is_method_error())
    {
        std::cerr << "replaceCacheFru: error getting managed objects\n";
        return IPMI_CC_RESPONSE_ERROR;
    }
    ManagedObjectType frus;
    resp.read(frus);

    deviceHashes.clear();

    // hash the object paths to create unique device id's. increment on
    // collision
    std::hash<std::string> hasher;
    for (const auto& fru : frus)
    {
        auto fruIface = fru.second.find("xyz.openbmc_project.FruDevice");
        if (fruIface == fru.second.end())
        {
            continue;
        }

        auto busFind = fruIface->second.find("BUS");
        auto addrFind = fruIface->second.find("ADDRESS");
        if (busFind == fruIface->second.end() ||
            addrFind == fruIface->second.end())
        {
            std::cerr << "fru device missing Bus or Address" << fru.first.str
                      << "\n";
            continue;
        }

        uint8_t fruBus =
            sdbusplus::message::variant_ns::get<uint32_t>(busFind->second);
        uint8_t fruAddr =
            sdbusplus::message::variant_ns::get<uint32_t>(addrFind->second);

        uint8_t fruHash = 0;
        if (fruBus == 0 && fruAddr == 0)
        {
            // fruHash = 0; baseboard specialization
        }
        else
        {
            fruHash = hasher(fru.first.str);
            // can't be 0xFF based on spec, and 0 is reserved for baseboard
            if (fruHash == 0 || fruHash == 0xFF)
            {
                fruHash = 1;
            }
        }
        std::pair<uint8_t, uint8_t> newDev(fruBus, fruAddr);

        bool emplacePassed = false;
        while (!emplacePassed)
        {
            auto resp = deviceHashes.emplace(fruHash, newDev);
            emplacePassed = resp.second;
            if (!emplacePassed)
            {
                fruHash++;
                // can't be 0xFF based on spec, and 0 is reserved for baseboard
                if (fruHash == 0XFF)
                {
                    fruHash = 0x1;
                }
            }
        }
        if (DEBUG)
        {
            std::cout << fru.first.str << " inserted at "
                      << static_cast<int>(fruHash) << "\n";
        }
    }
    auto deviceFind = deviceHashes.find(devId);
    if (deviceFind == deviceHashes.end())
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }

    fruCache.clear();
    sdbusplus::message::message getRawFru = dbus.new_method_call(
        FRU_DEVICE_SERVICE_NAME, "/xyz/openbmc_project/FruDevice",
        "xyz.openbmc_project.FruDeviceManager", "GetRawFru");
    cacheBus = deviceFind->second.first;
    cacheAddr = deviceFind->second.second;
    getRawFru.append(cacheBus, cacheAddr);
    sdbusplus::message::message getRawResp = dbus.call(getRawFru);
    if (getRawResp.is_method_error())
    {
        lastDevId = 0xFF;
        cacheBus = 0xFF;
        cacheAddr = 0xFF;
        std::cerr << "replaceCacheFru: error getting raw fru\n";
        return IPMI_CC_RESPONSE_ERROR;
    }

    getRawResp.read(fruCache);
    lastDevId = devId;
    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_storage_read_fru_data(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                      ipmi_request_t request,
                                      ipmi_response_t response,
                                      ipmi_data_len_t data_len,
                                      ipmi_context_t context)
{
    if (*data_len != 4)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t devId = *(static_cast<uint8_t*>(request));
    uint16_t offset = (*(static_cast<uint8_t*>(request) + 2) << 8) |
                      *(static_cast<uint8_t*>(request) + 1);
    uint8_t readCount = *(static_cast<uint8_t*>(request) + 3);

    if (readCount > MAX_MESSAGE_SIZE - 1)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    ipmi_return_codes status = replaceCacheFru(devId);

    if (status != IPMI_CC_OK)
    {
        return status;
    }

    uint8_t fromFruByteLen = 0;
    if (readCount + offset < fruCache.size())
    {
        fromFruByteLen = readCount;
    }
    else if (fruCache.size() > offset)
    {
        fromFruByteLen = fruCache.size() - offset;
    }
    uint8_t padByteLen = readCount - fromFruByteLen;
    uint8_t* respPtr = static_cast<uint8_t*>(response);
    *respPtr = readCount;
    std::copy(fruCache.begin() + offset,
              fruCache.begin() + offset + fromFruByteLen, ++respPtr);
    // if longer than the fru is requested, fill with 0xFF
    if (padByteLen)
    {
        respPtr += fromFruByteLen;
        std::fill(respPtr, respPtr + padByteLen, 0xFF);
    }
    *data_len = readCount + 1;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_storage_write_fru_data(ipmi_netfn_t netfn, ipmi_cmd_t cmd,
                                       ipmi_request_t request,
                                       ipmi_response_t response,
                                       ipmi_data_len_t data_len,
                                       ipmi_context_t context)
{
    if (*data_len < 4)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }
    uint8_t reqDev = *(static_cast<uint8_t*>(request));
    uint16_t reqOffset = (*(static_cast<uint8_t*>(request) + 2) << 8) |
                         *(static_cast<uint8_t*>(request) + 1);

    uint8_t* reqData = (static_cast<uint8_t*>(request) + 3);
    uint8_t writeLen = *data_len - 3;

    ipmi_return_codes status = replaceCacheFru(reqDev);
    if (status != IPMI_CC_OK)
    {
        return status;
    }
    int lastWriteAddr = reqOffset + writeLen;
    if (fruCache.size() < lastWriteAddr)
    {
        fruCache.resize(reqOffset + writeLen);
    }

    std::copy(reqData, reqData + writeLen, fruCache.begin() + reqOffset);

    bool atEnd = false;

    if (fruCache.size() >= sizeof(fruHeader_t))
    {

        fruHeader_t* header = reinterpret_cast<fruHeader_t*>(fruCache.data());

        int lastRecordStart =
            std::max(header->internalOffset,
                     std::max(header->chassisOffset,
                              std::max(header->boardOffset,
                                       std::max(header->productOffset,
                                                header->multiRecordOffset))));

        lastRecordStart *= 8; // header starts in are multiples of 8 bytes

        // get the length of the area in multiples of 8 bytes
        if (lastWriteAddr > (lastRecordStart + 1))
        {
            // second bit in record area is the length
            int areaLength(fruCache[lastRecordStart + 1]);
            areaLength *= 8; // it is in multiples of 8 bytes

            if (lastWriteAddr >= (areaLength + lastRecordStart))
            {
                atEnd = true;
            }
        }
    }
    if (atEnd)
    {
        // cancel timer, we're at the end so might as well send it
        cacheTimer->setTimer(SD_EVENT_OFF);
        if (!writeFru())
        {
            return IPMI_CC_INVALID_FIELD_REQUEST;
        }
    }
    else
    {
        // start a timer, if no further data is sent in CACHE_TIMEOUT_SECONDS
        // seconds, check to see if it is valid
        createTimer();
        cacheTimer->startTimer(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::seconds(CACHE_TIMEOUT_SECONDS)));
    }

    *data_len = 1;
    uint8_t* respPtr = static_cast<uint8_t*>(response);
    *respPtr = writeLen;

    return IPMI_CC_OK;
}

ipmi_ret_t ipmi_storage_get_fru_inv_area_info(
    ipmi_netfn_t netfn, ipmi_cmd_t cmd, ipmi_request_t request,
    ipmi_response_t response, ipmi_data_len_t data_len, ipmi_context_t context)
{
    if (*data_len != 1)
    {
        return IPMI_CC_REQ_DATA_LEN_INVALID;
    }

    uint8_t reqDev = *(static_cast<uint8_t*>(request));
    ipmi_return_codes status = replaceCacheFru(reqDev);

    if (status != IPMI_CC_OK)
    {
        return status;
    }

    getFruAreaResp_t* respPtr = static_cast<getFruAreaResp_t*>(response);
    respPtr->inventorySizeLSB = fruCache.size() & 0xFF;
    respPtr->inventorySizeMSB = fruCache.size() >> 8;
    respPtr->accessType = static_cast<uint8_t>(getFruAreaAccessType::byte);

    *data_len = sizeof(getFruAreaResp_t);
    return IPMI_CC_OK;
}

ipmi_ret_t getFruSdrCount(size_t& count)
{
    ipmi_ret_t ret = replaceCacheFru(0);
    if (ret != IPMI_CC_OK)
    {
        return ret;
    }
    count = deviceHashes.size();
    return IPMI_CC_OK;
}

ipmi_ret_t getFruSdrs(size_t index, get_sdr::SensorDataFruRecord& resp)
{
    ipmi_ret_t ret = replaceCacheFru(0); // this will update the hash list
    if (ret != IPMI_CC_OK)
    {
        return ret;
    }
    if (deviceHashes.size() < index)
    {
        return IPMI_CC_INVALID_FIELD_REQUEST;
    }
    auto device = deviceHashes.begin() + index;
    uint8_t& bus = device->second.first;
    uint8_t& address = device->second.second;

    ManagedObjectType frus;

    sdbusplus::message::message getObjects = dbus.new_method_call(
        FRU_DEVICE_SERVICE_NAME, "/", "org.freedesktop.DBus.ObjectManager",
        "GetManagedObjects");
    try
    {
        sdbusplus::message::message resp = dbus.call(getObjects);
        resp.read(frus);
    }
    catch (sdbusplus::exception_t&)
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    boost::container::flat_map<std::string, DbusVariant>* fruData = nullptr;
    auto fru =
        std::find_if(frus.begin(), frus.end(),
                     [bus, address, &fruData](ManagedEntry& entry) {
                         auto findFruDevice =
                             entry.second.find("xyz.openbmc_project.FruDevice");
                         if (findFruDevice == entry.second.end())
                         {
                             return false;
                         }
                         fruData = &(findFruDevice->second);
                         auto findBus = findFruDevice->second.find("BUS");
                         auto findAddress =
                             findFruDevice->second.find("ADDRESS");
                         if (findBus == findFruDevice->second.end() ||
                             findAddress == findFruDevice->second.end())
                         {
                             return false;
                         }
                         if (sdbusplus::message::variant_ns::get<uint32_t>(
                                 findBus->second) != bus)
                         {
                             return false;
                         }
                         if (sdbusplus::message::variant_ns::get<uint32_t>(
                                 findAddress->second) != address)
                         {
                             return false;
                         }
                         return true;
                     });
    if (fru == frus.end())
    {
        return IPMI_CC_RESPONSE_ERROR;
    }
    std::string name;
    auto findProductName = fruData->find("BOARD_PRODUCT_NAME");
    auto findBoardName = fruData->find("PRODUCT_PRODUCT_NAME");
    if (findProductName != fruData->end())
    {
        name = sdbusplus::message::variant_ns::get<std::string>(
            findProductName->second);
    }
    else if (findBoardName != fruData->end())
    {
        name = sdbusplus::message::variant_ns::get<std::string>(
            findBoardName->second);
    }
    else
    {
        name = "UNKNOWN";
    }
    if (name.size() > maxFruSdrNameSize)
    {
        name = name.substr(0, maxFruSdrNameSize);
    }
    size_t sizeDiff = maxFruSdrNameSize - name.size();

    resp.header.record_id_lsb = 0x0; // calling code is to implement these
    resp.header.record_id_msb = 0x0;
    resp.header.sdr_version = IPMI_SDR_VERSION;
    resp.header.record_type = 0x11; // FRU Device Locator
    resp.header.record_length = sizeof(resp.body) + sizeof(resp.key) - sizeDiff;
    resp.key.deviceAddress = 0x20;
    resp.key.fruID = device->first;
    resp.key.accessLun = 0x80; // logical / physical fru device
    resp.key.channelNumber = 0x0;
    resp.body.reserved = 0x0;
    resp.body.deviceType = 0x10;
    resp.body.entityID = 0x0;
    resp.body.entityInstance = 0x1;
    resp.body.oem = 0x0;
    resp.body.deviceIDLen = name.size();
    name.copy(resp.body.deviceID, name.size());

    return IPMI_CC_OK;
}

void register_netfn_storage_functions()
{
    // <Get FRU Inventory Area Info>
    print_registration(NETFUN_STORAGE,
                       ipmi_netfn_storage_cmds::IPMI_CMD_GET_FRU_INV_AREA_INFO);
    ipmi_register_callback(
        NETFUN_STORAGE, ipmi_netfn_storage_cmds::IPMI_CMD_GET_FRU_INV_AREA_INFO,
        NULL, ipmi_storage_get_fru_inv_area_info, PRIVILEGE_OPERATOR);

    // <Add READ FRU Data
    print_registration(NETFUN_STORAGE,
                       ipmi_netfn_storage_cmds::IPMI_CMD_READ_FRU_DATA);
    ipmi_register_callback(
        NETFUN_STORAGE, ipmi_netfn_storage_cmds::IPMI_CMD_READ_FRU_DATA, NULL,
        ipmi_storage_read_fru_data, PRIVILEGE_OPERATOR);

    // <Add WRITE FRU Data
    print_registration(NETFUN_STORAGE,
                       ipmi_netfn_storage_cmds::IPMI_CMD_WRITE_FRU_DATA);
    ipmi_register_callback(
        NETFUN_STORAGE, ipmi_netfn_storage_cmds::IPMI_CMD_WRITE_FRU_DATA, NULL,
        ipmi_storage_write_fru_data, PRIVILEGE_OPERATOR);
}
} // namespace storage
} // namespace ipmi